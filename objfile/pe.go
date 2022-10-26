// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// Parsing of PE executables (Microsoft Windows).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/mandiant/GoReSym/debug/dwarf"
	"github.com/mandiant/GoReSym/debug/pe"
)

type peFile struct {
	pe *pe.File
}

func openPE(r io.ReaderAt) (rawFile, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &peFile{f}, nil
}

func (f *peFile) read_memory(VA uint64, size uint64) (data []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	}

	VA -= imageBase
	for _, sect := range f.pe.Sections {
		if uint64(sect.VirtualAddress) <= VA && VA <= uint64(sect.VirtualAddress+sect.Size-1) {
			n := uint64(sect.VirtualAddress+sect.Size) - VA
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := sect.ReadAt(data, int64(VA-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, fmt.Errorf("Reading section data failed")
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("Failed to read memory")
}

func (f *peFile) symbols() ([]Sym, error) {
	// Build sorted list of addresses of all symbols.
	// We infer the size of a symbol by looking at where the next symbol begins.
	var addrs []uint64

	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	}

	var syms []Sym
	for _, s := range f.pe.Symbols {
		const (
			N_UNDEF = 0  // An undefined (extern) symbol
			N_ABS   = -1 // An absolute symbol (e_value is a constant, not an address)
			N_DEBUG = -2 // A debugging symbol
		)
		sym := Sym{Name: s.Name, Addr: uint64(s.Value), Code: '?'}
		switch s.SectionNumber {
		case N_UNDEF:
			sym.Code = 'U'
		case N_ABS:
			sym.Code = 'C'
		case N_DEBUG:
			sym.Code = '?'
		default:
			if s.SectionNumber < 0 || len(f.pe.Sections) < int(s.SectionNumber) {
				return nil, fmt.Errorf("invalid section number in symbol table")
			}
			sect := f.pe.Sections[s.SectionNumber-1]
			const (
				text  = 0x20
				data  = 0x40
				bss   = 0x80
				permW = 0x80000000
			)
			ch := sect.Characteristics
			switch {
			case ch&text != 0:
				sym.Code = 'T'
			case ch&data != 0:
				if ch&permW == 0 {
					sym.Code = 'R'
				} else {
					sym.Code = 'D'
				}
			case ch&bss != 0:
				sym.Code = 'B'
			}
			sym.Addr += imageBase + uint64(sect.VirtualAddress)
		}
		syms = append(syms, sym)
		addrs = append(addrs, sym.Addr)
	}

	sort.Sort(uint64s(addrs))
	for i := range syms {
		j := sort.Search(len(addrs), func(x int) bool { return addrs[x] > syms[i].Addr })
		if j < len(addrs) {
			syms[i].Size = int64(addrs[j] - syms[i].Addr)
		}
	}

	return syms, nil
}

func (f *peFile) pcln_scan() (candidates []PclntabCandidate, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return nil, fmt.Errorf("pe file format not recognized")
	}

	// 1) Locate pclntab via symbols (standard way)
	foundpcln := false
	var pclntab []byte

	if pclntab, err = loadPETable(f.pe, "runtime.pclntab", "runtime.epclntab"); err == nil {
		foundpcln = true
	} else {
		// We didn't find the symbols, so look for the names used in 1.3 and earlier.
		// TODO: Remove code looking for the old symbols when we no longer care about 1.3.
		var err2 error
		if pclntab, err2 = loadPETable(f.pe, "pclntab", "epclntab"); err2 == nil {
			foundpcln = true
		}
	}

	// 2) if not found, byte scan for it
ExitScan:
	for _, sec := range f.pe.Sections {
		// malware can split the pclntab across multiple sections, re-merge
		data := f.pe.DataAfterSection(sec)

		if !foundpcln {
			// https://github.com/golang/go/blob/2cb9042dc2d5fdf6013305a077d013dbbfbaac06/src/debug/gosym/pclntab.go#L172
			pclntab_sigs := [][]byte{[]byte("\xFB\xFF\xFF\xFF\x00\x00"), []byte("\xFA\xFF\xFF\xFF\x00\x00"), []byte("\xF0\xFF\xFF\xFF\x00\x00"),
				[]byte("\xFF\xFF\xFF\xFB\x00\x00"), []byte("\xFF\xFF\xFF\xFA\x00\x00"), []byte("\xFF\xFF\xFF\xF0\x00\x00")}
			matches := findAllOccurrences(data, pclntab_sigs)
			for _, pclntab_idx := range matches {
				if pclntab_idx != -1 {
					pclntab = data[pclntab_idx:]

					var candidate PclntabCandidate
					candidate.Pclntab = pclntab

					candidate.SecStart = imageBase + uint64(sec.VirtualAddress)
					candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

					candidates = append(candidates, candidate)
					// we must scan all signature for all sections. DO NOT BREAK
				}
			}
		} else {
			// 3) if we found it earlier, figure out which section base to return (might be wrong for packed things)
			pclntab_idx := bytes.Index(data, pclntab)
			if pclntab_idx != -1 {
				var candidate PclntabCandidate
				candidate.Pclntab = pclntab

				candidate.SecStart = imageBase + uint64(sec.VirtualAddress)
				candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

				candidates = append(candidates, candidate)
				break ExitScan
			}
		}
	}

	return candidates, nil
}

func (f *peFile) pcln() (candidates []PclntabCandidate, err error) {
	candidates, err = f.pcln_scan()
	if err != nil {
		return nil, err
	}

	// 4) symtab is completely optional, but try to find it
	var symtab []byte
	if symtab, err = loadPETable(f.pe, "runtime.symtab", "runtime.esymtab"); err != nil {
		symtab, err = loadPETable(f.pe, "symtab", "esymtab")
	}

	if err == nil {
		for _, c := range candidates {
			c.Symtab = symtab
		}
	}

	return candidates, nil
}

func (f *peFile) moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (secStart uint64, moduledataRVA uint64, moduledata []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return 0, 0, nil, fmt.Errorf("pe file format not recognized")
	}

	foundmodule := false
	foundsec := false
	var moduledata_idx int = 0

	// first type to find via symbols as per normal
	if sym, err := findPESymbol(f.pe, "runtime.firstmoduledata"); err == nil {
		if uint32(sym.SectionNumber) <= uint32(len(f.pe.Sections)) {
			sect := f.pe.Sections[sym.SectionNumber-1]
			data, err := sect.Data()
			if err == nil && sym.Value < uint32(len(data)) {
				moduledata = data[sym.Value:]
				foundmodule = true
			}
		}
	} else {
		// TODO: do we want to handle legacy symbols??
	}

scan:
	for _, sec := range f.pe.Sections {
		// malware can split the pclntab across multiple sections, re-merge
		data := f.pe.DataAfterSection(sec)

		if !foundmodule {
			// fall back to scanning for structure using address of pclntab, which is first value in struc
			var pclntabVA_bytes []byte
			if is64bit {
				pclntabVA_bytes = make([]byte, 8)
				if littleendian {
					binary.LittleEndian.PutUint64(pclntabVA_bytes, pclntabVA)
				} else {
					binary.BigEndian.PutUint64(pclntabVA_bytes, pclntabVA)
				}
			} else {
				pclntabVA_bytes = make([]byte, 4)
				if littleendian {
					binary.LittleEndian.PutUint32(pclntabVA_bytes, uint32(pclntabVA))
				} else {
					binary.BigEndian.PutUint32(pclntabVA_bytes, uint32(pclntabVA))
				}
			}

			moduledata_idx = bytes.Index(data, pclntabVA_bytes)
			if moduledata_idx != -1 && moduledata_idx < int(sec.Size) {
				moduledata = data[moduledata_idx:]
				secStart = imageBase + uint64(sec.VirtualAddress)

				// optionally consult ignore list, to skip past previous (bad) scan results
				if ignorelist != nil {
					for _, ignore := range ignorelist {
						if ignore == secStart+uint64(moduledata_idx) {
							continue scan
						}
					}
				}

				foundsec = true
				foundmodule = true
				break
			}
		} else {
			// locate the VA of the already found data
			moduledata_idx = bytes.Index(data, moduledata)
			if moduledata_idx != -1 && moduledata_idx < int(sec.Size) {
				secStart = imageBase + uint64(sec.VirtualAddress)
				foundsec = true
				break
			}
		}
	}

	if !foundmodule {
		return 0, 0, nil, fmt.Errorf("moduledata could not be located")
	}

	if !foundsec {
		return 0, 0, nil, fmt.Errorf("moduledata containing section could not be located")
	}

	return secStart, secStart + uint64(moduledata_idx), moduledata, nil
}

func (f *peFile) text() (textStart uint64, text []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return 0, nil, fmt.Errorf("pe file format not recognized")
	}
	sect := f.pe.Section(".text")
	if sect == nil {
		return 0, nil, fmt.Errorf("text section not found")
	}
	textStart = imageBase + uint64(sect.VirtualAddress)
	text, err = sect.Data()
	return
}

func (f *peFile) rdata() (textStart uint64, text []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return 0, nil, fmt.Errorf("pe file format not recognized")
	}
	sect := f.pe.Section(".rdata")
	if sect == nil {
		return 0, nil, fmt.Errorf("rdata section not found")
	}
	textStart = imageBase + uint64(sect.VirtualAddress)
	text, err = sect.Data()
	return
}

func findPESymbol(f *pe.File, name string) (*pe.Symbol, error) {
	for _, s := range f.Symbols {
		if s.Name != name {
			continue
		}
		if s.SectionNumber <= 0 {
			return nil, fmt.Errorf("symbol %s: invalid section number %d", name, s.SectionNumber)
		}
		if len(f.Sections) < int(s.SectionNumber) {
			return nil, fmt.Errorf("symbol %s: section number %d is larger than max %d", name, s.SectionNumber, len(f.Sections))
		}
		return s, nil
	}
	return nil, fmt.Errorf("no %s symbol found", name)
}

func loadPETable(f *pe.File, sname, ename string) ([]byte, error) {
	ssym, err := findPESymbol(f, sname)
	if err != nil {
		return nil, err
	}
	esym, err := findPESymbol(f, ename)
	if err != nil {
		return nil, err
	}
	if ssym.SectionNumber != esym.SectionNumber {
		return nil, fmt.Errorf("%s and %s symbols must be in the same section", sname, ename)
	}

	if uint32(ssym.SectionNumber) > uint32(len(f.Sections)) {
		return nil, fmt.Errorf("pclntab symbol section index out of range")
	}

	sect := f.Sections[ssym.SectionNumber-1]
	data, err := sect.Data()
	if err != nil {
		return nil, err
	}

	if ssym.Value > esym.Value || esym.Value > uint32(len(data)) {
		return nil, fmt.Errorf("pclntab symbols are malformed")
	}

	return data[ssym.Value:esym.Value], nil
}

func (f *peFile) goarch() string {
	switch f.pe.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	default:
		return ""
	}
}

func (f *peFile) loadAddress() (uint64, error) {
	return 0, fmt.Errorf("unknown load address")
}

func (f *peFile) dwarf() (*dwarf.Data, error) {
	return f.pe.DWARF()
}
