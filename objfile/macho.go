// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// Parsing of Mach-O executables (OS X).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/mandiant/GoReSym/debug/dwarf"
	"github.com/mandiant/GoReSym/debug/macho"
)

const stabTypeMask = 0xe0

type machoFile struct {
	macho *macho.File
}

func openMacho(r io.ReaderAt) (rawFile, error) {
	f, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &machoFile{f}, nil
}

func (f *machoFile) read_memory(VA uint64, size uint64) (data []byte, err error) {
	for _, load := range f.macho.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= VA && VA <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			n := seg.Addr + seg.Filesz - VA
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := seg.ReadAt(data, int64(VA-seg.Addr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("Failed to read memory")
}

func (f *machoFile) symbols() ([]Sym, error) {
	if f.macho.Symtab == nil {
		return nil, nil
	}

	// Build sorted list of addresses of all symbols.
	// We infer the size of a symbol by looking at where the next symbol begins.
	var addrs []uint64
	for _, s := range f.macho.Symtab.Syms {
		// Skip stab debug info.
		if s.Type&stabTypeMask == 0 {
			addrs = append(addrs, s.Value)
		}
	}
	sort.Sort(uint64s(addrs))

	var syms []Sym
	for _, s := range f.macho.Symtab.Syms {
		if s.Type&stabTypeMask != 0 {
			// Skip stab debug info.
			continue
		}
		sym := Sym{Name: s.Name, Addr: s.Value, Code: '?'}
		i := sort.Search(len(addrs), func(x int) bool { return addrs[x] > s.Value })
		if i < len(addrs) {
			sym.Size = int64(addrs[i] - s.Value)
		}
		if s.Sect == 0 {
			sym.Code = 'U'
		} else if int(s.Sect) <= len(f.macho.Sections) {
			sect := f.macho.Sections[s.Sect-1]
			switch sect.Seg {
			case "__TEXT", "__DATA_CONST":
				sym.Code = 'R'
			case "__DATA":
				sym.Code = 'D'
			}
			switch sect.Seg + " " + sect.Name {
			case "__TEXT __text":
				sym.Code = 'T'
			case "__DATA __bss", "__DATA __noptrbss":
				sym.Code = 'B'
			}
		}
		syms = append(syms, sym)
	}

	return syms, nil
}

func (f *machoFile) pcln_scan() (candidates []PclntabCandidate, err error) {
	// 1) Locate pclntab via symbols (standard way)
	foundpcln := false
	symbol_method := false
	var pclntab_sym []byte
	var pclntab []byte
	if sect := f.macho.Section("__gopclntab"); sect != nil {
		if pclntab, err = sect.Data(); err == nil {
			foundpcln = true
		}
	}

	// 2) if not found, byte scan for it
	var virtualOffset uint64 = 0
	var pclntabPtr uint32 = 0
	pclntab_sigs := [][]byte{
		[]byte("\xF1\xFF\xFF\xFF\x00\x00"),
		[]byte("\xF0\xFF\xFF\xFF\x00\x00"),
		[]byte("\xFA\xFF\xFF\xFF\x00\x00"),
		[]byte("\xFB\xFF\xFF\xFF\x00\x00"),   
		[]byte("\xFF\xFF\xFF\xFB\x00\x00"), 
		[]byte("\xFF\xFF\xFF\xFA\x00\x00"), 
		[]byte("\xFF\xFF\xFF\xF0\x00\x00"), 
		[]byte("\xFF\xFF\xFF\xF1\x00\x00"),
	}
	for _, sec := range f.macho.Sections {
		// malware can split the pclntab across multiple sections, re-merge

		data := f.macho.DataAfterSection(sec)
		sectionData, _ := sec.Data()
		if uint64(len(data)) < sec.Size {
			continue
		}

		// https://github.com/golang/go/blob/2cb9042dc2d5fdf6013305a077d013dbbfbaac06/src/debug/gosym/pclntab.go#L172
		matches := findAllOccurrences(data, pclntab_sigs)
		for _, pclntab_idx := range matches {
			if pclntab_idx != -1 && pclntab_idx < int(sec.Size) {
				pclntab = data[pclntab_idx:]

				var candidate PclntabCandidate
				candidate.Pclntab = pclntab

				candidate.SecStart = uint64(sec.Addr)
				candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

				candidates = append(candidates, candidate)
				// we must scan all signature for all sections. DO NOT BREAK
			}
		}
		
		pcHeader := findModuleInitPCHeader(machoScanner, sectionData)
		if len(pcHeader) == 2 {
			virtualOffset = (pcHeader[1] + sec.Addr) + pcHeader[0]
		}

		if virtualOffset != 0 {
			if virtualOffset >= sec.Addr && virtualOffset <= (sec.Addr + sec.Size) {
				// The virtual offset of moduledata is within this section
				moduleDataOffset := virtualOffset - sec.Addr
				pclntabPtr = binary.LittleEndian.Uint32(data[moduleDataOffset:][:4])
				virtualOffset = 0
			}
			
		}

		if foundpcln && !symbol_method {
			// 3) if we found it earlier, figure out which section base to return (might be wrong for packed things)
			pclntab_idx := bytes.Index(data, pclntab_sym)
			if pclntab_idx != -1 {
				var candidate PclntabCandidate
				candidate.Pclntab = pclntab_sym

				candidate.SecStart = uint64(sec.Addr)
				candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

				candidates = append(candidates, candidate)

				symbol_method = true
			}
		}
	}

	// 4) Find the section containing the pclntab, get the offset, repair the magic, and add as a candidate
	if pclntabPtr != 0 {
		for _, sec := range f.macho.Sections {
			data := f.macho.DataAfterSection(sec)
			if uint64(pclntabPtr) >= sec.Addr && uint64(pclntabPtr) <= (sec.Addr + sec.Size) {
				pclntabOffset := uint64(pclntabPtr) - sec.Addr

				for _, sig := range pclntab_sigs {
					var candidate PclntabCandidate

					pclntab = append(sig, data[pclntabOffset+uint64(len(sig)):]...)
					
					candidate.Pclntab = pclntab

					candidate.SecStart = uint64(sec.Addr)
					candidate.PclntabVA = candidate.SecStart + uint64(pclntabOffset)

					candidates = append(candidates, candidate)
				}
				break
			}
		}
	}

	return candidates, nil
}

func (f *machoFile) pcln() (candidates []PclntabCandidate, err error) {
	candidates, err = f.pcln_scan()
	if err != nil {
		return nil, err
	}

	// 4) symtab is completely optional, but try to find it
	var symtab []byte
	if sect := f.macho.Section("__gosymtab"); sect != nil {
		symtab, err = sect.Data()
	}

	if err == nil {
		for _, c := range candidates {
			c.Symtab = symtab
		}
	}

	return candidates, nil
}

func (f *machoFile) moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (secStart uint64, moduledataVA uint64, moduledata []byte, err error) {
	foundsym := false
	foundsec := false
	foundmodule := false

	syms, err := f.symbols()
	if err == nil {
		foundsym = false
		for _, sym := range syms {
			// TODO: handle legacy symbols ??
			if sym.Name == "runtime.firstmoduledata" {
				moduledataVA = sym.Addr
				foundsym = true // annoyingly the elf symbols dont give section #, so we delay getting data to later, unlike in pe
				break
			}
		}
	}

scan:
	for _, sec := range f.macho.Sections {
		// malware can split the pclntab across multiple sections, re-merge
		data := f.macho.DataAfterSection(sec)
		if !foundsym {
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

			moduledata_idx := bytes.Index(data, pclntabVA_bytes)
			if moduledata_idx != -1 && moduledata_idx < int(sec.Size) {
				moduledata = data[moduledata_idx:]
				moduledataVA = sec.Addr + uint64(moduledata_idx)
				secStart = sec.Addr

				// optionally consult ignore list, to skip past previous (bad) scan results
				if ignorelist != nil {
					for _, ignore := range ignorelist {
						if ignore == moduledataVA {
							continue scan
						}
					}
				}

				foundsec = true
				foundmodule = true
				break
			}
		} else {
			if moduledataVA > sec.Addr && moduledataVA < sec.Addr+sec.Size {
				sectionoffset := moduledataVA - sec.Addr
				moduledata = data[sectionoffset:]
				secStart = sec.Addr
				foundsec = true
				foundmodule = true
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

	return secStart, moduledataVA, moduledata, nil
}

func (f *machoFile) text() (textStart uint64, text []byte, err error) {
	sect := f.macho.Section("__text")
	if sect == nil {
		return 0, nil, fmt.Errorf("text section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *machoFile) rdata() (textStart uint64, text []byte, err error) {
	sect := f.macho.Section("__DATA")
	if sect == nil {
		return 0, nil, fmt.Errorf("data section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *machoFile) goarch() string {
	switch f.macho.Cpu {
	case macho.Cpu386:
		return "386"
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuPpc64:
		return "ppc64"
	}
	return ""
}

type uint64s []uint64

func (x uint64s) Len() int           { return len(x) }
func (x uint64s) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
func (x uint64s) Less(i, j int) bool { return x[i] < x[j] }

func (f *machoFile) loadAddress() (uint64, error) {
	return 0, fmt.Errorf("unknown load address")
}

func (f *machoFile) dwarf() (*dwarf.Data, error) {
	return f.macho.DWARF()
}
