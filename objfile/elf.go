// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Parsing of ELF executables (Linux, FreeBSD, and so on).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/stevemk14ebr/GoReSym/debug/dwarf"
	"github.com/stevemk14ebr/GoReSym/debug/elf"
)

type elfFile struct {
	elf *elf.File
}

func openElf(r io.ReaderAt) (rawFile, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &elfFile{f}, nil
}

func (f *elfFile) read_memory(VA uint64, size uint64) (data []byte, err error) {
	for _, prog := range f.elf.Progs {
		if prog.Vaddr <= VA && VA <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - VA
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(VA-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("Failed to read memory")
}

func (f *elfFile) symbols() ([]Sym, error) {
	elfSyms, err := f.elf.Symbols()
	if err != nil {
		return nil, err
	}

	var syms []Sym
	for _, s := range elfSyms {
		sym := Sym{Addr: s.Value, Name: s.Name, Size: int64(s.Size), Code: '?'}
		switch s.Section {
		case elf.SHN_UNDEF:
			sym.Code = 'U'
		case elf.SHN_COMMON:
			sym.Code = 'B'
		default:
			i := int(s.Section)
			if i < 0 || i >= len(f.elf.Sections) {
				break
			}
			sect := f.elf.Sections[i]
			switch sect.Flags & (elf.SHF_WRITE | elf.SHF_ALLOC | elf.SHF_EXECINSTR) {
			case elf.SHF_ALLOC | elf.SHF_EXECINSTR:
				sym.Code = 'T'
			case elf.SHF_ALLOC:
				sym.Code = 'R'
			case elf.SHF_ALLOC | elf.SHF_WRITE:
				sym.Code = 'D'
			}
		}
		if elf.ST_BIND(s.Info) == elf.STB_LOCAL {
			sym.Code += 'a' - 'A'
		}
		syms = append(syms, sym)
	}

	return syms, nil
}

func (f *elfFile) pcln_scan() (secStart uint64, pclntabVA uint64, pclntab []byte, err error) {
	// 1) Locate pclntab via symbols (standard way)
	foundpcln := false
	foundsec := false
	pclntab = nil
	secStart = 0
	var pclntab_idx int = 0

	if sect := f.elf.Section(".gopclntab"); sect != nil {
		if pclntab, err = sect.Data(); err == nil {
			foundpcln = true
		}
	}

	// 2) if not found, byte scan for it
ExitScan:
	for _, sec := range f.elf.Sections {
		// first section is all zeros, skip
		if sec.Type == elf.SHT_NULL {
			continue
		}

		// malware can split the pclntab across multiple sections, re-merge
		data := f.elf.DataAfterSection(sec.Name)

		if !foundpcln {
			// https://github.com/golang/go/blob/2cb9042dc2d5fdf6013305a077d013dbbfbaac06/src/debug/gosym/pclntab.go#L172
			pclntab_sigs := [][]byte{[]byte("\xFB\xFF\xFF\xFF\x00\x00"), []byte("\xFA\xFF\xFF\xFF\x00\x00"), []byte("\xF0\xFF\xFF\xFF\x00\x00"),
				[]byte("\xFF\xFF\xFF\xFB\x00\x00"), []byte("\xFF\xFF\xFF\xFA\x00\x00"), []byte("\xFF\xFF\xFF\xF0\x00\x00")}
			for _, v := range pclntab_sigs {
				pclntab_idx = bytes.Index(data, v)
				if pclntab_idx != -1 && pclntab_idx < int(sec.Size) {
					pclntab = data[pclntab_idx:]
					secStart = uint64(sec.Addr)
					foundsec = true
					foundpcln = true
					break ExitScan
				}
			}
		} else {
			// 3) if we found it earlier, figure out which section base to return (might be wrong for packed things)
			pclntab_idx = bytes.Index(data, pclntab)
			if pclntab_idx != -1 && pclntab_idx < int(sec.Size) {
				secStart = uint64(sec.Addr)
				foundsec = true
				break ExitScan
			}
		}
	}

	if !foundpcln {
		return 0, 0, nil, fmt.Errorf("pclntab could not be located")
	}

	if !foundsec {
		return 0, 0, nil, fmt.Errorf("pclntab containing section could not be located")
	}

	return secStart, secStart + uint64(pclntab_idx), pclntab, nil
}

func (f *elfFile) pcln() (secStart uint64, symtab []byte, pclntabVA uint64, pclntab []byte, err error) {
	secStart, pclntabVA, pclntab, err = f.pcln_scan()
	if err != nil {
		return 0, nil, 0, nil, err
	}

	// 4) symtab is completely optional, but try to find it
	if sect := f.elf.Section(".gosymtab"); sect != nil {
		if symtab, err = sect.Data(); err != nil {
			return secStart, []byte{}, pclntabVA, pclntab, nil
		}
	}
	return secStart, symtab, pclntabVA, pclntab, nil
}

func (f *elfFile) moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (secStart uint64, moduledataVA uint64, moduledata []byte, err error) {
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
	for _, sec := range f.elf.Sections {
		// first section is all zeros, skip
		if sec.Type == elf.SHT_NULL {
			continue
		}

		// malware can split the pclntab across multiple sections, re-merge
		data := f.elf.DataAfterSection(sec.Name)
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

func (f *elfFile) text() (textStart uint64, text []byte, err error) {
	sect := f.elf.Section(".text")
	if sect == nil {
		return 0, nil, fmt.Errorf("text section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *elfFile) rdata() (textStart uint64, text []byte, err error) {
	sect := f.elf.Section(".rodata")
	if sect == nil {
		return 0, nil, fmt.Errorf("rdata section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *elfFile) rel_rdata() (textStart uint64, text []byte, err error) {
	sect := f.elf.Section(".data.rel.ro")
	if sect == nil {
		return 0, nil, fmt.Errorf(".data.rel.ro section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *elfFile) goarch() string {
	switch f.elf.Machine {
	case elf.EM_386:
		return "386"
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_PPC64:
		if f.elf.ByteOrder == binary.LittleEndian {
			return "ppc64le"
		}
		return "ppc64"
	case elf.EM_S390:
		return "s390x"
	}
	return ""
}

func (f *elfFile) loadAddress() (uint64, error) {
	for _, p := range f.elf.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			return p.Vaddr, nil
		}
	}
	return 0, fmt.Errorf("unknown load address")
}

func (f *elfFile) dwarf() (*dwarf.Data, error) {
	return f.elf.DWARF()
}
