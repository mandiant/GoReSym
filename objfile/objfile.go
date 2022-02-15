// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package objfile implements portable access to OS-specific executable files.
package objfile

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unsafe"

	"github.com/elliotchance/orderedmap"
	"github.com/stevemk14ebr/GoReSym/debug/dwarf"
	"github.com/stevemk14ebr/GoReSym/debug/gosym"
)

type rawFile interface {
	symbols() (syms []Sym, err error)
	pcln() (textStart uint64, symtab []byte, pclntabVA uint64, pclntab []byte, err error)
	pcln_scan() (secStart uint64, pclntabVA uint64, pclntab []byte, err error)
	moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (secStart uint64, moduledataVA uint64, moduledata []byte, err error)
	read_memory(VA uint64, size uint64) (data []byte, err error)
	text() (textStart uint64, text []byte, err error)
	goarch() string
	loadAddress() (uint64, error)
	dwarf() (*dwarf.Data, error)
}

// A File is an opened executable file.
type File struct {
	r       *os.File
	entries []*Entry
}

type Entry struct {
	name string
	raw  rawFile
}

// A Sym is a symbol defined in an executable file.
type Sym struct {
	Name   string  // symbol name
	Addr   uint64  // virtual address of symbol
	Size   int64   // size in bytes
	Code   rune    // nm code (T for text, D for data, and so on)
	Type   string  // XXX?
	Relocs []Reloc // in increasing Addr order
}

type Reloc struct {
	Addr     uint64 // Address of first byte that reloc applies to.
	Size     uint64 // Number of bytes
	Stringer RelocStringer
}

type RelocStringer interface {
	// insnOffset is the offset of the instruction containing the relocation
	// from the start of the symbol containing the relocation.
	String(insnOffset uint64) string
}

var openers = []func(io.ReaderAt) (rawFile, error){
	openElf,
	openMacho,
	openPE,
}

// Open opens the named file.
// The caller must call f.Close when the file is no longer needed.
func Open(name string) (*File, error) {
	r, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	if f, err := openGoFile(r); err == nil {
		return f, nil
	}
	for _, try := range openers {
		if raw, err := try(r); err == nil {
			return &File{r, []*Entry{{raw: raw}}}, nil
		}
	}
	r.Close()
	return nil, fmt.Errorf("open %s: unrecognized object file or bad filepath", name)
}

func (f *File) Close() error {
	return f.r.Close()
}

func (f *File) Entries() []*Entry {
	return f.entries
}

func (f *File) Symbols() ([]Sym, error) {
	return f.entries[0].Symbols()
}

// previously : func (f *File) PCLineTable() (Liner, error) {
func (f *File) PCLineTable() (*gosym.Table, uint64, error) {
	return f.entries[0].PCLineTable()
}

func (f *File) ModuleDataTable(pclntabVA uint64, runtimeVersion string, version string, is64bit bool, littleendian bool) (secStart uint64, moduleData *ModuleData, err error) {
	return f.entries[0].ModuleDataTable(pclntabVA, runtimeVersion, version, is64bit, littleendian)
}

func (f *File) ParseType(runtimeVersion string, moduleData *ModuleData, typeAddress uint64, is64bit bool, littleendian bool) (types []Type, err error) {
	return f.entries[0].ParseType(runtimeVersion, moduleData, typeAddress, is64bit, littleendian)
}

func (f *File) ParseTypeLinks(runtimeVersion string, moduleData *ModuleData, is64bit bool, littleendian bool) (types []Type, err error) {
	return f.entries[0].ParseTypeLinks(runtimeVersion, moduleData, is64bit, littleendian)
}

func (f *File) ParseITabLinks(runtimeVersion string, moduleData *ModuleData, is64bit bool, littleendian bool) (types []Type, err error) {
	return f.entries[0].ParseITabLinks(runtimeVersion, moduleData, is64bit, littleendian)
}

func (f *File) Text() (uint64, []byte, error) {
	return f.entries[0].Text()
}

func (f *File) GOARCH() string {
	return f.entries[0].GOARCH()
}

func (f *File) LoadAddress() (uint64, error) {
	return f.entries[0].LoadAddress()
}

func (f *File) DWARF() (*dwarf.Data, error) {
	return f.entries[0].DWARF()
}

func (f *File) Disasm() (*Disasm, error) {
	return f.entries[0].Disasm()
}

func (e *Entry) Name() string {
	return e.name
}

func (e *Entry) Symbols() ([]Sym, error) {
	syms, err := e.raw.symbols()
	if err != nil {
		return nil, err
	}
	sort.Sort(byAddr(syms))
	return syms, nil
}

type byAddr []Sym

func (x byAddr) Less(i, j int) bool { return x[i].Addr < x[j].Addr }
func (x byAddr) Len() int           { return len(x) }
func (x byAddr) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

// previously: func (e *Entry) PCLineTable() (Liner, error)
func (e *Entry) PCLineTable() (*gosym.Table, uint64, error) {
	// If the raw file implements Liner directly, use that.
	// Currently, only Go intermediate objects and archives (goobj) use this path.

	// PATCH: DISABLED, We want to gopclntab table 95% of the time
	// if pcln, ok := e.raw.(Liner); ok {
	// 	return pcln, nil
	// }

	// Otherwise, read the pcln tables and build a Liner out of that.
	// https://github.com/golang/go/blob/89f687d6dbc11613f715d1644b4983905293dd33/src/debug/gosym/pclntab.go#L169
	// https://github.com/golang/go/issues/42954
	secStart, symtab, tableVA, pclntab, err := e.raw.pcln()
	if err != nil {
		return nil, 0, err
	}

	table, err := gosym.NewTable(symtab, gosym.NewLineTable(pclntab, secStart))
	if err != nil {
		return nil, 0, err
	}
	return table, tableVA, nil
}

func (e *Entry) ModuleDataTable(pclntabVA uint64, runtimeVersion string, version string, is64bit bool, littleendian bool) (secStart uint64, moduleData *ModuleData, err error) {
	moduleData = &ModuleData{}

	// Major version only, 1.15.5 -> 1.15
	parts := strings.Split(runtimeVersion, ".")
	if len(parts) >= 2 {
		runtimeVersion = parts[0] + "." + parts[1]
	}

	const maxattempts = 5
	var ignorelist []uint64
	for i := 0; i < maxattempts; i++ {
		secStart, moduledataVA, rawmoduleData, err := e.raw.moduledata_scan(pclntabVA, is64bit, littleendian, ignorelist)
		if err != nil {
			continue
		}

		// there's really only 3 main versions for these internal runtime changes 1.2 (<= 1.15), 1.16 (<= 1.17), 1.18 (>= 1.18)
		// this routine needs the pclntab version, NOT the go runtime version (ex: go 1.15 generates 1.2 style tables)
		switch version {
		case "1.18":
			if is64bit {
				var module ModuleData118_64
				err := module.parse(rawmoduleData, littleendian)
				if err != nil {
					return 0, nil, err
				}

				var firstFunc FuncTab118
				ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
				if err != nil {
					return 0, nil, err
				}

				err = firstFunc.parse(ftab_raw, littleendian)
				if err != nil {
					return 0, nil, err
				}

				var textsectmap []Textsect_64
				for i := 0; i < int(module.Textsectmap.Len); i++ {
					var textsect Textsect_64
					var sectSize = uint64(unsafe.Sizeof(textsect))
					textsec_raw, err := e.raw.read_memory(uint64(module.Textsectmap.Data)+uint64(i)*sectSize, sectSize)
					if err != nil {
						continue
					}

					err = textsect.parse(textsec_raw, littleendian)
					if err != nil {
						continue
					}
					textsectmap = append(textsectmap, textsect)
				}

				// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
				// https://github.com/golang/go/blob/9ecb853cf2252f3cd9ed2e7b3401d17df2d1ab06/src/runtime/symtab.go#L630-L632
				if textAddr64(uint64(firstFunc.Entryoffset), uint64(module.Text), textsectmap) != uint64(module.Minpc) {
					// wrong moduledata, try next
					ignorelist = append(ignorelist, moduledataVA)
					continue
				}

				moduleData.VA = moduledataVA
				moduleData.Types = uint64(module.Types)
				moduleData.ETypes = uint64(module.Etypes)
				moduleData.Typelinks = module.Typelinks
				moduleData.ITablinks = module.Itablinks
				return secStart, moduleData, err
			} else {
				var module ModuleData118_32
				err := module.parse(rawmoduleData, littleendian)
				if err != nil {
					return 0, nil, err
				}

				var firstFunc FuncTab118
				ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
				if err != nil {
					return 0, nil, err
				}

				err = firstFunc.parse(ftab_raw, littleendian)
				if err != nil {
					return 0, nil, err
				}

				var textsectmap []Textsect_32
				for i := 0; i < int(module.Textsectmap.Len); i++ {
					var textsect Textsect_32
					var sectSize = uint64(unsafe.Sizeof(textsect))
					textsec_raw, err := e.raw.read_memory(uint64(module.Textsectmap.Data)+uint64(i)*sectSize, sectSize)
					if err != nil {
						continue
					}

					err = textsect.parse(textsec_raw, littleendian)
					if err != nil {
						continue
					}
					textsectmap = append(textsectmap, textsect)
				}

				// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
				// https://github.com/golang/go/blob/9ecb853cf2252f3cd9ed2e7b3401d17df2d1ab06/src/runtime/symtab.go#L630-L632
				if textAddr32(uint64(firstFunc.Entryoffset), uint64(module.Text), textsectmap) != uint64(module.Minpc) {
					// wrong moduledata, try next
					ignorelist = append(ignorelist, moduledataVA)
					continue
				}

				moduleData.VA = moduledataVA
				moduleData.Types = uint64(module.Types)
				moduleData.ETypes = uint64(module.Etypes)
				moduleData.Typelinks.Data = pvoid64(module.Typelinks.Data)
				moduleData.Typelinks.Len = uint64(module.Typelinks.Len)
				moduleData.Typelinks.Capacity = uint64(module.Typelinks.Capacity)

				moduleData.ITablinks.Data = pvoid64(module.Itablinks.Data)
				moduleData.ITablinks.Len = uint64(module.Itablinks.Len)
				moduleData.ITablinks.Capacity = uint64(module.Itablinks.Capacity)
				return secStart, moduleData, err
			}
		case "1.16":
			if is64bit {
				var module ModuleData116_64
				err := module.parse(rawmoduleData, littleendian)
				if err != nil {
					return 0, nil, err
				}

				var firstFunc FuncTab12_116_64
				ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
				if err != nil {
					return 0, nil, err
				}

				err = firstFunc.parse(ftab_raw, littleendian)
				if err != nil {
					return 0, nil, err
				}

				// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
				if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
					// wrong moduledata, try next
					ignorelist = append(ignorelist, moduledataVA)
					continue
				}

				moduleData.VA = moduledataVA
				moduleData.Types = uint64(module.Types)
				moduleData.ETypes = uint64(module.Etypes)
				moduleData.Typelinks = module.Typelinks
				moduleData.ITablinks = module.Itablinks
				return secStart, moduleData, err
			} else {
				var module ModuleData116_32
				err := module.parse(rawmoduleData, littleendian)
				if err != nil {
					return 0, nil, err
				}

				var firstFunc FuncTab12_116_32
				ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
				if err != nil {
					return 0, nil, err
				}

				err = firstFunc.parse(ftab_raw, littleendian)
				if err != nil {
					return 0, nil, err
				}

				// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
				if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
					// wrong moduledata, try next
					ignorelist = append(ignorelist, moduledataVA)
					continue
				}

				moduleData.VA = moduledataVA
				moduleData.Types = uint64(module.Types)
				moduleData.ETypes = uint64(module.Etypes)
				moduleData.Typelinks.Data = pvoid64(module.Typelinks.Data)
				moduleData.Typelinks.Len = uint64(module.Typelinks.Len)
				moduleData.Typelinks.Capacity = uint64(module.Typelinks.Capacity)

				moduleData.ITablinks.Data = pvoid64(module.Itablinks.Data)
				moduleData.ITablinks.Len = uint64(module.Itablinks.Len)
				moduleData.ITablinks.Capacity = uint64(module.Itablinks.Capacity)
				return secStart, moduleData, err
			}

		case "1.2":
			// this layout changes <= 1.5 even though the tab version stays constant
			switch runtimeVersion {
			case "1.5":
				fallthrough
			case "1.6":
				if is64bit {
					var module ModuleData12_r15_r16_64
					err := module.parse(rawmoduleData, littleendian)
					if err != nil {
						return 0, nil, err
					}

					var firstFunc FuncTab12_116_64
					ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
					if err != nil {
						return 0, nil, err
					}

					err = firstFunc.parse(ftab_raw, littleendian)
					if err != nil {
						return 0, nil, err
					}

					// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
					if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
						// wrong moduledata, try next
						ignorelist = append(ignorelist, moduledataVA)
						continue
					}

					// Fake the same Types + Typelinks offsets that later moduledata's use.
					// The base would be the normal typelinks pointer, and then we
					moduleData.VA = moduledataVA
					moduleData.LegacyTypes = module.Typelinks
					return secStart, moduleData, err
				} else {
					var module ModuleData12_r15_r16_32
					err := module.parse(rawmoduleData, littleendian)
					if err != nil {
						return 0, nil, err
					}

					var firstFunc FuncTab12_116_32
					ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
					if err != nil {
						return 0, nil, err
					}

					err = firstFunc.parse(ftab_raw, littleendian)
					if err != nil {
						return 0, nil, err
					}

					// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
					if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
						// wrong moduledata, try next
						ignorelist = append(ignorelist, moduledataVA)
						continue
					}

					moduleData.VA = moduledataVA
					moduleData.LegacyTypes.Data = pvoid64(module.Typelinks.Data)
					moduleData.LegacyTypes.Len = uint64(module.Typelinks.Len)
					moduleData.LegacyTypes.Capacity = uint64(module.Typelinks.Capacity)
					return secStart, moduleData, err
				}
			case "1.7":
				if is64bit {
					var module ModuleData12_r17_64
					err := module.parse(rawmoduleData, littleendian)
					if err != nil {
						return 0, nil, err
					}

					var firstFunc FuncTab12_116_64
					ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
					if err != nil {
						return 0, nil, err
					}

					err = firstFunc.parse(ftab_raw, littleendian)
					if err != nil {
						return 0, nil, err
					}

					// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
					if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
						// wrong moduledata, try next
						ignorelist = append(ignorelist, moduledataVA)
						continue
					}

					// Fake the same Types + Typelinks offsets that later moduledata's use.
					// The base would be the normal typelinks pointer, and then we
					moduleData.VA = moduledataVA
					moduleData.Types = uint64(module.Types)
					moduleData.ETypes = uint64(module.Etypes)
					moduleData.Typelinks = module.Typelinks
					moduleData.ITablinks = module.Itablinks
					return secStart, moduleData, err
				} else {
					var module ModuleData12_r17_32
					err := module.parse(rawmoduleData, littleendian)
					if err != nil {
						return 0, nil, err
					}

					var firstFunc FuncTab12_116_32
					ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
					if err != nil {
						return 0, nil, err
					}

					err = firstFunc.parse(ftab_raw, littleendian)
					if err != nil {
						return 0, nil, err
					}

					// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
					if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
						// wrong moduledata, try next
						ignorelist = append(ignorelist, moduledataVA)
						continue
					}

					moduleData.VA = moduledataVA
					moduleData.Types = uint64(module.Types)
					moduleData.ETypes = uint64(module.Etypes)
					moduleData.Typelinks.Data = pvoid64(module.Typelinks.Data)
					moduleData.Typelinks.Len = uint64(module.Typelinks.Len)
					moduleData.Typelinks.Capacity = uint64(module.Typelinks.Capacity)

					moduleData.ITablinks.Data = pvoid64(module.Itablinks.Data)
					moduleData.ITablinks.Len = uint64(module.Itablinks.Len)
					moduleData.ITablinks.Capacity = uint64(module.Itablinks.Capacity)
					return secStart, moduleData, err
				}
			case "1.8":
				fallthrough
			case "1.9":
				fallthrough
			case "1.10":
				fallthrough
			case "1.11":
				fallthrough
			case "1.12":
				fallthrough
			case "1.13":
				fallthrough
			case "1.14":
				fallthrough
			case "1.15":
				if is64bit {
					var module ModuleData12_64
					err := module.parse(rawmoduleData, littleendian)
					if err != nil {
						return 0, nil, err
					}

					var firstFunc FuncTab12_116_64
					ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
					if err != nil {
						return 0, nil, err
					}

					err = firstFunc.parse(ftab_raw, littleendian)
					if err != nil {
						return 0, nil, err
					}

					// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
					if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
						// wrong moduledata, try next
						ignorelist = append(ignorelist, moduledataVA)
						continue
					}

					moduleData.VA = moduledataVA
					moduleData.Types = uint64(module.Types)
					moduleData.ETypes = uint64(module.Etypes)
					moduleData.Typelinks = module.Typelinks
					moduleData.ITablinks = module.Itablinks
					return secStart, moduleData, err
				} else {
					var module ModuleData12_32
					err := module.parse(rawmoduleData, littleendian)
					if err != nil {
						return 0, nil, err
					}

					var firstFunc FuncTab12_116_32
					ftab_raw, err := e.raw.read_memory(uint64(module.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
					if err != nil {
						return 0, nil, err
					}

					err = firstFunc.parse(ftab_raw, littleendian)
					if err != nil {
						return 0, nil, err
					}

					// functab's first function should equal the minpc value of moduledata. If not, parse failed, or we found wrong moduledata
					if uint64(firstFunc.Entryoffset) != uint64(module.Minpc) {
						// wrong moduledata, try next
						ignorelist = append(ignorelist, moduledataVA)
						continue
					}

					moduleData.VA = moduledataVA
					moduleData.Types = uint64(module.Types)
					moduleData.ETypes = uint64(module.Etypes)
					moduleData.Typelinks.Data = pvoid64(module.Typelinks.Data)
					moduleData.Typelinks.Len = uint64(module.Typelinks.Len)
					moduleData.Typelinks.Capacity = uint64(module.Typelinks.Capacity)

					moduleData.ITablinks.Data = pvoid64(module.Itablinks.Data)
					moduleData.ITablinks.Len = uint64(module.Itablinks.Len)
					moduleData.ITablinks.Capacity = uint64(module.Itablinks.Capacity)
					return secStart, moduleData, err
				}
			}
		}
	}

	// should only happen if all scans and validation fail
	return 0, nil, fmt.Errorf("moduledata not found")
}

func (e *Entry) readVarint(address uint64) (int, int, error) {
	v := 0
	for i := 0; ; i++ {
		data, err := e.raw.read_memory(address+uint64(i), 1)
		if err != nil {
			return 0, 0, fmt.Errorf("Failed to read varint")
		}
		x := data[0]
		v += int(x&0x7f) << (7 * i)
		if x&0x80 == 0 {
			return i + 1, v, nil
		}
	}
}

func (e *Entry) readRTypeName(runtimeVersion string, typeFlags tflag, namePtr uint64, is64bit bool, littleendian bool) (name string, err error) {
	// name str (for <= 1.16 encodes length like this, beyond it uses a varint encoding)
	// The first byte is a bit field containing:
	//
	//	1<<0 the name is exported
	//	1<<1 tag data follows the name
	//	1<<2 pkgPath nameOff follows the name and tag
	//
	// The next two bytes are the data length OR varint encoding if newer version OR pointer to gostring if really old
	//
	//	 l := uint16(data[1])<<8 | uint16(data[2])
	//
	// Bytes [3:3+l] are the string data.

	// Starting in >= 1.8 An rtype's string often has an extra *, the go runtime says:
	// func (t *rtype) String() string {
	// if t.tflag&tflagExtraStar then strip leading *
	// tflagExtraStar means the name in the str field has an
	// extraneous '*' prefix. This is because for most types T in
	// a program, the type *T also exists and reusing the str data
	// saves binary size.

	var ptrSize uint64 = 0
	if is64bit {
		ptrSize = 8
	} else {
		ptrSize = 4
	}

	switch runtimeVersion {
	case "1.5":
		fallthrough
	case "1.6":
		// pointer to GoString
		nameLen, err := e.ReadPointerSizeMem(namePtr+ptrSize, is64bit, littleendian)
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		deref, err := e.ReadPointerSizeMem(namePtr, is64bit, littleendian)
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		name_raw, err := e.raw.read_memory(deref, nameLen)
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		return string(name_raw), nil
	case "1.7": // types flags exists >= 1.7
		fallthrough
	case "1.8": // type flag tflagExtraStart exists >= 1.8
		fallthrough
	case "1.9":
		fallthrough
	case "1.10":
		fallthrough
	case "1.11":
		fallthrough
	case "1.12":
		fallthrough
	case "1.13":
		fallthrough
	case "1.14":
		fallthrough
	case "1.15":
		fallthrough
	case "1.16":
		name_len_raw, err := e.raw.read_memory(namePtr, 3)
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		name_len := uint16(uint16(name_len_raw[1])<<8 | uint16(name_len_raw[2]))
		name_raw, err := e.raw.read_memory(namePtr+3, uint64(name_len))
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		name := string(name_raw)
		if typeFlags&tflagExtraStar != 0 {
			return name[1:], nil
		} else {
			return name, nil
		}
	case "1.17":
		fallthrough
	case "1.18":
		varint_len, namelen, err := e.readVarint(namePtr + 1)
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		name_raw, err := e.raw.read_memory(namePtr+1+uint64(varint_len), uint64(namelen))
		if err != nil {
			return "", fmt.Errorf("Failed to read name")
		}

		name := string(name_raw)
		if typeFlags&tflagExtraStar != 0 {
			return name[1:], nil
		} else {
			return name, nil
		}
	}
	return "", fmt.Errorf("Failed to read name")
}

func decodePtrSizeBytes(data []byte, is64bit bool, littleendian bool) (result uint64) {
	if is64bit {
		if littleendian {
			return binary.LittleEndian.Uint64(data)
		} else {
			return binary.BigEndian.Uint64(data)
		}
	} else {
		if littleendian {
			return uint64(binary.LittleEndian.Uint32(data))
		} else {
			return uint64(binary.BigEndian.Uint32(data))
		}
	}
}

func (e *Entry) ReadPointerSizeMem(addr uint64, is64bit bool, littleendian bool) (result uint64, err error) {
	var ptrSize uint64 = 0
	if is64bit {
		ptrSize = 8
	} else {
		ptrSize = 4
	}

	deref, err := e.raw.read_memory(addr, ptrSize)
	if err != nil {
		return 0, fmt.Errorf("Failed to dereference pointer memory")
	}

	return decodePtrSizeBytes(deref, is64bit, littleendian), nil
}

func (e *Entry) ParseType_impl(runtimeVersion string, moduleData *ModuleData, typeAddress uint64, is64bit bool, littleendian bool, parsedTypesIn *orderedmap.OrderedMap) (*orderedmap.OrderedMap, error) {
	// all return paths must return the original map, even if there's an error. An empty map rather than a nil simplifies recursion and allows tail calls.
	// exit condition: type address seen before
	if _, exists := parsedTypesIn.Get(typeAddress); exists {
		return parsedTypesIn, nil
	}

	var _type *Type = nil

	switch runtimeVersion {
	case "1.5":
		if is64bit {
			var rtype Rtype15_64
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}

			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}

			name, err := e.readRTypeName(runtimeVersion, 0, uint64(rtype.Str), is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: tflagNamed}
		} else {
			var rtype Rtype15_32
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}

			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}

			name, err := e.readRTypeName(runtimeVersion, 0, uint64(rtype.Str), is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: tflagNamed}
		}
	case "1.6":
		if is64bit {
			var rtype Rtype16_64
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}

			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}

			name, err := e.readRTypeName(runtimeVersion, 0, uint64(rtype.Str), is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: tflagNamed}
		} else {
			var rtype Rtype16_32
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}

			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}

			name, err := e.readRTypeName(runtimeVersion, 0, uint64(rtype.Str), is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: tflagNamed}
		}
	case "1.7":
		fallthrough
	case "1.8":
		fallthrough
	case "1.9":
		fallthrough
	case "1.10":
		fallthrough
	case "1.11":
		fallthrough
	case "1.12":
		fallthrough
	case "1.13":
		if is64bit {
			var rtype Rtype17_18_19_110_111_112_113_64
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}
			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}
			name_ptr := moduleData.Types + uint64(rtype.Str)
			name, err := e.readRTypeName(runtimeVersion, rtype.Tflag, name_ptr, is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: rtype.Tflag}
		} else {
			var rtype Rtype17_18_19_110_111_112_113_32
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}
			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}
			name_ptr := moduleData.Types + uint64(rtype.Str)
			name, err := e.readRTypeName(runtimeVersion, rtype.Tflag, name_ptr, is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: rtype.Tflag}
		}
	case "1.14":
		fallthrough
	case "1.15":
		fallthrough
	case "1.16":
		fallthrough
	case "1.17":
		fallthrough
	case "1.18":
		if is64bit {
			var rtype Rtype114_115_116_117_118_64
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}
			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}
			name_ptr := moduleData.Types + uint64(rtype.Str)
			name, err := e.readRTypeName(runtimeVersion, rtype.Tflag, name_ptr, is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: rtype.Tflag}
		} else {
			var rtype Rtype114_115_116_117_118_32
			rtype_raw, err := e.raw.read_memory(typeAddress, uint64(unsafe.Sizeof(rtype)))
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type address")
			}
			err = rtype.parse(rtype_raw, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to parse type")
			}
			name_ptr := moduleData.Types + uint64(rtype.Str)
			name, err := e.readRTypeName(runtimeVersion, rtype.Tflag, name_ptr, is64bit, littleendian)
			if err != nil {
				return parsedTypesIn, fmt.Errorf("Failed to read type name")
			}
			_type = &Type{VA: typeAddress, Str: name, Kind: ((Kind)(rtype.Kind & 0x1f)).String(), baseSize: uint16(unsafe.Sizeof(rtype)), kindEnum: ((Kind)(rtype.Kind & 0x1f)), flags: rtype.Tflag}
		}
	default:
		return parsedTypesIn, fmt.Errorf("Unknown runtime version")
	}

	// insert into seen list
	parsedTypesIn.Set(typeAddress, *_type)

	var ptrSize uint64 = 0
	if is64bit {
		ptrSize = 8
	} else {
		ptrSize = 4
	}

	// recurse (optionally)
	// src/runtume/type.go
	switch _type.kindEnum {
	case Array:
		// type arraytype struct {
		// 	typ   _type
		// 	elem  *_type
		// 	slice *_type
		// 	len   uintptr
		// }
		elemTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize), is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Array's elem")
		}

		sliceTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize)+ptrSize, is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Array's slice")
		}

		parsed, _ := e.ParseType_impl(runtimeVersion, moduleData, elemTypeAddress, is64bit, littleendian, parsedTypesIn)
		return e.ParseType_impl(runtimeVersion, moduleData, sliceTypeAddress, is64bit, littleendian, parsed)
	case Chan:
		// type chantype struct {
		// 	typ  _type
		// 	elem *_type
		// 	dir  uintptr
		// }
		elemTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize), is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Chan's elem")
		}

		// append channel direction to Str of type
		channelDir, err := e.raw.read_memory(typeAddress+uint64(_type.baseSize)+ptrSize, ptrSize)
		if err == nil {
			var dir string = ""
			if is64bit {
				if littleendian {
					dir = (ChanDir)(binary.LittleEndian.Uint64(channelDir)).String()
				} else {
					dir = (ChanDir)(binary.BigEndian.Uint64(channelDir)).String()
				}
			} else {
				if littleendian {
					dir = (ChanDir)(binary.LittleEndian.Uint32(channelDir)).String()
				} else {
					dir = (ChanDir)(binary.BigEndian.Uint32(channelDir)).String()
				}
			}

			_type.Str += " Direction: (" + dir + ")"
			parsedTypesIn.Set(typeAddress, *_type)
		}
		return e.ParseType_impl(runtimeVersion, moduleData, elemTypeAddress, is64bit, littleendian, parsedTypesIn)
	case Slice:
		// type slicetype struct {
		// 	typ  _type
		// 	elem *_type
		// }
		elemTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize), is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Slice's elem")
		}
		return e.ParseType_impl(runtimeVersion, moduleData, elemTypeAddress, is64bit, littleendian, parsedTypesIn)
	case Pointer:
		// type ptrtype struct {
		// 	typ  _type
		// 	elem *_type
		// }
		elemTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize), is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Pointer's elem")
		}

		return e.ParseType_impl(runtimeVersion, moduleData, elemTypeAddress, is64bit, littleendian, parsedTypesIn)
	case Map:
		// type mapType struct {
		// 	rtype
		// 	key    *rtype // map key type
		// 	elem   *rtype // map element (value) type
		// 	bucket *rtype // internal bucket structure
		// 	// function for hashing keys (ptr to key, seed) -> hash
		// 	hasher     func(unsafe.Pointer, uintptr) uintptr
		// 	keysize    uint8  // size of key slot
		// 	valuesize  uint8  // size of value slot
		// 	bucketsize uint16 // size of bucket
		// 	flags      uint32
		// }
		keyTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize), is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Map's elem")
		}

		elemTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize)+ptrSize, is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Array's slice")
		}

		bucketTypeAddress, err := e.ReadPointerSizeMem(typeAddress+uint64(_type.baseSize)+ptrSize+ptrSize, is64bit, littleendian)
		if err != nil {
			return parsedTypesIn, fmt.Errorf("Failed to read Kind Array's slice")
		}

		parsed, _ := e.ParseType_impl(runtimeVersion, moduleData, keyTypeAddress, is64bit, littleendian, parsedTypesIn)
		parsed2, _ := e.ParseType_impl(runtimeVersion, moduleData, elemTypeAddress, is64bit, littleendian, parsed)
		return e.ParseType_impl(runtimeVersion, moduleData, bucketTypeAddress, is64bit, littleendian, parsed2)
	case Interface:
		// type interfaceType struct {
		// 	rtype
		// 	pkgPath name      // import path (pointer)
		// 	methods []imethod // sorted by hash
		// }

		switch runtimeVersion {
		case "1.5":
			fallthrough
		case "1.6":
			//
			// type interfaceType struct {
			// 	rtype   `reflect:"interface"`
			// 	methods []imethod // sorted by hash
			// }
			var methodsStartAddr uint64 = typeAddress + uint64(_type.baseSize)
			var methods GoSlice64 = GoSlice64{}
			if is64bit {
				data, err := e.raw.read_memory(methodsStartAddr, uint64(unsafe.Sizeof(GoSlice64{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}
				methods.parse(data, littleendian)
			} else {
				data, err := e.raw.read_memory(methodsStartAddr, uint64(unsafe.Sizeof(GoSlice32{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}

				var tmp GoSlice32 = GoSlice32{}
				tmp.parse(data, littleendian)

				methods.Data = pvoid64(tmp.Data)
				methods.Len = uint64(tmp.Len)
				methods.Capacity = uint64(tmp.Capacity)
			}

			interfaceDef := fmt.Sprintf("type %s interface {", _type.Str)

			// type imethod struct {
			// 	name    *string // name of method
			// 	pkgPath *string // nil for exported Names; otherwise import path
			// 	typ     *rtype  // .(*FuncType) underneath
			// }
			// size = 3 * ptrsize
			for i := 0; i < int(methods.Len); i++ {
				imethoddata, err := e.raw.read_memory(uint64(methods.Data)+(uint64(i)*3*ptrSize), 3*ptrSize)
				if err != nil {
					continue
				}

				typeAddr := decodePtrSizeBytes(imethoddata[ptrSize*2:ptrSize*3], is64bit, littleendian)
				parsedTypesIn, _ = e.ParseType_impl(runtimeVersion, moduleData, typeAddr, is64bit, littleendian, parsedTypesIn)
				methodfunc, found := parsedTypesIn.Get(typeAddr)
				if found {
					interfaceDef += fmt.Sprintf("\n    %s", methodfunc.(Type).Str)
				}
			}
			interfaceDef += "\n}"
			(*_type).Reconstructed = interfaceDef
			parsedTypesIn.Set(typeAddress, *_type)
			return parsedTypesIn, nil
		case "1.7":
			fallthrough
		case "1.8":
			fallthrough
		case "1.9":
			fallthrough
		case "1.10":
			fallthrough
		case "1.11":
			fallthrough
		case "1.12":
			fallthrough
		case "1.13":
			fallthrough
		case "1.14":
			fallthrough
		case "1.15":
			fallthrough
		case "1.17":
			fallthrough
		case "1.18":
			var methodsStartAddr uint64 = typeAddress + uint64(_type.baseSize) + ptrSize
			var methods GoSlice64 = GoSlice64{}
			if is64bit {
				data, err := e.raw.read_memory(methodsStartAddr, uint64(unsafe.Sizeof(GoSlice64{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}
				methods.parse(data, littleendian)
			} else {
				data, err := e.raw.read_memory(methodsStartAddr, uint64(unsafe.Sizeof(GoSlice32{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}

				var tmp GoSlice32 = GoSlice32{}
				tmp.parse(data, littleendian)

				methods.Data = pvoid64(tmp.Data)
				methods.Len = uint64(tmp.Len)
				methods.Capacity = uint64(tmp.Capacity)
			}

			interfaceDef := "type interface {"
			if *&_type.flags&tflagNamed != 0 {
				interfaceDef = fmt.Sprintf("type %s interface {", _type.Str)
			}

			// type imethod struct {
			// 	name nameOff // name of method
			// 	typ  typeOff // .(*FuncType) underneath
			// }
			entrySize := uint64(unsafe.Sizeof(IMethod{}))
			for i := 0; i < int(methods.Len); i++ {
				imethoddata, err := e.raw.read_memory(uint64(methods.Data)+entrySize*uint64(i), entrySize)
				if err != nil {
					continue
				}

				var method IMethod
				err = method.parse(imethoddata, littleendian)
				if err != nil {
					continue
				}

				typeAddr := moduleData.Types + uint64(method.Typ)
				parsedTypesIn, _ = e.ParseType_impl(runtimeVersion, moduleData, typeAddr, is64bit, littleendian, parsedTypesIn)

				methodfunc, found := parsedTypesIn.Get(typeAddr)
				if found {
					interfaceDef += fmt.Sprintf("\n    %s", methodfunc.(Type).Str)
				}
			}
			interfaceDef += "\n}"
			(*_type).Reconstructed = interfaceDef
			parsedTypesIn.Set(typeAddress, *_type)
			return parsedTypesIn, nil
		}
	case Struct:
		switch runtimeVersion {
		case "1.5":
			fallthrough
		case "1.6":
			// type structType struct {
			// 	rtype  `reflect:"struct"`
			// 	fields []structField // sorted by offset
			// }
			var fieldsStartAddr uint64 = typeAddress + uint64(_type.baseSize)
			var fields GoSlice64 = GoSlice64{}
			if is64bit {
				data, err := e.raw.read_memory(fieldsStartAddr, uint64(unsafe.Sizeof(GoSlice64{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}
				fields.parse(data, littleendian)
			} else {
				data, err := e.raw.read_memory(fieldsStartAddr, uint64(unsafe.Sizeof(GoSlice32{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}

				var tmp GoSlice32 = GoSlice32{}
				tmp.parse(data, littleendian)

				fields.Data = pvoid64(tmp.Data)
				fields.Len = uint64(tmp.Len)
				fields.Capacity = uint64(tmp.Capacity)
			}

			structDef := fmt.Sprintf("type %s struct {", _type.Str)

			// type structField struct {
			// 	name    *string // nil for embedded fields
			// 	pkgPath *string // nil for exported Names; otherwise import path
			// 	typ     *rtype  // type of field
			// 	tag     *string // nil if no tag
			// 	offset  uintptr // byte offset of field within struct
			// }
			// size = 5 * ptrsize
			for i := 0; i < int(fields.Len); i++ {
				data, err := e.raw.read_memory(uint64(fields.Data)+(uint64(i)*(ptrSize*5)), ptrSize*5)
				if err != nil {
					continue
				}

				typeAddr := decodePtrSizeBytes(data[ptrSize*2:ptrSize*3], is64bit, littleendian)
				parsedTypesIn, _ = e.ParseType_impl(runtimeVersion, moduleData, typeAddr, is64bit, littleendian, parsedTypesIn)
				field, found := parsedTypesIn.Get(typeAddr)
				if found {
					typeNameAddr := decodePtrSizeBytes(data[0:ptrSize], is64bit, littleendian)
					typeName, err := e.readRTypeName(runtimeVersion, 0, typeNameAddr, is64bit, littleendian)
					if err == nil {
						structDef += fmt.Sprintf("\n    %-10s %s", typeName, field.(Type).Str)
					}
				}
			}
			structDef += "\n}"
			(*_type).Reconstructed = structDef
			parsedTypesIn.Set(typeAddress, *_type)
			return parsedTypesIn, nil
		case "1.7":
			fallthrough
		case "1.8":
			fallthrough
		case "1.9":
			fallthrough
		case "1.10":
			fallthrough
		case "1.11":
			fallthrough
		case "1.12":
			fallthrough
		case "1.13":
			fallthrough
		case "1.14":
			fallthrough
		case "1.15":
			fallthrough
		case "1.17":
			fallthrough
		case "1.18":
			// type structType struct {
			// 	rtype
			// 	pkgPath name // pointer
			// 	fields  []structField // sorted by offset
			// }
			var fieldsStartAddr uint64 = typeAddress + uint64(_type.baseSize) + ptrSize
			var fields GoSlice64 = GoSlice64{}
			if is64bit {
				data, err := e.raw.read_memory(fieldsStartAddr, uint64(unsafe.Sizeof(GoSlice64{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}
				fields.parse(data, littleendian)
			} else {
				data, err := e.raw.read_memory(fieldsStartAddr, uint64(unsafe.Sizeof(GoSlice32{})))
				if err != nil {
					return parsedTypesIn, fmt.Errorf("Failed to parse Kind Interface's method slice")
				}

				var tmp GoSlice32 = GoSlice32{}
				tmp.parse(data, littleendian)

				fields.Data = pvoid64(tmp.Data)
				fields.Len = uint64(tmp.Len)
				fields.Capacity = uint64(tmp.Capacity)
			}

			structDef := "type struct {"
			if *&_type.flags&tflagNamed != 0 {
				structDef = fmt.Sprintf("type %s struct {", _type.Str)
			}

			// type structField struct {
			// 	name   name    // name is empty for embedded fields (ptr)
			// 	typ    *rtype  // type of field
			// 	offset uintptr // byte offset of field within struct
			// }
			//
			// size = ptrsize * 3
			for i := 0; i < int(fields.Len); i++ {
				data, err := e.raw.read_memory(uint64(fields.Data)+(uint64(i)*(ptrSize*3)), ptrSize*3)
				if err != nil {
					continue
				}

				typeAddr := decodePtrSizeBytes(data[ptrSize:ptrSize*2], is64bit, littleendian)
				parsedTypesIn, _ = e.ParseType_impl(runtimeVersion, moduleData, typeAddr, is64bit, littleendian, parsedTypesIn)

				field, found := parsedTypesIn.Get(typeAddr)
				if found {
					typeNameAddr := decodePtrSizeBytes(data[0:ptrSize], is64bit, littleendian)
					typeName, err := e.readRTypeName(runtimeVersion, 0, typeNameAddr, is64bit, littleendian)
					if err == nil {
						structDef += fmt.Sprintf("\n    %-10s %s", typeName, field.(Type).Str)
					}
				}
			}
			structDef += "\n}"
			(*_type).Reconstructed = structDef
			parsedTypesIn.Set(typeAddress, *_type)
			return parsedTypesIn, nil
		}
	default:
		// this is not an error, we just may not support recursion on this 'Kind'
	}
	return parsedTypesIn, nil
}

func (e *Entry) ParseType(runtimeVersion string, moduleData *ModuleData, typeAddress uint64, is64bit bool, littleendian bool) (_type []Type, err error) {
	// Major version only, 1.15.5 -> 1.15
	parts := strings.Split(runtimeVersion, ".")
	if len(parts) >= 2 {
		runtimeVersion = parts[0] + "." + parts[1]
	}

	m := orderedmap.NewOrderedMap()

	parsedTypes, err := e.ParseType_impl(runtimeVersion, moduleData, typeAddress, is64bit, littleendian, m)
	if err != nil {
		return nil, err
	}

	// map values to array
	values := make([]Type, 0, parsedTypes.Len())

	for el := m.Front(); el != nil; el = el.Next() {
		values = append(values, (el.Value).(Type))
	}

	return values, nil
}

func (e *Entry) ParseTypeLinks(runtimeVersion string, moduleData *ModuleData, is64bit bool, littleendian bool) (types []Type, err error) {
	// Major version only, 1.15.5 -> 1.15
	parts := strings.Split(runtimeVersion, ".")
	if len(parts) >= 2 {
		runtimeVersion = parts[0] + "." + parts[1]
	}

	var ptrSize uint64 = 0
	if is64bit {
		ptrSize = 8
	} else {
		ptrSize = 4
	}

	// Handle legacy layout first (1.5, 1.6). The typelinks is a pointer array
	if moduleData.LegacyTypes.Data != 0 && moduleData.LegacyTypes.Len != 0 {
		for i := 0; i < int(moduleData.LegacyTypes.Len); i++ {
			typeAddress, err := e.ReadPointerSizeMem(uint64(moduleData.LegacyTypes.Data)+ptrSize*uint64(i), is64bit, littleendian)
			if err != nil {
				continue
			}

			parsed, err := e.ParseType(runtimeVersion, moduleData, typeAddress, is64bit, littleendian)
			if err == nil {
				types = append(types, parsed...)
			}
		}
		return types, nil
	}

	// Modern layout, the typelinks is an array of offsets
	for i := 0; i < int(moduleData.Typelinks.Len); i++ {
		// array of int32 offsets into moduleData.Types
		offset, err := e.raw.read_memory(uint64(moduleData.Typelinks.Data)+uint64(i)*4, 4)
		if err != nil {
			continue
		}

		var typeAddress uint64 = 0
		if littleendian {
			offset_signed := int32(binary.LittleEndian.Uint32(offset))
			typeAddress = uint64(int64(moduleData.Types) + int64(offset_signed))
		} else {
			offset_signed := int32(binary.BigEndian.Uint32(offset))
			typeAddress = uint64(int64(moduleData.Types) + int64(offset_signed))
		}

		parsed, err := e.ParseType(runtimeVersion, moduleData, typeAddress, is64bit, littleendian)
		if err == nil {
			types = append(types, parsed...)
		}
	}
	return types, nil
}

func (e *Entry) ParseITabLinks(runtimeVersion string, moduleData *ModuleData, is64bit bool, littleendian bool) (types []Type, err error) {
	// Major version only, 1.15.5 -> 1.15
	parts := strings.Split(runtimeVersion, ".")
	if len(parts) >= 2 {
		runtimeVersion = parts[0] + "." + parts[1]
	}

	var ptrSize uint64 = 0
	if is64bit {
		ptrSize = 8
	} else {
		ptrSize = 4
	}

	for i := 0; i < int(moduleData.ITablinks.Len); i++ {
		itabAddr, err := e.ReadPointerSizeMem(uint64(moduleData.ITablinks.Data)+ptrSize*uint64(i), is64bit, littleendian)
		if err != nil {
			continue
		}

		interfaceAddr, err := e.ReadPointerSizeMem(itabAddr, is64bit, littleendian)
		if err != nil {
			continue
		}

		typeAddr, err := e.ReadPointerSizeMem(itabAddr+ptrSize, is64bit, littleendian)
		if err != nil {
			continue
		}

		// type itab struct {
		// 	inter *interfacetype
		// 	_type *_type
		// 	hash  uint32 // copy of _type.hash. Used for type switches.
		// 	_     [4]byte
		// 	fun   [1]uintptr // variable sized. fun[0]==0 means _type does not implement inter.
		// }
		parsed, err := e.ParseType(runtimeVersion, moduleData, interfaceAddr, is64bit, littleendian)
		if err == nil {
			types = append(types, parsed...)
		}

		parsed2, err2 := e.ParseType(runtimeVersion, moduleData, typeAddr, is64bit, littleendian)
		if err2 == nil {
			types = append(types, parsed2...)
		}

		// the interface itself, we need to insert as a type. We'll name it after its interface + its implementing type, the 0th of each parsed array
		if err == nil && err2 == nil && len(parsed) > 0 && len(parsed2) > 0 {
			interfaceName := parsed[0].Str
			implementerName := parsed2[0].Str
			types = append(types, Type{VA: itabAddr, Str: fmt.Sprintf("interface_%s_impl_%s", interfaceName, implementerName), Kind: Interface.String()})
		}
	}
	return types, nil
}

func (e *Entry) Text() (uint64, []byte, error) {
	return e.raw.text()
}

func (e *Entry) GOARCH() string {
	return e.raw.goarch()
}

// LoadAddress returns the expected load address of the file.
// This differs from the actual load address for a position-independent
// executable.
func (e *Entry) LoadAddress() (uint64, error) {
	return e.raw.loadAddress()
}

// DWARF returns DWARF debug data for the file, if any.
// This is for cmd/pprof to locate cgo functions.
func (e *Entry) DWARF() (*dwarf.Data, error) {
	return e.raw.dwarf()
}
