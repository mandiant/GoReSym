/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package objfile

import (
	"fmt"
	"unsafe"
)

// FieldInfo describes a single field's location and type in a binary structure
type FieldInfo struct {
	Name     string // Field name (e.g., "Text", "Types")
	Offset64 int    // Byte offset in 64-bit binaries
	Offset32 int    // Byte offset in 32-bit binaries
	Type     string // Field type: "pvoid", "slice", "string"
}

// ModuleDataLayout describes the binary layout of a moduledata structure for a specific Go version
type ModuleDataLayout struct {
	Version string
	Fields  []FieldInfo
}

// getModuleDataLayout returns the layout for a given Go version
// Multiple versions may share the same layout
func getModuleDataLayout(version string) *ModuleDataLayout {
	// Map version to layout name (many versions share layouts)
	layoutName := version
	switch version {
	case "1.24", "1.23", "1.22", "1.21":
		layoutName = "1.21"
	case "1.20":
		layoutName = "1.20"
	case "1.19", "1.18":
		layoutName = "1.18"
	case "1.17", "1.16":
		layoutName = "1.16"
	}

	layout, exists := moduleDataLayouts[layoutName]
	if !exists {
		// Fallback to closest known version
		return moduleDataLayouts["1.21"]
	}
	return layout
}

// moduleDataLayouts defines field layouts for different Go versions
// Only fields that GoReSym actually uses are included
var moduleDataLayouts = map[string]*ModuleDataLayout{
	"1.21": {
		Version: "1.21",
		Fields: []FieldInfo{
			{Name: "Ftab", Offset64: 128, Offset32: 64, Type: "slice"},
			{Name: "Minpc", Offset64: 160, Offset32: 80, Type: "pvoid"},
			{Name: "Text", Offset64: 176, Offset32: 88, Type: "pvoid"},
			{Name: "Types", Offset64: 296, Offset32: 148, Type: "pvoid"},
			{Name: "Etypes", Offset64: 304, Offset32: 152, Type: "pvoid"},
			{Name: "Textsectmap", Offset64: 328, Offset32: 164, Type: "slice"},
			{Name: "Typelinks", Offset64: 352, Offset32: 176, Type: "slice"},
			{Name: "Itablinks", Offset64: 376, Offset32: 188, Type: "slice"},
		},
	},
	"1.20": {
		Version: "1.20",
		Fields: []FieldInfo{
			{Name: "Ftab", Offset64: 128, Offset32: 64, Type: "slice"},
			{Name: "Minpc", Offset64: 160, Offset32: 80, Type: "pvoid"},
			{Name: "Text", Offset64: 176, Offset32: 88, Type: "pvoid"},
			{Name: "Types", Offset64: 296, Offset32: 148, Type: "pvoid"},
			{Name: "Etypes", Offset64: 304, Offset32: 152, Type: "pvoid"},
			{Name: "Textsectmap", Offset64: 328, Offset32: 164, Type: "slice"},
			{Name: "Typelinks", Offset64: 352, Offset32: 176, Type: "slice"},
			{Name: "Itablinks", Offset64: 376, Offset32: 188, Type: "slice"},
		},
	},
	"1.18": {
		Version: "1.18",
		Fields: []FieldInfo{
			{Name: "Ftab", Offset64: 128, Offset32: 64, Type: "slice"},
			{Name: "Minpc", Offset64: 160, Offset32: 80, Type: "pvoid"},
			{Name: "Text", Offset64: 176, Offset32: 88, Type: "pvoid"},
			{Name: "Types", Offset64: 280, Offset32: 140, Type: "pvoid"},
			{Name: "Etypes", Offset64: 288, Offset32: 144, Type: "pvoid"},
			{Name: "Textsectmap", Offset64: 312, Offset32: 156, Type: "slice"},
			{Name: "Typelinks", Offset64: 336, Offset32: 168, Type: "slice"},
			{Name: "Itablinks", Offset64: 360, Offset32: 180, Type: "slice"},
		},
	},
	"1.16": {
		Version: "1.16",
		Fields: []FieldInfo{
			{Name: "Ftab", Offset64: 128, Offset32: 64, Type: "slice"},
			{Name: "Minpc", Offset64: 160, Offset32: 80, Type: "pvoid"},
			{Name: "Text", Offset64: 176, Offset32: 88, Type: "pvoid"},
			{Name: "Types", Offset64: 280, Offset32: 140, Type: "pvoid"},
			{Name: "Etypes", Offset64: 288, Offset32: 144, Type: "pvoid"},
			{Name: "Textsectmap", Offset64: 296, Offset32: 148, Type: "slice"},
			{Name: "Typelinks", Offset64: 320, Offset32: 160, Type: "slice"},
			{Name: "Itablinks", Offset64: 344, Offset32: 172, Type: "slice"},
		},
	},
}

// Helper functions to read fields from raw bytes

func readPointer(data []byte, offset int, is64bit bool, littleendian bool) uint64 {
	if is64bit {
		if littleendian {
			return uint64(data[offset]) |
				uint64(data[offset+1])<<8 |
				uint64(data[offset+2])<<16 |
				uint64(data[offset+3])<<24 |
				uint64(data[offset+4])<<32 |
				uint64(data[offset+5])<<40 |
				uint64(data[offset+6])<<48 |
				uint64(data[offset+7])<<56
		} else {
			return uint64(data[offset])<<56 |
				uint64(data[offset+1])<<48 |
				uint64(data[offset+2])<<40 |
				uint64(data[offset+3])<<32 |
				uint64(data[offset+4])<<24 |
				uint64(data[offset+5])<<16 |
				uint64(data[offset+6])<<8 |
				uint64(data[offset+7])
		}
	} else {
		// 32-bit
		if littleendian {
			return uint64(uint32(data[offset]) |
				uint32(data[offset+1])<<8 |
				uint32(data[offset+2])<<16 |
				uint32(data[offset+3])<<24)
		} else {
			return uint64(uint32(data[offset])<<24 |
				uint32(data[offset+1])<<16 |
				uint32(data[offset+2])<<8 |
				uint32(data[offset+3]))
		}
	}
}

func readSlice(data []byte, offset int, is64bit bool, littleendian bool) (sliceData uint64, sliceLen uint64) {
	// Go slice layout: {Data ptr, Len int, Cap int}
	sliceData = readPointer(data, offset, is64bit, littleendian)

	ptrSize := 4
	if is64bit {
		ptrSize = 8
	}

	sliceLen = readPointer(data, offset+ptrSize, is64bit, littleendian)

	return sliceData, sliceLen
}

// ModuleDataIntermediate holds all fields parsed from moduledata
// Used internally by generic parser before validation
type ModuleDataIntermediate struct {
	Ftab        GoSlice64
	Minpc       uint64
	Text        uint64
	Types       uint64
	Etypes      uint64
	Textsectmap GoSlice64
	Typelinks   GoSlice64
	Itablinks   GoSlice64
}

// parseModuleDataGeneric parses moduledata from raw bytes using layout tables
// This replaces the version-specific switch statements with a generic approach
func parseModuleDataGeneric(rawData []byte, version string, is64bit bool, littleendian bool) (*ModuleDataIntermediate, error) {
	layout := getModuleDataLayout(version)

	md := &ModuleDataIntermediate{}

	// Parse fields based on layout
	for _, field := range layout.Fields {
		offset := field.Offset64
		if !is64bit {
			offset = field.Offset32
		}

		// Make sure we don't read past buffer
		requiredSize := offset + 8
		if !is64bit {
			requiredSize = offset + 4
		}
		if field.Type == "slice" {
			requiredSize = offset + 24 // slice is 3 pointers
			if !is64bit {
				requiredSize = offset + 12
			}
		}

		if len(rawData) < requiredSize {
			continue
		}

		switch field.Name {
		case "Ftab":
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Ftab = GoSlice64{Data: pvoid64(data), Len: len}
		case "Minpc":
			md.Minpc = readPointer(rawData, offset, is64bit, littleendian)
		case "Text":
			md.Text = readPointer(rawData, offset, is64bit, littleendian)
		case "Types":
			md.Types = readPointer(rawData, offset, is64bit, littleendian)
		case "Etypes":
			md.Etypes = readPointer(rawData, offset, is64bit, littleendian)
		case "Textsectmap":
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Textsectmap = GoSlice64{Data: pvoid64(data), Len: len}
		case "Typelinks":
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Typelinks = GoSlice64{Data: pvoid64(data), Len: len}
		case "Itablinks":
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Itablinks = GoSlice64{Data: pvoid64(data), Len: len}
		}
	}

	return md, nil
}

// getFieldOffset returns the offset for a named field in a layout
func getFieldOffset(layout *ModuleDataLayout, fieldName string, is64bit bool) (int, bool) {
	for _, field := range layout.Fields {
		if field.Name == fieldName {
			if is64bit {
				return field.Offset64, true
			}
			return field.Offset32, true
		}
	}
	return 0, false
}

// validateAndConvertModuleData performs validation and converts intermediate moduledata
// to the final ModuleData struct used by GoReSym
// This replaces the duplicated validation logic in version-specific switch cases
// For Go 1.18+
func (e *Entry) validateAndConvertModuleData(
	md *ModuleDataIntermediate,
	moduleDataVA uint64,
	version string,
	is64bit bool,
	littleendian bool,
	ignorelist []uint64,
) (*ModuleData, []uint64, error) {

	// Read and validate first function from ftab
	var firstFunc FuncTab118
	ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
	if err != nil {
		return nil, ignorelist, err
	}

	err = firstFunc.parse(ftab_raw, littleendian)
	if err != nil {
		return nil, ignorelist, err
	}

	// Prevent loop on invalid modules with bogus length
	if md.Textsectmap.Len > 0x100 {
		return nil, ignorelist, fmt.Errorf("textsectmap length too large: %d", md.Textsectmap.Len)
	}

	// Read textsectmap entries
	var textsectmap64 []Textsect_64
	var textsectmap32 []Textsect_32

	if is64bit {
		for i := 0; i < int(md.Textsectmap.Len); i++ {
			var textsect Textsect_64
			var sectSize = uint64(unsafe.Sizeof(textsect))
			textsec_raw, err := e.raw.read_memory(uint64(md.Textsectmap.Data)+uint64(i)*sectSize, sectSize)
			if err != nil {
				return nil, ignorelist, err
			}

			err = textsect.parse(textsec_raw, littleendian)
			if err != nil {
				return nil, ignorelist, err
			}
			textsectmap64 = append(textsectmap64, textsect)
		}

		// Validate: functab's first function should equal minpc value
		if textAddr64(uint64(firstFunc.Entryoffset), md.Text, textsectmap64) != md.Minpc {
			// Wrong moduledata, add to ignorelist
			ignorelist = append(ignorelist, moduleDataVA)
			return nil, ignorelist, fmt.Errorf("minpc validation failed")
		}
	} else {
		for i := 0; i < int(md.Textsectmap.Len); i++ {
			var textsect Textsect_32
			var sectSize = uint64(unsafe.Sizeof(textsect))
			textsec_raw, err := e.raw.read_memory(uint64(md.Textsectmap.Data)+uint64(i)*sectSize, sectSize)
			if err != nil {
				return nil, ignorelist, err
			}

			err = textsect.parse(textsec_raw, littleendian)
			if err != nil {
				return nil, ignorelist, err
			}
			textsectmap32 = append(textsectmap32, textsect)
		}

		// Validate: functab's first function should equal minpc value
		if textAddr32(uint64(firstFunc.Entryoffset), md.Text, textsectmap32) != md.Minpc {
			// Wrong moduledata, add to ignorelist
			ignorelist = append(ignorelist, moduleDataVA)
			return nil, ignorelist, fmt.Errorf("minpc validation failed")
		}
	}

	// Validation passed, create final ModuleData struct
	result := &ModuleData{
		VA:        moduleDataVA,
		TextVA:    md.Text,
		Types:     md.Types,
		ETypes:    md.Etypes,
		Typelinks: md.Typelinks,
		ITablinks: md.Itablinks,
	}

	return result, ignorelist, nil
}

// validateAndConvertModuleData_116 performs validation for Go 1.16-1.17
// These versions use simpler validation (no textsectmap)
func (e *Entry) validateAndConvertModuleData_116(
	md *ModuleDataIntermediate,
	moduleDataVA uint64,
	version string,
	is64bit bool,
	littleendian bool,
	ignorelist []uint64,
) (*ModuleData, []uint64, error) {

	// Read and validate first function from ftab
	if is64bit {
		var firstFunc FuncTab12_116_64
		ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
		if err != nil {
			return nil, ignorelist, err
		}

		err = firstFunc.parse(ftab_raw, littleendian)
		if err != nil {
			return nil, ignorelist, err
		}

		// Validate: functab's first function should equal minpc value
		if uint64(firstFunc.Entryoffset) != md.Minpc {
			// Wrong moduledata, add to ignorelist
			ignorelist = append(ignorelist, moduleDataVA)
			return nil, ignorelist, fmt.Errorf("minpc validation failed")
		}
	} else {
		var firstFunc FuncTab12_116_32
		ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(unsafe.Sizeof(firstFunc)))
		if err != nil {
			return nil, ignorelist, err
		}

		err = firstFunc.parse(ftab_raw, littleendian)
		if err != nil {
			return nil, ignorelist, err
		}

		// Validate: functab's first function should equal minpc value
		if uint64(firstFunc.Entryoffset) != md.Minpc {
			// Wrong moduledata, add to ignorelist
			ignorelist = append(ignorelist, moduleDataVA)
			return nil, ignorelist, fmt.Errorf("minpc validation failed")
		}
	}

	// Validation passed, create final ModuleData struct
	result := &ModuleData{
		VA:        moduleDataVA,
		TextVA:    md.Text,
		Types:     md.Types,
		ETypes:    md.Etypes,
		Typelinks: md.Typelinks,
		ITablinks: md.Itablinks,
	}

	return result, ignorelist, nil
}
