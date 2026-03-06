/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package objfile

import (
	"encoding/binary"
	"fmt"
)

// FieldName represents the name of a field in binary structures
type FieldName uint8

const (
	// ModuleData fields
	FieldFtab        FieldName = iota // 0
	FieldMinpc                        // 1
	FieldText                         // 2
	FieldTypes                        // 3
	FieldEtypes                       // 4
	FieldTextsectmap                  // 5
	FieldTypelinks                    // 6
	FieldItablinks                    // 7
	FieldTypedesclen                  // 8
	FieldPkgPath                      // 9 (for Interface)
	FieldMethods                      // 10 (for Interface)
	// Rtype fields (Go reflection types)
	FieldSize       // 10
	FieldPtrdata    // 11
	FieldHash       // 12
	FieldUnused     // 13
	FieldAlign      // 14
	FieldFieldAlign // 15
	FieldKind       // 16
	FieldStr        // 17
	FieldTflag      // 18
	// Textsect fields
	FieldVaddr    // 19
	FieldEnd      // 20
	FieldBaseaddr // 21
	// FuncTab fields
	FieldEntryoffset // 22
	FieldFuncoffset  // 23
)

// String representation for debugging/logging
func (f FieldName) String() string {
	switch f {
	case FieldFtab:
		return "Ftab"
	case FieldMinpc:
		return "Minpc"
	case FieldText:
		return "Text"
	case FieldTypes:
		return "Types"
	case FieldEtypes:
		return "Etypes"
	case FieldTextsectmap:
		return "Textsectmap"
	case FieldTypelinks:
		return "Typelinks"
	case FieldItablinks:
		return "Itablinks"
	case FieldTypedesclen:
		return "Typedesclen"
	case FieldPkgPath:
		return "PkgPath"
	case FieldMethods:
		return "Methods"
	case FieldSize:
		return "Size"
	case FieldPtrdata:
		return "Ptrdata"
	case FieldHash:
		return "Hash"
	case FieldUnused:
		return "Unused"
	case FieldAlign:
		return "Align"
	case FieldFieldAlign:
		return "FieldAlign"
	case FieldKind:
		return "Kind"
	case FieldStr:
		return "Str"
	case FieldTflag:
		return "Tflag"
	case FieldVaddr:
		return "Vaddr"
	case FieldEnd:
		return "End"
	case FieldBaseaddr:
		return "Baseaddr"
	case FieldEntryoffset:
		return "Entryoffset"
	case FieldFuncoffset:
		return "Funcoffset"
	default:
		return "Unknown"
	}
}

// FieldType represents the type of a field in binary structures
type FieldType uint8

const (
	FieldTypePvoid  FieldType = iota // 0 - pointer/address (void *)
	FieldTypeSlice                   // 1 - Go slice (ptr, len, cap)
	FieldTypeUint32                  // 2 - unsigned 32-bit integer
	FieldTypeUint8                   // 3 - unsigned 8-bit integer
	FieldTypeInt32                   // 4 - signed 32-bit integer
)

// String representation for debugging
func (f FieldType) String() string {
	switch f {
	case FieldTypePvoid:
		return "pvoid"
	case FieldTypeSlice:
		return "slice"
	case FieldTypeUint32:
		return "uint32"
	case FieldTypeUint8:
		return "uint8"
	case FieldTypeInt32:
		return "int32"
	default:
		return "unknown"
	}
}

// FieldInfo describes a single field's location and type in a binary structure
type FieldInfo struct {
	Name     FieldName // Field name enum (e.g., FieldText, FieldTypes)
	Offset64 int       // Byte offset in 64-bit binaries
	Offset32 int       // Byte offset in 32-bit binaries
	Type     FieldType // Field type enum: FieldTypePvoid, FieldTypeSlice, FieldTypeString
}

// ModuleDataLayout describes the binary layout of a moduledata structure for a specific Go version
type ModuleDataLayout struct {
	Version string
	Fields  []FieldInfo
}

// StructLayout describes the binary layout of a generic structure
type StructLayout struct {
	Fields     []FieldInfo
	BaseSize64 int
	BaseSize32 int
}

// MemoryReader provides utility methods for reading fields from a byte slice based on a StructLayout
type MemoryReader struct {
	Data         []byte
	Layout       *StructLayout
	Is64Bit      bool
	LittleEndian bool
}

func (m *MemoryReader) ReadPointer(field FieldName) uint64 {
	offset, found := getFieldOffsetFromList(m.Layout.Fields, field, m.Is64Bit)
	if !found {
		return 0
	}
	return readPointer(m.Data, offset, m.Is64Bit, m.LittleEndian)
}

func (m *MemoryReader) ReadUint32(field FieldName) uint32 {
	offset, found := getFieldOffsetFromList(m.Layout.Fields, field, m.Is64Bit)
	if !found {
		return 0
	}
	return readUint32(m.Data, offset, m.LittleEndian)
}

func getFieldOffsetFromList(fields []FieldInfo, fieldName FieldName, is64bit bool) (int, bool) {
	for _, field := range fields {
		if field.Name == fieldName {
			if is64bit {
				return field.Offset64, true
			}
			return field.Offset32, true
		}
	}
	return 0, false
}

// getModuleDataLayout returns the layout for a given Go version
// Multiple versions may share the same layout.
// Note: Versions like "1.21" and "1.22" are "fake" layout versions.
// Go stopped bumping the pclntab magic byte after 1.20, so 1.20-1.26 all share the same layoutVersion ("1.20").
// However, the internal moduledata struct continued to change (e.g., offsets shifted in 1.22).
// We use the runtimeVersion (extracted from buildinfo) to map to these fake layout versions
// so we can correctly parse the shifted fields.
func getModuleDataLayout(runtimeVersion string) *ModuleDataLayout {
	// Map version to layout name (many versions share layouts)
	layoutName := runtimeVersion
	switch runtimeVersion {
	case "1.27":
		layoutName = "1.27"
	case "1.26":
		layoutName = "1.22"
	case "1.25", "1.24", "1.23", "1.22", "1.21":
		layoutName = "1.21"
	case "1.20":
		layoutName = "1.20"
	case "1.19", "1.18":
		layoutName = "1.18"
	case "1.17", "1.16":
		layoutName = "1.16"
	case "1.15", "1.14", "1.13", "1.12", "1.11", "1.10", "1.9", "1.8":
		layoutName = "1.8"
	case "1.7":
		layoutName = "1.7"
	case "1.6", "1.5":
		layoutName = "1.5"
	}

	layout, exists := moduleDataLayouts[layoutName]
	if !exists {
		// Fallback to closest known version
		return moduleDataLayouts["1.22"]
	}
	return layout
}

// IsValidLayoutForRuntime checks if the layoutVersion (derived from pclntab magic)
// is compatible with the given runtimeVersion.
// This is critical because pclntab_scan attempts to brute-force the magic byte to handle obfuscated binaries.
// Without this validation, we could incorrectly accept a candidate with a newer magic byte (e.g., 1.20)
// for an older binary (e.g., 1.17), which would cause subsequent function parsing to fail even if the
// moduledata itself happens to parse successfully.
func IsValidLayoutForRuntime(layoutVersion, runtimeVersion string) bool {
	if runtimeVersion == "unknown" || layoutVersion == "unknown" {
		return true
	}

	expectedLayout := runtimeVersion
	switch runtimeVersion {
	case "1.27", "1.26", "1.25", "1.24", "1.23", "1.22", "1.21":
		expectedLayout = "1.20" // pclntab magic 1.20 is used for 1.20+
	case "1.20":
		expectedLayout = "1.20"
	case "1.19", "1.18":
		expectedLayout = "1.18"
	case "1.17", "1.16":
		expectedLayout = "1.16"
	case "1.15", "1.14", "1.13", "1.12", "1.11", "1.10", "1.9", "1.8":
		expectedLayout = "1.2" // gosym uses 1.2 for 1.2-1.15
	case "1.7", "1.6", "1.5", "1.4", "1.3", "1.2":
		expectedLayout = "1.2"
	}

	return layoutVersion == expectedLayout
}

var textsectLayout = &StructLayout{
	Fields: []FieldInfo{
		{Name: FieldVaddr, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
		{Name: FieldEnd, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
		{Name: FieldBaseaddr, Offset64: 16, Offset32: 8, Type: FieldTypePvoid},
	},
	BaseSize64: 24,
	BaseSize32: 12,
}

var functabLayout118 = &StructLayout{
	Fields: []FieldInfo{
		{Name: FieldEntryoffset, Offset64: 0, Offset32: 0, Type: FieldTypeUint32},
		{Name: FieldFuncoffset, Offset64: 4, Offset32: 4, Type: FieldTypeUint32},
	},
	BaseSize64: 8,
	BaseSize32: 8,
}

var functabLayoutLegacy = &StructLayout{
	Fields: []FieldInfo{
		{Name: FieldEntryoffset, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
		{Name: FieldFuncoffset, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
	},
	BaseSize64: 16,
	BaseSize32: 8,
}

// moduleDataLayouts defines field layouts for different Go versions
// Only fields that GoReSym actually uses are included
var moduleDataLayouts = map[string]*ModuleDataLayout{
	"1.27": {
		Version: "1.27",
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 128, Offset32: 64, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 160, Offset32: 80, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 176, Offset32: 88, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 296, Offset32: 148, Type: FieldTypePvoid},
			{Name: FieldTypedesclen, Offset64: 304, Offset32: 152, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 312, Offset32: 156, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 344, Offset32: 172, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 368, Offset32: 184, Type: FieldTypeSlice},
		},
	},
	"1.22": {
		Version: "1.22",
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 128, Offset32: 64, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 160, Offset32: 80, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 176, Offset32: 88, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 296, Offset32: 148, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 304, Offset32: 152, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 336, Offset32: 168, Type: FieldTypeSlice},
			{Name: FieldTypelinks, Offset64: 360, Offset32: 180, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 384, Offset32: 192, Type: FieldTypeSlice},
		},
	},
	"1.21": {
		Version: "1.21",
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 128, Offset32: 64, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 160, Offset32: 80, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 176, Offset32: 88, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 296, Offset32: 148, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 304, Offset32: 152, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 328, Offset32: 164, Type: FieldTypeSlice},
			{Name: FieldTypelinks, Offset64: 352, Offset32: 176, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 376, Offset32: 188, Type: FieldTypeSlice},
		},
	},
	"1.20": {
		Version: "1.20",
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 128, Offset32: 64, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 160, Offset32: 80, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 176, Offset32: 88, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 296, Offset32: 148, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 304, Offset32: 152, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 328, Offset32: 164, Type: FieldTypeSlice},
			{Name: FieldTypelinks, Offset64: 352, Offset32: 176, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 376, Offset32: 188, Type: FieldTypeSlice},
		},
	},
	"1.18": {
		Version: "1.18",
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 128, Offset32: 64, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 160, Offset32: 80, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 176, Offset32: 88, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 280, Offset32: 140, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 288, Offset32: 144, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 312, Offset32: 156, Type: FieldTypeSlice},
			{Name: FieldTypelinks, Offset64: 336, Offset32: 168, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 360, Offset32: 180, Type: FieldTypeSlice},
		},
	},
	"1.16": {
		Version: "1.16",
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 128, Offset32: 64, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 160, Offset32: 80, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 176, Offset32: 88, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 280, Offset32: 140, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 288, Offset32: 144, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 296, Offset32: 148, Type: FieldTypeSlice},
			{Name: FieldTypelinks, Offset64: 320, Offset32: 160, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 344, Offset32: 172, Type: FieldTypeSlice},
		},
	},
	// Legacy Go versions (1.2-1.15)
	"1.8": {
		Version: "1.8", // Go 1.8-1.15 (ModuleData12_64/32)
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 24, Offset32: 12, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 80, Offset32: 40, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 96, Offset32: 48, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 200, Offset32: 100, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 208, Offset32: 104, Type: FieldTypePvoid},
			{Name: FieldTextsectmap, Offset64: 216, Offset32: 108, Type: FieldTypeSlice},
			{Name: FieldTypelinks, Offset64: 240, Offset32: 120, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 264, Offset32: 132, Type: FieldTypeSlice},
		},
	},
	"1.7": {
		Version: "1.7", // Go 1.7 (ModuleData12_r17_64/32)
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 24, Offset32: 12, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 80, Offset32: 40, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 96, Offset32: 48, Type: FieldTypePvoid},
			{Name: FieldTypes, Offset64: 200, Offset32: 100, Type: FieldTypePvoid},
			{Name: FieldEtypes, Offset64: 208, Offset32: 104, Type: FieldTypePvoid},
			{Name: FieldTypelinks, Offset64: 216, Offset32: 108, Type: FieldTypeSlice},
			{Name: FieldItablinks, Offset64: 240, Offset32: 120, Type: FieldTypeSlice},
		},
	},
	"1.5": {
		Version: "1.5", // Go 1.5-1.6 (ModuleData12_r15_r16_64/32)
		Fields: []FieldInfo{
			{Name: FieldFtab, Offset64: 24, Offset32: 12, Type: FieldTypeSlice},
			{Name: FieldMinpc, Offset64: 80, Offset32: 40, Type: FieldTypePvoid},
			{Name: FieldText, Offset64: 96, Offset32: 48, Type: FieldTypePvoid},
			// Note: No Types/Etypes/Itablinks for 1.5-1.6
			{Name: FieldTypelinks, Offset64: 200, Offset32: 100, Type: FieldTypeSlice}, // Legacy format
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
	Typedesclen uint64
	Etypes      uint64
	Textsectmap GoSlice64
	Typelinks   GoSlice64
	Itablinks   GoSlice64
}

// parseModuleDataGeneric parses moduledata from raw bytes using layout tables
// This replaces the version-specific switch statements with a generic approach
func parseModuleDataGeneric(rawData []byte, runtimeVersion string, layoutVersion string, is64bit bool, littleendian bool) (*ModuleDataIntermediate, error) {
	if !IsValidLayoutForRuntime(layoutVersion, runtimeVersion) {
		return nil, fmt.Errorf("layoutVersion %s is incompatible with runtimeVersion %s", layoutVersion, runtimeVersion)
	}

	layout := getModuleDataLayout(runtimeVersion)
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
		if field.Type == FieldTypeSlice {
			requiredSize = offset + 24 // slice is 3 pointers
			if !is64bit {
				requiredSize = offset + 12
			}
		}

		if len(rawData) < requiredSize {
			continue
		}

		switch field.Name {
		case FieldFtab:
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Ftab = GoSlice64{Data: pvoid64(data), Len: len}
		case FieldMinpc:
			md.Minpc = readPointer(rawData, offset, is64bit, littleendian)
		case FieldText:
			md.Text = readPointer(rawData, offset, is64bit, littleendian)
		case FieldTypes:
			md.Types = readPointer(rawData, offset, is64bit, littleendian)
		case FieldTypedesclen:
			md.Typedesclen = readPointer(rawData, offset, is64bit, littleendian)
		case FieldEtypes:
			md.Etypes = readPointer(rawData, offset, is64bit, littleendian)
		case FieldTextsectmap:
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Textsectmap = GoSlice64{Data: pvoid64(data), Len: len}
		case FieldTypelinks:
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Typelinks = GoSlice64{Data: pvoid64(data), Len: len}
		case FieldItablinks:
			data, len := readSlice(rawData, offset, is64bit, littleendian)
			md.Itablinks = GoSlice64{Data: pvoid64(data), Len: len}
		}
	}

	return md, nil
}

// validateAndConvertModuleData performs validation and converts intermediate moduledata
// to the final ModuleData struct used by GoReSym
// This replaces the duplicated validation logic in version-specific switch cases
// For Go 1.18+
func (e *Entry) validateAndConvertModuleData(
	md *ModuleDataIntermediate,
	moduleDataVA uint64,
	is64bit bool,
	littleendian bool,
	ignorelist []uint64,
) (*ModuleData, []uint64, error) {

	// Read and validate first function from ftab
	ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(functabLayout118.BaseSize64))
	if err != nil {
		return nil, ignorelist, err
	}

	ftabReader := MemoryReader{
		Data:         ftab_raw,
		Layout:       functabLayout118,
		Is64Bit:      is64bit,
		LittleEndian: littleendian,
	}
	entryOffset := ftabReader.ReadUint32(FieldEntryoffset)

	// Prevent loop on invalid modules with bogus length
	if md.Textsectmap.Len > 0x100 {
		return nil, ignorelist, fmt.Errorf("textsectmap length too large: %d", md.Textsectmap.Len)
	}

	// Read textsectmap entries
	var textsectmap []Textsect

	sectSize := textsectLayout.BaseSize64
	if !is64bit {
		sectSize = textsectLayout.BaseSize32
	}

	for i := 0; i < int(md.Textsectmap.Len); i++ {
		textsec_raw, err := e.raw.read_memory(uint64(md.Textsectmap.Data)+(uint64(i)*uint64(sectSize)), uint64(sectSize))
		if err != nil {
			return nil, ignorelist, err
		}

		sectReader := MemoryReader{
			Data:         textsec_raw,
			Layout:       textsectLayout,
			Is64Bit:      is64bit,
			LittleEndian: littleendian,
		}

		textsectmap = append(textsectmap, Textsect{
			Vaddr:    sectReader.ReadPointer(FieldVaddr),
			End:      sectReader.ReadPointer(FieldEnd),
			Baseaddr: sectReader.ReadPointer(FieldBaseaddr),
		})
	}

	// Validate: functab's first function should equal minpc value
	if textAddr(uint64(entryOffset), md.Text, textsectmap) != md.Minpc {
		// Wrong moduledata, add to ignorelist
		ignorelist = append(ignorelist, moduleDataVA)
		return nil, ignorelist, fmt.Errorf("minpc validation failed")
	}

	// Validation passed, create final ModuleData struct
	result := &ModuleData{
		VA:          moduleDataVA,
		TextVA:      md.Text,
		Types:       md.Types,
		Typedesclen: md.Typedesclen,
		ETypes:      md.Etypes,
		Typelinks:   md.Typelinks,
		ITablinks:   md.Itablinks,
	}

	return result, ignorelist, nil
}

// validateAndConvertModuleData_116 performs validation for Go 1.16-1.17
// These versions use simpler validation (no textsectmap)
func (e *Entry) validateAndConvertModuleData_116(
	md *ModuleDataIntermediate,
	moduleDataVA uint64,
	is64bit bool,
	littleendian bool,
	ignorelist []uint64,
) (*ModuleData, []uint64, error) {

	// Read and validate first function from ftab
	ftabSize := functabLayoutLegacy.BaseSize64
	if !is64bit {
		ftabSize = functabLayoutLegacy.BaseSize32
	}

	ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(ftabSize))
	if err != nil {
		fmt.Printf("DEBUG: validateAndConvertModuleData_116 failed to read ftab: %v\n", err)
		return nil, ignorelist, err
	}

	ftabReader := MemoryReader{
		Data:         ftab_raw,
		Layout:       functabLayoutLegacy,
		Is64Bit:      is64bit,
		LittleEndian: littleendian,
	}
	entryOffset := ftabReader.ReadPointer(FieldEntryoffset)

	// Validate: functab's first function should equal minpc value
	if entryOffset != md.Minpc {
		fmt.Printf("DEBUG: validateAndConvertModuleData_116 minpc validation failed: %x != %x\n", entryOffset, md.Minpc)
		// Wrong moduledata, add to ignorelist
		ignorelist = append(ignorelist, moduleDataVA)
		return nil, ignorelist, fmt.Errorf("minpc validation failed")
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

// validateAndConvertModuleData_Legacy performs validation for Go 1.7-1.15
// These versions have Types/Etypes/Itablinks but use simpler validation (direct minpc check)
func (e *Entry) validateAndConvertModuleData_Legacy(
	md *ModuleDataIntermediate,
	moduleDataVA uint64,
	is64bit bool,
	littleendian bool,
	ignorelist []uint64,
) (*ModuleData, []uint64, error) {

	// Read and validate first function from ftab
	ftabSize := functabLayoutLegacy.BaseSize64
	if !is64bit {
		ftabSize = functabLayoutLegacy.BaseSize32
	}

	ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(ftabSize))
	if err != nil {
		return nil, ignorelist, err
	}

	ftabReader := MemoryReader{
		Data:         ftab_raw,
		Layout:       functabLayoutLegacy,
		Is64Bit:      is64bit,
		LittleEndian: littleendian,
	}
	entryOffset := ftabReader.ReadPointer(FieldEntryoffset)

	// Validate: functab's first function should equal minpc value
	if entryOffset != md.Minpc {
		// Wrong moduledata, add to ignorelist
		ignorelist = append(ignorelist, moduleDataVA)
		return nil, ignorelist, fmt.Errorf("minpc validation failed")
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

// validateAndConvertModuleData_Legacy_NoTypes performs validation for Go 1.5-1.6
// These versions use LegacyTypes instead of Types/Etypes, no Itablinks
func (e *Entry) validateAndConvertModuleData_Legacy_NoTypes(
	md *ModuleDataIntermediate,
	moduleDataVA uint64,
	is64bit bool,
	littleendian bool,
	ignorelist []uint64,
) (*ModuleData, []uint64, error) {

	// Read and validate first function from ftab
	ftabSize := functabLayoutLegacy.BaseSize64
	if !is64bit {
		ftabSize = functabLayoutLegacy.BaseSize32
	}

	ftab_raw, err := e.raw.read_memory(uint64(md.Ftab.Data), uint64(ftabSize))
	if err != nil {
		return nil, ignorelist, err
	}

	ftabReader := MemoryReader{
		Data:         ftab_raw,
		Layout:       functabLayoutLegacy,
		Is64Bit:      is64bit,
		LittleEndian: littleendian,
	}
	entryOffset := ftabReader.ReadPointer(FieldEntryoffset)

	// Validate: functab's first function should equal minpc value
	if entryOffset != md.Minpc {
		// Wrong moduledata, add to ignorelist
		ignorelist = append(ignorelist, moduleDataVA)
		return nil, ignorelist, fmt.Errorf("minpc validation failed")
	}

	// Validation passed, create final ModuleData struct
	// Use LegacyTypes instead of Types/Etypes for Go 1.5-1.6
	result := &ModuleData{
		VA:     moduleDataVA,
		TextVA: md.Text,
		LegacyTypes: GoSlice64{
			Data:     pvoid64(md.Typelinks.Data),
			Len:      md.Typelinks.Len,
			Capacity: md.Typelinks.Capacity,
		},
	}

	return result, ignorelist, nil
}

// ========================================
// Type (Rtype) Layout System
// ========================================

// RtypeLayout describes the binary layout of a Go runtime type structure
type RtypeLayout struct {
	Version    string
	Fields     []FieldInfo
	StrType    string // "pointer" for 1.5-1.6, "offset" for 1.7+
	FlagsField string // "Unused" for 1.5-1.6, "Tflag" for 1.7+
	BaseSize64 int    // Size of the Rtype struct in 64-bit binaries
	BaseSize32 int    // Size of the Rtype struct in 32-bit binaries
}

// RtypeIntermediate holds parsed Rtype fields
type RtypeIntermediate struct {
	Size       uint64
	Ptrdata    uint64
	Hash       uint32
	Tflag      tflag // or Unused for older versions
	Align      uint8
	FieldAlign uint8
	Kind       uint8
	Str        uint64 // Pointer (1.5-1.6) or offset (1.7+)
}

// getRtypeLayout returns the layout for a given Go runtime version
func getRtypeLayout(runtimeVersion string) *RtypeLayout {
	rTypeLayout := ""

	switch runtimeVersion {
	case "1.5":
		rTypeLayout = "1.5"
	case "1.6":
		rTypeLayout = "1.6"
	case "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13":
		rTypeLayout = "1.7"
	case "1.14", "1.15", "1.16", "1.17", "1.18", "1.19":
		rTypeLayout = "1.14"
	case "1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27":
		rTypeLayout = "1.20"
	default:
		return nil
	}

	return rtypeLayouts[rTypeLayout]
}

// rtypeLayouts defines field layouts for different Go runtime type versions
var rtypeLayouts = map[string]*RtypeLayout{
	"1.5": {
		Version: "1.5",
		Fields: []FieldInfo{
			{Name: FieldSize, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
			{Name: FieldPtrdata, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
			{Name: FieldHash, Offset64: 16, Offset32: 8, Type: FieldTypeUint32},
			{Name: FieldUnused, Offset64: 20, Offset32: 12, Type: FieldTypeUint8},
			{Name: FieldAlign, Offset64: 21, Offset32: 13, Type: FieldTypeUint8},
			{Name: FieldFieldAlign, Offset64: 22, Offset32: 14, Type: FieldTypeUint8},
			{Name: FieldKind, Offset64: 23, Offset32: 15, Type: FieldTypeUint8},
			{Name: FieldStr, Offset64: 40, Offset32: 24, Type: FieldTypePvoid}, // Direct pointer
		},
		StrType:    "pointer",
		FlagsField: "Unused",
		BaseSize64: 72,
		BaseSize32: 40,
	},
	"1.6": {
		Version: "1.6",
		Fields: []FieldInfo{
			{Name: FieldSize, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
			{Name: FieldPtrdata, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
			{Name: FieldHash, Offset64: 16, Offset32: 8, Type: FieldTypeUint32},
			{Name: FieldUnused, Offset64: 20, Offset32: 12, Type: FieldTypeUint8},
			{Name: FieldAlign, Offset64: 21, Offset32: 13, Type: FieldTypeUint8},
			{Name: FieldFieldAlign, Offset64: 22, Offset32: 14, Type: FieldTypeUint8},
			{Name: FieldKind, Offset64: 23, Offset32: 15, Type: FieldTypeUint8},
			{Name: FieldStr, Offset64: 40, Offset32: 24, Type: FieldTypePvoid}, // Direct pointer
		},
		StrType:    "pointer",
		FlagsField: "Unused",
		BaseSize64: 64,
		BaseSize32: 36,
	},
	"1.7": {
		Version: "1.7", // Go 1.7-1.13
		Fields: []FieldInfo{
			{Name: FieldSize, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
			{Name: FieldPtrdata, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
			{Name: FieldHash, Offset64: 16, Offset32: 8, Type: FieldTypeUint32},
			{Name: FieldTflag, Offset64: 20, Offset32: 12, Type: FieldTypeUint8},
			{Name: FieldAlign, Offset64: 21, Offset32: 13, Type: FieldTypeUint8},
			{Name: FieldFieldAlign, Offset64: 22, Offset32: 14, Type: FieldTypeUint8},
			{Name: FieldKind, Offset64: 23, Offset32: 15, Type: FieldTypeUint8},
			{Name: FieldStr, Offset64: 40, Offset32: 24, Type: FieldTypeInt32}, // Offset from Types base
		},
		StrType:    "offset",
		FlagsField: "Tflag",
		BaseSize64: 48,
		BaseSize32: 32,
	},
	"1.14": {
		Version: "1.14", // Go 1.14-1.19 (same layout as 1.7, different Equal vs Alg)
		Fields: []FieldInfo{
			{Name: FieldSize, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
			{Name: FieldPtrdata, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
			{Name: FieldHash, Offset64: 16, Offset32: 8, Type: FieldTypeUint32},
			{Name: FieldTflag, Offset64: 20, Offset32: 12, Type: FieldTypeUint8},
			{Name: FieldAlign, Offset64: 21, Offset32: 13, Type: FieldTypeUint8},
			{Name: FieldFieldAlign, Offset64: 22, Offset32: 14, Type: FieldTypeUint8},
			{Name: FieldKind, Offset64: 23, Offset32: 15, Type: FieldTypeUint8},
			{Name: FieldStr, Offset64: 40, Offset32: 24, Type: FieldTypeInt32}, // Offset from Types base
		},
		StrType:    "offset",
		FlagsField: "Tflag",
		BaseSize64: 48,
		BaseSize32: 32,
	},
	"1.20": {
		Version: "1.20", // Go 1.20+ (ABIType, same layout as 1.14)
		Fields: []FieldInfo{
			{Name: FieldSize, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
			{Name: FieldPtrdata, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
			{Name: FieldHash, Offset64: 16, Offset32: 8, Type: FieldTypeUint32},
			{Name: FieldTflag, Offset64: 20, Offset32: 12, Type: FieldTypeUint8},
			{Name: FieldAlign, Offset64: 21, Offset32: 13, Type: FieldTypeUint8},
			{Name: FieldFieldAlign, Offset64: 22, Offset32: 14, Type: FieldTypeUint8},
			{Name: FieldKind, Offset64: 23, Offset32: 15, Type: FieldTypeUint8},
			{Name: FieldStr, Offset64: 40, Offset32: 24, Type: FieldTypeInt32}, // Offset from Types base
		},
		StrType:    "offset",
		FlagsField: "Tflag",
		BaseSize64: 48,
		BaseSize32: 32,
	},
}

// Helper functions for reading type-specific fields

func readUint32(data []byte, offset int, littleendian bool) uint32 {
	if littleendian {
		return uint32(data[offset]) |
			uint32(data[offset+1])<<8 |
			uint32(data[offset+2])<<16 |
			uint32(data[offset+3])<<24
	} else {
		return uint32(data[offset])<<24 |
			uint32(data[offset+1])<<16 |
			uint32(data[offset+2])<<8 |
			uint32(data[offset+3])
	}
}

func readInt32(data []byte, offset int, littleendian bool) int32 {
	return int32(readUint32(data, offset, littleendian))
}

// parseRtypeGeneric parses Rtype data using the layout table approach
func parseRtypeGeneric(rawData []byte, runtimeVersion string, is64bit bool, littleendian bool) (*RtypeIntermediate, uint64, error) {
	layout := getRtypeLayout(runtimeVersion)
	if layout == nil {
		return nil, 0, fmt.Errorf("unknown runtime version: %s", runtimeVersion)
	}

	rt := &RtypeIntermediate{}

	for _, field := range layout.Fields {
		offset := field.Offset64
		if !is64bit {
			offset = field.Offset32
		}

		switch field.Name {
		case FieldSize:
			rt.Size = readPointer(rawData, offset, is64bit, littleendian)
		case FieldPtrdata:
			rt.Ptrdata = readPointer(rawData, offset, is64bit, littleendian)
		case FieldHash:
			rt.Hash = readUint32(rawData, offset, littleendian)
		case FieldUnused, FieldTflag:
			rt.Tflag = tflag(rawData[offset])
		case FieldAlign:
			rt.Align = rawData[offset]
		case FieldFieldAlign:
			rt.FieldAlign = rawData[offset]
		case FieldKind:
			rt.Kind = rawData[offset]
		case FieldStr:
			if layout.StrType == "pointer" {
				// Go 1.5-1.6: Str is a direct pointer
				rt.Str = readPointer(rawData, offset, is64bit, littleendian)
			} else {
				// Go 1.7+: Str is an int32 offset from moduledata.Types
				rt.Str = uint64(readInt32(rawData, offset, littleendian))
			}
		}
	}

	// Return baseSize as well
	var baseSize uint64
	if is64bit {
		baseSize = uint64(layout.BaseSize64)
	} else {
		baseSize = uint64(layout.BaseSize32)
	}

	return rt, baseSize, nil
}

// getRtypeFieldOffset returns the offset for a named field in an Rtype layout
func getRtypeFieldOffset(layout *RtypeLayout, fieldName FieldName, is64bit bool) (int, bool) {
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

// Interface methods encoding format
type InterfaceMethodsFormat uint8

const (
	IFMethodsPre17  InterfaceMethodsFormat = iota // 1.5-1.6: pointers in imethod
	IFMethodsPost17                               // 1.7+: nameOff/typeOff in IMethod
)

// InterfaceLayout describes offsets relative to the rtype base for interfaceType
// MethodsOffsetPtrs is the number of pointer-size units after base where the methods slice resides
// PkgPathOffsetPtrs is the number of pointer-size units after base for pkgPath (or -1 if absent)
type InterfaceLayout struct {
	MethodsOffsetPtrs int
	PkgPathOffsetPtrs int // -1 if not present
	MethodsFormat     InterfaceMethodsFormat
}

// getInterfaceLayout returns the interface layout info for a Go runtime version
func getInterfaceLayout(version string) *InterfaceLayout {
	switch version {
	case "1.5", "1.6":
		return &InterfaceLayout{
			MethodsOffsetPtrs: 0,
			PkgPathOffsetPtrs: -1,
			MethodsFormat:     IFMethodsPre17,
		}
	case "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14",
		"1.15", "1.16", "1.17", "1.18", "1.19", "1.20", "1.21", "1.22", "1.23", "1.24", "1.25":
		return &InterfaceLayout{
			MethodsOffsetPtrs: 1, // pkgPath at +0, methods slice at +1
			PkgPathOffsetPtrs: 0,
			MethodsFormat:     IFMethodsPost17,
		}
	default:
		// Default to post-1.7 layout
		return &InterfaceLayout{
			MethodsOffsetPtrs: 1,
			PkgPathOffsetPtrs: 0,
			MethodsFormat:     IFMethodsPost17,
		}
	}
}

// computeTypeDescriptorSize computes the memory size of a type descriptor.
// Matches Go's internal/abi/type.go DescriptorSize() function.
//
// Actual sizeof for each type on 64-bit (based on Go 1.27 internal/abi source):
//
//	Type=48, ArrayType=72, ChanType=64, FuncType=56
//	InterfaceType=80, MapType=112, PtrType=56, SliceType=56
//	StructType=80, StructField=24, UncommonType=16, Method=16, Imethod=8
//
// Actual sizeof for each type on 32-bit:
//
//	Type=32, ArrayType=44, ChanType=40, FuncType=36
//	InterfaceType=48, MapType=60, PtrType=36, SliceType=36
//	StructType=48, StructField=12, UncommonType=16, Method=16, Imethod=8
func computeTypeDescriptorSize(rt *RtypeIntermediate, is64bit bool, rawData []byte, littleEndian bool) uint64 {
	// sizeof for each type struct in Go 1.27 internal/abi
	var typeSize uint64
	var arrayTypeSize uint64
	var chanTypeSize uint64
	var funcTypeSize uint64
	var ifaceTypeSize uint64
	var mapTypeSize uint64
	var ptrTypeSize uint64
	var sliceTypeSize uint64
	var structTypeSize uint64
	var structFieldSize uint64
	var ptrSize uint64

	if is64bit {
		typeSize = 48
		arrayTypeSize = 72
		chanTypeSize = 64
		funcTypeSize = 56
		ifaceTypeSize = 80
		mapTypeSize = 112
		ptrTypeSize = 56
		sliceTypeSize = 56
		structTypeSize = 80
		structFieldSize = 24
		ptrSize = 8
	} else {
		typeSize = 32
		arrayTypeSize = 44
		chanTypeSize = 40
		funcTypeSize = 36
		ifaceTypeSize = 48
		mapTypeSize = 60
		ptrTypeSize = 36
		sliceTypeSize = 36
		structTypeSize = 48
		structFieldSize = 12
		ptrSize = 4
	}

	var baseSize uint64 = 0
	var addSize uint64 = 0

	kind := rt.Kind & 0x1f
	switch kind {
	case 17: // Array
		baseSize = arrayTypeSize
	case 18: // Chan
		baseSize = chanTypeSize
	case 19: // Func
		baseSize = funcTypeSize
		// addSize = (inCount + outCount) * ptrSize
		if len(rawData) >= int(baseSize) {
			var inCount, outCount uint16
			if littleEndian {
				inCount = binary.LittleEndian.Uint16(rawData[typeSize:])
				outCount = binary.LittleEndian.Uint16(rawData[typeSize+2:])
			} else {
				inCount = binary.BigEndian.Uint16(rawData[typeSize:])
				outCount = binary.BigEndian.Uint16(rawData[typeSize+2:])
			}
			outCount = outCount & 0x7FFF
			addSize = uint64(inCount+outCount) * ptrSize
		}
	case 20: // Interface
		baseSize = ifaceTypeSize
		// addSize = len(Methods) * sizeof(Imethod=8)
		// Methods slice offset in InterfaceType: typeSize + sizeof(Name=ptrSize)
		methodsSliceOff := typeSize + ptrSize
		if len(rawData) >= int(baseSize) {
			var methodsLen uint64
			if is64bit {
				// slice header: Data(8), Len(8), Cap(8)
				if littleEndian {
					methodsLen = binary.LittleEndian.Uint64(rawData[methodsSliceOff+8:])
				} else {
					methodsLen = binary.BigEndian.Uint64(rawData[methodsSliceOff+8:])
				}
			} else {
				if littleEndian {
					methodsLen = uint64(binary.LittleEndian.Uint32(rawData[methodsSliceOff+4:]))
				} else {
					methodsLen = uint64(binary.BigEndian.Uint32(rawData[methodsSliceOff+4:]))
				}
			}
			addSize = methodsLen * 8 // sizeof(Imethod)
		}
	case 21: // Map
		baseSize = mapTypeSize
	case 22: // Pointer
		baseSize = ptrTypeSize
	case 23: // Slice
		baseSize = sliceTypeSize
	case 25: // Struct
		baseSize = structTypeSize
		// addSize = len(Fields) * sizeof(StructField)
		// Fields slice offset in StructType: typeSize + sizeof(Name=ptrSize)
		fieldsSliceOff := typeSize + ptrSize
		if len(rawData) >= int(baseSize) {
			var fieldsLen uint64
			if is64bit {
				if littleEndian {
					fieldsLen = binary.LittleEndian.Uint64(rawData[fieldsSliceOff+8:])
				} else {
					fieldsLen = binary.BigEndian.Uint64(rawData[fieldsSliceOff+8:])
				}
			} else {
				if littleEndian {
					fieldsLen = uint64(binary.LittleEndian.Uint32(rawData[fieldsSliceOff+4:]))
				} else {
					fieldsLen = uint64(binary.BigEndian.Uint32(rawData[fieldsSliceOff+4:]))
				}
			}
			addSize = fieldsLen * structFieldSize
		}
	default:
		// Bool, Int*, Uint*, Float*, Complex*, String, UnsafePointer
		baseSize = typeSize
	}

	ret := baseSize

	// uncommonType follows immediately after the concrete type struct
	var mcount uint16 = 0
	if uint8(rt.Tflag)&uint8(tflagUncommon) != 0 {
		uncommonSize := uint64(16) // sizeof(UncommonType) = 16
		ret += uncommonSize

		if len(rawData) >= int(baseSize+uncommonSize) {
			up := rawData[baseSize : baseSize+uncommonSize]
			if littleEndian {
				mcount = binary.LittleEndian.Uint16(up[4:6])
			} else {
				mcount = binary.BigEndian.Uint16(up[4:6])
			}
		}
	}

	ret += addSize

	// Method = NameOff(4) + Mtyp(4) + Ifn(4) + Tfn(4) = 16 bytes
	ret += uint64(mcount) * 16

	return ret
}
