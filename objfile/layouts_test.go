/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package objfile

import (
	"reflect"
	"testing"
)

// TestVersionMapping verifies that version aliases work correctly
func TestVersionMapping(t *testing.T) {
	testCases := []struct {
		version           string
		expectedLayoutVer string
	}{
		{"1.21", "1.21"},
		{"1.22", "1.21"}, // 1.22 uses same layout as 1.21
		{"1.23", "1.21"}, // 1.23 uses same layout as 1.21
		{"1.24", "1.21"}, // 1.24 uses same layout as 1.21
		{"1.27", "1.27"}, // 1.27 has its own layout (Typedesclen replaces Typelinks)
		{"1.26", "1.22"}, // 1.26 uses 1.22 layout
		{"1.25", "1.21"}, // 1.25 uses same layout as 1.21
		{"1.20", "1.20"},
		{"1.18", "1.18"},
		{"1.19", "1.18"}, // 1.19 uses same layout as 1.18
	}

	for _, tc := range testCases {
		t.Run(tc.version, func(t *testing.T) {
			layout := getModuleDataLayout(tc.version)
			if layout.Version != tc.expectedLayoutVer {
				t.Errorf("Version %s mapped to layout %s, expected %s",
					tc.version, layout.Version, tc.expectedLayoutVer)
			}
		})
	}
}

// TestReadPointer verifies the pointer reading logic
func TestReadPointer(t *testing.T) {
	t.Run("64-bit little-endian", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		result := readPointer(data, 0, true, true)
		expected := uint64(0x0807060504030201)
		if result != expected {
			t.Errorf("Got 0x%x, want 0x%x", result, expected)
		}
	})

	t.Run("64-bit big-endian", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		result := readPointer(data, 0, true, false)
		expected := uint64(0x0102030405060708)
		if result != expected {
			t.Errorf("Got 0x%x, want 0x%x", result, expected)
		}
	})

	t.Run("32-bit little-endian", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04}
		result := readPointer(data, 0, false, true)
		expected := uint64(0x04030201)
		if result != expected {
			t.Errorf("Got 0x%x, want 0x%x", result, expected)
		}
	})

	t.Run("32-bit big-endian", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04}
		result := readPointer(data, 0, false, false)
		expected := uint64(0x01020304)
		if result != expected {
			t.Errorf("Got 0x%x, want 0x%x", result, expected)
		}
	})
}

// TestReadSlice verifies the slice reading logic
func TestReadSlice(t *testing.T) {
	t.Run("64-bit little-endian", func(t *testing.T) {
		// Slice: {Data: 0x1000, Len: 42, Cap: 100}
		data := make([]byte, 24)
		// Data pointer
		data[0] = 0x00
		data[1] = 0x10
		// Len
		data[8] = 42
		// Cap
		data[16] = 100

		sliceData, sliceLen := readSlice(data, 0, true, true)
		if sliceData != 0x1000 {
			t.Errorf("Data pointer: got 0x%x, want 0x1000", sliceData)
		}
		if sliceLen != 42 {
			t.Errorf("Len: got %d, want 42", sliceLen)
		}
	})

	t.Run("32-bit little-endian", func(t *testing.T) {
		// Slice: {Data: 0x1000, Len: 42, Cap: 100}
		data := make([]byte, 12)
		// Data pointer
		data[0] = 0x00
		data[1] = 0x10
		// Len
		data[4] = 42
		// Cap
		data[8] = 100

		sliceData, sliceLen := readSlice(data, 0, false, true)
		if sliceData != 0x1000 {
			t.Errorf("Data pointer: got 0x%x, want 0x1000", sliceData)
		}
		if sliceLen != 42 {
			t.Errorf("Len: got %d, want 42", sliceLen)
		}
	})
}

// TestMemoryReader verifies the MemoryReader utility
func TestMemoryReader(t *testing.T) {
	layout := &StructLayout{
		Fields: []FieldInfo{
			{Name: FieldVaddr, Offset64: 0, Offset32: 0, Type: FieldTypePvoid},
			{Name: FieldEnd, Offset64: 8, Offset32: 4, Type: FieldTypePvoid},
			{Name: FieldEntryoffset, Offset64: 16, Offset32: 8, Type: FieldTypeUint32},
		},
		BaseSize64: 24,
		BaseSize32: 12,
	}

	t.Run("64-bit little-endian", func(t *testing.T) {
		data := make([]byte, 24)
		// Vaddr = 0x1000
		data[0] = 0x00
		data[1] = 0x10
		// End = 0x2000
		data[8] = 0x00
		data[9] = 0x20
		// Entryoffset = 42
		data[16] = 42

		reader := MemoryReader{
			Data:         data,
			Layout:       layout,
			Is64Bit:      true,
			LittleEndian: true,
		}

		if v := reader.ReadPointer(FieldVaddr); v != 0x1000 {
			t.Errorf("Vaddr: got 0x%x, want 0x1000", v)
		}
		if v := reader.ReadPointer(FieldEnd); v != 0x2000 {
			t.Errorf("End: got 0x%x, want 0x2000", v)
		}
		if v := reader.ReadUint32(FieldEntryoffset); v != 42 {
			t.Errorf("Entryoffset: got %d, want 42", v)
		}
		// Test missing field
		if v := reader.ReadPointer(FieldBaseaddr); v != 0 {
			t.Errorf("Baseaddr (missing): got %d, want 0", v)
		}
	})

	t.Run("32-bit little-endian", func(t *testing.T) {
		data := make([]byte, 12)
		// Vaddr = 0x1000
		data[0] = 0x00
		data[1] = 0x10
		// End = 0x2000
		data[4] = 0x00
		data[5] = 0x20
		// Entryoffset = 42
		data[8] = 42

		reader := MemoryReader{
			Data:         data,
			Layout:       layout,
			Is64Bit:      false,
			LittleEndian: true,
		}

		if v := reader.ReadPointer(FieldVaddr); v != 0x1000 {
			t.Errorf("Vaddr: got 0x%x, want 0x1000", v)
		}
		if v := reader.ReadPointer(FieldEnd); v != 0x2000 {
			t.Errorf("End: got 0x%x, want 0x2000", v)
		}
		if v := reader.ReadUint32(FieldEntryoffset); v != 42 {
			t.Errorf("Entryoffset: got %d, want 42", v)
		}
	})
}

// TestModuleDataIntermediate_FieldTypes verifies the intermediate struct has correct types
func TestModuleDataIntermediate_FieldTypes(t *testing.T) {
	var md ModuleDataIntermediate

	// Use reflection to verify field types
	mdType := reflect.TypeOf(md)

	expectedFields := map[FieldName]string{
		FieldFtab:        "objfile.GoSlice64",
		FieldMinpc:       "uint64",
		FieldText:        "uint64",
		FieldTypes:       "uint64",
		FieldEtypes:      "uint64",
		FieldTextsectmap: "objfile.GoSlice64",
		FieldTypelinks:   "objfile.GoSlice64",
		FieldItablinks:   "objfile.GoSlice64",
	}

	for fieldName, expectedType := range expectedFields {
		field, found := mdType.FieldByName(fieldName.String())
		if !found {
			t.Errorf("Field %s not found in ModuleDataIntermediate", fieldName.String())
			continue
		}
		actualType := field.Type.String()
		if actualType != expectedType {
			t.Errorf("Field %s has type %s, expected %s",
				fieldName.String(), actualType, expectedType)
		}
	}
}

// Test version mapping for legacy versions
func TestVersionMapping_Legacy(t *testing.T) {
	testCases := []struct {
		version      string
		expectedName string
	}{
		{"1.5", "1.5"},
		{"1.6", "1.5"},
		{"1.7", "1.7"},
		{"1.8", "1.8"},
		{"1.9", "1.8"},
		{"1.10", "1.8"},
		{"1.11", "1.8"},
		{"1.12", "1.8"},
		{"1.13", "1.8"},
		{"1.14", "1.8"},
		{"1.15", "1.8"},
	}

	for _, tc := range testCases {
		t.Run(tc.version, func(t *testing.T) {
			layout := getModuleDataLayout(tc.version)
			if layout == nil {
				t.Fatalf("Layout for version %s is nil", tc.version)
			}
			if layout.Version != tc.expectedName {
				t.Errorf("Version %s mapped to layout %s, expected %s",
					tc.version, layout.Version, tc.expectedName)
			}
		})
	}
}

// Test Rtype version mapping
func TestRtypeVersionMapping(t *testing.T) {
	testCases := []struct {
		version      string
		expectedName string
	}{
		{"1.5", "1.5"},
		{"1.6", "1.6"},
		{"1.7", "1.7"},
		{"1.8", "1.7"},
		{"1.9", "1.7"},
		{"1.10", "1.7"},
		{"1.11", "1.7"},
		{"1.12", "1.7"},
		{"1.13", "1.7"},
		{"1.14", "1.14"},
		{"1.15", "1.14"},
		{"1.16", "1.14"},
		{"1.17", "1.14"},
		{"1.18", "1.14"},
		{"1.19", "1.14"},
		{"1.20", "1.14"},
		{"1.21", "1.14"},
		{"1.22", "1.14"},
		{"1.23", "1.20"},
		{"1.24", "1.20"},
		{"1.25", "1.20"},
		{"1.26", "1.20"},
		{"1.27", "1.20"},
	}

	for _, tc := range testCases {
		t.Run(tc.version, func(t *testing.T) {
			layout := getRtypeLayout(tc.version)
			if layout == nil {
				t.Fatalf("Layout for version %s is nil", tc.version)
			}
			if layout.Version != tc.expectedName {
				t.Errorf("Version %s mapped to layout %s, expected %s",
					tc.version, layout.Version, tc.expectedName)
			}
		})
	}
}
