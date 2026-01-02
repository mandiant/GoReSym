/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package objfile

import (
	"reflect"
	"testing"
	"unsafe"
)

// TestLayoutOffsets_Match_StructDefinitions verifies that our layout offset tables
// match the actual struct definitions from internals.go
func TestLayoutOffsets_Match_StructDefinitions(t *testing.T) {
	t.Run("ModuleData121_64", func(t *testing.T) {
		var md ModuleData121_64
		layout := getModuleDataLayout("1.21")

		testCases := []struct {
			fieldName      string
			actualOffset64 int
		}{
			{"Ftab", int(unsafe.Offsetof(md.Ftab))},
			{"Minpc", int(unsafe.Offsetof(md.Minpc))},
			{"Text", int(unsafe.Offsetof(md.Text))},
			{"Types", int(unsafe.Offsetof(md.Types))},
			{"Etypes", int(unsafe.Offsetof(md.Etypes))},
			{"Textsectmap", int(unsafe.Offsetof(md.Textsectmap))},
			{"Typelinks", int(unsafe.Offsetof(md.Typelinks))},
			{"Itablinks", int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName)
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})

	t.Run("ModuleData121_32", func(t *testing.T) {
		var md ModuleData121_32
		layout := getModuleDataLayout("1.21")

		testCases := []struct {
			fieldName      string
			actualOffset32 int
		}{
			{"Ftab", int(unsafe.Offsetof(md.Ftab))},
			{"Minpc", int(unsafe.Offsetof(md.Minpc))},
			{"Text", int(unsafe.Offsetof(md.Text))},
			{"Types", int(unsafe.Offsetof(md.Types))},
			{"Etypes", int(unsafe.Offsetof(md.Etypes))},
			{"Textsectmap", int(unsafe.Offsetof(md.Textsectmap))},
			{"Typelinks", int(unsafe.Offsetof(md.Typelinks))},
			{"Itablinks", int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, false)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName)
				continue
			}
			if layoutOffset != tc.actualOffset32 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset32)
			}
		}
	})

	t.Run("ModuleData120_64", func(t *testing.T) {
		var md ModuleData120_64
		layout := getModuleDataLayout("1.20")

		testCases := []struct {
			fieldName      string
			actualOffset64 int
		}{
			{"Ftab", int(unsafe.Offsetof(md.Ftab))},
			{"Minpc", int(unsafe.Offsetof(md.Minpc))},
			{"Text", int(unsafe.Offsetof(md.Text))},
			{"Types", int(unsafe.Offsetof(md.Types))},
			{"Etypes", int(unsafe.Offsetof(md.Etypes))},
			{"Textsectmap", int(unsafe.Offsetof(md.Textsectmap))},
			{"Typelinks", int(unsafe.Offsetof(md.Typelinks))},
			{"Itablinks", int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName)
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})

	t.Run("ModuleData118_64", func(t *testing.T) {
		var md ModuleData118_64
		layout := getModuleDataLayout("1.18")

		testCases := []struct {
			fieldName      string
			actualOffset64 int
		}{
			{"Ftab", int(unsafe.Offsetof(md.Ftab))},
			{"Minpc", int(unsafe.Offsetof(md.Minpc))},
			{"Text", int(unsafe.Offsetof(md.Text))},
			{"Types", int(unsafe.Offsetof(md.Types))},
			{"Etypes", int(unsafe.Offsetof(md.Etypes))},
			{"Textsectmap", int(unsafe.Offsetof(md.Textsectmap))},
			{"Typelinks", int(unsafe.Offsetof(md.Typelinks))},
			{"Itablinks", int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName)
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})

	t.Run("ModuleData116_64", func(t *testing.T) {
		var md ModuleData116_64
		layout := getModuleDataLayout("1.16")

		testCases := []struct {
			fieldName      string
			actualOffset64 int
		}{
			{"Ftab", int(unsafe.Offsetof(md.Ftab))},
			{"Minpc", int(unsafe.Offsetof(md.Minpc))},
			{"Text", int(unsafe.Offsetof(md.Text))},
			{"Types", int(unsafe.Offsetof(md.Types))},
			{"Etypes", int(unsafe.Offsetof(md.Etypes))},
			{"Textsectmap", int(unsafe.Offsetof(md.Textsectmap))},
			{"Typelinks", int(unsafe.Offsetof(md.Typelinks))},
			{"Itablinks", int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName)
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})
}

// TestParseModuleDataGeneric_BackwardCompatibility verifies that the generic parser
// produces identical results to the old version-specific parsing
func TestParseModuleDataGeneric_BackwardCompatibility(t *testing.T) {
	// Create synthetic moduledata bytes (simplified for testing)
	// In reality this would be actual binary data, but for unit testing
	// we just verify the parsing logic works correctly

	t.Run("64-bit little-endian", func(t *testing.T) {
		// Create a buffer large enough to hold ModuleData121_64
		// Need to match actual struct size
		var sizeCheck ModuleData121_64
		rawData := make([]byte, unsafe.Sizeof(sizeCheck))

		// Manually set some test values at known offsets (from layout)
		// Text at offset 176
		rawData[176] = 0x00
		rawData[177] = 0x10
		rawData[178] = 0x00
		rawData[179] = 0x00
		rawData[180] = 0x00
		rawData[181] = 0x00
		rawData[182] = 0x00
		rawData[183] = 0x00 // Text = 0x1000

		// Types at offset 296
		rawData[296] = 0x00
		rawData[297] = 0x20
		rawData[298] = 0x00
		rawData[299] = 0x00
		rawData[300] = 0x00
		rawData[301] = 0x00
		rawData[302] = 0x00
		rawData[303] = 0x00 // Types = 0x2000

		// Parse with new generic approach
		result, err := parseModuleDataGeneric(rawData, "1.21", true, true)
		if err != nil {
			t.Fatalf("Generic parse failed: %v", err)
		}

		// Verify results
		if result.Text != 0x1000 {
			t.Errorf("Text mismatch: got 0x%x, want 0x1000", result.Text)
		}
		if result.Types != 0x2000 {
			t.Errorf("Types mismatch: got 0x%x, want 0x2000", result.Types)
		}

		// Also parse with old approach for comparison
		var oldModule ModuleData121_64
		err = oldModule.parse(rawData, true)
		if err != nil {
			t.Fatalf("Old parse failed: %v", err)
		}

		// Compare results
		if result.Text != uint64(oldModule.Text) {
			t.Errorf("Text doesn't match old parser: new=0x%x old=0x%x",
				result.Text, oldModule.Text)
		}
		if result.Types != uint64(oldModule.Types) {
			t.Errorf("Types doesn't match old parser: new=0x%x old=0x%x",
				result.Types, oldModule.Types)
		}
	})
}

// TestVersionMapping verifies that version aliases work correctly
func TestVersionMapping(t *testing.T) {
	testCases := []struct {
		version          string
		expectedLayoutVer string
	}{
		{"1.21", "1.21"},
		{"1.22", "1.21"}, // 1.22 uses same layout as 1.21
		{"1.23", "1.21"}, // 1.23 uses same layout as 1.21
		{"1.24", "1.21"}, // 1.24 uses same layout as 1.21
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

// TestModuleDataIntermediate_FieldTypes verifies the intermediate struct has correct types
func TestModuleDataIntermediate_FieldTypes(t *testing.T) {
	var md ModuleDataIntermediate

	// Use reflection to verify field types
	mdType := reflect.TypeOf(md)

	expectedFields := map[string]string{
		"Ftab":        "objfile.GoSlice64",
		"Minpc":       "uint64",
		"Text":        "uint64",
		"Types":       "uint64",
		"Etypes":      "uint64",
		"Textsectmap": "objfile.GoSlice64",
		"Typelinks":   "objfile.GoSlice64",
		"Itablinks":   "objfile.GoSlice64",
	}

	for fieldName, expectedType := range expectedFields {
		field, found := mdType.FieldByName(fieldName)
		if !found {
			t.Errorf("Field %s not found in ModuleDataIntermediate", fieldName)
			continue
		}
		actualType := field.Type.String()
		if actualType != expectedType {
			t.Errorf("Field %s has type %s, expected %s",
				fieldName, actualType, expectedType)
		}
	}
}
