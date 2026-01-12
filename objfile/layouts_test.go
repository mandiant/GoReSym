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
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
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
			fieldName      FieldName
			actualOffset32 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, false)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
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
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
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
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
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
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
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

// Test legacy Go versions (1.5-1.15)
func TestLayoutOffsets_Legacy_Versions(t *testing.T) {
	t.Run("ModuleData12_64_Go18-15", func(t *testing.T) {
		var md ModuleData12_64
		layout := getModuleDataLayout("1.8")

		testCases := []struct {
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})

	t.Run("ModuleData12_32_Go18-15", func(t *testing.T) {
		var md ModuleData12_32
		layout := getModuleDataLayout("1.8")

		testCases := []struct {
			fieldName      FieldName
			actualOffset32 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTextsectmap, int(unsafe.Offsetof(md.Textsectmap))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, false)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset32 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset32)
			}
		}
	})

	t.Run("ModuleData12_r17_64_Go17", func(t *testing.T) {
		var md ModuleData12_r17_64
		layout := getModuleDataLayout("1.7")

		testCases := []struct {
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})

	t.Run("ModuleData12_r17_32_Go17", func(t *testing.T) {
		var md ModuleData12_r17_32
		layout := getModuleDataLayout("1.7")

		testCases := []struct {
			fieldName      FieldName
			actualOffset32 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypes, int(unsafe.Offsetof(md.Types))},
			{FieldEtypes, int(unsafe.Offsetof(md.Etypes))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
			{FieldItablinks, int(unsafe.Offsetof(md.Itablinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, false)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset32 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset32)
			}
		}
	})

	t.Run("ModuleData12_r15_r16_64_Go15-16", func(t *testing.T) {
		var md ModuleData12_r15_r16_64
		layout := getModuleDataLayout("1.5")

		testCases := []struct {
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}
	})

	t.Run("ModuleData12_r15_r16_32_Go15-16", func(t *testing.T) {
		var md ModuleData12_r15_r16_32
		layout := getModuleDataLayout("1.5")

		testCases := []struct {
			fieldName      FieldName
			actualOffset32 int
		}{
			{FieldFtab, int(unsafe.Offsetof(md.Ftab))},
			{FieldMinpc, int(unsafe.Offsetof(md.Minpc))},
			{FieldText, int(unsafe.Offsetof(md.Text))},
			{FieldTypelinks, int(unsafe.Offsetof(md.Typelinks))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getFieldOffset(layout, tc.fieldName, false)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset32 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset32)
			}
		}
	})
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
			if layout.Version != tc.expectedName {
				t.Errorf("Version %s mapped to layout %s, expected %s",
					tc.version, layout.Version, tc.expectedName)
			}
		})
	}
}

// Test Rtype layout offsets
func TestRtypeLayoutOffsets(t *testing.T) {
	t.Run("Rtype15_64", func(t *testing.T) {
		var rt Rtype15_64
		layout := getRtypeLayout("1.5")
		if layout == nil {
			t.Fatal("Layout for 1.5 is nil")
		}

		testCases := []struct {
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldSize, int(unsafe.Offsetof(rt.Size))},
			{FieldPtrdata, int(unsafe.Offsetof(rt.Ptrdata))},
			{FieldHash, int(unsafe.Offsetof(rt.Hash))},
			{FieldUnused, int(unsafe.Offsetof(rt.Unused))},
			{FieldAlign, int(unsafe.Offsetof(rt.Align))},
			{FieldFieldAlign, int(unsafe.Offsetof(rt.FieldAlign))},
			{FieldKind, int(unsafe.Offsetof(rt.Kind))},
			{FieldStr, int(unsafe.Offsetof(rt.Str))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getRtypeFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}

		// Check size
		if layout.BaseSize64 != int(unsafe.Sizeof(rt)) {
			t.Errorf("BaseSize64 mismatch: layout=%d actual=%d",
				layout.BaseSize64, unsafe.Sizeof(rt))
		}
	})

	t.Run("Rtype17_64", func(t *testing.T) {
		var rt Rtype17_18_19_110_111_112_113_64
		layout := getRtypeLayout("1.7")
		if layout == nil {
			t.Fatal("Layout for 1.7 is nil")
		}

		testCases := []struct {
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldSize, int(unsafe.Offsetof(rt.Size))},
			{FieldPtrdata, int(unsafe.Offsetof(rt.Ptrdata))},
			{FieldHash, int(unsafe.Offsetof(rt.Hash))},
			{FieldTflag, int(unsafe.Offsetof(rt.Tflag))},
			{FieldAlign, int(unsafe.Offsetof(rt.Align))},
			{FieldFieldAlign, int(unsafe.Offsetof(rt.FieldAlign))},
			{FieldKind, int(unsafe.Offsetof(rt.Kind))},
			{FieldStr, int(unsafe.Offsetof(rt.Str))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getRtypeFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}

		// Check size
		if layout.BaseSize64 != int(unsafe.Sizeof(rt)) {
			t.Errorf("BaseSize64 mismatch: layout=%d actual=%d",
				layout.BaseSize64, unsafe.Sizeof(rt))
		}
	})

	t.Run("ABIType64", func(t *testing.T) {
		var rt ABIType64
		layout := getRtypeLayout("1.20")
		if layout == nil {
			t.Fatal("Layout for 1.20 is nil")
		}

		testCases := []struct {
			fieldName      FieldName
			actualOffset64 int
		}{
			{FieldSize, int(unsafe.Offsetof(rt.Size))},
			{FieldPtrdata, int(unsafe.Offsetof(rt.Ptrdata))},
			{FieldHash, int(unsafe.Offsetof(rt.Hash))},
			{FieldTflag, int(unsafe.Offsetof(rt.Tflag))},
			{FieldAlign, int(unsafe.Offsetof(rt.Align))},
			{FieldFieldAlign, int(unsafe.Offsetof(rt.FieldAlign))},
			{FieldKind, int(unsafe.Offsetof(rt.Kind))},
			{FieldStr, int(unsafe.Offsetof(rt.Str))},
		}

		for _, tc := range testCases {
			layoutOffset, found := getRtypeFieldOffset(layout, tc.fieldName, true)
			if !found {
				t.Errorf("Field %s not found in layout", tc.fieldName.String())
				continue
			}
			if layoutOffset != tc.actualOffset64 {
				t.Errorf("Field %s offset mismatch: layout=%d actual=%d",
					tc.fieldName, layoutOffset, tc.actualOffset64)
			}
		}

		// Check size
		if layout.BaseSize64 != int(unsafe.Sizeof(rt)) {
			t.Errorf("BaseSize64 mismatch: layout=%d actual=%d",
				layout.BaseSize64, unsafe.Sizeof(rt))
		}
	})
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
		{"1.20", "1.20"},
		{"1.21", "1.20"},
		{"1.22", "1.20"},
		{"1.23", "1.20"},
		{"1.24", "1.20"},
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
