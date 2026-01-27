package objfile

import (
	"path/filepath"
	"testing"
)

// TestExtractStrings_ELF tests string extraction from an ELF binary (Linux)
func TestExtractStrings_ELF(t *testing.T) {
	testBinary := filepath.Join("..", "testproject", "testproject")
	
	file, err := Open(testBinary)
	if err != nil {
		t.Skipf("Could not open test binary: %v (run: cd testproject && go build)", err)
	}
	defer file.Close()

	strings, err := file.ExtractStrings()
	if err != nil {
		t.Fatalf("ExtractStrings() failed: %v", err)
	}

	// Should extract a reasonable number of Go strings
	if len(strings) < 100 {
		t.Errorf("Expected at least 100 strings from ELF binary, got %d", len(strings))
	}

	// Verify common Go type/keyword strings are present
	expectedStrings := []string{"func", "chan", "bool", "uint"}
	assertStringsPresent(t, strings, expectedStrings)
}

// TestExtractStrings_PE tests string extraction from a PE binary (Windows)
func TestExtractStrings_PE(t *testing.T) {
	testBinary := filepath.Join("..", "testproject", "testproject.exe")
	
	file, err := Open(testBinary)
	if err != nil {
		t.Skipf("Could not open Windows test binary: %v (run: cd testproject && GOOS=windows GOARCH=amd64 go build -o testproject.exe)", err)
	}
	defer file.Close()

	strings, err := file.ExtractStrings()
	if err != nil {
		t.Fatalf("ExtractStrings() failed: %v", err)
	}

	// Should extract a reasonable number of Go strings
	if len(strings) < 100 {
		t.Errorf("Expected at least 100 strings from PE binary, got %d", len(strings))
	}

	// Verify common Go type/keyword strings are present
	expectedStrings := []string{"func", "chan", "bool", "uint"}
	assertStringsPresent(t, strings, expectedStrings)
}

// TestFindLongestMonotonicRun validates the core algorithm
// Note: function requires at least 10 entries for a valid run (practical filter)
func TestFindLongestMonotonicRun(t *testing.T) {
	t.Run("finds monotonic run in realistic data", func(t *testing.T) {
		// Create realistic test data: monotonically increasing lengths
		candidates := make([]StringCandidate, 50)
		for i := range candidates {
			candidates[i] = StringCandidate{
				Pointer: uint64(0x1000 + i*10),
				Length:  uint64(i + 4), // lengths 4, 5, 6, ... 53
			}
		}

		start, end := findLongestMonotonicRun(candidates)

		// Should find the entire sequence as one run
		if start == -1 || end == -1 {
			t.Error("Expected to find a valid run, got (-1, -1)")
		}

		runLength := end - start + 1
		if runLength < 10 {
			t.Errorf("Expected run length >= 10, got %d", runLength)
		}
	})

	t.Run("too short returns -1", func(t *testing.T) {
		candidates := []StringCandidate{
			{Length: 1}, {Length: 2}, {Length: 3}, // Only 3 entries
		}
		start, end := findLongestMonotonicRun(candidates)
		if start != -1 || end != -1 {
			t.Errorf("Expected (-1, -1) for short input, got (%d, %d)", start, end)
		}
	})
}

// TestIsFullyPrintable validates the printability filter.
// All characters must be printable (unicode.IsPrint) or common whitespace (\t, \n, \r).
func TestIsFullyPrintable(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello world", true},
		{"runtime.error", true},
		{"line1\nline2", true},          // newlines are allowed
		{"col1\tcol2", true},            // tabs are allowed
		{"windows\r\n", true},           // carriage return allowed
		{"\x00\x01\x02\x03", false},    // all non-printable
		{"abc\x00\x01", false},          // any non-printable fails (was 80% threshold)
		{"mostly ok \x01", false},       // even one non-printable byte fails
		{"", false},                     // empty string
	}

	for _, tt := range tests {
		got := isFullyPrintable(tt.input)
		if got != tt.want {
			t.Errorf("isFullyPrintable(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestExtractStrings_MinLength validates minimum length filtering
func TestExtractStrings_MinLength(t *testing.T) {
	testBinary := filepath.Join("..", "testproject", "testproject")
	
	file, err := Open(testBinary)
	if err != nil {
		t.Skip("Test binary not available")
	}
	defer file.Close()

	strings, err := file.ExtractStrings()
	if err != nil {
		t.Fatalf("ExtractStrings() failed: %v", err)
	}

	// All strings must be >= 4 characters (MIN_STRING_LENGTH)
	for _, s := range strings {
		if len(s) < 4 {
			t.Errorf("Found string shorter than 4 chars: %q (len=%d)", s, len(s))
		}
	}
}

// TestFindLongestMonotonicRun_MixedData tests that the algorithm correctly
// finds the blob candidates among noise. This simulates address-sorted
// candidates where only the middle portion points into the string blob.
func TestFindLongestMonotonicRun_MixedData(t *testing.T) {
	// Simulate: 5 noise candidates, then 20 blob candidates, then 5 noise
	var candidates []StringCandidate

	// Noise before blob (random lengths, not monotonic)
	noise1 := []uint64{50, 3, 100, 7, 42}
	for i, l := range noise1 {
		candidates = append(candidates, StringCandidate{
			Pointer: uint64(0x1000 + i*8),
			Length:  l,
		})
	}

	// String blob candidates: sorted by address, monotonically increasing lengths
	// This is what Go's string internment table looks like
	for i := 0; i < 20; i++ {
		candidates = append(candidates, StringCandidate{
			Pointer: uint64(0x4000 + i*10),
			Length:  uint64(4 + i), // 4, 5, 6, ..., 23
		})
	}

	// Noise after blob
	noise2 := []uint64{2, 80, 1, 60, 5}
	for i, l := range noise2 {
		candidates = append(candidates, StringCandidate{
			Pointer: uint64(0x8000 + i*8),
			Length:  l,
		})
	}

	start, end := findLongestMonotonicRun(candidates)

	if start == -1 || end == -1 {
		t.Fatal("Expected to find a valid run, got (-1, -1)")
	}

	runLength := end - start + 1
	if runLength != 20 {
		t.Errorf("Expected run length 20 (the blob candidates), got %d", runLength)
	}

	// The run should start at index 5 (after the 5 noise entries)
	if start != 5 {
		t.Errorf("Expected run to start at index 5, got %d", start)
	}
}

// TestDeduplicateUint64 validates the deduplication helper
func TestDeduplicateUint64(t *testing.T) {
	tests := []struct {
		name   string
		input  []uint64
		expect []uint64
	}{
		{"no duplicates", []uint64{1, 2, 3}, []uint64{1, 2, 3}},
		{"with duplicates", []uint64{1, 1, 2, 3, 3, 3, 4}, []uint64{1, 2, 3, 4}},
		{"all same", []uint64{5, 5, 5}, []uint64{5}},
		{"single element", []uint64{42}, []uint64{42}},
		{"empty", []uint64{}, []uint64{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateUint64(tt.input)
			if len(got) != len(tt.expect) {
				t.Errorf("deduplicateUint64(%v) returned %d elements, want %d", tt.input, len(got), len(tt.expect))
				return
			}
			for i := range got {
				if got[i] != tt.expect[i] {
					t.Errorf("deduplicateUint64(%v)[%d] = %d, want %d", tt.input, i, got[i], tt.expect[i])
				}
			}
		})
	}
}

// TestIsDataSection validates section name matching across ELF/PE/Mach-O formats
func TestIsDataSection(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// ELF sections
		{".rodata", true},
		{".data", true},
		{".noptrdata", true},
		// Mach-O sections
		{"__rodata", true},
		{"__data", true},
		{"__noptrdata", true},
		// PE sections
		{".rdata", true},
		// Suffixed variants (some formats append .__)
		{".rodata.__", true},
		// Non-data sections
		{".text", false},
		{".bss", false},
		{"__TEXT", false},
		{".got", false},
	}

	for _, tt := range tests {
		got := isDataSection(tt.name)
		if got != tt.want {
			t.Errorf("isDataSection(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestFindStringCandidates validates candidate extraction from raw binary data
func TestFindStringCandidates(t *testing.T) {
	t.Run("64-bit little-endian", func(t *testing.T) {
		// Create a fake section with one string struct:
		// struct: pointer=0x5000, length=5
		// Scanner steps at ptrSize (8-byte) alignment, so we use exactly
		// one 16-byte struct to avoid overlapping false positives.
		data := make([]byte, 16)
		// pointer = 0x5000 (little-endian uint64)
		data[0] = 0x00
		data[1] = 0x50
		data[2] = 0x00
		data[3] = 0x00
		data[4] = 0x00
		data[5] = 0x00
		data[6] = 0x00
		data[7] = 0x00
		// length = 5 (little-endian uint64)
		data[8] = 0x05
		data[9] = 0x00
		data[10] = 0x00
		data[11] = 0x00
		data[12] = 0x00
		data[13] = 0x00
		data[14] = 0x00
		data[15] = 0x00

		// imageMin=0x1000, imageMax=0x10000 (pointer 0x5000 is in range), maxSectionSize=1000
		candidates := findStringCandidates(data, 0x1000, true, true, 0x1000, 0x10000, 1000)

		if len(candidates) != 1 {
			t.Fatalf("Expected 1 candidate, got %d", len(candidates))
		}
		if candidates[0].Pointer != 0x5000 || candidates[0].Length != 5 {
			t.Errorf("candidate[0] = {%#x, %d}, want {0x5000, 5}", candidates[0].Pointer, candidates[0].Length)
		}
	})

	t.Run("skips zero pointer and length", func(t *testing.T) {
		data := make([]byte, 16)
		// pointer=0, length=0 -- should be skipped
		candidates := findStringCandidates(data, 0x1000, true, true, 0x1000, 0x10000, 1000)
		if len(candidates) != 0 {
			t.Errorf("Expected 0 candidates for zero data, got %d", len(candidates))
		}
	})

	t.Run("skips pointer outside image range", func(t *testing.T) {
		data := make([]byte, 16)
		// pointer = 0x5000 (outside range [0x1000, 0x4000))
		data[0] = 0x00
		data[1] = 0x50
		data[8] = 0x05
		candidates := findStringCandidates(data, 0x1000, true, true, 0x1000, 0x4000, 1000)
		if len(candidates) != 0 {
			t.Errorf("Expected 0 candidates for out-of-range pointer, got %d", len(candidates))
		}
	})

	t.Run("skips length exceeding max section size", func(t *testing.T) {
		data := make([]byte, 16)
		// pointer = 0x2000 (in range), length = 500 (exceeds maxSectionSize=100)
		data[0] = 0x00
		data[1] = 0x20
		data[8] = 0xF4 // 500 in little-endian
		data[9] = 0x01
		candidates := findStringCandidates(data, 0x1000, true, true, 0x1000, 0x10000, 100)
		if len(candidates) != 0 {
			t.Errorf("Expected 0 candidates for oversized length, got %d", len(candidates))
		}
	})
}

// Helper function to check if expected strings are present
func assertStringsPresent(t *testing.T, strings []string, expected []string) {
	t.Helper()
	stringSet := make(map[string]bool)
	for _, s := range strings {
		stringSet[s] = true
	}

	for _, exp := range expected {
		if !stringSet[exp] {
			t.Errorf("Expected string %q not found in extracted strings", exp)
		}
	}
}
