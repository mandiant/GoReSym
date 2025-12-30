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

// TestIsMostlyPrintable validates the printability filter
func TestIsMostlyPrintable(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello world", true},
		{"runtime.error", true},
		{"\x00\x01\x02\x03", false},  // all non-printable
		{"abc\x00\x01", false},        // less than 80% printable
	}

	for _, tt := range tests {
		got := isMostlyPrintable(tt.input)
		if got != tt.want {
			t.Errorf("isMostlyPrintable(%q) = %v, want %v", tt.input, got, tt.want)
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
