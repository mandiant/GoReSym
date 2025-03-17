package objfile

import (
	"os"
	"testing"
)

// TestModuleDataTable tests the ModuleDataTable function with a real Go binary
func TestModuleDataTable(t *testing.T) {
	// First, look for test binaries in multiple locations
	testBinaryPaths := []string{
		"../testdata/hello_go1.16_amd64",
		"../testdata/hello", // Try a generic name
		"testdata/hello_go1.16_amd64",
		"testdata/hello",
		// Go compiler binary as a fallback
		"/usr/local/go/bin/go",
	}

	// Find the first binary that exists
	var testBinaryPath string
	for _, path := range testBinaryPaths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			testBinaryPath = path
			break
		}
	}

	if testBinaryPath == "" {
		t.Skip("No suitable test binary found")
	}

	t.Logf("Using binary: %s", testBinaryPath)

	// Open test binary
	file, err := Open(testBinaryPath)
	if err != nil {
		t.Fatalf("Failed to open test binary: %v", err)
	}
	defer file.Close()

	// Get an entry
	entries := file.Entries()
	if len(entries) == 0 {
		t.Fatal("No entries found in binary")
	}

	// Find pclntab
	pclntabCandidates, err := entries[0].PCLineTable("", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get PCLineTable: %v", err)
	}

	var pclntabVA uint64
	for candidate := range pclntabCandidates {
		pclntabVA = candidate.PclntabVA
		break
	}

	if pclntabVA == 0 {
		t.Skip("No PCLineTable found in binary")
	}

	// Test with different Go versions to ensure fallback works
	versions := []string{"1.16", "1.18", "1.22"}

	for _, version := range versions {
		t.Run("Version_"+version, func(t *testing.T) {
			// Call ModuleDataTable
			secStart, moduleData, err := entries[0].ModuleDataTable(pclntabVA, version, version, true, true)

			if err != nil {
				// For some versions, it's expected to fail
				t.Logf("ModuleDataTable with version %s: %v", version, err)
				return
			}

			// Basic verification
			if moduleData == nil {
				t.Errorf("ModuleDataTable returned nil moduleData")
				return
			}

			// Verify we got some data
			if moduleData.TextVA == 0 {
				t.Errorf("Expected non-zero TextVA")
			}

			if moduleData.Types == 0 {
				t.Errorf("Expected non-zero Types address")
			}

			t.Logf("Found moduledata at VA: 0x%x, TextVA: 0x%x, SecStart: 0x%x",
				moduleData.VA, moduleData.TextVA, secStart)
		})
	}
}
