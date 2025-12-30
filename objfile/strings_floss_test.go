// Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
package objfile

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtractStrings_CompareWithFLOSS validates our Go string extraction
// against FLOSS's output. The reference output was generated using:
// python -m floss.language.go.extract testproject/testproject.exe -n 4
func TestExtractStrings_CompareWithFLOSS(t *testing.T) {
	// Load FLOSS reference output
	flossOutputPath := filepath.Join("..", "testdata", "floss_reference.txt")
	file, err := os.Open(flossOutputPath)
	if err != nil {
		t.Skipf("FLOSS reference output not found: %v", err)
	}
	defer file.Close()

	// Parse FLOSS output (format: "0x12345: string content")
	flossStrings := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "0x") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				flossStrings[parts[1]] = true
			}
		}
	}

	t.Logf("FLOSS reference contains %d strings", len(flossStrings))

	// Extract strings using GoReSym
	testBinary := filepath.Join("..", "testproject", "testproject.exe")
	f, err := Open(testBinary)
	if err != nil {
		t.Fatalf("Failed to open test binary: %v", err)
	}
	defer f.Close()

	goresymStrings, err := f.ExtractStrings()
	if err != nil {
		t.Fatalf("ExtractStrings() failed: %v", err)
	}

	// Convert to set
	goresymSet := make(map[string]bool)
	for _, s := range goresymStrings {
		goresymSet[s] = true
	}

	// Calculate overlap
	inBoth := 0
	for s := range goresymSet {
		if flossStrings[s] {
			inBoth++
		}
	}

	goresymCount := len(goresymSet)
	matchRate := float64(inBoth) / float64(goresymCount) * 100

	t.Logf("GoReSym extracted: %d strings", goresymCount)
	t.Logf("Overlap with FLOSS: %d strings (%.1f%% match rate)", inBoth, matchRate)

	// Validate high match rate (>= 95%)
	if matchRate < 95.0 {
		t.Errorf("Match rate too low: %.1f%% (expected >= 95%%)", matchRate)

		// Show examples of mismatches
		t.Log("Sample strings only in GoReSym:")
		count := 0
		for s := range goresymSet {
			if !flossStrings[s] && count < 5 {
				t.Logf("  %q", s)
				count++
			}
		}
	}

	// Ensure reasonable extraction
	if goresymCount < 100 {
		t.Errorf("GoReSym extracted too few strings: %d (expected >= 100)", goresymCount)
	}
}
