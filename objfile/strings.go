/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// String extraction for Go binaries
// Based on FLOSS algorithm for finding Go string internment tables

package objfile

import (
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf8"
)

// StringCandidate represents a potential Go string structure found in the binary.
// Go strings are represented as a struct with a pointer and length:
//   type string struct {
//       str unsafe.Pointer
//       len int
//   }
type StringCandidate struct {
	Pointer uint64 // Pointer to string data
	Length  uint64 // Length of string in bytes
}

// ExtractStrings finds embedded Go strings in the binary by analyzing the string
// internment table. Go's compiler stores strings in length-sorted order, which
// creates a distinctive pattern we can detect.
//
// Algorithm (from FLOSS floss/language/go/extract.py):
// 1. Scan binary for string structure candidates (pointer + length pairs)
// 2. Sort candidates by length
// 3. Find the longest monotonically increasing run of lengths
// 4. Extract strings from the winning run and validate UTF-8
func (f *File) ExtractStrings() ([]string, error) {
	var allStrings []string

	// Process each entry in the file (handles fat binaries with multiple architectures)
	for _, entry := range f.entries {
		strings, err := entry.extractStrings()
		if err != nil {
			// Log error but continue with other entries
			continue
		}
		allStrings = append(allStrings, strings...)
	}

	return allStrings, nil
}

// extractStrings performs string extraction for a single Entry
func (e *Entry) extractStrings() ([]string, error) {
	// Determine binary properties
	is64bit := e.is64Bit()
	isLittleEndian := e.isLittleEndian()

	var allCandidates []StringCandidate

	// Use callback pattern to avoid loading all sections into memory at once
	err := e.iterateSections(func(section Section) error {
		// Skip sections that are unlikely to contain string structures
		// Focus on .rodata, .data, .noptrdata sections
		if !isDataSection(section.Name) {
			return nil
		}

		candidates := findStringCandidates(section.Data, section.Addr, is64bit, isLittleEndian)
		allCandidates = append(allCandidates, candidates...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(allCandidates) == 0 {
		return []string{}, nil
	}

	// Find the string internment table using monotonic run detection
	start, end := findLongestMonotonicRun(allCandidates)
	if start == -1 || end == -1 {
		return []string{}, nil
	}

	// Extract actual strings from the winning candidates
	var strings []string
	for i := start; i <= end; i++ {
		candidate := allCandidates[i]
		str, err := e.extractString(candidate)
		if err != nil {
			// Skip invalid strings
			continue
		}
		if str != "" {
			strings = append(strings, str)
		}
	}

	return strings, nil
}

// iterateSections calls the provided function for each section in the binary.
// This uses a callback pattern to avoid memory pressure from loading all sections at once.
func (e *Entry) iterateSections(fn func(Section) error) error {
	// Use the rawFile interface to iterate sections
	if sectioner, ok := e.raw.(interface {
		iterateSections(func(Section) error) error
	}); ok {
		return sectioner.iterateSections(fn)
	}
	return fmt.Errorf("binary format does not support section enumeration")
}

// Section represents a binary section
type Section struct {
	Name string
	Addr uint64
	Data []byte
}

// isDataSection returns true if the section name suggests it contains data
func isDataSection(name string) bool {
	dataNames := []string{
		".rodata", ".data", ".noptrdata",   // ELF
		"__rodata", "__data", "__noptrdata", // Mach-O
		".rdata",                             // PE
	}
	for _, dataName := range dataNames {
		if name == dataName || name == dataName+".__" {
			return true
		}
	}
	return false
}

// findStringCandidates scans binary data for potential Go string structures
func findStringCandidates(data []byte, baseAddr uint64, is64bit bool, isLittleEndian bool) []StringCandidate {
	var candidates []StringCandidate
	ptrSize := 4
	if is64bit {
		ptrSize = 8
	}

	// String structure size: pointer + length
	structSize := ptrSize * 2
	if len(data) < structSize {
		return candidates
	}

	// Scan for aligned string structures
	for i := 0; i <= len(data)-structSize; i += ptrSize {
		var ptr, length uint64

		if is64bit {
			if isLittleEndian {
				ptr = binary.LittleEndian.Uint64(data[i : i+8])
				length = binary.LittleEndian.Uint64(data[i+8 : i+16])
			} else {
				ptr = binary.BigEndian.Uint64(data[i : i+8])
				length = binary.BigEndian.Uint64(data[i+8 : i+16])
			}
		} else {
			if isLittleEndian {
				ptr = uint64(binary.LittleEndian.Uint32(data[i : i+4]))
				length = uint64(binary.LittleEndian.Uint32(data[i+4 : i+8]))
			} else {
				ptr = uint64(binary.BigEndian.Uint32(data[i : i+4]))
				length = uint64(binary.BigEndian.Uint32(data[i+4 : i+8]))
			}
		}

		// Sanity checks for valid string structure
		if ptr == 0 || length == 0 || length > 100000 {
			continue
		}

		candidates = append(candidates, StringCandidate{
			Pointer: ptr,
			Length:  length,
		})
	}

	return candidates
}

// findLongestMonotonicRun finds the longest sequence of string candidates where
// each length is >= the previous length. This identifies the string internment table.
//
// Go's compiler stores strings sorted by length (shortest to longest), creating a
// distinctive monotonically increasing pattern that is much longer than random data.
func findLongestMonotonicRun(candidates []StringCandidate) (start, end int) {
	if len(candidates) == 0 {
		return -1, -1
	}

	// Sort candidates by length to find the pre-sorted internment table
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Length < candidates[j].Length
	})

	maxRunStart := 0
	maxRunEnd := 0
	maxRunLength := 0

	currentRunStart := 0
	currentRunLength := 1

	for i := 1; i < len(candidates); i++ {
		// Monotonically increasing (allows equal lengths)
		if candidates[i].Length >= candidates[i-1].Length {
			currentRunLength++
		} else {
			// Run ended, check if it's the longest
			if currentRunLength > maxRunLength {
				maxRunLength = currentRunLength
				maxRunStart = currentRunStart
				maxRunEnd = i - 1
			}
			// Start new run
			currentRunStart = i
			currentRunLength = 1
		}
	}

	// Check final run
	if currentRunLength > maxRunLength {
		maxRunLength = currentRunLength
		maxRunStart = currentRunStart
		maxRunEnd = len(candidates) - 1
	}

	// Only return if run is significant (at least 10 strings)
	// Real internment tables have hundreds/thousands of entries
	if maxRunLength < 10 {
		return -1, -1
	}

	return maxRunStart, maxRunEnd
}

// extractString reads the actual string data from the binary and validates it
func (e *Entry) extractString(candidate StringCandidate) (string, error) {
	// Use the raw file interface to read memory by virtual address
	if reader, ok := e.raw.(interface {
		read_memory(addr uint64, size uint64) (data []byte, err error)
	}); ok {
		data, err := reader.read_memory(candidate.Pointer, candidate.Length)
		if err != nil {
			return "", err
		}

		// Validate UTF-8
		if !utf8.Valid(data) {
			return "", fmt.Errorf("invalid UTF-8")
		}

		str := string(data)

		// Filter out very short or non-printable strings
		if len(str) < 4 {
			return "", fmt.Errorf("string too short")
		}

		// Check if string is mostly printable
		if !isMostlyPrintable(str) {
			return "", fmt.Errorf("not printable")
		}

		return str, nil
	}

	return "", fmt.Errorf("cannot read memory for string extraction")
}

// isMostlyPrintable returns true if at least 80% of the string is printable
func isMostlyPrintable(s string) bool {
	if len(s) == 0 {
		return false
	}

	printable := 0
	for _, r := range s {
		// Consider printable: letters, digits, punctuation, space, tab, newline
		if (r >= 32 && r < 127) || r == '\t' || r == '\n' || r == '\r' {
			printable++
		}
	}

	ratio := float64(printable) / float64(len(s))
	return ratio >= 0.8
}

// is64Bit determines if the binary is 64-bit
func (e *Entry) is64Bit() bool {
	// Check if raw file implements a method to determine bitness
	if bitChecker, ok := e.raw.(interface {
		is64Bit() bool
	}); ok {
		return bitChecker.is64Bit()
	}

	// Default to 64-bit (most common)
	return true
}

// isLittleEndian determines if the binary is little-endian
func (e *Entry) isLittleEndian() bool {
	// Check if raw file implements a method to determine endianness
	if endianChecker, ok := e.raw.(interface {
		isLittleEndian() bool
	}); ok {
		return endianChecker.isLittleEndian()
	}

	// Default to little-endian (most common - x86, x64, most ARM)
	return true
}
