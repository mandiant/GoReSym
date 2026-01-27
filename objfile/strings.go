/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// String extraction for Go binaries
// Algorithm aligned with FLOSS (floss/language/go/extract.py)
//
// FLOSS reference: https://github.com/mandiant/flare-floss
// Specifically: floss/language/go/extract.py
//
// The Go compiler stores strings in a "string blob" within data sections,
// sorted by length (shortest to longest). Each string is referenced by a
// struct { pointer, length } pair elsewhere in the binary.
//
// This algorithm:
//  1. Scans data sections for candidate string structures (pointer + length pairs)
//  2. Sorts candidates by pointer address (where the string data lives)
//  3. Finds the longest monotonically increasing run of lengths, which
//     identifies candidates pointing into the string blob
//  4. Locates the blob boundaries by searching for null terminator sequences
//  5. Walks the blob using sorted pointers to extract individual strings
//
// Stack strings are out of scope (acceptable difference from FLOSS).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"
)

const minStringLength = 4

// StringCandidate represents a potential Go string structure found in the binary.
// Go strings are represented as a struct with a pointer and length:
//
//	type string struct {
//	    str unsafe.Pointer
//	    len int
//	}
type StringCandidate struct {
	Pointer uint64 // VA where the actual string data lives
	Length  uint64 // Length of the string in bytes
}

// ExtractStrings finds embedded Go strings in the binary by analyzing the
// string internment table. Returns deduplicated, validated strings.
func (f *File) ExtractStrings() ([]string, error) {
	var allStrings []string

	for _, entry := range f.entries {
		strings, err := entry.extractStrings()
		if err != nil {
			continue
		}
		allStrings = append(allStrings, strings...)
	}

	return allStrings, nil
}

// extractStrings performs string extraction for a single Entry.
//
// This is the main orchestration function, following the FLOSS algorithm:
//
//	FLOSS: get_string_blob_strings() in extract.py:266
func (e *Entry) extractStrings() ([]string, error) {
	is64bit := e.is64Bit()
	isLittleEndian := e.isLittleEndian()

	// ---------------------------------------------------------------
	// Step 1a: Compute the binary's virtual address range
	// ---------------------------------------------------------------
	// FLOSS: low, high = get_image_range(pe) in utils.py:71
	//
	// Candidates whose pointer falls outside the binary's address space
	// are noise. We compute the range from ALL sections (not just data).
	var imageMin, imageMax uint64
	var maxSectionSize uint64
	first := true

	err := e.iterateSections(func(section Section) error {
		// Skip sections with no virtual address (e.g., ELF .shstrtab,
		// .symtab, .strtab, debug sections, and the null section).
		// These are metadata sections not mapped to virtual memory.
		if section.Addr == 0 {
			return nil
		}
		sectionEnd := section.Addr + uint64(len(section.Data))
		if first || section.Addr < imageMin {
			imageMin = section.Addr
		}
		if first || sectionEnd > imageMax {
			imageMax = sectionEnd
		}
		if uint64(len(section.Data)) > maxSectionSize {
			maxSectionSize = uint64(len(section.Data))
		}
		first = false
		return nil
	})
	if err != nil {
		return nil, err
	}

	// ---------------------------------------------------------------
	// Step 1b: Collect string structure candidates from data sections
	// ---------------------------------------------------------------
	// We also keep section data for blob boundary detection later.
	// Only data sections are kept (not code), so memory impact is limited.
	var allCandidates []StringCandidate
	var dataSections []Section

	err = e.iterateSections(func(section Section) error {
		if !isDataSection(section.Name) {
			return nil
		}
		dataSections = append(dataSections, section)
		candidates := findStringCandidates(section.Data, section.Addr, is64bit, isLittleEndian, imageMin, imageMax, maxSectionSize)
		allCandidates = append(allCandidates, candidates...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(allCandidates) == 0 {
		return []string{}, nil
	}

	// ---------------------------------------------------------------
	// Step 2: Sort candidates by pointer address
	// ---------------------------------------------------------------
	// FLOSS: struct_strings.sort(key=lambda s: s.address)
	//
	// This is the KEY difference from the previous implementation which
	// sorted by length. Sorting by address groups candidates that point
	// into the same memory region (the string blob) together.
	sort.Slice(allCandidates, func(i, j int) bool {
		return allCandidates[i].Pointer < allCandidates[j].Pointer
	})

	// ---------------------------------------------------------------
	// Step 3: Find longest monotonically increasing run of lengths
	// ---------------------------------------------------------------
	// FLOSS: find_longest_monotonically_increasing_run(lengths)
	//
	// Since Go stores string data sorted by length in the blob, candidates
	// pointing into the blob will have monotonically increasing lengths
	// when sorted by address. This run is typically hundreds/thousands of
	// entries long, far longer than any random run.
	runStart, runEnd := findLongestMonotonicRun(allCandidates)
	if runStart == -1 || runEnd == -1 {
		return []string{}, nil
	}

	// ---------------------------------------------------------------
	// Step 4: Find string blob boundaries
	// ---------------------------------------------------------------
	// FLOSS: find_string_blob_range() in extract.py:210
	//
	// Pick the mid-point candidate (to avoid edge corruption), find the
	// section containing its string data, then search for |00 00 00 00|
	// null sequences before and after to delimit the blob.
	blobStart, blobEnd, blobData := findStringBlobRange(allCandidates, runStart, runEnd, dataSections)
	if blobData == nil {
		return []string{}, nil
	}

	// ---------------------------------------------------------------
	// Step 5: Extract strings using candidate (pointer, length) pairs
	// ---------------------------------------------------------------
	// FLOSS walks consecutive pointer pairs, augmented with LEA xrefs
	// (PE-specific, requires disassembly) for additional granularity.
	//
	// Since we operate cross-platform (ELF/PE/Mach-O), we instead use
	// each candidate's own (pointer, length) to extract its exact string
	// from the blob. This is more precise: each Go string struct already
	// knows its exact length, so we don't need pointer-gap inference.
	//
	// The blob boundary still serves its purpose: only candidates whose
	// pointer falls within the blob are considered (filtering noise).
	seen := make(map[string]bool)
	var result []string

	for _, c := range allCandidates {
		// Only consider candidates pointing into the blob
		if c.Pointer < blobStart || c.Pointer >= blobEnd {
			continue
		}

		offset := c.Pointer - blobStart
		if offset+c.Length > uint64(len(blobData)) {
			continue
		}

		buf := blobData[offset : offset+c.Length]

		// FLOSS: sbuf.decode("utf-8") -- skip on UnicodeDecodeError
		if !utf8.Valid(buf) {
			continue
		}

		s := string(buf)

		if len(s) < minStringLength {
			continue
		}

		// Maintainer requirement: 100% printable (not 80%)
		if !isFullyPrintable(s) {
			continue
		}

		// Deduplicate: multiple struct string candidates may reference
		// the same string (e.g., same string used in different packages)
		if seen[s] {
			continue
		}
		seen[s] = true

		result = append(result, s)
	}

	return result, nil
}

// iterateSections calls the provided function for each section in the binary.
// Uses a callback pattern to avoid memory pressure from loading all sections.
func (e *Entry) iterateSections(fn func(Section) error) error {
	if sectioner, ok := e.raw.(interface {
		iterateSections(func(Section) error) error
	}); ok {
		return sectioner.iterateSections(fn)
	}
	return fmt.Errorf("binary format does not support section enumeration")
}

// Section represents a binary section with its virtual address and raw data.
type Section struct {
	Name string
	Addr uint64
	Data []byte
}

// isDataSection returns true if the section name suggests it contains data
// (string structures or string blob data).
func isDataSection(name string) bool {
	dataNames := []string{
		".rodata", ".data", ".noptrdata", // ELF
		"__rodata", "__data", "__noptrdata", // Mach-O
		".rdata", // PE
	}
	for _, dataName := range dataNames {
		if name == dataName || name == dataName+".__" {
			return true
		}
	}
	return false
}

// findStringCandidates scans binary data for potential Go string structures.
// Each candidate is a (pointer, length) pair found at pointer-aligned offsets.
//
// Filtering (aligned with FLOSS utils.py:331):
//   - Pointer must fall within the binary's VA range [imageMin, imageMax)
//   - Length must be > 0 and <= maxSectionSize
//   - Both pointer and length must be non-zero
//
// FLOSS equivalent: get_struct_string_candidates_with_pointer_size() in utils.py:331
func findStringCandidates(data []byte, baseAddr uint64, is64bit bool, isLittleEndian bool, imageMin, imageMax, maxSectionSize uint64) []StringCandidate {
	var candidates []StringCandidate
	ptrSize := 4
	if is64bit {
		ptrSize = 8
	}

	structSize := ptrSize * 2
	if len(data) < structSize {
		return candidates
	}

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

		// FLOSS: skips address==0, length==0
		if ptr == 0 || length == 0 {
			continue
		}

		// FLOSS: if length > limit (max section size), skip
		if length > maxSectionSize {
			continue
		}

		// FLOSS: if not (low <= address < high), skip
		// The pointer must point within the binary's virtual address space.
		if ptr < imageMin || ptr >= imageMax {
			continue
		}

		candidates = append(candidates, StringCandidate{
			Pointer: ptr,
			Length:  length,
		})
	}

	return candidates
}

// findLongestMonotonicRun finds the longest consecutive subsequence where each
// candidate's Length is >= the previous candidate's Length.
//
// IMPORTANT: candidates must already be sorted by Pointer address before calling.
// The lengths form a monotonically increasing pattern for candidates pointing
// into the Go string blob (because Go stores strings sorted by length).
//
// FLOSS equivalent: find_longest_monotonically_increasing_run() in extract.py:143
//
// Example with address-sorted candidates:
//
//	Pointer: 0x4000  0x4005  0x400A  0x4011  0x5000  0x5002
//	Length:     5        5       7       4       2       1
//	           ^^^^^^^^^^^^^^^^^^^
//	           monotonic run (5, 5, 7) = the string blob candidates
//	                                ^^^^^^^^^^^^^^^^^^^
//	                                non-blob (lengths decrease)
func findLongestMonotonicRun(candidates []StringCandidate) (start, end int) {
	if len(candidates) == 0 {
		return -1, -1
	}

	maxRunLength := 0
	maxRunEndIndex := 0

	currentRunLength := 0
	var priorLength uint64

	for i, c := range candidates {
		if c.Length >= priorLength {
			currentRunLength++
		} else {
			currentRunLength = 1
		}

		if currentRunLength > maxRunLength {
			maxRunLength = currentRunLength
			maxRunEndIndex = i
		}

		priorLength = c.Length
	}

	maxRunStartIndex := maxRunEndIndex - maxRunLength + 1

	// Real string tables have hundreds/thousands of entries
	if maxRunLength < 10 {
		return -1, -1
	}

	return maxRunStartIndex, maxRunEndIndex
}

// findStringBlobRange locates the string blob boundaries in memory.
//
// Algorithm (from FLOSS extract.py:210):
//  1. Pick the mid-point candidate from the monotonic run (avoids edge junk)
//  2. Find the section containing that candidate's string data
//  3. Search forward for |00 00 00 00| to find blob end
//  4. Search backward for |00 00 00 00| to find blob start
//
// Returns the blob's VA range and raw data, or nil if not found.
func findStringBlobRange(candidates []StringCandidate, runStart, runEnd int, sections []Section) (blobStart, blobEnd uint64, blobData []byte) {
	// Pick mid-point to avoid junk at the edges
	// FLOSS: run_mid = (run_start + run_end) // 2
	runMid := (runStart + runEnd) / 2
	midCandidate := candidates[runMid]

	// Find the section containing this string's data
	// FLOSS: section = pe.get_section_by_rva(instance_rva)
	var section *Section
	for i := range sections {
		sectionEnd := sections[i].Addr + uint64(len(sections[i].Data))
		if midCandidate.Pointer >= sections[i].Addr && midCandidate.Pointer < sectionEnd {
			section = &sections[i]
			break
		}
	}
	if section == nil {
		return 0, 0, nil
	}

	// Calculate offset within section
	// FLOSS: instance_offset = instance_rva - section.VirtualAddress
	instanceOffset := int(midCandidate.Pointer - section.Addr)
	if instanceOffset < 0 || instanceOffset >= len(section.Data) {
		return 0, 0, nil
	}

	// Search for |00 00 00 00| boundaries
	// FLOSS uses this larger needle because some binaries have embedded |00 00|
	// See: https://github.com/Arker123/flare-floss/pull/3#issuecomment-1623354852
	nullNeedle := []byte{0x00, 0x00, 0x00, 0x00}

	// Search forward from the instance for the blob end
	// FLOSS: next_null = section_data.find(b"\x00\x00\x00\x00", instance_offset)
	nextNullRel := bytes.Index(section.Data[instanceOffset:], nullNeedle)
	if nextNullRel == -1 {
		return 0, 0, nil
	}
	nextNull := instanceOffset + nextNullRel

	// Search backward from the instance for the blob start
	// FLOSS: prev_null = section_data.rfind(b"\x00\x00\x00\x00", 0, instance_offset)
	prevNull := bytes.LastIndex(section.Data[:instanceOffset], nullNeedle)
	if prevNull == -1 {
		return 0, 0, nil
	}

	// Convert section-relative offsets to VAs
	// FLOSS: blob_start, blob_end = (section_start + prev_null, section_start + next_null)
	blobStart = section.Addr + uint64(prevNull)
	blobEnd = section.Addr + uint64(nextNull)
	blobData = section.Data[prevNull:nextNull]

	return blobStart, blobEnd, blobData
}

// isFullyPrintable returns true if ALL characters in the string are printable.
// This replaces the previous isMostlyPrintable (80% threshold).
//
// Printable means: unicode.IsPrint(r) returns true, OR the character is a
// common whitespace character (tab, newline, carriage return).
//
// Maintainer requirement: "ensure all strings are fully printable"
func isFullyPrintable(s string) bool {
	if len(s) == 0 {
		return false
	}

	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// deduplicateUint64 removes duplicate values from a sorted slice.
func deduplicateUint64(sorted []uint64) []uint64 {
	if len(sorted) <= 1 {
		return sorted
	}
	result := make([]uint64, 0, len(sorted))
	result = append(result, sorted[0])
	for i := 1; i < len(sorted); i++ {
		if sorted[i] != sorted[i-1] {
			result = append(result, sorted[i])
		}
	}
	return result
}

// is64Bit determines if the binary is 64-bit
func (e *Entry) is64Bit() bool {
	if bitChecker, ok := e.raw.(interface {
		is64Bit() bool
	}); ok {
		return bitChecker.is64Bit()
	}
	return true
}

// isLittleEndian determines if the binary is little-endian
func (e *Entry) isLittleEndian() bool {
	if endianChecker, ok := e.raw.(interface {
		isLittleEndian() bool
	}); ok {
		return endianChecker.isLittleEndian()
	}
	return true
}
