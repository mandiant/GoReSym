/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "net/http/pprof"
)

var versions = []string{"126", "125", "124", "123", "122", "121", "120", "119", "118", "117", "116", "115", "114", "113", "112", "111", "110", "19", "18", "17", "16", "15"}
var fileNames = []string{"testproject_lin", "testproject_lin_32", "testproject_lin_stripped", "testproject_lin_stripped_32", "testproject_mac", "testproject_mac_stripped", "testproject_win_32.exe", "testproject_win_stripped_32.exe", "testproject_win_stripped.exe", "testproject_win.exe"}

func TestAllVersions(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get working directory")
	}

	for _, v := range versions {
		for _, file := range fileNames {
			versionPath := fmt.Sprintf("%s/%s", v, file)
			filePath := fmt.Sprintf("%s/test/build/%s", workingDirectory, versionPath)
			if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
				fmt.Printf("Test file %s doesn't exist\n", filePath)
				continue
			}

			t.Run(versionPath, func(t *testing.T) {
				data, err := main_impl(filePath, true, true, true, false, 0, "", true)
				if err != nil {
					t.Errorf("Go %s failed on %s: %s", v, file, err)
				}

				if data.TabMeta.VA == 0 {
					t.Errorf("Go %s pclntab location failed on %s: %s", v, file, err)
				}

				if data.ModuleMeta.VA == 0 {
					t.Errorf("Go %s moduledata location failed on %s: %s", v, file, err)
				}

				if len(data.Types) == 0 {
					t.Errorf("Go %s type parsing failed on %s: %s", v, file, err)
				}

				// unsupported
				if v != "15" && v != "16" {
					if len(data.Interfaces) == 0 {
						t.Errorf("Go %s interface parsing failed on %s: %s", v, file, err)
					}
				}

				if v != "15" && v != "16" {
					found_interface := false
					for _, typ := range data.Types {
						if typ.Str == "io.Writer" && typ.Kind == "Interface" {
							found_interface = true
							if !strings.Contains(typ.Reconstructed, "Write([]uint8) (int, error)") {
								t.Errorf("Go %s interface method name recovery failed", v)
							}
						}
					}

					if !found_interface {
						t.Errorf("Go %s interface recovery failed", v)
					}
					found_single_return := false
					found_multi_return := false
					found_unsafe_ptr := false
					found_ptr := false
					for _, typ := range data.Types {
						if typ.Kind != "Func" {
							continue
						}
						// multi-return: func([]uint8) (int, error) — from io.Writer
						if typ.Str == "func([]uint8) (int, error)" {
							found_single_return = true
							if typ.CStr != "tuple(int, error) (_slice_uint8)" {
								t.Errorf("Go %s func([]uint8)(int,error) CStr wrong: got %q", v, typ.CStr)
							}
						}
						// multi-return: func() (int, bool)
						if typ.Str == "func() (int, bool)" {
							found_multi_return = true
							if !strings.Contains(typ.CStr, "tuple(") {
								t.Errorf("Go %s func()(int,bool) CStr missing tuple: got %q", v, typ.CStr)
							}
						}
						// func(unsafe.Pointer, unsafe.Pointer) bool — complete signature check
						if typ.Str == "func(unsafe.Pointer, unsafe.Pointer) bool" {
							found_unsafe_ptr = true
							if typ.CStr != "bool (unsafe_Pointer, unsafe_Pointer)" {
								t.Errorf("Go %s func(unsafe.Pointer, unsafe.Pointer) bool CStr wrong: got %q", v, typ.CStr)
							}
						}
						// func(*os.file) error — complete signature check for pointer param
						if typ.Str == "func(*os.file) error" {
							found_ptr = true
							if typ.CStr != "error (_ptr_os_file)" {
								t.Errorf("Go %s func(*os.file) error CStr wrong: got %q", v, typ.CStr)
							}
						}
					}
					if !found_single_return {
						t.Logf("Go %s func([]uint8)(int,error) not found (may not exist in this version)", v)
					}
					if !found_multi_return {
						t.Logf("Go %s func()(int,bool) not found (may not exist in this version)", v)
					}
					if !found_unsafe_ptr {
						t.Errorf("Go %s no Func type with unsafe_Pointer in CStr found", v)
					}
					if !found_ptr {
						t.Errorf("Go %s no Func type with _ptr_ in CStr found", v)
					}

					// --- Inline function recovery tests ---
					// Positive: main.main must have inlined functions (add, multiply)
					for _, fn := range data.UserFunctions {
						if fn.FullName == "main.main" {
							if len(fn.InlinedList) == 0 {
								t.Errorf("Go %s main.main expected inlined functions, got none", v)
							}
							found_add := false
							found_multiply := false
							for _, inl := range fn.InlinedList {
								if inl.Funcname == "main.add" {
									found_add = true
								}
								if inl.Funcname == "main.multiply" {
									found_multiply = true
								}
							}
							if !found_add {
								t.Errorf("Go %s main.add not found in main.main InlinedList", v)
							}
							if !found_multiply {
								t.Errorf("Go %s main.multiply not found in main.main InlinedList", v)
							}
							if len(fn.InlinedList) < 2 {
								t.Errorf("Go %s main.main expected >= 2 inlines, got %d", v, len(fn.InlinedList))
							}
						}
					}

					// Negative: neverInlined must have empty InlinedList
					for _, fn := range data.UserFunctions {
						if fn.FullName == "main.neverInlined" && len(fn.InlinedList) != 0 {
							t.Errorf("Go %s main.neverInlined should have no InlinedList entries", v)
						}
					}

					// Negative: validate all InlinedList entries across all functions
					for _, fn := range data.UserFunctions {
						seen := map[uint64]bool{}
						funcSize := fn.End - fn.Start
						for _, inl := range fn.InlinedList {
							if inl.Funcname == "" {
								t.Errorf("Go %s empty Funcname in %s InlinedList", v, fn.FullName)
							}
							for _, c := range inl.Funcname {
								if c < 32 || c > 126 {
									t.Errorf("Go %s non-printable char in Funcname %q in %s", v, inl.Funcname, fn.FullName)
								}
							}
							if !strings.Contains(inl.Funcname, ".") {
								t.Errorf("Go %s Funcname %q missing package prefix in %s", v, inl.Funcname, fn.FullName)
							}
							if inl.CallingPc >= funcSize {
								t.Errorf("Go %s CallingPc %x >= funcSize %x in %s", v, inl.CallingPc, funcSize, fn.FullName)
							}
							if inl.ParentEntry != fn.Start {
								t.Errorf("Go %s ParentEntry %x != fn.Start %x in %s", v, inl.ParentEntry, fn.Start, fn.FullName)
							}
							if seen[inl.CallingPc] {
								t.Errorf("Go %s duplicate CallingPc %x in %s", v, inl.CallingPc, fn.FullName)
							}
							seen[inl.CallingPc] = true
						}
					}

				} else {
					found_interface := false
					for _, typ := range data.Types {
						if typ.Str == "os.FileInfo" && typ.Kind == "Interface" {
							found_interface = true
							if !strings.Contains(typ.Reconstructed, "IsDir() bool") {
								t.Errorf("Go %s interface method name recovery failed", v)
							}
						}
					}

					if !found_interface {
						t.Errorf("Go %s interface recovery failed", v)
					}
				}

				// --- Struct field Tag recovery tests ---
				if v != "15" && v != "16" {
					found_tagged := false
					for _, typ := range data.Types {
						if typ.Str == "main.TaggedStruct" && typ.Kind == "Struct" {
							found_tagged = true
							if !strings.Contains(typ.Reconstructed, `json:"id"`) {
								t.Errorf("Go %s exported field tag json:id missing in TaggedStruct", v)
							}
							if !strings.Contains(typ.Reconstructed, `db:"user_id"`) {
								t.Errorf("Go %s multi-tag db:user_id missing in TaggedStruct", v)
							}
							if !strings.Contains(typ.Reconstructed, `json:"name"`) {
								t.Errorf("Go %s exported field tag json:name missing in TaggedStruct", v)
							}
							if !strings.Contains(typ.Reconstructed, `json:"password"`) {
								t.Errorf("Go %s unexported field tag json:password missing in TaggedStruct", v)
							}
							if strings.Contains(typ.Reconstructed, "Active`") || strings.Contains(typ.Reconstructed, "`Active") {
								t.Errorf("Go %s Active field has spurious backtick in TaggedStruct", v)
							}
							if strings.Contains(typ.Reconstructed, "``") {
								t.Errorf("Go %s empty backtick pair in TaggedStruct Reconstructed", v)
							}
						}
					}
					if !found_tagged {
						t.Errorf("Go %s TaggedStruct not found in types", v)
					}
				}

				if len(data.StdFunctions) == 0 {
					t.Errorf("Go %s std functions failed on %s: %s", v, file, err)
				}

				if len(data.UserFunctions) == 0 {
					t.Errorf("Go %s user functions failed on %s: %s", v, file, err)
				}

				if len(data.Files) == 0 {
					t.Errorf("Go %s files failed on %s: %s", v, file, err)
				}

				if data.Version == "" {
					t.Errorf("Go %s version failed on %s: %s", v, file, err)
				}

				if data.OS == "" {
					t.Errorf("Go %s OS failed on %s: %s", v, file, err)
				}

				if data.Arch == "" {
					t.Errorf("Go %s Arch failed on %s: %s", v, file, err)
				}

				// String extraction requires Go 1.7+ (SSA-based linker).
				// Old Go 1.5/1.6 used C linker which doesn't produce sorted string blobs.
				if v != "15" && v != "16" {
					if len(data.Strings) == 0 {
						t.Errorf("Go %s Strings failed on %s: %s", v, file, err)
					}
				}
			})
		}
	}
}

func testSymbolRecovery(t *testing.T, workingDirectory string, binaryName string, pclntabVA uint64, moduledataVa uint64, mainVA uint64) {
	filePath := fmt.Sprintf("%s/test/weirdbins/%s", workingDirectory, binaryName)
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		t.Errorf("Test file %s doesn't exist\n", filePath)
		return
	}

	data, err := main_impl(filePath, true, true, true, false, 0, "", false)
	if err != nil {
		t.Errorf("GoReSym failed: %s", err)
	}

	if data.TabMeta.VA != pclntabVA {
		t.Errorf("incorrect pclntab VA: %016x", data.TabMeta.VA)
	}

	if data.ModuleMeta.VA != moduledataVa {
		t.Errorf("incorrect moduledata VA: %016x", data.ModuleMeta.VA)
	}

	foundMain := false
	for _, fn := range data.UserFunctions {
		if fn.FullName == "main.main" {
			if fn.Start != mainVA {
				t.Errorf("main.main has wrong VA: %016x", fn.Start)
			}
			foundMain = true
			break
		}
	}

	if !foundMain {
		t.Errorf("main.main symbol not recovered")
	}
}

func TestWeirdBins(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get working directory")
	}

	t.Run("bigendian", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "bigendian", 0x1F6500, 0x2A70C0, 0x150c30)
	})

	t.Run("elf_data_rel_ro_pclntab", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "elf_data_rel_ro_pclntab", 0x412dc0, 0x4be120, 0x17c080)
	})

	t.Run("fmtisfun_lin", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "fmtisfun_lin", 0x4b1d80, 0x4f9160, 0x47c070)
	})

	t.Run("fmtisfun_lin_stripped", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "fmtisfun_lin_stripped", 0x4b1ce0, 0x4f9160, 0x47c070)
	})

	t.Run("fmtisfun_macho", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "fmtisfun_macho", 0x10be140, 0x1109260, 0x10879b0)
	})

	t.Run("fmtisfun_win", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "fmtisfun_win", 0x4bf940, 0x5082a0, 0x489310)
	})

	t.Run("fmtisfun_win_stripped", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "fmtisfun_win_stripped", 0x4bf940, 0x5082a0, 0x489310)
	})

	t.Run("hello", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "hello", 0x4de6e0, 0x544140, 0x499080)
	})

	t.Run("hello_lin", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "hello_lin", 0x4de6e0, 0x544140, 0x499080)
	})

	t.Run("hello_stripped_lin", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "hello_stripped_lin", 0x4de5e0, 0x543140, 0x499080)
	})

	t.Run("windows_rdata_pclntab", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "windows_rdata_pclntab", 0x4ef820, 0x5582c0, 0x4a57a0)
	})

	t.Run("windows_stripped_rdata_pclntab", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "windows_stripped_rdata_pclntab", 0x4ef820, 0x5582c0, 0x4a57a0)
	})

	t.Run("GoReSym_garbled", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "GoReSym_garbled", 0x6042c0, 0x71c080, 0x55b800)
	})

	// We previosly threw on this binary. It has invalid section size for .bss section
	t.Run("notgo_invalid_bss_secsize", func(t *testing.T) {
		filePath := fmt.Sprintf("%s/test/weirdbins/%s", workingDirectory, "notgo_invalid_bss_secsize")
		if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
			t.Errorf("Test file %s doesn't exist\n", filePath)
			return
		}

		_, err := main_impl(filePath, true, true, true, false, 0, "", false)
		if err == nil {
			t.Errorf("GoReSym found pclntab in a non-go binary, this is not possible.")
		}
	})

	// reading the buildid with notes section at the start and alignment of 0 previously caused underflow in offset calculations
	t.Run("zero_elf_palignment", func(t *testing.T) {
		filePath := fmt.Sprintf("%s/test/weirdbins/%s", workingDirectory, "zero_elf_palignment")
		if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
			t.Errorf("Test file %s doesn't exist\n", filePath)
			return
		}

		_, err := main_impl(filePath, true, true, true, false, 0, "", false)
		if err == nil {
			t.Errorf("GoReSym found pclntab in a non-go binary, this is not possible.")
		}
	})
}

func TestBig(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get working directory")
	}

	t.Run("kubectl_macho", func(t *testing.T) {
		testSymbolRecovery(t, workingDirectory, "kubectl_macho", 0x6C6CB20, 0x7F8CB20, 0x5CD9E40)
	})
}

func isPrintable(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

func TestStringExtraction(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get working directory")
		return
	}

	// Test string extraction on multiple test binaries
	testCases := []struct {
		version     string
		filename    string
		minStrings  int
		description string
	}{
		{"117", "testproject_lin", 100, "Go 1.17 Linux binary"},
		{"117", "testproject_lin_stripped", 100, "Go 1.17 Linux stripped binary"},
		{"117", "testproject_mac", 100, "Go 1.17 macOS binary"},
		{"117", "testproject_win.exe", 100, "Go 1.17 Windows binary"},
		{"116", "testproject_lin", 100, "Go 1.16 Linux binary"},
		{"115", "testproject_lin_32", 50, "Go 1.15 Linux 32-bit binary"},
		{"18", "testproject_mac_stripped", 100, "Go 1.8 macOS stripped binary"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_%s", tc.version, tc.filename), func(t *testing.T) {
			filePath := fmt.Sprintf("%s/test/build/%s/%s", workingDirectory, tc.version, tc.filename)
			if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
				t.Skipf("Test file %s doesn't exist", filePath)
				return
			}

			// Extract with strings enabled
			data, err := main_impl(filePath, false, false, false, true, 0, "", true)
			if err != nil {
				t.Errorf("Failed to extract from %s: %v", tc.description, err)
				return
			}

			// Check that strings were extracted
			if len(data.Strings) == 0 {
				t.Errorf("No strings extracted from %s", tc.description)
				return
			}

			// Check minimum number of strings
			if len(data.Strings) < tc.minStrings {
				t.Errorf("Expected at least %d strings from %s, got %d", tc.minStrings, tc.description, len(data.Strings))
			}

			// Check that all extracted strings are printable and have a non-zero start address
			nonPrintableCount := 0
			for _, entry := range data.Strings {
				if !isPrintable(entry.Str) {
					nonPrintableCount++
				}
				if entry.Start == 0 {
					t.Errorf("String %q has zero start address in %s", entry.Str, tc.description)
				}
			}

			// Allow up to 5% non-printable strings (some edge cases may exist)
			maxNonPrintable := len(data.Strings) / 20
			if nonPrintableCount > maxNonPrintable {
				t.Errorf("Too many non-printable strings in %s: %d out of %d (max allowed: %d)",
					tc.description, nonPrintableCount, len(data.Strings), maxNonPrintable)
			}

			// Check for some expected common Go strings
			expectedSubstrings := []string{"main", "go", "runtime"}
			foundCount := 0
			for _, expected := range expectedSubstrings {
				for _, entry := range data.Strings {
					if strings.Contains(entry.Str, expected) {
						foundCount++
						break
					}
				}
			}

			if foundCount == 0 {
				t.Errorf("No common Go strings found in %s (expected at least one of: %v)", tc.description, expectedSubstrings)
			}

			t.Logf("%s: extracted %d strings (%d printable)", tc.description, len(data.Strings), len(data.Strings)-nonPrintableCount)
		})
	}
}
