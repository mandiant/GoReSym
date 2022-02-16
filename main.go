/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	// we copy the go src directly, then change every include to github.com/mandiant/GoReSym/<whatever>
	// this is required since we're using internal files. Our modifications are directly inside the copied source
	"github.com/mandiant/GoReSym/buildid"
	"github.com/mandiant/GoReSym/buildinfo"
	"github.com/mandiant/GoReSym/objfile"
	"github.com/mandiant/GoReSym/runtime/debug"
)

func isStdPackage(pkg string) bool {
	// Empty name is common for reflect/type functions and some runtime symbols
	if len(strings.TrimSpace(pkg)) <= 0 {
		return true
	}

	for _, v := range standardPackages {
		if v == pkg {
			return true
		}
	}

	return false
}

// pclntab header info
type PcLnTabMetadata struct {
	VA            uint64
	Version       string
	Endianess     string
	CpuQuantum    uint32
	CpuQuantumStr string
	PointerSize   uint32
}

type FuncMetadata struct {
	Start       uint64
	End         uint64
	PackageName string
	FullName    string
}

type ExtractMetadata struct {
	Version       string
	BuildId       string
	Arch          string
	OS            string
	TabMeta       PcLnTabMetadata
	ModuleMeta    objfile.ModuleData
	Types         []objfile.Type
	Interfaces    []objfile.Type
	BuildInfo     debug.BuildInfo
	Files         []string
	UserFunctions []FuncMetadata
	StdFunctions  []FuncMetadata
}

func main_impl(fileName string, printStdPkgs bool, printFilePaths bool, printTypes bool, manualTypeAddress int, versionOverride string) (metadata ExtractMetadata, err error) {
	extractMetadata := ExtractMetadata{}

	file, err := objfile.Open(fileName)
	if err != nil {
		return ExtractMetadata{}, fmt.Errorf("invalid file: %w", err)
	}

	buildId, err := buildid.ReadFile(fileName)
	if err == nil {
		extractMetadata.BuildId = buildId
	} else {
		extractMetadata.BuildId = ""
	}

	// try to get version the 'correct' way, also fill out buildSettings if parsing was ok
	bi, err := buildinfo.ReadFile(fileName)
	if err == nil {
		extractMetadata.Version = bi.GoVersion

		for _, setting := range bi.Settings {
			if setting.Key == "GOOS" {
				extractMetadata.OS = setting.Value
			} else if setting.Key == "GOARCH" {
				extractMetadata.Arch = setting.Value
			}
		}

		extractMetadata.BuildInfo = *bi
	}

	// Optional bruteforce any one of these, but only if they weren't previous found in the buildinfo
	if extractMetadata.OS == "" || extractMetadata.Arch == "" || extractMetadata.Version == "" {
		// GOARCH
		if extractMetadata.Arch == "" {
			extractMetadata.Arch = file.GOARCH()
		}

		fileData, fileDataErr := ioutil.ReadFile(fileName)
		if fileDataErr == nil {

			// GOVERSION
			if extractMetadata.Version == "" {
				// go1.<varies><garbage data>
				idx := bytes.Index(fileData, []byte{0x67, 0x6F, 0x31, 0x2E})
				if idx != -1 && len(fileData[idx:]) > 10 {
					extractMetadata.Version = "go1."
					ver := fileData[idx+4 : idx+10]
					for i, c := range ver {
						// the string is _not_ null terminated, nor length delimited. So, filter till first non-numeric ascii
						nextIsNumeric := (i+1) < len(ver) && ver[i+1] >= 0x30 && ver[i+1] <= 0x39

						// careful not to end with a . at the end
						if (c >= 0x30 && c <= 0x39 && c != ' ') || (c == '.' && nextIsNumeric) {
							extractMetadata.Version += string([]byte{c})
						} else {
							break
						}
					}
				}
			}

			// GOOS
			if extractMetadata.OS == "" {
				// try to find the OS by locating the source file name from https://github.com/golang/go/tree/master/src/runtime/os_<os name>.go or the asm file name rt0_<os name>_<arch>.s
				// if this is bad, we can end up signaturing the asm file manually (todo)
				// /src/runtime/os_
				needleSrcFile := []byte{0x2F, 0x73, 0x72, 0x63, 0x2F, 0x72, 0x75, 0x6E, 0x74, 0x69, 0x6D, 0x65, 0x2F, 0x6F, 0x73, 0x5F}
				needleSrcFileLen := len(needleSrcFile)
				idx := bytes.Index(fileData, needleSrcFile)
				if idx != -1 && len(fileData[idx:]) > needleSrcFileLen+20 {
					os_str := fileData[idx+needleSrcFileLen : idx+needleSrcFileLen+20]
					for _, c := range os_str {
						// end our search at the first '.', which should be the .go soure file extension, or a space as fallback
						if (c >= 0x30 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) && c != '.' && c != ' ' {
							extractMetadata.OS += string([]byte{c})
						} else {
							break
						}
					}
				} else {
					// /src/runtime/rt0_
					needleAsmFile := []byte{0x2F, 0x73, 0x72, 0x63, 0x2F, 0x72, 0x75, 0x6E, 0x74, 0x69, 0x6D, 0x65, 0x2F, 0x72, 0x74, 0x30, 0x5F}
					needleAsmFileLen := len(needleAsmFile)
					idx := bytes.Index(fileData, needleAsmFile)
					if idx != -1 && len(fileData[idx:]) > needleAsmFileLen+20 {
						os_str := fileData[idx+needleAsmFileLen : idx+needleAsmFileLen+20]
						for _, c := range os_str {
							// end our search at the first '_', which should be the _arch, space as fallback
							if (c >= 0x30 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) && c != '_' && c != '.' && c != ' ' {
								extractMetadata.OS += string([]byte{c})
							} else {
								break
							}
						}
					}
				}
			}
		}
	}

	if len(versionOverride) > 0 {
		extractMetadata.Version = versionOverride
	}

	// numeric only, go1.17 -> 1.17
	goVersionIdx := strings.Index(extractMetadata.Version, "go")
	if goVersionIdx != -1 {
		// "devel go1.18-2d1d548 Tue Dec 21 03:55:43 2021 +0000"
		extractMetadata.Version = strings.Split(extractMetadata.Version[goVersionIdx+2:]+" ", " ")[0]

		// go1.18-2d1d548
		extractMetadata.Version = strings.Split(extractMetadata.Version+"-", "-")[0]
	}

	tab, tabva, err := file.PCLineTable()
	if err != nil {
		return ExtractMetadata{}, fmt.Errorf("failed to read pclntab: %w", err)
	}

	if tab.Go12line == nil {
		log.Fatalf("pclntab read, but is nil")
		return ExtractMetadata{}, fmt.Errorf("read pclntab, but parsing failed. The file may not be fully unpacked or corrupted: %w", err)
	}

	extractMetadata.TabMeta.CpuQuantum = tab.Go12line.Quantum

	// quantum is the minimal unit for a program counter (1 on x86, 4 on most other systems).
	// 386: 1, amd64: 1, arm: 4, arm64: 4, mips: 4, mips/64/64le/64be: 4, ppc64/64le: 4, riscv64: 4, s390x: 2, wasm: 1
	extractMetadata.TabMeta.CpuQuantumStr = "x86/x64/wasm"
	if extractMetadata.TabMeta.CpuQuantum == 2 {
		extractMetadata.TabMeta.CpuQuantumStr = "s390x"
	} else if extractMetadata.TabMeta.CpuQuantum == 4 {
		extractMetadata.TabMeta.CpuQuantumStr = "arm/mips/ppc/riscv"
	}

	extractMetadata.TabMeta.VA = tabva
	extractMetadata.TabMeta.Version = tab.Go12line.Version.String()
	extractMetadata.TabMeta.Endianess = tab.Go12line.Binary.String()
	extractMetadata.TabMeta.PointerSize = tab.Go12line.Ptrsize

	// this can be a little tricky to locate and parse properly across all go versions
	_, moduleData, err := file.ModuleDataTable(tabva, extractMetadata.Version, extractMetadata.TabMeta.Version, extractMetadata.TabMeta.PointerSize == 8, extractMetadata.TabMeta.Endianess == "LittleEndian")
	if err == nil {
		extractMetadata.ModuleMeta = *moduleData
		if printTypes && manualTypeAddress == 0 {
			types, err := file.ParseTypeLinks(extractMetadata.Version, moduleData, extractMetadata.TabMeta.PointerSize == 8, extractMetadata.TabMeta.Endianess == "LittleEndian")
			if err == nil {
				extractMetadata.Types = types
			}

			interfaces, err := file.ParseITabLinks(extractMetadata.Version, moduleData, extractMetadata.TabMeta.PointerSize == 8, extractMetadata.TabMeta.Endianess == "LittleEndian")
			if err == nil {
				extractMetadata.Interfaces = interfaces
			}
		} else if manualTypeAddress != 0 {
			types, err := file.ParseType(extractMetadata.Version, moduleData, uint64(manualTypeAddress), extractMetadata.TabMeta.PointerSize == 8, extractMetadata.TabMeta.Endianess == "LittleEndian")
			if err == nil {
				extractMetadata.Types = types
			}
		}
	}

	if printFilePaths {
		for k := range tab.Files {
			extractMetadata.Files = append(extractMetadata.Files, k)
		}
	}

	for _, elem := range tab.Funcs {
		if isStdPackage(elem.PackageName()) {
			if printStdPkgs {
				extractMetadata.StdFunctions = append(extractMetadata.StdFunctions, FuncMetadata{
					Start:       elem.Entry,
					End:         elem.End,
					PackageName: elem.PackageName(),
					FullName:    elem.Name,
				})
			}
		} else {
			extractMetadata.UserFunctions = append(extractMetadata.UserFunctions, FuncMetadata{
				Start:       elem.Entry,
				End:         elem.End,
				PackageName: elem.PackageName(),
				FullName:    elem.Name,
			})
		}
	}

	return extractMetadata, nil
}

func printForHuman(metadata ExtractMetadata) {
	fmt.Println("----GoReSym----")
	fmt.Println("Some information is ommitted, for a full listing do not use human view")
	fmt.Printf("%-20s %s\n", "Version:", metadata.Version)
	fmt.Printf("%-20s %s\n", "Arch:", metadata.Arch)
	fmt.Printf("%-20s %s\n", "OS:", metadata.OS)
	fmt.Println("\n-BUILD INFO-")
	fmt.Printf("%-20s %s\n", "GoVersion", metadata.BuildInfo.GoVersion)
	fmt.Printf("%-20s %s\n", "Path", metadata.BuildInfo.Path)
	fmt.Printf("%-20s %s\n", "Main.Path", metadata.BuildInfo.Main.Path)
	fmt.Printf("%-20s %s\n", "Main.Version", metadata.BuildInfo.Main.Version)
	fmt.Printf("%-20s %s\n", "Main.Sum", metadata.BuildInfo.Main.Sum)
	fmt.Printf("%-20s %s\n", "Main.Path", metadata.BuildInfo.Main.Path)
	for i, dep := range metadata.BuildInfo.Deps {
		depPrefix := fmt.Sprintf("Dep%d.", i)
		fmt.Printf("%-20s %s\n", depPrefix+"Path", dep.Path)
		fmt.Printf("%-20s %s\n", depPrefix+"Version", dep.Version)
		fmt.Printf("%-20s %s\n", depPrefix+"Sum", dep.Sum)
	}

	fmt.Println("\n  -BUILD SETTINGS-")
	if len(metadata.BuildInfo.Settings) > 0 {
		for _, setting := range metadata.BuildInfo.Settings {
			fmt.Printf("  %-20s %s\n", "Setting."+setting.Key, setting.Value)
		}
	} else {
		fmt.Println("  <NO SETTINGS PRESENT>")
	}

	fmt.Println("\n-TYPE STRUCTURES-")
	printedStruct := false
	for _, typ := range metadata.Types {
		if len(typ.Reconstructed) > 0 {
			fmt.Printf("VA: 0x%x\n", typ.VA)
			fmt.Printf("%s\n\n", typ.Reconstructed)
			printedStruct = true
		}
	}
	if !printedStruct {
		fmt.Println("<NO TYPE STRUCTURES EXTRACTED>")
	}

	fmt.Println("\n-INTERFACES-")
	printedInterface := false
	for _, typ := range metadata.Interfaces {
		if len(typ.Reconstructed) > 0 {
			fmt.Printf("%-20s 0x%x\n", "VA:", typ.VA)
			fmt.Printf("%s\n\n", typ.Reconstructed)
			printedInterface = true
		}
	}
	if !printedInterface {
		fmt.Println("<NO INTERFACES EXTRACTED>")
	}

	fmt.Println("\n-Files-")
	if len(metadata.Files) > 0 {
		for _, file := range metadata.Files {
			fmt.Println(file)
		}
	} else {
		fmt.Println("<NO FILES EXTRACTED>")
	}

	fmt.Println("\n-User Functions-")
	if len(metadata.UserFunctions) > 0 {
		for i, fn := range metadata.UserFunctions {
			fnPrefix := fmt.Sprintf("UserFunc%d.", i)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"StartVA:", fn.Start)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"EndVA:", fn.End)
			fmt.Printf("%-20s %s\n", fnPrefix+"Package:", fn.PackageName)
			fmt.Printf("%-20s %s\n", fnPrefix+"Name:", strings.TrimLeft(strings.TrimLeft(fn.FullName, fn.PackageName), "."))
		}
	} else {
		fmt.Println("<NO USER FUNCTIONS EXTRACTED>")
	}

	fmt.Println("\n-Standard Functions-")
	if len(metadata.StdFunctions) > 0 {
		for i, fn := range metadata.StdFunctions {
			fnPrefix := fmt.Sprintf("StdFunc%d.", i)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"StartVA:", fn.Start)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"EndVA:", fn.End)
			fmt.Printf("%-20s %s\n", fnPrefix+"Name:", fn.FullName)
		}
	} else {
		fmt.Println("<NO STANDARD FUNCTIONS EXTRACTED>")
	}
}

func DataToJson(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "{\"error\": \"failed to format output\"}"
	}
	return string(jsonBytes)
}

func TextToJson(key string, text string) string {
	return fmt.Sprintf("{\"%s\": \"%s\"}", key, text)
}

func main() {
	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()

	log.SetFlags(0)
	log.SetPrefix("GoReSym: ")

	printStdPkgs := flag.Bool("d", false, "Print Default Packages")
	printFilePaths := flag.Bool("p", false, "Print File Paths")
	printTypes := flag.Bool("t", false, "Print types automatically, enumerate typelinks and itablinks")
	typeAddress := flag.Int("m", 0, "Manually parse the RTYPE at the provided virtual address, disables automated enumeration of moduledata typelinks itablinks")
	versionOverride := flag.String("v", "", "Override the automated version detection, ex: 1.17. If this is wrong, parsing may fail or produce nonsense")
	humanView := flag.Bool("human", false, "Human view, print information flat rather than json, some information is ommited for clarity")

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println(TextToJson("error", "filepath must be provided as first argument"))
		os.Exit(1)
	}

	metadata, err := main_impl(flag.Arg(0), *printStdPkgs, *printFilePaths, *printTypes, *typeAddress, *versionOverride)
	if err != nil {
		fmt.Println(TextToJson("error", fmt.Sprintf("Failed to parse file: %s", err)))
		os.Exit(1)
	} else {
		if *humanView {
			printForHuman(metadata)
		} else {
			fmt.Println(DataToJson((metadata)))
		}
	}
}
