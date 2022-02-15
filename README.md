# GoReSym
Go symbol parser. This is designed to extract binary metadata (arch, os, endianness, version, etc), functions (start,end,name,classification), filename/line number information when it exists, and structures/embedded types. This library is cross platform and based directly on the open source GO code from https://github.com/golang/go/tree/master/src/debug/gosym as well as other internal runtime code stitched together as needed. 

There are modifications to the original go runtime code to handle:
* stripped binaries
* malformed unpacked binaries, such as from UPX
* binaries which split single section data cross multiple sections
* location of the moduledata structure

# Version Support
* all combinations of x86/x64 macho/elf/exe big/little endian
* pclntab parsing: >= Go 1.2
* moduledata location: >= Go 1.2
* moduledata type parsing: >= Go 1.5

The moduledata table used to parse types doesn't exist prior to go 1.5, and will never be supported by this library.

# Use
```
go build
./GoReSym -d -p -t <binary path>
```

* Optional -d (default) flag will print standard Go packages in addition to user packages.
* Optional -p (paths) flag will print any file paths embedded in the pclntab.
* Optional -t (types) flag will print Go type names.
* Optional -m <virtual address> (manual) flag will dump the RTYPE structure recursively at the given virtual address
* Optional -v <version string> flag will override automated version detection and use the provided version. This is needed for some stripped binaries. Type parsing will fail if the version is not accurate.
* Optional -human flag will print a flat text listing instead of JSON. Especially useful when printing structure and interface types.

To import this information into IDA Pro there is a small script to read the json output of this tool and label symbols. Please see the IDAPython directory.

Output:
```
{
    "Version": "1.14.15",
    "BuildId": "Zb9QmokKTiOUgHKmaIwz/wd2rtE3W9PN-um1Ocdzh/qTdqcTY_jVajHy_-TtYv/Z_kJu9M77OjfijEiHMcF",
    "Arch": "amd64",
    "TabMeta": {
        "VA": 5174784,
        "Version": "1.2",
        "Endianess": "LittleEndian",
        "CpuQuantum": 1,
        "CpuQuantumStr": "x86/x64",
        "PointerSize": 8
    },
    "ModuleMeta": {
        "VA": 5678816,
        "Types": 4845568,
        "ETypes": 5171904,
        "Typelinks": {
            "Data": 5171904,
            "Len": 695,
            "Capacity": 695
        },
        "ITablinks": {
            "Data": 5174688,
            "Len": 11,
            "Capacity": 11
        },
        "LegacyTypes": {
            "Data": 0,
            "Len": 0,
            "Capacity": 0
        }
    },
    "Types": [ ... ],
    "Files": [ ... ],
    "UserFunctions": [ ... ],
    "StdFunctions": [ ... ]
}
```

# Contributions
The source code is copied from `/internal` Go package sources. Due to the way go works we need to remove the `/internal` path from the file tree to use these internal sources. What this results in is lots of copying of internal Go files, where the directory tree is mostly intact but many imports have their `/internal` paths replaced with `github.com/stevemk14ebr/GoReSym/`. Many internal structures are also modified to export fields and method, this is not great, but it's not easily avoidable. 

With that, most of the modified logic exists in `/objfile`, and the file `objfile/internals` defines the reversed internal go structures that are parsed out. When updating this repository with new code from the upstream Go source care must be taken to keep the current modifications intact. I am open to suggestions on how to better structure this project to avoid these issues while still compiling with the typical `go build`, there is a previous discussion here on the issues leading to this: https://github.com/golang/go/issues/46792.

# References
* pclntab specification: golang.org/s/go12symtab (https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub)
* pclntab magics: https://github.com/golang/go/blob/89f687d6dbc11613f715d1644b4983905293dd33/src/debug/gosym/pclntab.go#L169
* objfile bug(s): https://github.com/golang/go/issues/42954, https://github.com/golang/go/issues/47981, https://github.com/golang/go/issues/47852
* buildID legacy issue: https://github.com/golang/go/issues/50809

This library current handles legacy pclntab (pre go 1.2), 1.2, 1.16, and 1.18

# Changes
* pcln() functions in objfile/<fileformat> have been extended to support byte scanning the pclntab magic
* file format parsers in /debug/<fileformat> have added routines such as DataAfterSection to support the signature scan
* debug/gosym/symtab.go's walksymtab has an added check to bail early when the optional symtab section is empty
* capitalization of many members and internal structs were changed to capital, so that they could be used as public exported symbols. Go uses capitalization to declare public vs private. The changes here are too many to enumerate
* objfile/objfile.go's PCLineTable() has had goobj liner support removed. This object time is not common to see, and the liner table cannot be signatured for, so goobj file support is removed.
* extra sanity checks around loadPeTable (and other format variants) to avoid panic when symbols are present but malicious modified to be invalid (https://github.com/golang/go/issues/47981)
* the signatures of some internal functions have been modified to provide lower level access to information such as section addresses and offsets. 
* read_memory routines for supported file formats implemented to read file data by virtual address
* moduledata scan routines introduced to help locate moduledata in support of scanning for types and interfaces (via typelinks)
