# GoReSym
GoReSym is a Go symbol parser that extracts program metadata (such as CPU architecture, OS, endianness, compiler version, etc), function metadata (start & end addresses, names, sources), filename and line number metadata, and embedded structures and types. This cross platform program is based directly on the [open source Go compiler](https://github.com/golang/go/tree/master/src/debug/gosym) and runtime code. 

The upstream Go runtime code is extended to handle:
* stripped binaries
* malformed unpacked binaries, such as from UPX
* binaries that split single data ranges across multiple sections
* the location of the `moduledata` structure


# Usage
You can download pre-built GoReSym binaries from the [Releases tab](https://github.com/mandiant/GoReSym/releases/) or build from source with a recent Go compiler:

```
go build
```

Invoke GoReSym like this:

```
GoReSym.exe -t -d -p /path/to/input.exe
```

In this example, we ask GoReSym to recover type names (`-t`), user package names, standard Go package names (`-d`), and input file paths (`-p`) embedded within the file `/path/to/input.exe`. The output looks like this:

```json
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

Here are all the available flags:

* `-d` ("default", optional) flag will print standard Go packages in addition to user packages.
* `-p` ("paths", optional) flag will print any file paths embedded in the `pclntab`.
* `-t` ("types", optional) flag will print Go type names.
* `-m <virtual address>` ("manual", optional) flag will dump the `RTYPE` structure recursively at the given virtual address
* `-v <version string>` ("version", optional) flag will override automated version detection and use the provided version. This is needed for some stripped binaries. Type parsing will fail if the version is not accurate.
* `-human` (optional) flag will print a flat text listing instead of JSON. Especially useful when printing structure and interface types.

To import this information into IDA Pro you can run the script found in [https://github.com/mandiant/GoReSym/blob/master/IDAPython/goresym_rename.py](IDAPython/goresym_rename.py). It will read a json file produced by GoReSym and set symbols/labels in IDA.
    
# Version Support

As the Go compiler and runtime have changed, so have the embedded metadata structures. GoReSym supports the following combinations of Go releases & metadata:

* all combinations of Intel x86/x64  𝒙  MACH-O/ELF/PE  𝒙  big/little endian
* `pclntab` parsing: >= Go 1.2
* `moduledata` location: >= Go 1.2
* `moduledata` type parsing: >= Go 1.5

The `moduledata` table used to extract types doesn't exist prior to Go 1.5, so this library will never support extracting types from very old Go versions.

This library current handles legacy `pclntab` (pre Go 1.2), 1.2, 1.16, 1.18, 1.19, and 1.20.

# Contributions
Much of the source code from GoReSym is copied from the upstream Go compiler source directory  `/internal`. To make this work, we've had to massage the source a bit. If you want to contribute to GoReSym, read on so we can explain this import process.

Due to the way Go packages work, we needed to remove the `/internal` path from the source file tree. This resulted in a lot of copying of internal Go files, where the directory tree is mostly intact but with small changes to many files' imports: references to `/internal` paths were replaced with `github.com/mandiant/GoReSym/`. 

We also modified many internal structures to export fields and methods. These are not exported by Go upstream because users should not rely upon them. However, the purpose of this tool is to extract internal information, so we're taking on the task of maintaining these structures. Its not a great situation, but it's not easily avoidable. If you update this repository, you must take care to keep these modifications intact. Its probably better to manually merge in commits from upstream rather than copying upstream files wholesale.

I am open to suggestions on how to better structure this project to avoid these issues while still compiling with the typical `go build`. There is a previous discussion involving Go maintainers [here](https://github.com/golang/go/issues/46792).

Ignoring some trivial changes, most new logic exists in `/objfile`. For example, the file `objfile/internals` defines the reversed internal Go structures that GoReSym parses.

# References
* `pclntab` specification: [golang.org/s/go12symtab](https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub)
* `pclntab` magics: [pclntab.go#L169](https://github.com/golang/go/blob/89f687d6dbc11613f715d1644b4983905293dd33/src/debug/gosym/pclntab.go#L169)
* `objfile` bug(s): 
  *  [golang/go#42954](https://github.com/golang/go/issues/42954)
  *  [golang/go#47981](https://github.com/golang/go/issues/47981)
  *  [golang/go#47852](https://github.com/golang/go/issues/47852)
* `buildID` legacy bug: [golang/go#50809](https://github.com/golang/go/issues/50809)

# Changes
* `pcln()` functions in `objfile/<fileformat>` have been extended to support byte scanning the `pclntab` magic
* file format parsers in `/debug/<fileformat>` have added routines such as `DataAfterSection` to support the signature scan
* `debug/gosym/symtab.go`'s `walksymtab` has an added check to bail early when the optional `symtab` section is empty
* many members and internal structs have been exported. Go uses capitalization to declare public vs private. The changes here are too many to enumerate
* `objfile/objfile.go`'s `PCLineTable()` has had `goobj` liner support removed. This object time is not common to see, and the liner table cannot be signatured for, so `goobj` file support is removed.
* extra sanity checks around `loadPeTable` (and other format variants) to avoid panic when symbols are present but malicious modified to be invalid (ref: [golang/go#47981](https://github.com/golang/go/issues/47981))
* the signatures of some internal functions have been modified to provide lower level access to information such as section addresses and offsets. 
* `read_memory` routines for supported file formats implemented to read file data by virtual address
* `moduledata` scan routines introduced to help locate moduledata in support of scanning for types and interfaces (via `typelinks`)
    
# License
MIT
