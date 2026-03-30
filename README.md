# GoReSym
![GoReSym Logo](./goresym_scaled.png)

GoReSym is a Go symbol parser that extracts program metadata (such as CPU architecture, OS, endianness, compiler version, etc), function metadata (start & end addresses, names, sources), filename and line number metadata, and embedded structures and types.
This cross platform program is based directly on the open source Go compiler and runtime code.
The upstream Go runtime code is extended to handle:
* stripped binaries
* malformed unpacked binaries, such as from UPX
* binaries that split single data ranges across multiple sections
* the location of the `moduledata` structure

---

## Quick Start

### 1. Clone the repository
git clone https://github.com/mandiant/GoReSym
cd GoReSym

### 2. Build the tool
go build

### 3. Run GoReSym
./goresym -t -d -p /path/to/binary

---

## Example Usage
./goresym -t -d -p sample_binary

### Example Output (simplified)
main.main
crypto.encrypt
net.connect
This output represents recovered function names and metadata extracted from the binary.

---

## Flags
| Flag | Description |
|------|------------|
| -d | Include standard Go packages along with user-defined packages |
| -p | Print file paths embedded in the binary |
| -t | Extract Go type names |
| -strings | Extract embedded Go strings |
| -m <virtual address> | Dump RTYPE structure recursively |
| -v <version string> | Override Go version detection |
| -human | Print output in human-readable format |
| -about | Display license information |

---

## Use Cases
- Reverse engineering Go binaries
- Malware analysis
- Recovering symbols from stripped binaries
- Understanding program structure without source code

---

## Typical Workflow
1. Obtain a Go binary (compiled program or malware sample)
2. Run GoReSym to extract symbols and metadata
3. Analyze output or import into tools like IDA Pro or Ghidra
4. Use recovered information to understand program behavior

---

## Usage
Refer to the following blog for reverse engineering details and advanced usage:
https://www.mandiant.com/resources/blog/golang-internals-symbol-recovery
You can download pre-built binaries for Linux, macOS, and Windows from the Releases tab:
https://github.com/mandiant/GoReSym/releases/

---

## Example Output (Full)

```json
{
    "Version": "1.14.15",
    "BuildId": "...",
    "Arch": "amd64",
    "Types": [ ... ],
    "Files": [ ... ],
    "Strings": [ ... ],
    "UserFunctions": [ ... ],
    "StdFunctions": [ ... ]
}
Version Support

As the Go compiler and runtime evolve, metadata structures also change.

GoReSym supports:
ARM64 and x86/x64 architectures
MACH-O, ELF, and PE formats
Big and little endian systems
Supported Features
pclntab parsing: >= Go 1.2
moduledata location: >= Go 1.2
moduledata type parsing: >= Go 1.5
Contributions

Much of the source code is derived from the Go compiler /internal packages, with modifications.

Key notes for contributors:

/internal imports have been rewritten to local paths
internal structures have been exported for analysis
changes must preserve compatibility with upstream Go structures

Most new logic exists in /objfile.

References
pclntab Specification: https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub
Go pclntab source: https://github.com/golang/go
Go bugs:
https://github.com/golang/go/issues/42954
https://github.com/golang/go/issues/47981
https://github.com/golang/go/issues/47852
https://github.com/golang/go/issues/50809

Changes
Added parsing support for newer Go versions
Improved pclntab detection and repair
Added moduledata scanning routines
Enhanced error handling and safety checks

License
MIT
