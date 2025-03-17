package objfile

import (
    "fmt"
)

// readModuleDataField reads a field from the moduledata struct
func (e *Entry) readModuleDataField(moduleDataAddr uint64, version string, field string, is64bit bool, littleendian bool) (uint64, error) {
    arch := "x86"  // Changed from "386"
    if is64bit {
        arch = "x64"  // Changed from "amd64"
    }
    
    offset, ok := GetModuleDataOffset(version, arch, field)
    if !ok {
        return 0, fmt.Errorf("unknown moduledata field %s for Go version %s/%s", field, version, arch)
    }
    
    return e.ReadPointerSizeMem(moduleDataAddr+offset, is64bit, littleendian)
}

// tryGetDWARFOffsets attempts to get moduledata struct offsets from DWARF debug info
func (e *Entry) tryGetDWARFOffsets() (map[string]uint64, error) {
    // Try to get DWARF data
    dwarfData, err := e.raw.dwarf()
    if err != nil {
        return nil, err
    }
    
    // Try to find moduledata type
    reader := dwarfData.Reader()
    offsets := make(map[string]uint64)
    
    // This is a simplified implementation - in reality, parsing DWARF for struct
    // field offsets is more complex and would require walking the DWARF tree
    for {
        entry, err := reader.Next()
        if err != nil || entry == nil {
            break
        }
        
        // Look for moduledata structure definition
        // This is a placeholder - actual DWARF parsing would be more involved
    }
    
    // If we didn't find enough fields, return an error
    if len(offsets) < 5 {
        return nil, fmt.Errorf("insufficient struct field information in DWARF data")
    }
    
    return offsets, nil
}

