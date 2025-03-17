package objfile

// ModuleDataOffsets contains the offsets for moduledata struct fields by Go version and architecture
var ModuleDataOffsets = map[string]map[string]map[string]uint64{
    // Go 1.5-1.15
    "1.5": {
        "x64": {
            "text":      0x8,
            "types":     0x10,
            "etypes":    0x18,
            "typelinks": 0x20,
            "itablinks": 0x30,
        },
        "x86": {
            "text":      0x4,
            "types":     0x8,
            "etypes":    0xC,
            "typelinks": 0x10,
            "itablinks": 0x18,
        },
    },
    // Go 1.16-1.17
    "1.16": {
        "x64": {
            "text":      0x8,
            "types":     0x10,
            "etypes":    0x18,
            "typelinks": 0x20,
            "itablinks": 0x38,
        },
        "x86": {
            "text":      0x4,
            "types":     0x8,
            "etypes":    0xC,
            "typelinks": 0x10,
            "itablinks": 0x1C,
        },
    },
    // Go 1.18+
    "1.18": {
        "x64": {
            "text":      0x8,
            "types":     0x10,
            "etypes":    0x18,
            "typelinks": 0x20,
            "itablinks": 0x38,
            "minpc":     0xA8,  // Only included fields used in the code
            "maxpc":     0xB0,
        },
        "x86": {
            "text":      0x4,
            "types":     0x8,
            "etypes":    0xC,
            "typelinks": 0x10,
            "itablinks": 0x1C,
            "minpc":     0x54,
            "maxpc":     0x58,
        },
    },
}

// VersionFallbacks defines which version to fall back to if the exact version isn't found
var VersionFallbacks = map[string]string{
    "1.6":  "1.5",
    "1.7":  "1.5",
    "1.8":  "1.5",
    "1.9":  "1.5",
    "1.10": "1.5",
    "1.11": "1.5",
    "1.12": "1.5",
    "1.13": "1.5",
    "1.14": "1.5",
    "1.15": "1.5",
    "1.17": "1.16",
    "1.19": "1.18",
    "1.20": "1.18",
    "1.21": "1.18",
    "1.22": "1.18",
}

// GetModuleDataOffset returns the offset for a moduledata field
func GetModuleDataOffset(version, arch, field string) (uint64, bool) {
    // Function remains unchanged
    // Try exact version match first
    if offsets, ok := ModuleDataOffsets[version]; ok {
        if archOffsets, ok := offsets[arch]; ok {
            if offset, ok := archOffsets[field]; ok {
                return offset, true
            }
        }
    }
    
    // Try fallback versions
    fallbackVersion := version
    for {
        fallback, ok := VersionFallbacks[fallbackVersion]
        if !ok {
            break
        }
        fallbackVersion = fallback
        if offsets, ok := ModuleDataOffsets[fallbackVersion]; ok {
            if archOffsets, ok := offsets[arch]; ok {
                if offset, ok := archOffsets[field]; ok {
                    return offset, true
                }
            }
        }
    }
    
    return 0, false
}