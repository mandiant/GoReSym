package objfile

// ModuleDataOffsets contains the offsets for moduledata struct fields by Go version and architecture
var ModuleDataOffsets = map[string]map[string]map[string]uint64{
    // Go 1.5-1.15
    "1.5": {
        "amd64": {
            "text":      0x8,
            "types":     0x10,
            "etypes":    0x18,
            "typelinks": 0x20,
            "itablinks": 0x30,
            "next":      0xA0,
        },
        "386": {
            "text":      0x4,
            "types":     0x8,
            "etypes":    0xC,
            "typelinks": 0x10,
            "itablinks": 0x18,
            "next":      0x50,
        },
    },
    // Go 1.16-1.17
    "1.16": {
        "amd64": {
            "text":         0x8,
            "types":        0x10,
            "etypes":       0x18,
            "typelinks":    0x20,
            "itablinks":    0x38,
            "ptab":         0x50,
            "pluginpath":   0x60,
            "pkghashes":    0x70,
            "modulename":   0x80,
            "modulehashes": 0x90,
            "hasmain":      0xA0,
            "gcdatamask":   0xA8,
            "gcbssmask":    0xB0,
            "typemap":      0xB8,
            "bad":          0xC0,
            "next":         0xC8,
        },
        "386": {
            "text":         0x4,
            "types":        0x8,
            "etypes":       0xC,
            "typelinks":    0x10,
            "itablinks":    0x1C,
            "ptab":         0x28,
            "pluginpath":   0x30,
            "pkghashes":    0x38,
            "modulename":   0x40,
            "modulehashes": 0x48,
            "hasmain":      0x50,
            "gcdatamask":   0x54,
            "gcbssmask":    0x5C,
            "typemap":      0x64,
            "bad":          0x68,
            "next":         0x6C,
        },
    },
    // Go 1.18+
    "1.18": {
        "amd64": {
            "text":         0x8,
            "types":        0x10,
            "etypes":       0x18,
            "typelinks":    0x20,
            "itablinks":    0x38,
            "ptab":         0x50,
            "pluginpath":   0x60,
            "pkghashes":    0x70,
            "modulename":   0x80,
            "modulehashes": 0x90,
            "hasmain":      0xA0,
            "minpc":        0xA8,  // New in 1.18
            "maxpc":        0xB0,  // New in 1.18
            "filetab":      0xB8,  // New in 1.18
            "pclntable":    0xC0,  // New in 1.18
            "gcdatamask":   0xD0,
            "gcbssmask":    0xD8,
            "typemap":      0xE0,
            "bad":          0xE8,
            "next":         0xF0,
        },
        "386": {
            "text":         0x4,
            "types":        0x8,
            "etypes":       0xC,
            "typelinks":    0x10,
            "itablinks":    0x1C,
            "ptab":         0x28,
            "pluginpath":   0x30,
            "pkghashes":    0x38,
            "modulename":   0x40,
            "modulehashes": 0x48,
            "hasmain":      0x50,
            "minpc":        0x54,  // New in 1.18
            "maxpc":        0x58,  // New in 1.18
            "filetab":      0x5C,  // New in 1.18
            "pclntable":    0x60,  // New in 1.18
            "gcdatamask":   0x68,
            "gcbssmask":    0x70,
            "typemap":      0x78,
            "bad":          0x7C,
            "next":         0x80,
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