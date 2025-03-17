package objfile

import (
    "testing"
)

func TestModuleDataOffsets(t *testing.T) {
    testCases := []struct {
        version string
        arch    string
        field   string
        want    uint64
        exists  bool
    }{
        // Test known offsets for 1.5
        {"1.5", "x64", "text", 0x8, true},
        {"1.5", "x64", "types", 0x10, true},
        {"1.5", "x86", "text", 0x4, true},
        
        // Test known offsets for 1.16
        {"1.16", "x64", "text", 0x8, true},
        {"1.16", "x64", "itablinks", 0x38, true},
        
        // Test known offsets for 1.18
        {"1.18", "x64", "minpc", 0xA8, true},
        {"1.18", "x64", "maxpc", 0xB0, true},
        
        // Test fallbacks
        {"1.17", "x64", "text", 0x8, true},  // Falls back to 1.16
        {"1.22", "x64", "minpc", 0xA8, true},  // Falls back to 1.18
        
        // Test unknown versions/fields
        {"0.1", "x64", "text", 0, false},
        {"1.16", "x64", "nonexistent", 0, false},
        {"1.5", "arm", "text", 0, false},  // Unsupported architecture
    }
    
    for _, tc := range testCases {
        t.Run(tc.version+"/"+tc.arch+"/"+tc.field, func(t *testing.T) {
            got, exists := GetModuleDataOffset(tc.version, tc.arch, tc.field)
            
            if exists != tc.exists {
                t.Errorf("GetModuleDataOffset(%q, %q, %q) existence = %v, want %v", 
                    tc.version, tc.arch, tc.field, exists, tc.exists)
            }
            
            if exists && got != tc.want {
                t.Errorf("GetModuleDataOffset(%q, %q, %q) = %#x, want %#x", 
                    tc.version, tc.arch, tc.field, got, tc.want)
            }
        })
    }
}

func TestVersionFallbacks(t *testing.T) {
    // Test remains mostly unchanged but with updated architecture names
    fallbackTests := []struct {
        version  string
        field    string
        expected uint64
    }{
        {"1.6", "text", 0x8},      // 1.6 falls back to 1.5
        {"1.15", "text", 0x8},     // 1.15 falls back to 1.5
        {"1.17", "text", 0x8},     // 1.17 falls back to 1.16
        {"1.22", "minpc", 0xA8},   // 1.22 falls back to 1.18
    }
    
    for _, test := range fallbackTests {
        t.Run(test.version+"/"+test.field, func(t *testing.T) {
            offset, ok := GetModuleDataOffset(test.version, "x64", test.field)
            if !ok {
                t.Errorf("Expected to find offset for %s.%s via fallback, but didn't", 
                    test.version, test.field)
                return
            }
            
            if offset != test.expected {
                t.Errorf("Expected offset %#x for %s.%s via fallback, got %#x", 
                    test.expected, test.version, test.field, offset)
            }
        })
    }
}