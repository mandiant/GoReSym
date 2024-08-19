package objfile

import (
	"bytes"
	"testing"

	"rsc.io/binaryregexp"
)

// basic demonstration of binaryregexp handling
func TestBinaryRegex(t *testing.T) {
	t.Run("basic non-UTF-8 data", func(t *testing.T) {
		r := binaryregexp.MustCompile(`\xfd\xe2`)

		if !r.MatchString("\xfd\xe2") {
			t.Errorf("failed to match non-UTF-8 data")
		}
	})

	// x64firstmoduledata
	// $sig = { 48 8D 0? ?? ?? ?? ?? EB ?? 48 8? 8? ?? 02 00 00 66 0F 1F 44 00 00 }
	t.Run("x64firstmoduledata", func(t *testing.T) {
		// manually constructed
		r := binaryregexp.MustCompile(`\x48\x8D[\x00-\x0F]....\xEB.\x48[\x80-\x8F][\x80-\x8F].\x02\x00\x00\x66\x0F\x1F\x44\x00\x00`)

		// 0x000000000044D80A: 48 8D 0D 8F DA 26 00                    lea     rcx, runtime_firstmoduledata
		// 0x000000000044D811: EB 0D                                   jmp     short loc_44D820
		// 0x000000000044D813: 48 8B 89 30 02 00 00                    mov     rcx, [rcx+230h]
		// 0x000000000044D81A: 66 0F 1F 44 00 00                       nop     word ptr [rax+rax+00h]    <- always seems to be present
		if !r.Match([]byte{0x48, 0x8D, 0x0D, 0x8F, 0xDA, 0x26, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x89, 0x30, 0x02, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}) {
			t.Errorf("failed to match data verbatim")
		}

		// extra bytes at start
		if !r.Match([]byte{0xFF, 0xFF, 0x48, 0x8D, 0x0D, 0x8F, 0xDA, 0x26, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x89, 0x30, 0x02, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}) {
			t.Errorf("failed to match data with prefix bytes")
		}

		// extra bytes at end
		if !r.Match([]byte{0x48, 0x8D, 0x0D, 0x8F, 0xDA, 0x26, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x89, 0x30, 0x02, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0xFF, 0xFF}) {
			t.Errorf("failed to match data with postfix bytes")
		}

		// first byte doesn't match
		if r.Match([]byte{0xFF, 0x8D, 0x0D, 0x8F, 0xDA, 0x26, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x89, 0x30, 0x02, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}) {
			t.Errorf("unexpected match")
		}

		// byte 2 range is different
		if !r.Match([]byte{0x48, 0x8D, 0x00, 0x8F, 0xDA, 0x26, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x89, 0x30, 0x02, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}) {
			t.Errorf("failed to match data variant 1")
		}
		// byte 2 range is different
		if !r.Match([]byte{0x48, 0x8D, 0x0F, 0x8F, 0xDA, 0x26, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x89, 0x30, 0x02, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}) {
			t.Errorf("failed to match data variant 2")
		}
	})
}

func compare(a [][]int, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}

		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}

	}

	return true
}

// basic demonstration of binaryregexp group handling.
func TestRegexGrouping(t *testing.T) {
	t.Run("documentation examples", func(t *testing.T) {
		// from source: https://pkg.go.dev/regexp#Regexp.FindAllStringSubmatchIndex
		re := binaryregexp.MustCompile(`a(x*)b`)

		if !compare(re.FindAllStringSubmatchIndex("-ab-", -1), [][]int{{1, 3, 2, 2}}) {
			t.Errorf("1")
		}

		if !compare(re.FindAllStringSubmatchIndex("-axxb-", -1), [][]int{{1, 5, 2, 4}}) {
			t.Errorf("2")
		}

		if !compare(re.FindAllStringSubmatchIndex("-ab-axb-", -1), [][]int{{1, 3, 2, 2}, {4, 7, 5, 6}}) {
			t.Errorf("3")
		}

		if !compare(re.FindAllStringSubmatchIndex("-axxb-ab-", -1), [][]int{{1, 5, 2, 4}, {6, 8, 7, 7}}) {
			t.Errorf("4")
		}

		if !compare(re.FindAllStringSubmatchIndex("-foo-", -1), [][]int{}) {
			t.Errorf("5")
		}
	})
}

func TestRegexpPatternFromYaraPattern(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := RegexpPatternFromYaraPattern(""); err == nil {
			t.Errorf("empty pattern should have errored")
		}

		reg, err := RegexpPatternFromYaraPattern("{}")
		if err != nil {
			t.Errorf("empty pattern errored")
		}
		if reg.rawre != "" {
			t.Errorf("incorrect empty pattern")
		}
	})

	t.Run("x64firstmoduledata", func(t *testing.T) {
		reg, err := RegexpPatternFromYaraPattern("{ 48 8D 0? ?? ?? ?? ?? EB ?? 48 8? 8? ?? 02 00 00 66 0F 1F 44 00 00 }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		// manually translated
		if reg.rawre != `\x48\x8D[\x00-\x0F]....\xEB.\x48[\x80-\x8F][\x80-\x8F].\x02\x00\x00\x66\x0F\x1F\x44\x00\x00` {
			t.Errorf("incorrect pattern")
		}

		if !bytes.Equal(reg.needle, []byte{02, 00, 00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}) {
			t.Errorf("incorrect needle")
		}
	})

	t.Run("x86sig", func(t *testing.T) {
		reg, err := RegexpPatternFromYaraPattern("{ 8D ?? ?? ?? ?? ?? EB ?? [0-50] 8B ?? ?? 01 00 00 8B ?? ?? ?? 85 ?? 75 ?? }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		// manually translated
		if reg.rawre != `\x8D.....\xEB..{0,50}?\x8B..\x01\x00\x00\x8B...\x85.\x75.` {
			t.Errorf("incorrect pattern")
		}

		if reg.len != 72 {
			t.Errorf("incorrect pattern length")
		}

		if reg.needleOffset != 61 {
			t.Errorf("incorrect needle offset")
		}

		if !bytes.Equal(reg.needle, []byte{0x01, 0x00, 0x00, 0x8B}) {
			t.Errorf("incorrect needle")
		}
	})

	t.Run("arm64", func(t *testing.T) {
		reg, err := RegexpPatternFromYaraPattern("{ ?? ?? ?? (90 | b0 | f0 | d0) ?? ?? ?? 91 ?? ?? ?? (14 | 17) ?? ?? 41 F9 ?? ?? ?? B4 }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		// manually translated
		if reg.rawre != `...(\x90|\xB0|\xF0|\xD0)...\x91...(\x14|\x17)..\x41\xF9...\xB4` {
			t.Errorf("incorrect pattern")
		}

		if reg.len != 20 {
			t.Errorf("incorrect reg length")
		}

		if !bytes.Equal(reg.needle, []byte{0x41, 0xF9}) {
			t.Errorf("incorrect needle")
		}

		if reg.needleOffset != 14 {
			t.Errorf("incorrect needle offset")
		}
	})

	t.Run("AllSubMatches", func(t *testing.T) {
		reg, err := RegexpPatternFromYaraPattern("{ AA [0-1] BB CC }")
		if err != nil {
			t.Errorf("pattern errored")
		}

		if !bytes.Equal(reg.needle, []byte{0xBB, 0xCC}) {
			t.Errorf("incorrect needle")
		}

		if reg.needleOffset != 2 {
			// needle offset is pessimistic, AA ?? ?? == 3, we choose the range max
			t.Errorf("incorrect needle offset")
		}

		if reg.len != 4 {
			// length is also pessimistic
			t.Errorf("incorrect pattern length")
		}

		matches := FindRegex([]byte{0xAA, 0xAA, 0xBB, 0xCC}, reg)
		if len(matches) != 2 {
			t.Errorf("Wrong sub match count")
		}

		matches2 := FindRegex([]byte{0xAA, 0xBB, 0xCC}, reg)
		if len(matches2) != 1 {
			t.Errorf("Wrong sub match count")
		}

		matches3 := FindRegex([]byte{0x00, 0x00, 0x11, 0xAA, 0xBB, 0xCC, 0xAA, 0xAA, 0xBB, 0xCC}, reg)
		if len(matches3) != 3 {
			t.Errorf("Wrong sub match count")
		}

		matches4 := FindRegex([]byte{0xFF, 0xAA, 0xFF, 0xBB, 0xCC, 0x00, 0x00, 0x11, 0xAA, 0xBB, 0xCC, 0xAA, 0xAA, 0xBB, 0xCC}, reg)
		if len(matches4) != 4 {
			t.Errorf("Wrong sub match count")
		}
	})

	t.Run("NewLineByte", func(t *testing.T) {
		// ensure ?? (dot) matches \n (0x0A)
		reg, err := RegexpPatternFromYaraPattern("{ ?? AA BB CC }")
		if err != nil {
			t.Errorf("pattern errored")
		}

		if !bytes.Equal(reg.needle, []byte{0xAA, 0xBB, 0xCC}) {
			t.Errorf("incorrect needle")
		}

		matches := FindRegex([]byte{0x0A, 0xAA, 0xBB, 0xCC, 0x0A, 0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0xCC, 0x0A}, reg)
		if len(matches) != 2 {
			t.Errorf("Wrong match count")
		}
	})

	t.Run("RangePatLength", func(t *testing.T) {
		reg, err := RegexpPatternFromYaraPattern("{ ?? [0-50] 8B [8-12] AA (AA|CC|DD) }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		if reg.len != 66 {
			t.Errorf("incorrect pattern length")
		}

		if reg.needleOffset != 51 {
			t.Errorf("incorrect needle offset")
		}

		if !bytes.Equal(reg.needle, []byte{0x8B}) {
			t.Errorf("incorrect needle")
		}
	})
}
