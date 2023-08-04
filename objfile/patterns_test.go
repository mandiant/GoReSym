package objfile

import (
	"fmt"
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

// fetch the index of the subexp for the given regexp.
//
// this is called `(*Regexp) SubexpIndex` in recent Go,
// but doesn't seem to be implemented in binaryregexp.
// https://pkg.go.dev/regexp#Regexp.SubexpIndex
func subexpIndex(re *binaryregexp.Regexp, name string) int {
	for i, n := range re.SubexpNames() {
		if n == name {
			return i
		}
	}

	return -1
}

// fetch the [start, end] pairs for the subexp with the given name in the given matches.
func subexpIndexMatches(re *binaryregexp.Regexp, matches [][]int, name string) [][]int {
	index := subexpIndex(re, name)

	var ret [][]int
	for _, match := range matches {

		start := match[2*index]
		end := match[2*index+1]

		if start == -1 && end == -1 {
			continue
		}

		ret = append(ret, []int{start, end})
	}

	fmt.Println(ret)
	return ret
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

	t.Run("two groups", func(t *testing.T) {
		re := binaryregexp.MustCompile(`((?P<xxx>a(x*)b)|(?P<yyy>c(y*)d))`)

		fmt.Printf("aa: %v\n", re)
		fmt.Printf("%q\n", re.SubexpNames())

		if subexpIndex(re, "xxx") != 2 {
			t.Errorf("xxx index")
		}

		if subexpIndex(re, "yyy") != 4 {
			t.Errorf("yyy index")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--ab--", -1), "xxx"), [][]int{{2, 4}}) {
			t.Errorf("1")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--axxb--", -1), "xxx"), [][]int{{2, 6}}) {
			t.Errorf("2")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--ab--", -1), "yyy"), [][]int{}) {
			t.Errorf("3: no matches")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--cd--", -1), "xxx"), [][]int{}) {
			t.Errorf("4: no matches")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--cd--", -1), "yyy"), [][]int{{2, 4}}) {
			t.Errorf("5")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--cyyd--", -1), "yyy"), [][]int{{2, 6}}) {
			t.Errorf("6")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--abcd--", -1), "xxx"), [][]int{{2, 4}}) {
			t.Errorf("7")
		}

		if !compare(subexpIndexMatches(re, re.FindAllStringSubmatchIndex("--abcd--", -1), "yyy"), [][]int{{4, 6}}) {
			t.Errorf("8")
		}
	})
}

func TestRegexpPatternFromYaraPattern(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := RegexpPatternFromYaraPattern(""); err == nil {
			t.Errorf("empty pattern should have errored")
		}

		p, err := RegexpPatternFromYaraPattern("{}")
		if err != nil {
			t.Errorf("empty pattern errored")
		}
		if p != "" {
			t.Errorf("incorrect empty pattern")
		}
	})

	t.Run("x64firstmoduledata", func(t *testing.T) {
		p, err := RegexpPatternFromYaraPattern("{ 48 8D 0? ?? ?? ?? ?? EB ?? 48 8? 8? ?? 02 00 00 66 0F 1F 44 00 00 }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		// manually translated
		if p != `\x48\x8D[\x00-\x0F]....\xEB.\x48[\x80-\x8F][\x80-\x8F].\x02\x00\x00\x66\x0F\x1F\x44\x00\x00` {
			t.Errorf("incorrect pattern")
		}
	})

	t.Run("x86sig", func(t *testing.T) {
		p, err := RegexpPatternFromYaraPattern("{ 8D ?? ?? ?? ?? ?? EB ?? [0-50] 8B ?? ?? 01 00 00 8B ?? ?? ?? 85 ?? 75 ?? }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		// manually translated
		if p != `\x8D.....\xEB..{0,50}\x8B..\x01\x00\x00\x8B...\x85.\x75.` {
			t.Errorf("incorrect pattern")
		}
	})

	t.Run("arm64", func(t *testing.T) {
		p, err := RegexpPatternFromYaraPattern("{ ?? ?? ?? (90 | b0 | f0 | d0) ?? ?? ?? 91 ?? ?? ?? (14 | 17) ?? ?? 41 F9 ?? ?? ?? B4 }")

		if err != nil {
			t.Errorf("pattern errored")
		}

		// manually translated
		if p != `...(\x90|\xB0|\xF0|\xD0)...\x91...(\x14|\x17)..\x41\xF9...\xB4` {
			t.Errorf("incorrect pattern")
		}
	})
}
