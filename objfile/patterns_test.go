package objfile

import (
	"testing"
)

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
