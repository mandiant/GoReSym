package objfile

import (
	"errors"
	"strconv"
	"strings"

	"rsc.io/binaryregexp"
)

func contains(s []rune, c rune) bool {
	for _, v := range s {
		if v == c {
			return true
		}
	}

	return false
}

func isHexRune(c rune) bool {
	return contains([]rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}, c)
}

func isHex(s string) bool {
	for _, c := range s {
		if !isHexRune(c) {
			return false
		}
	}
	return true
}

// translate from a yara-style pattern, like:
//
//	{ 48 8D 0? ?? ?? ?? ?? EB ?? 48 8? 8? ?? 02 00 00 66 0F 1F 44 00 00 }
//
// to a regular expression string compatible with the binaryregexp module, like:
//
//	\x48\x8D[\x00-\x0F]....\xEB.\x48[\x80-\x8F][\x80-\x8F].\x02\x00\x00\x66\x0F\x1F\x44\x00\x00
//
// although this requires more code, we provide this functionality
// because these patterns are *much* more readable than raw regular expressions,
// we strongly value people being able to understand GoReSym's algorithm.
func RegexpPatternFromYaraPattern(pattern string) (string, error) {

	if !strings.HasPrefix(pattern, "{") {
		return "", errors.New("missing prefix")
	}

	if !strings.HasSuffix(pattern, "}") {
		return "", errors.New("missing suffix")
	}

	pattern = strings.Trim(pattern, "{}")

	pattern = strings.ReplaceAll(pattern, " ", "")

	pattern = strings.ToLower(pattern)

	var regex_pattern string
	for i := 0; i < len(pattern); {
		// at the start of this loop,
		// i will be aligned to the start of a nibble (or [] range),
		// so both i and i+1 will be valid.

		c := pattern[i : i+1]
		d := pattern[i+1 : i+2]

		// input: ??
		// output: .
		if c == "?" {
			if d != "?" {
				return "", errors.New("cannot mask the first nibble")
			}

			regex_pattern += "."

			i += 2
			continue
		}

		// input: [x-y]
		// output: .{x,y}
		if c == "[" {
			end := strings.Index(pattern[i:], "]")
			if end == -1 {
				return "", errors.New("unbalanced [")
			}

			chunk := pattern[i+1 : i+end]
			low, high, found := strings.Cut(chunk, "-")
			if !found {
				return "", errors.New("[] didn't contain a dash")
			}

			_, err := strconv.Atoi(low)
			if err != nil {
				return "", errors.New("invalid number")
			}

			_, err = strconv.Atoi(high)
			if err != nil {
				return "", errors.New("invalid number")
			}

			regex_pattern += "."
			regex_pattern += "{"
			regex_pattern += low
			regex_pattern += ","
			regex_pattern += high
			regex_pattern += "}"

			i += end + 1
			continue
		}

		// input: (AA|BB|CC)
		// output: (\xAA|\xBB|\xCC)
		if c == "(" {
			end := strings.Index(pattern[i:], ")")
			if end == -1 {
				return "", errors.New("unbalanced (")
			}

			chunk := pattern[i+1 : i+end]
			choices := strings.Split(chunk, "|")

			regex_pattern += "("
			for j, choice := range choices {
				if !isHex(choice) {
					return "", errors.New("choice not hex")
				}

				if j != 0 {
					regex_pattern += "|"
				}

				regex_pattern += `\x` + strings.ToUpper(choice)
			}
			regex_pattern += ")"

			i += end + 1
			continue
		}

		// input: 0?
		// output: [\x00-\x0F]
		if d == "?" {
			if !isHex(c) {
				return "", errors.New("not hex digit")
			}

			regex_pattern += "["
			regex_pattern += `\x` + strings.ToUpper(c) + "0"
			regex_pattern += "-"
			regex_pattern += `\x` + strings.ToUpper(c) + "F"
			regex_pattern += "]"

			i += 2
			continue
		}

		// input: AB
		// output: \xAB
		if isHex(c) && isHex(d) {
			regex_pattern += `\x` + strings.ToUpper(c+d)

			i += 2
			continue
		}

		return "", errors.New("unexpected value")
	}

	return regex_pattern, nil
}

func RegexpFromYaraPattern(pattern string) (*binaryregexp.Regexp, error) {
	regex_pattern, e := RegexpPatternFromYaraPattern(pattern)
	if e != nil {
		return nil, e
	}

	r := binaryregexp.MustCompile(regex_pattern)
	if r == nil {
		return nil, errors.New("failed to compile regex")
	}

	return r, nil
}

type BinaryRegexpGroup struct {
	patterns map[string]string

	re *binaryregexp.Regexp
}

func NewBinaryRegexpGroup(patterns map[string]string) (*BinaryRegexpGroup, error) {

	var pattern string

	i := 0
	pattern += "("
	for k, v := range patterns {
		if i != 0 {
			pattern += "|"
		}
		i += 1

		pattern += "(?P"
		pattern += "<" + k + ">"
		pattern += v
		pattern += ")"
	}
	pattern += ")"

	re := binaryregexp.MustCompile(pattern)
	if re == nil {
		return nil, errors.New("failed to compile regex")
	}

	return &BinaryRegexpGroup{
		patterns: patterns,
		re:       re,
	}, nil
}

type BinaryRegexGroupMatches struct {
	g       *BinaryRegexpGroup
	matches [][]int
}

func (g *BinaryRegexpGroup) FindAllIndex(buf []byte, n int) *BinaryRegexGroupMatches {
	matches := g.re.FindAllIndex(buf, n)

	return &BinaryRegexGroupMatches{
		g:       g,
		matches: matches,
	}
}

// fetch the index of the subexp for the given regexp.
//
// this is called `(*Regexp) SubexpIndex` in recent Go,
// but doesn't seem to be implemented in binaryregexp.
// https://pkg.go.dev/regexp#Regexp.SubexpIndex
func SubexpIndex(re *binaryregexp.Regexp, name string) int {
	for i, n := range re.SubexpNames() {
		if n == name {
			return i
		}
	}

	return -1
}

// fetch the [start, end] pairs for the subexp with the given name in the given matches.
func SubexpIndexMatches(re *binaryregexp.Regexp, matches [][]int, name string) [][]int {
	index := SubexpIndex(re, name)

	var ret [][]int
	for _, match := range matches {

		start := match[2*index]
		end := match[2*index+1]

		if start == -1 && end == -1 {
			continue
		}

		ret = append(ret, []int{start, end})
	}

	return ret
}

// fetch the [start, end] pairs for the subexp with the given name.
func (m *BinaryRegexGroupMatches) MatchesForSubexp(name string) [][]int {
	return SubexpIndexMatches(m.g.re, m.matches, name)
}
