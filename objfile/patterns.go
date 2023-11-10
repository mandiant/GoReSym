package objfile

import (
	"errors"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
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
func RegexpPatternFromYaraPattern(pattern string) (*RegexAndNeedle, error) {

	if !strings.HasPrefix(pattern, "{") {
		return nil, errors.New("missing prefix")
	}

	if !strings.HasSuffix(pattern, "}") {
		return nil, errors.New("missing suffix")
	}

	pattern = strings.Trim(pattern, "{}")

	pattern = strings.ReplaceAll(pattern, " ", "")

	pattern = strings.ToLower(pattern)

	patLen := 0
	needle := make([]byte, 0)
	tmpNeedle := make([]byte, 0)

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
				return nil, errors.New("cannot mask the first nibble")
			}

			regex_pattern += "."

			i += 2
			patLen += 1
			if len(tmpNeedle) > len(needle) {
				needle = slices.Clone(tmpNeedle)
				tmpNeedle = make([]byte, 0)
			} else {
				tmpNeedle = make([]byte, 0)
			}
			continue
		}

		// input: [x-y]
		// output: .{x,y}
		if c == "[" {
			end := strings.Index(pattern[i:], "]")
			if end == -1 {
				return nil, errors.New("unbalanced [")
			}

			chunk := pattern[i+1 : i+end]
			low, high, found := strings.Cut(chunk, "-")
			if !found {
				return nil, errors.New("[] didn't contain a dash")
			}

			_, err := strconv.Atoi(low)
			if err != nil {
				return nil, errors.New("invalid number")
			}

			_, err = strconv.Atoi(high)
			if err != nil {
				return nil, errors.New("invalid number")
			}

			regex_pattern += "."
			regex_pattern += "{"
			regex_pattern += low
			regex_pattern += ","
			regex_pattern += high
			regex_pattern += "}"

			i += end + 1
			patLen += 1

			if len(tmpNeedle) > len(needle) {
				needle = slices.Clone(tmpNeedle)
				tmpNeedle = make([]byte, 0)
			} else {
				tmpNeedle = make([]byte, 0)
			}
			continue
		}

		// input: (AA|BB|CC)
		// output: (\xAA|\xBB|\xCC)
		if c == "(" {
			end := strings.Index(pattern[i:], ")")
			if end == -1 {
				return nil, errors.New("unbalanced (")
			}

			chunk := pattern[i+1 : i+end]
			choices := strings.Split(chunk, "|")

			regex_pattern += "("
			for j, choice := range choices {
				if !isHex(choice) {
					return nil, errors.New("choice not hex")
				}

				if j != 0 {
					regex_pattern += "|"
				}

				regex_pattern += `\x` + strings.ToUpper(choice)
			}
			regex_pattern += ")"

			i += end + 1
			patLen += len(choices)
			if len(tmpNeedle) > len(needle) {
				needle = slices.Clone(tmpNeedle)
				tmpNeedle = make([]byte, 0)
			} else {
				tmpNeedle = make([]byte, 0)
			}
			continue
		}

		// input: 0?
		// output: [\x00-\x0F]
		if d == "?" {
			if !isHex(c) {
				return nil, errors.New("not hex digit")
			}

			regex_pattern += "["
			regex_pattern += `\x` + strings.ToUpper(c) + "0"
			regex_pattern += "-"
			regex_pattern += `\x` + strings.ToUpper(c) + "F"
			regex_pattern += "]"

			i += 2
			patLen += 1
			if len(tmpNeedle) > len(needle) {
				needle = slices.Clone(tmpNeedle)
				tmpNeedle = make([]byte, 0)
			} else {
				tmpNeedle = make([]byte, 0)
			}
			continue
		}

		// input: AB
		// output: \xAB
		if isHex(c) && isHex(d) {
			regex_pattern += `\x` + strings.ToUpper(c+d)
			byt, err := strconv.ParseInt(c+d, 16, 64)
			if err != nil {
				return nil, errors.New("not hex digit")
			}
			tmpNeedle = append(tmpNeedle, byte(byt))
			i += 2
			patLen += 1
			continue
		}

		return nil, errors.New("unexpected value")
	}

	if len(tmpNeedle) > len(needle) {
		needle = slices.Clone(tmpNeedle)
		//tmpNeedle = make([]byte, 0) not needed at exit
	}

	r := binaryregexp.MustCompile(regex_pattern)
	if r == nil {
		return nil, errors.New("failed to compile regex")
	}
	return &RegexAndNeedle{patLen, regex_pattern, r, needle}, nil
}

func FindRegex(data []byte, regexInfo *RegexAndNeedle) []int {
	data_len := len(data)
	matches := make([]int, 0)

	// use an optimized memscan to find some candidates chunks from the much large haystack
	needleMatches := findAllOccurrences(data, [][]byte{regexInfo.needle})
	for _, needleMatch := range needleMatches {
		// we might have found a needle beginning at the very end of our regex
		// widen the window to regex scan from the [-regexLen:regexLen] so we scan the front too
		data_start := needleMatch - regexInfo.len
		data_end := needleMatch + regexInfo.len
		if data_start >= data_len {
			continue
		} else if data_start <= 0 {
			data_start = 0
		}

		if data_end >= data_len {
			data_end = data_len - 1
		}

		// do the full regex scan on a very small chunk
		for _, reMatch := range regexInfo.re.FindAllIndex(data[data_start:data_end], -1) {
			// the match offset is the start index of the chunk + reMatch index
			start := reMatch[0] + data_start

			//end := reMatch[1]
			matches = append(matches, start)
		}
	}
	return matches
}

type RegexAndNeedle struct {
	len    int
	rawre  string
	re     *binaryregexp.Regexp
	needle []byte // longest fixed sub-sequence of regex
}
