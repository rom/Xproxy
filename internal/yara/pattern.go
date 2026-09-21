package yara

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Pattern is one string of a rule: a literal, a hex pattern or a
// regular expression, with the modifiers that decide how it is looked
// for.
type Pattern struct {
	Name    string // "$a"
	Private bool
	// literals are the byte sequences any of which counts as a match:
	// the text itself, its wide (UTF-16LE) form, and the case folded
	// variants when nocase is set.
	literals [][]byte
	nocase   bool
	fullword bool
	// hex is the token sequence of a { } pattern.
	hex []hexToken
	// re is a compiled regular expression.
	re *regexp.Regexp
	// width is the longest run of bytes this pattern can match, which
	// is what decides the overlap a stream needs between windows.
	width int
}

// hexToken is one element of a hex pattern.
type hexToken struct {
	// kind: 'b' an exact byte, 'm' a byte under a mask (?? or 4?),
	// 'j' a jump of lo..hi bytes.
	kind   byte
	value  byte
	mask   byte
	lo, hi int
}

// parseHex reads the body of a { } pattern.
func parseHex(body string) ([]hexToken, error) {
	var out []hexToken
	f := strings.Fields(strings.NewReplacer("[", " [ ", "]", " ] ", "-", " - ", "(", " ( ", ")", " ) ", "|", " | ").Replace(body))
	for i := 0; i < len(f); i++ {
		tok := f[i]
		switch {
		case tok == "[":
			// A jump: [n], [n-m] or [n-].
			var nums []string
			for i++; i < len(f) && f[i] != "]"; i++ {
				if f[i] != "-" {
					nums = append(nums, f[i])
				} else {
					nums = append(nums, "-")
				}
			}
			if i >= len(f) {
				return nil, errors.New("unterminated jump")
			}
			j, err := parseJump(nums)
			if err != nil {
				return nil, err
			}
			out = append(out, j)
		case tok == "(" || tok == ")" || tok == "|":
			return nil, errors.New("alternation in a hex string is not supported; write the alternatives as separate strings")
		case len(tok) == 2:
			hi, ok1 := hexVal(tok[0])
			lo, ok2 := hexVal(tok[1])
			switch {
			case tok == "??":
				out = append(out, hexToken{kind: 'm', value: 0, mask: 0})
			case ok1 && tok[1] == '?':
				out = append(out, hexToken{kind: 'm', value: hi << 4, mask: 0xf0})
			case tok[0] == '?' && ok2:
				out = append(out, hexToken{kind: 'm', value: lo, mask: 0x0f})
			case ok1 && ok2:
				out = append(out, hexToken{kind: 'b', value: hi<<4 | lo})
			default:
				return nil, fmt.Errorf("%q is not a hex byte", tok)
			}
		default:
			return nil, fmt.Errorf("%q is not a hex byte", tok)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty hex string")
	}
	if out[0].kind == 'j' || out[len(out)-1].kind == 'j' {
		return nil, errors.New("a hex string may not begin or end with a jump")
	}
	return out, nil
}

func parseJump(nums []string) (hexToken, error) {
	j := hexToken{kind: 'j'}
	switch {
	case len(nums) == 1:
		n, err := parseInt(nums[0])
		if err != nil {
			return j, fmt.Errorf("jump: %w", err)
		}
		j.lo, j.hi = int(n), int(n)
	case len(nums) == 3 && nums[1] == "-":
		lo, err := parseInt(nums[0])
		if err != nil {
			return j, fmt.Errorf("jump: %w", err)
		}
		hi, err := parseInt(nums[2])
		if err != nil {
			return j, fmt.Errorf("jump: %w", err)
		}
		j.lo, j.hi = int(lo), int(hi)
	case len(nums) == 2 && nums[1] == "-":
		return j, errors.New("an unbounded jump is not supported in a stream: it has no width, so there is no overlap that would make a straddling match reliable")
	default:
		return j, errors.New("a jump is [n] or [n-m]")
	}
	if j.lo < 0 || j.hi < j.lo {
		return j, errors.New("jump bounds are out of order")
	}
	if j.hi > 4096 {
		return j, errors.New("a jump of more than 4096 bytes is refused: the window it would need is not a window")
	}
	return j, nil
}

// hexWidth is the longest run a hex pattern can match.
func hexWidth(toks []hexToken) int {
	n := 0
	for _, t := range toks {
		if t.kind == 'j' {
			n += t.hi
			continue
		}
		n++
	}
	return n
}

// matchHexAt reports whether the pattern matches starting at i.
func matchHexAt(toks []hexToken, b []byte, i int) bool {
	return hexStep(toks, 0, b, i)
}

func hexStep(toks []hexToken, ti int, b []byte, i int) bool {
	for ti < len(toks) {
		t := toks[ti]
		switch t.kind {
		case 'b':
			if i >= len(b) || b[i] != t.value {
				return false
			}
			i++
		case 'm':
			if i >= len(b) || b[i]&t.mask != t.value {
				return false
			}
			i++
		case 'j':
			for n := t.lo; n <= t.hi; n++ {
				if i+n > len(b) {
					break
				}
				if hexStep(toks, ti+1, b, i+n) {
					return true
				}
			}
			return false
		}
		ti++
	}
	return true
}

// compilePattern builds a pattern from its parsed pieces.
func compilePattern(name string, kind tokenKind, text string, mods map[string]bool) (*Pattern, error) {
	p := &Pattern{Name: name, nocase: mods["nocase"], fullword: mods["fullword"], Private: mods["private"]}
	switch kind {
	case tokString:
		ascii := !mods["wide"] || mods["ascii"]
		var forms [][]byte
		if ascii {
			forms = append(forms, []byte(text))
		}
		if mods["wide"] {
			forms = append(forms, wide([]byte(text)))
		}
		if len(forms) == 0 {
			forms = append(forms, []byte(text))
		}
		for _, f := range forms {
			if len(f) == 0 {
				return nil, errors.New("empty string")
			}
			p.literals = append(p.literals, f)
			if len(f) > p.width {
				p.width = len(f)
			}
		}
	case tokHex:
		toks, err := parseHex(text)
		if err != nil {
			return nil, err
		}
		p.hex = toks
		p.width = hexWidth(toks)
	case tokRegex:
		body, flags, _ := strings.Cut(text, "\x00")
		prefix := "(?s)"
		if strings.Contains(flags, "i") || mods["nocase"] {
			prefix = "(?is)"
		}
		re, err := regexp.Compile(prefix + body)
		if err != nil {
			return nil, fmt.Errorf("regular expression: %w", err)
		}
		re.Longest()
		p.re = re
		// A regular expression has no fixed width. The window bound
		// from the configuration is what limits it, and the scanner
		// uses that as the overlap.
		p.width = 0
	default:
		return nil, errors.New("unknown string kind")
	}
	return p, nil
}

// wide is the UTF-16LE form of ASCII text, which is what "wide" means
// in a rule.
func wide(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c, 0)
	}
	return out
}

// count returns how many times the pattern occurs in b, and whether it
// occurs at all. Overlapping occurrences are counted once per starting
// offset, as YARA does.
func (p *Pattern) count(b []byte) int {
	switch {
	case p.re != nil:
		n := 0
		for _, m := range p.re.FindAllIndex(b, -1) {
			if p.wordOK(b, m[0], m[1]) {
				n++
			}
		}
		return n
	case p.hex != nil:
		n := 0
		for i := 0; i < len(b); i++ {
			if matchHexAt(p.hex, b, i) {
				n++
			}
		}
		return n
	default:
		n := 0
		for _, lit := range p.literals {
			n += p.countLiteral(b, lit)
		}
		return n
	}
}

func (p *Pattern) countLiteral(b, lit []byte) int {
	n, from := 0, 0
	for from <= len(b)-len(lit) {
		var at int
		if p.nocase {
			at = indexFold(b[from:], lit)
		} else {
			at = bytes.Index(b[from:], lit)
		}
		if at < 0 {
			return n
		}
		start := from + at
		if p.wordOK(b, start, start+len(lit)) {
			n++
		}
		from = start + 1
	}
	return n
}

// indexFold is a case insensitive byte search. It folds ASCII only,
// which is what nocase means for a byte pattern.
func indexFold(b, lit []byte) int {
	if len(lit) == 0 || len(b) < len(lit) {
		return -1
	}
	first := lower(lit[0])
	for i := 0; i+len(lit) <= len(b); i++ {
		if lower(b[i]) != first {
			continue
		}
		ok := true
		for j := 1; j < len(lit); j++ {
			if lower(b[i+j]) != lower(lit[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// wordOK applies the fullword modifier: the match must not be flanked
// by an alphanumeric byte or an underscore.
func (p *Pattern) wordOK(b []byte, start, end int) bool {
	if !p.fullword {
		return true
	}
	if start > 0 && isWordByte(b[start-1]) {
		return false
	}
	if end < len(b) && isWordByte(b[end]) {
		return false
	}
	return true
}

func isWordByte(c byte) bool {
	return c == '_' || unicode.IsLetter(rune(c)) || isDigit(c)
}
