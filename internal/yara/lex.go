// Package yara reads YARA rules and applies them to a stream.
//
// It implements a subset of the language, in Go, with no libyara and no
// cgo: this proxy builds with CGO_ENABLED=0 and links no C library into
// the data plane, which is a property worth more here than the last few
// features of the grammar. What is supported is stated in Limits, and
// anything outside it is refused at load rather than ignored — a rule
// that silently matched nothing would be worse than one that would not
// load.
//
// The other difference from a file scanner is that the input is a
// stream. Rules are evaluated as the bytes go past, over a sliding
// window with an overlap wide enough for the longest pattern, so a
// match that straddles two reads is still a match. filesize means the
// bytes seen so far, because in a stream there is no other honest
// answer.
package yara

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

// tokenKind is what the lexer produces.
type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString     // "text"
	tokRegex      // /pattern/flags
	tokHex        // { 4D 5A ?? }
	tokNumber     // 123, 0x10, 4KB
	tokIdentifier // $a, #a, @a, !a
	tokPunct      // { } ( ) : = , . and the operators
)

type token struct {
	kind tokenKind
	text string
	num  int64
	line int
}

type lexer struct {
	src  string
	pos  int
	line int
}

func newLexer(src string) *lexer { return &lexer{src: src, line: 1} }

func (l *lexer) errf(format string, args ...any) error {
	return fmt.Errorf("line %d: "+format, append([]any{l.line}, args...)...)
}

// next returns the next token.
func (l *lexer) next() (token, error) {
	if err := l.skipSpace(); err != nil {
		return token{}, err
	}
	if l.pos >= len(l.src) {
		return token{kind: tokEOF, line: l.line}, nil
	}
	c := l.src[l.pos]
	switch {
	case c == '"':
		return l.lexString()
	case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] != '/' && l.src[l.pos+1] != '*':
		return l.lexRegex()
	case c == '{':
		// A brace begins a rule body or a hex string; only the parser
		// knows which, so it asks for a hex string explicitly.
		l.pos++
		return token{kind: tokPunct, text: "{", line: l.line}, nil
	case c == '$' || c == '#' || c == '@' ||
		// "!" is the sigil of YARA's string-length operator, !a, which
		// this package refuses in a condition. It is also the first
		// byte of "!=", and taking it as a sigil here made that
		// operator unreachable: "#a != 0" lexed as the identifier "!"
		// followed by "= 0" and never got as far as the comparison the
		// parser and compare() both already supported.
		(c == '!' && !strings.HasPrefix(l.src[l.pos:], "!=")):
		return l.lexIdentifier()
	case isDigit(c):
		return l.lexNumber()
	case isIdentStart(c):
		return l.lexIdent()
	default:
		return l.lexPunct()
	}
}

func (l *lexer) skipSpace() error {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				return l.errf("unterminated comment")
			}
			l.line += strings.Count(l.src[l.pos:l.pos+2+end+2], "\n")
			l.pos += 2 + end + 2
		default:
			return nil
		}
	}
	return nil
}

func (l *lexer) lexString() (token, error) {
	start := l.line
	l.pos++ // the quote
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case '"':
			l.pos++
			return token{kind: tokString, text: b.String(), line: start}, nil
		case '\n':
			return token{}, l.errf("unterminated string")
		case '\\':
			l.pos++
			if l.pos >= len(l.src) {
				return token{}, l.errf("unterminated escape")
			}
			switch e := l.src[l.pos]; e {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\', '"':
				b.WriteByte(e)
			case 'x':
				if l.pos+2 >= len(l.src) {
					return token{}, l.errf("truncated \\x escape")
				}
				hi, ok1 := hexVal(l.src[l.pos+1])
				lo, ok2 := hexVal(l.src[l.pos+2])
				if !ok1 || !ok2 {
					return token{}, l.errf("bad \\x escape")
				}
				b.WriteByte(hi<<4 | lo)
				l.pos += 2
			default:
				return token{}, l.errf("unknown escape \\%c", e)
			}
			l.pos++
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return token{}, l.errf("unterminated string")
}

func (l *lexer) lexRegex() (token, error) {
	start := l.line
	l.pos++ // the slash
	var b strings.Builder
	escaped := false
	inClass := false
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			return token{}, l.errf("unterminated regular expression")
		case escaped:
			b.WriteByte(c)
			escaped = false
		case c == '\\':
			b.WriteByte(c)
			escaped = true
		case c == '[':
			inClass = true
			b.WriteByte(c)
		case c == ']':
			inClass = false
			b.WriteByte(c)
		case c == '/' && !inClass:
			l.pos++
			// The flags follow the closing slash.
			flags := ""
			for l.pos < len(l.src) && (l.src[l.pos] == 'i' || l.src[l.pos] == 's') {
				flags += string(l.src[l.pos])
				l.pos++
			}
			return token{kind: tokRegex, text: b.String() + "\x00" + flags, line: start}, nil
		default:
			b.WriteByte(c)
		}
		l.pos++
	}
	return token{}, l.errf("unterminated regular expression")
}

func (l *lexer) lexIdentifier() (token, error) {
	start := l.pos
	l.pos++ // the sigil
	for l.pos < len(l.src) && (isIdentPart(l.src[l.pos]) || l.src[l.pos] == '*') {
		l.pos++
	}
	return token{kind: tokIdentifier, text: l.src[start:l.pos], line: l.line}, nil
}

func (l *lexer) lexNumber() (token, error) {
	start := l.pos
	if strings.HasPrefix(l.src[l.pos:], "0x") || strings.HasPrefix(l.src[l.pos:], "0X") {
		l.pos += 2
		for l.pos < len(l.src) && isHex(l.src[l.pos]) {
			l.pos++
		}
	} else {
		for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.pos++
		}
	}
	text := l.src[start:l.pos]
	mult := int64(1)
	unit := ""
	// Only the two bytes after the digits can be a size suffix. This
	// read the rest of the file and upper-cased it, three times, for
	// every number in it.
	two := ""
	if l.pos+2 <= len(l.src) {
		two = strings.ToUpper(l.src[l.pos : l.pos+2])
	}
	for _, suffix := range []struct {
		s string
		m int64
	}{{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}} {
		if two == suffix.s {
			mult, unit = suffix.m, l.src[l.pos:l.pos+2]
			l.pos += 2
			break
		}
	}
	n, err := parseInt(text)
	if err != nil {
		return token{}, l.errf("%q is not a number: %v", text, err)
	}
	if n > math.MaxInt64/mult {
		// The suffix overflows where the digits did not, and a size
		// bound that wrapped is one no stream is ever on the wrong side
		// of. Refuse it here rather than hand the parser a negative.
		return token{}, l.errf("%s%s does not fit in a 64-bit integer", text, unit)
	}
	return token{kind: tokNumber, text: text, num: n * mult, line: l.line}, nil
}

func (l *lexer) lexIdent() (token, error) {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	return token{kind: tokIdent, text: l.src[start:l.pos], line: l.line}, nil
}

func (l *lexer) lexPunct() (token, error) {
	two := ""
	if l.pos+1 < len(l.src) {
		two = l.src[l.pos : l.pos+2]
	}
	switch two {
	case "==", "!=", "<=", ">=":
		l.pos += 2
		return token{kind: tokPunct, text: two, line: l.line}, nil
	}
	c := l.src[l.pos]
	if !strings.ContainsRune("}():=,.<>*-+", rune(c)) {
		return token{}, l.errf("unexpected character %q", string(c))
	}
	l.pos++
	return token{kind: tokPunct, text: string(c), line: l.line}, nil
}

// hexString reads a { ... } hex pattern; the opening brace is already
// consumed.
func (l *lexer) hexString() (string, error) {
	start := l.pos
	depth := 1
	for l.pos < len(l.src) {
		switch l.src[l.pos] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				text := l.src[start:l.pos]
				l.pos++
				return text, nil
			}
		case '\n':
			l.line++
		}
		l.pos++
	}
	return "", l.errf("unterminated hex string")
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isHex(c byte) bool        { _, ok := hexVal(c); return ok }
func isIdentStart(c byte) bool { return c == '_' || unicode.IsLetter(rune(c)) }
func isIdentPart(c byte) bool  { return isIdentStart(c) || isDigit(c) }

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func parseInt(s string) (int64, error) {
	digits, base := s, int64(10)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		digits, base = s[2:], 16
	}
	if digits == "" {
		// "0x" with no digits after it read as zero, so "filesize < 0x"
		// compiled into a bound no stream is ever under: a rule that can
		// never fire and never says so. A typo in a rule file deserves a
		// refusal at load, which is where this package puts everything
		// else it cannot honour.
		return 0, fmt.Errorf("%q has no digits", s)
	}
	var n int64
	for _, c := range []byte(digits) {
		v, ok := hexVal(c)
		if !ok || int64(v) >= base {
			if base == 16 {
				return 0, fmt.Errorf("bad hex digit %q", string(c))
			}
			return 0, fmt.Errorf("bad digit %q", string(c))
		}
		if n > (math.MaxInt64-int64(v))/base {
			// The same fault from the other end: a literal past the top
			// of int64 wrapped to a negative count, and "#a > <that>" is
			// then true for every stream while "filesize < <that>" is
			// true for none. Neither is what the rule says.
			return 0, fmt.Errorf("%q does not fit in a 64-bit integer", s)
		}
		n = n*base + int64(v)
	}
	return n, nil
}
