package ldap

import (
	"errors"
	"fmt"
	"strings"
)

// Filter context tags (RFC 4511 §4.5.1).
const (
	filterAnd     = 0
	filterOr      = 1
	filterNot     = 2
	filterEqual   = 3
	filterPresent = 7
)

// ParseFilter parses an RFC 4515 filter string into a BER packet. It
// supports the &, | and ! operators, equality (attr=value), presence
// (attr=*) and substring (attr=a*b*c) items — the forms directory
// authentication filters use. Values may carry \HH byte escapes.
func ParseFilter(s string) (*packet, error) {
	p := &filterParser{s: s}
	f, err := p.parseFilter()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("ldap: trailing characters in filter %q", s)
	}
	return f, nil
}

// maxFilterDepth bounds how deeply a filter string may nest. The parser
// is recursive, and the BER decoder refuses anything deeper than maxDepth
// anyway, so a filter nested further could never be encoded and read back.
// Without the bound the recursion meets the goroutine stack limit instead
// of an error, and the filter is parsed once per login attempt: a template
// somebody pasted in would take the proxy down at the next login rather
// than fail validation.
const maxFilterDepth = maxDepth

type filterParser struct {
	s     string
	pos   int
	depth int
}

func (p *filterParser) parseFilter() (*packet, error) {
	if p.depth >= maxFilterDepth {
		return nil, fmt.Errorf("ldap: filter nested deeper than %d", maxFilterDepth)
	}
	p.depth++
	defer func() { p.depth-- }()
	if p.pos >= len(p.s) || p.s[p.pos] != '(' {
		return nil, errors.New("ldap: filter must start with (")
	}
	p.pos++ // consume (
	if p.pos >= len(p.s) {
		return nil, errors.New("ldap: truncated filter")
	}
	var f *packet
	var err error
	switch p.s[p.pos] {
	case '&':
		f, err = p.parseSet(filterAnd)
	case '|':
		f, err = p.parseSet(filterOr)
	case '!':
		p.pos++
		sub, e := p.parseFilter()
		if e != nil {
			return nil, e
		}
		f = node(classContext, filterNot, sub)
	default:
		f, err = p.parseItem()
	}
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.s) || p.s[p.pos] != ')' {
		return nil, errors.New("ldap: filter missing )")
	}
	p.pos++ // consume )
	return f, nil
}

func (p *filterParser) parseSet(tag byte) (*packet, error) {
	p.pos++ // consume &, | or !
	set := node(classContext, tag)
	for p.pos < len(p.s) && p.s[p.pos] == '(' {
		sub, err := p.parseFilter()
		if err != nil {
			return nil, err
		}
		set.add(sub)
	}
	if len(set.kids) == 0 {
		return nil, errors.New("ldap: empty filter list")
	}
	return set, nil
}

// parseItem parses attr=value up to the closing paren (which the caller
// consumes).
func (p *filterParser) parseItem() (*packet, error) {
	end := strings.IndexByte(p.s[p.pos:], ')')
	if end < 0 {
		return nil, errors.New("ldap: item missing )")
	}
	item := p.s[p.pos : p.pos+end]
	p.pos += end
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return nil, fmt.Errorf("ldap: bad filter item %q", item)
	}
	attr := item[:eq]
	if !attributeOK(attr) {
		return nil, fmt.Errorf("ldap: bad attribute %q", attr)
	}
	value := item[eq+1:]
	if value == "*" {
		return leaf(classContext, filterPresent, []byte(attr)), nil
	}
	if strings.Contains(value, "*") {
		return nil, errors.New("ldap: substring filters are not supported")
	}
	raw, err := unescapeValue(value)
	if err != nil {
		return nil, err
	}
	return node(classContext, filterEqual, str(attr), str(raw)), nil
}

// attributeOK reports whether s is a plausible attribute description.
func attributeOK(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == ';':
		default:
			return false
		}
	}
	return true
}

// unescapeValue turns the \HH escapes of a filter assertion value back into
// raw bytes.
func unescapeValue(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("ldap: truncated \\ escape")
		}
		hi, ok1 := hexVal(s[i+1])
		lo, ok2 := hexVal(s[i+2])
		if !ok1 || !ok2 {
			return "", errors.New("ldap: bad \\ escape")
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

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

// EscapeFilter escapes a value for safe substitution into a filter string
// (RFC 4515 §3): the bytes NUL, *, (, ) and \ become \HH.
func EscapeFilter(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case 0x00, '*', '(', ')', '\\':
			b.WriteString(fmt.Sprintf("\\%02x", c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// EscapeDN escapes a value for safe substitution into a distinguished name
// (RFC 4514 §2.4): the leading/trailing space and #, and the set ,+"\<>;.
func EscapeDN(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == 0x00:
			b.WriteString("\\00")
		case (c == ' ' || c == '#') && i == 0:
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == ' ' && i == len(s)-1:
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
