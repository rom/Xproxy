package ldap

import (
	"fmt"
	"strings"
)

// Distinguished names, read far enough to compare one against another.
//
// This is the LDAP analogue of an object identifier subtree, and it has the
// same trap in a sharper form. A policy that says "this client may search
// under ou=people,dc=example,dc=com" and tests it with a string suffix
// allows dc=notexample,dc=com to pass against a suffix of "example,dc=com",
// and allows "ou=peoplex,dc=example,dc=com" to pass against a prefix. So a
// name is split into its relative names and compared one at a time, from the
// right, which is the direction a directory tree is actually rooted in.
//
// What is *not* done here is full RFC 4514 normalisation, because that needs
// the schema: whether a given attribute's values are case-sensitive, which
// ones are numeric or telephone strings, which have their own equality
// rules. What is done is the part that is schema-independent and is what a
// policy is written about: the escaping, the attribute type folded to lower
// case, and the value trimmed of the insignificant space RFC 4514 allows
// around it and folded to lower case. That last one is a deliberate choice
// on the safe side of the schema: a directory whose values are
// case-sensitive would treat cn=Bob and cn=bob as different entries, and
// this comparison treats them as the same -- so a *deny* by DN cannot be
// evaded with a capital letter, and an *allow* by DN may admit a name the
// directory then says does not exist, which the directory refuses itself.

// RDN is one relative distinguished name: one or more type=value pairs,
// which a multi-valued RDN joins with a plus sign.
type RDN struct {
	// Types and Values are aligned and sorted by type, so that
	// "cn=a+ou=b" and "ou=b+cn=a" -- the same RDN written two ways --
	// compare equal.
	Types  []string
	Values []string
}

// DN is a distinguished name, most specific relative name first, which is
// the order the string form writes it in.
type DN []RDN

// ParseDN reads a distinguished name. An empty string is the root DSE, which
// is a real and important name: a subtree search from it is a request for the
// whole directory.
func ParseDN(s string) (DN, error) {
	if len(s) > MaxDNLength {
		return nil, fmt.Errorf("ldap: distinguished name of %d octets", len(s))
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return DN{}, nil
	}
	parts, err := splitUnescaped(s, ',')
	if err != nil {
		return nil, err
	}
	out := make(DN, 0, len(parts))
	for _, part := range parts {
		pairs, err := splitUnescaped(part, '+')
		if err != nil {
			return nil, err
		}
		r := RDN{}
		for _, pair := range pairs {
			t, v, err := splitPair(pair)
			if err != nil {
				return nil, err
			}
			r.Types = append(r.Types, t)
			r.Values = append(r.Values, v)
		}
		sortRDN(&r)
		out = append(out, r)
	}
	return out, nil
}

// splitPair reads one type=value, with the escaping RFC 4514 defines.
func splitPair(s string) (string, string, error) {
	i := indexUnescaped(s, '=')
	if i <= 0 {
		return "", "", fmt.Errorf("ldap: %q is not type=value in a distinguished name", s)
	}
	t := strings.ToLower(strings.TrimSpace(s[:i]))
	v, err := unescapeDNValue(s[i+1:])
	if err != nil {
		return "", "", err
	}
	return t, v, nil
}

// splitUnescaped splits on a separator that is not escaped and not inside
// quotes. The quoted form is the old one (RFC 1779) and directories still
// emit it, so a reader that did not understand it would mis-split a name
// with a comma in a value -- and mis-splitting is how a check is evaded.
func splitUnescaped(s string, sep byte) ([]string, error) {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
			if i >= len(s) {
				return nil, fmt.Errorf("ldap: distinguished name ends in an escape")
			}
		case '"':
			quoted = !quoted
		case sep:
			if !quoted {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if quoted {
		return nil, fmt.Errorf("ldap: unterminated quoted value in a distinguished name")
	}
	out = append(out, s[start:])
	return out, nil
}

func indexUnescaped(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case c:
			return i
		}
	}
	return -1
}

// unescapeDNValue resolves the escaping of RFC 4514 §3: a backslash before a
// special character, a backslash and two hex digits, and the quoted form.
// The result is folded to lower case and trimmed of the leading and trailing
// space the grammar calls insignificant.
func unescapeDNValue(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("ldap: value ends in an escape")
		}
		if h1, ok := hexDigit(s[i+1]); ok {
			if i+2 >= len(s) {
				return "", fmt.Errorf("ldap: half a hex escape in a value")
			}
			h2, ok := hexDigit(s[i+2])
			if !ok {
				return "", fmt.Errorf("ldap: half a hex escape in a value")
			}
			b.WriteByte(h1<<4 | h2)
			i += 2
			continue
		}
		b.WriteByte(s[i+1])
		i++
	}
	return strings.ToLower(strings.TrimSpace(b.String())), nil
}

func hexDigit(c byte) (byte, bool) {
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

// sortRDN orders a multi-valued RDN's pairs by type, so that one written in
// two orders compares equal. Insertion sort: an RDN with more than two pairs
// is already unusual.
func sortRDN(r *RDN) {
	for i := 1; i < len(r.Types); i++ {
		for j := i; j > 0 && r.Types[j] < r.Types[j-1]; j-- {
			r.Types[j], r.Types[j-1] = r.Types[j-1], r.Types[j]
			r.Values[j], r.Values[j-1] = r.Values[j-1], r.Values[j]
		}
	}
}

// Equal says whether two names are the same name.
func (d DN) Equal(o DN) bool {
	if len(d) != len(o) {
		return false
	}
	for i := range d {
		if !d[i].equal(o[i]) {
			return false
		}
	}
	return true
}

func (r RDN) equal(o RDN) bool {
	if len(r.Types) != len(o.Types) {
		return false
	}
	for i := range r.Types {
		if r.Types[i] != o.Types[i] || r.Values[i] != o.Values[i] {
			return false
		}
	}
	return true
}

// Under says whether this name is at or below a suffix, comparing relative
// name by relative name from the root.
//
// The empty suffix -- the root DSE -- is above everything, which is the
// right answer and also the dangerous one: a rule whose base is "" covers
// the whole directory, and that is why an empty base in a policy is
// something validation warns about rather than something this function
// second-guesses.
func (d DN) Under(suffix DN) bool {
	if len(suffix) == 0 {
		return true
	}
	if len(d) < len(suffix) {
		return false
	}
	off := len(d) - len(suffix)
	for i := range suffix {
		if !d[off+i].equal(suffix[i]) {
			return false
		}
	}
	return true
}

// Depth is how many relative names the name has, which is what a scope
// bound is measured in.
func (d DN) Depth() int { return len(d) }

// String writes the name back in the RFC 4514 form, escaped. It is the
// normalised form -- lower case, insignificant space gone -- rather than
// what arrived, so two spellings of one name log as one string.
func (d DN) String() string {
	var b strings.Builder
	for i, r := range d {
		if i > 0 {
			b.WriteByte(',')
		}
		for j := range r.Types {
			if j > 0 {
				b.WriteByte('+')
			}
			b.WriteString(r.Types[j])
			b.WriteByte('=')
			b.WriteString(escapeValue(r.Values[j]))
		}
	}
	return b.String()
}

// escapeValue writes a value back with the escaping RFC 4514 requires.
func escapeValue(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '"' || c == '+' || c == ',' || c == ';' || c == '<' ||
			c == '>' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == ' ' && (i == 0 || i == len(v)-1):
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '#' && i == 0:
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			b.WriteString(fmt.Sprintf("\\%02x", c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
