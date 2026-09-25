package ldap

import (
	"fmt"
	"strings"
)

// Reading a search filter off the wire, as a shape rather than as a query.
//
// A filter is the one part of an LDAP request whose *size* is chosen by the
// client and whose cost is paid by the directory. `(|(cn=*a*)(cn=*b*)...)`
// with a hundred terms, each a substring with a leading wildcard, is a
// hundred full scans of a directory that cannot use an index for any of
// them -- a request of two hundred octets that can occupy a server for
// minutes. So what this reads is what a bound can be set on: how deep it
// nests, how many terms it has, which attributes it names, and whether any
// term is a substring that no index can serve.
//
// What it does not read is the assertion values. What a client is looking
// *for* is the estate's business; what it is looking *in*, and how hard the
// looking is, is the relay's.

// The remaining filter context tags of RFC 4511 §4.5.1, beside the four the
// client's own filter writer uses.
const (
	filterSubstrings = 4
	filterGE         = 5
	filterLE         = 6
	filterApprox     = 8
	filterExtensible = 9
)

// Filter is a search filter's shape.
type Filter struct {
	// Depth is how many levels of and/or/not the filter nests.
	Depth int
	// Terms is how many assertions it contains, counting each item in an
	// and or an or.
	Terms int
	// Attributes are the attribute descriptions the filter names, lower
	// cased, in first-seen order and without repeats. These are what an
	// attribute policy is about: a filter that tests userPassword is
	// testing a password, one character at a time if it is allowed to.
	Attributes []string
	// Present counts presence assertions -- `(objectClass=*)` and its
	// relatives -- which are how a directory is enumerated rather than
	// queried.
	Present int
	// Substrings counts substring assertions, and LeadingWildcard those
	// whose first component is a wildcard: `(cn=*smith)` cannot use an
	// index and is a scan of the subtree.
	Substrings      int
	LeadingWildcard int
	// Extensible counts extensible match assertions, which name a matching
	// rule by OID and can carry the dnAttributes flag. Active Directory's
	// bit-and and bit-or rules are extensible matches, and
	// `(userAccountControl:1.2.840.113556.1.4.803:=2)` is how a
	// disabled-account list is built.
	Extensible int
	// Approx counts approximate matches, which almost no directory
	// implements and which therefore usually mean a client is confused.
	Approx int
}

// ReadFilter reads a filter's shape from its BER encoding.
func ReadFilter(p *packet) (*Filter, error) {
	f := &Filter{}
	seen := map[string]bool{}
	if err := f.read(p, 1, seen); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Filter) read(p *packet, depth int, seen map[string]bool) error {
	if depth > MaxFilterDepth {
		return fmt.Errorf("%w: filter nested deeper than %d", ErrCount, MaxFilterDepth)
	}
	if depth > f.Depth {
		f.Depth = depth
	}
	if f.Terms > MaxFilterTerms {
		return fmt.Errorf("%w: more than %d filter terms", ErrCount, MaxFilterTerms)
	}
	if p.class != classContext {
		return fmt.Errorf("%w: a filter item is a context tag, not %#02x", ErrShape, p.class)
	}
	switch p.tag {
	case filterAnd, filterOr:
		if len(p.kids) == 0 {
			// An empty and is "true" and an empty or is "false" in the
			// grammar, and a directory that evaluated either would be
			// answering a filter nobody wrote. Refusing is the reading
			// this relay will defend.
			return fmt.Errorf("%w: an empty and/or filter", ErrShape)
		}
		for _, kid := range p.kids {
			if err := f.read(kid, depth+1, seen); err != nil {
				return err
			}
		}
	case filterNot:
		if len(p.kids) != 1 {
			return fmt.Errorf("%w: a not filter with %d items", ErrShape, len(p.kids))
		}
		return f.read(p.kids[0], depth+1, seen)
	case filterEqual, filterGE, filterLE, filterApprox:
		f.Terms++
		if len(p.kids) != 2 {
			return fmt.Errorf("%w: an assertion with %d fields", ErrShape, len(p.kids))
		}
		f.note(string(p.kids[0].data), seen)
		if p.tag == filterApprox {
			f.Approx++
		}
	case filterPresent:
		f.Terms++
		f.Present++
		// The present item is a bare attribute description, not a
		// sequence: a leaf whose data is the name. A present item with no
		// name is `(=*)`, which is not a filter -- and a reader that let it
		// through would hand the directory an assertion about nothing.
		if p.cons || len(p.data) == 0 {
			return fmt.Errorf("%w: a presence filter with no attribute", ErrShape)
		}
		f.note(string(p.data), seen)
	case filterSubstrings:
		f.Terms++
		f.Substrings++
		if len(p.kids) != 2 {
			return fmt.Errorf("%w: a substring filter with %d fields", ErrShape, len(p.kids))
		}
		f.note(string(p.kids[0].data), seen)
		// The second field is a sequence of initial [0], any [1] and final
		// [2] parts. A filter whose first part is not `initial` begins with
		// a wildcard, which is the shape no index can serve: `(cn=*smith)`
		// is a scan of the subtree however narrow the base is.
		parts := p.kids[1].kids
		if len(parts) == 0 {
			return fmt.Errorf("%w: a substring filter with no parts", ErrShape)
		}
		if first := parts[0]; first.class != classContext || first.tag != 0 {
			f.LeadingWildcard++
		}
	case filterExtensible:
		f.Terms++
		f.Extensible++
		// matchingRule [1], type [2], matchValue [3], dnAttributes [4].
		for _, kid := range p.kids {
			if kid.class == classContext && kid.tag == 2 {
				f.note(string(kid.data), seen)
			}
		}
	default:
		return fmt.Errorf("%w: filter item %#02x", ErrShape, p.tag)
	}
	return nil
}

// note records an attribute the filter names, once.
func (f *Filter) note(attr string, seen map[string]bool) {
	// An attribute description may carry options after a semicolon --
	// `userCertificate;binary` -- and a policy is written about the
	// attribute rather than the transfer encoding.
	name := strings.ToLower(strings.TrimSpace(attr))
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}
	if name == "" || seen[name] {
		return
	}
	seen[name] = true
	f.Attributes = append(f.Attributes, name)
}
