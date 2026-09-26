package intel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// STIX 2.1 and MISP, read as indicators.
//
// Both are JSON, both carry far more than this proxy can act on, and both are
// read here for exactly the parts it can: an address, a name, a URL, a digest.
// Everything else in a bundle -- the attack patterns, the campaigns, the
// relationships, the kill-chain phases -- is intelligence for a human or for a
// system that correlates. A proxy either refuses a request or does not, so what
// it needs from a feed is the handful of values it can compare against traffic.
//
// Two rules the parsing holds to:
//
//   - **An object it does not understand is skipped, not an error.** A bundle is
//     written by somebody else, the standard grows, and a feed that stopped
//     loading because it gained an object type would be a feed that fails on the
//     day its publisher improves it. What *is* an error is a document that is
//     not the format at all, and a document that yields no indicators -- because
//     a list that silently matches nothing is the failure this package exists to
//     refuse.
//   - **A pattern this cannot read exactly is skipped rather than approximated.**
//     STIX patterning is a language with AND, OR, NOT, sets, regular-expression
//     matches and observation operators. Guessing at an expression would produce
//     an entry that matches something nobody named -- so only the shapes below
//     are taken, and the rest are counted and reported as skipped.

// Format names, for the status view and for a configuration that says which to
// expect rather than sniffing.
const (
	FormatLines = "lines" // one indicator per line, as the plain feeds are
	FormatSTIX  = "stix"  // a STIX 2.1 bundle, or a TAXII envelope of objects
	FormatMISP  = "misp"  // a MISP event, a MISP feed manifest's event, or restSearch
	FormatAuto  = "auto"  // decide from the bytes
)

// parsed is what a feed document yielded: the entries, and what was skipped.
type parsed struct {
	// byKind holds the normalised keys found, per list kind.
	byKind map[string][]string
	// skipped counts objects or attributes this could not read as an
	// indicator of a kind the proxy matches on. It is reported rather than
	// hidden: a bundle of ten thousand objects that yields four entries is
	// either the wrong feed or a feed of things this cannot act on, and an
	// operator should see which.
	skipped int
}

func newParsed() *parsed { return &parsed{byKind: map[string][]string{}} }

func (p *parsed) add(kind, key string) {
	p.byKind[kind] = append(p.byKind[kind], key)
}

// total is how many indicators were found across every kind.
func (p *parsed) total() int {
	n := 0
	for _, v := range p.byKind {
		n += len(v)
	}
	return n
}

// detectFormat decides what a document is from its first bytes.
//
// It is a fallback for a configuration that did not say. Saying is better: a
// feed whose format is named fails loudly when the publisher changes it, and a
// sniffed one quietly starts yielding nothing.
func detectFormat(data []byte) string {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			// JSON. Which JSON is decided by what is in it, because a MISP
			// event and a STIX bundle are both objects with a type field.
			if looksMISP(data) {
				return FormatMISP
			}
			return FormatSTIX
		}
		return FormatLines
	}
	return FormatLines
}

// looksMISP reports whether a JSON document is MISP-shaped. MISP wraps an event
// in "Event", an attribute search in "response", and a feed's attribute list in
// "Attribute"; a STIX bundle has none of those and does have "objects" or
// "spec_version".
func looksMISP(data []byte) bool {
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	s := string(head)
	for _, key := range []string{`"Event"`, `"Attribute"`, `"response"`} {
		if strings.Contains(s, key) {
			return true
		}
	}
	return false
}

// stixBundle is the part of a bundle or a TAXII envelope this reads.
type stixBundle struct {
	// Objects is a bundle's own field; TAXII 2.1 calls the same list
	// "objects" inside an envelope, so one struct serves both.
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	// PatternType is "stix" for the patterning language. A bundle may carry a
	// snort or yara pattern in the same field, and this must not read one as
	// if it were a STIX expression.
	PatternType string `json:"pattern_type"`
	Revoked     bool   `json:"revoked"`
	ValidUntil  string `json:"valid_until"`
	// Value and Hashes are the cyber-observable forms, which a feed of
	// observed-data or of bare SCOs uses instead of an indicator pattern.
	Value  string            `json:"value"`
	Hashes map[string]string `json:"hashes"`
}

// parseSTIX reads a bundle or a TAXII envelope.
func parseSTIX(data []byte) (*parsed, error) {
	var b stixBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("not a STIX bundle: %w", err)
	}
	if len(b.Objects) == 0 {
		return nil, errors.New("no objects in the bundle")
	}
	out := newParsed()
	for _, o := range b.Objects {
		// A revoked indicator is one the publisher withdrew. Loading it would
		// be this proxy acting on intelligence its author has retracted.
		if o.Revoked {
			continue
		}
		switch o.Type {
		case "indicator":
			// pattern_type is optional in practice and defaults to stix.
			if o.PatternType != "" && o.PatternType != "stix" {
				out.skipped++
				continue
			}
			if n := stixPattern(o.Pattern, out); n == 0 {
				out.skipped++
			}
		case "ipv4-addr", "ipv6-addr":
			if o.Value != "" {
				out.add(KindCIDR, o.Value)
			}
		case "domain-name":
			if key, err := domainKey(o.Value); err == nil {
				out.add(KindDomain, key)
			} else {
				out.skipped++
			}
		case "url":
			if key, err := urlKey(o.Value); err == nil {
				out.add(KindURL, key)
			} else {
				out.skipped++
			}
		case "file":
			found := false
			for _, v := range o.Hashes {
				if h, ok := digest(v); ok {
					out.add(KindHash, h)
					found = true
				}
			}
			if !found {
				out.skipped++
			}
		default:
			// A campaign, an attack pattern, a relationship, a marking. Not
			// an error: a bundle is mostly these, and they are for a human.
			out.skipped++
		}
	}
	if out.total() == 0 {
		return nil, fmt.Errorf("no indicators this proxy can match on among %d objects", len(b.Objects))
	}
	return out, nil
}

// stixPattern reads the comparison expressions of a STIX pattern, and reports
// how many indicators it yielded.
//
// What is read: a conjunction or disjunction of equality comparisons on the
// object paths this proxy can match. What is not: NOT, the set and LIKE and
// MATCHES operators, qualifiers (REPEATS, WITHIN, START/STOP) and comparisons
// on anything else.
//
// A pattern that mixes what this reads with what it does not is skipped whole
// rather than in part. Taking the readable half of
//
//	[domain-name:value = 'a.example' AND NOT file:size > 1024]
//
// would turn "this domain serving a small file" into "this domain", which is a
// broader rule than the publisher wrote -- and a broader rule is somebody
// else's outage.
func stixPattern(pattern string, out *parsed) int {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return 0
	}
	// Qualifiers and negation appear outside or inside the brackets; either
	// way this will not read the pattern.
	upper := strings.ToUpper(p)
	for _, word := range []string{" NOT ", "REPEATS", "WITHIN", "START", "STOP", " LIKE ", "MATCHES", " IN ", " ISSUBSET ", " ISSUPERSET "} {
		if strings.Contains(upper, word) {
			return 0
		}
	}
	// One observation expression, which is what a feed of indicators writes.
	// Several joined by FOLLOWEDBY or AND across brackets describe a sequence
	// of observations, which is not something a single request can satisfy.
	if strings.Count(p, "[") != 1 || strings.Count(p, "]") != 1 {
		return 0
	}
	open := strings.Index(p, "[")
	close := strings.Index(p, "]")
	if open > close {
		return 0
	}
	inner := p[open+1 : close]
	// Anything outside the brackets other than whitespace is a qualifier this
	// did not recognise by name.
	if strings.TrimSpace(p[:open]) != "" || strings.TrimSpace(p[close+1:]) != "" {
		return 0
	}
	// Staged, and committed only if *every* term read. Adding as it goes and
	// returning zero on the first unreadable term would leave the readable half
	// of a mixed pattern in the list while reporting that nothing was taken --
	// which is the broadening this function exists to prevent, wearing the
	// clothes of a refusal. A test that joined a readable term to an
	// unreadable one is what found it.
	type indicator struct{ kind, key string }
	terms := splitTerms(inner)
	staged := make([]indicator, 0, len(terms))
	for _, term := range terms {
		path, value, ok := comparison(term)
		if !ok {
			return 0
		}
		kind, key, ok := observablePath(path, value)
		if !ok {
			return 0
		}
		staged = append(staged, indicator{kind, key})
	}
	for _, ind := range staged {
		out.add(ind.kind, ind.key)
	}
	return len(staged)
}

// splitTerms splits an observation expression on AND and OR at the top level.
// Both are taken the same way, which is the conservative reading: for OR every
// branch is an indicator on its own, and for AND the publisher named several
// things about one payload and any of them identifies it.
func splitTerms(inner string) []string {
	var (
		terms []string
		buf   strings.Builder
		quote bool
		depth int
	)
	flush := func() {
		if t := strings.TrimSpace(buf.String()); t != "" {
			terms = append(terms, t)
		}
		buf.Reset()
	}
	s := inner
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			quote = !quote
			buf.WriteByte(c)
		case quote:
			buf.WriteByte(c)
		case c == '(':
			depth++
			buf.WriteByte(c)
		case c == ')':
			depth--
			buf.WriteByte(c)
		case depth == 0 && hasWordAt(s, i, "AND"):
			flush()
			i += 2
		case depth == 0 && hasWordAt(s, i, "OR"):
			flush()
			i++
		default:
			buf.WriteByte(c)
		}
	}
	flush()
	return terms
}

// hasWordAt reports whether word appears at i bounded by non-word characters.
func hasWordAt(s string, i int, word string) bool {
	if i+len(word) > len(s) || !strings.EqualFold(s[i:i+len(word)], word) {
		return false
	}
	if i > 0 && !isSpaceOrParen(s[i-1]) {
		return false
	}
	if j := i + len(word); j < len(s) && !isSpaceOrParen(s[j]) {
		return false
	}
	return true
}

func isSpaceOrParen(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '(', ')':
		return true
	}
	return false
}

// comparison reads "path = 'value'", the only operator this takes.
func comparison(term string) (path, value string, ok bool) {
	t := strings.Trim(strings.TrimSpace(term), "()")
	i := strings.Index(t, "=")
	if i < 0 {
		return "", "", false
	}
	// != and the ordering operators are not equality.
	if i > 0 {
		switch t[i-1] {
		case '!', '<', '>':
			return "", "", false
		}
	}
	path = strings.TrimSpace(t[:i])
	value = strings.TrimSpace(t[i+1:])
	if !strings.HasPrefix(value, "'") || !strings.HasSuffix(value, "'") || len(value) < 2 {
		return "", "", false
	}
	value = value[1 : len(value)-1]
	// STIX escapes a quote and a backslash inside a string literal.
	value = strings.ReplaceAll(value, `\'`, `'`)
	value = strings.ReplaceAll(value, `\\`, `\`)
	if path == "" || value == "" {
		return "", "", false
	}
	return path, value, true
}

// observablePath maps a STIX object path to a list kind, and normalises the
// value the way that kind's entries are.
func observablePath(path, value string) (kind, key string, ok bool) {
	p := strings.ToLower(strings.TrimSpace(path))
	switch {
	case p == "ipv4-addr:value", p == "ipv6-addr:value":
		// A CIDR entry is parsed by the caller, which refuses what is not an
		// address or a network -- and a STIX value may be either.
		if _, err := parsePrefix(value); err != nil {
			return "", "", false
		}
		return KindCIDR, value, true
	case p == "domain-name:value":
		k, err := domainKey(value)
		if err != nil {
			return "", "", false
		}
		return KindDomain, k, true
	case p == "url:value":
		k, err := urlKey(value)
		if err != nil {
			return "", "", false
		}
		return KindURL, k, true
	case strings.HasPrefix(p, "file:hashes."):
		h, ok := digest(value)
		if !ok {
			return "", "", false
		}
		return KindHash, h, true
	}
	// network-traffic, process, windows-registry-key, email-message and the
	// rest: real intelligence this proxy has nothing to compare against.
	return "", "", false
}
