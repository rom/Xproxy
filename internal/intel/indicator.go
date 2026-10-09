package intel

import (
	"errors"
	"fmt"
	"strings"
)

// Indicators that are not about the client: a domain, a URL, a digest.
//
// The three are the bulk of what a STIX bundle or a MISP feed actually carries,
// and they answer a different question from an address list. An address says
// who is connecting, which a compromised machine on a network nobody has
// attributed will pass. A domain, a URL or a hash says what the client asked
// for, and a machine reaching for a name somebody else has attributed is worth
// knowing about whatever its address.
//
// Each has one normalisation and one matching rule, and both are written here
// rather than at the point of use, because the same feed is matched against an
// HTTP Host, a DNS question, a CONNECT target and an uploaded file, and a rule
// that differed between them would be four policies wearing one name.

// domainKey normalises a name as a feed writes it into the key a lookup uses.
//
// Feeds write a name in every shape there is: with a trailing dot, with a
// leading dot to mean "and subdomains", in mixed case, as a URL, with a port.
// All of those mean one name, so all of them normalise to it.
func domainKey(text string) (string, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return "", errors.New("empty")
	}
	if len(s) > maxName {
		return "", fmt.Errorf("longer than %d bytes", maxName)
	}
	// A feed line may be a URL where a name was meant. Take the host.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:] // userinfo
	}
	// A port is not part of the name. IPv6 in brackets is not a name at all
	// and is rejected below for having no dot.
	if h, ok := trimPort(s); ok {
		s = h
	}
	// A leading dot is the convention for "and subdomains", which is what
	// every entry means here anyway, so it carries no extra information.
	s = strings.Trim(s, ".")
	s = strings.ToLower(s)
	if s == "" {
		return "", errors.New("empty")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			// No IDN decoding: a feed that means a non-ASCII name writes it
			// in punycode, and guessing an encoding here would produce a key
			// that never matches what the resolver saw.
			return "", fmt.Errorf("%q is not a name; non-ASCII names belong in a feed as punycode", string(r))
		}
	}
	// A single label matches every name under it, which for "com" is every
	// name there is. A feed line with one label is either a mistake or a
	// public suffix, and both are an outage nobody can explain from a log.
	if !strings.Contains(s, ".") {
		return "", errors.New("a single label would match every name under it; write the whole name")
	}
	if strings.Contains(s, "..") {
		return "", errors.New("an empty label")
	}
	return s, nil
}

// urlKey normalises a URL as a feed writes it into the key a lookup uses:
// host and path, no scheme, no fragment.
//
// The scheme is dropped on purpose. A feed lists http://evil.example/p and the
// same payload is served over https the next day; a policy that distinguished
// them would be one an operator has to maintain against the attacker's choice
// of port.
func urlKey(text string) (string, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return "", errors.New("empty")
	}
	if len(s) > maxURL {
		return "", fmt.Errorf("longer than %d bytes", maxURL)
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	host, rest := s, ""
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		host, rest = s[:i], s[i:]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if h, ok := trimPort(host); ok {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" {
		return "", errors.New("no host")
	}
	// The host half is held to the same rule as a domain entry, so a URL
	// feed cannot smuggle in the single-label match a domain feed refuses.
	if !strings.Contains(host, ".") {
		return "", errors.New("a single-label host would match every name under it; write the whole name")
	}
	// The path keeps its case: a path is case-sensitive and a feed that
	// lower-cased one would stop matching the thing it names.
	if rest == "" {
		rest = "/"
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest // a bare query, as some feeds write it
	}
	// A trailing slash carries no information under the boundary rule below:
	// evil.example/dl and evil.example/dl/ match the same requests.
	if len(rest) > 1 {
		rest = strings.TrimRight(rest, "/")
	}
	return host + rest, nil
}

// hashKey normalises a digest: lower-case hex of a length this recognises.
//
// The length is the algorithm. A feed line saying "sha256" beside the digest is
// not needed and is not always there, so it is not asked for -- and a digest of
// an unrecognised length is refused rather than stored, because an entry that
// can never match is an entry an operator believes is protecting them.
//
// A line is searched field by field for the first digest in it, rather than
// having its shape guessed. Feeds write both orders -- "<digest> malware-name"
// and "sha256:<digest>" and "SHA256 <digest> 2026-01-01" -- and a rule that
// took the first field or the last would silently store the wrong half of half
// of them. Searching says what it does, and a line with no digest in it at all
// is an error rather than an entry that can never match.
func hashKey(text string) (string, error) {
	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ' ', '\t', ',', ';', ':', '=', '"', '\'', '|':
			return true
		}
		return false
	}) {
		if h, ok := digest(field); ok {
			return h, nil
		}
	}
	return "", errors.New("no MD5, SHA-1 or SHA-256 digest on the line")
}

// digest reports whether a field is a hex digest of a length this recognises,
// and its normalised form.
func digest(field string) (string, bool) {
	s := strings.ToLower(field)
	switch len(s) {
	case 32, 40, 64: // MD5, SHA-1, SHA-256
	default:
		return "", false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return "", false
		}
	}
	return s, true
}

// trimPort removes a trailing :port from a host, reporting whether there was
// one. It does not use net.SplitHostPort, which refuses a bare host, and it
// discards the port rather than returning it: a port is not part of an
// indicator, because the same payload on another port is the same payload.
func trimPort(s string) (host string, ok bool) {
	if strings.HasPrefix(s, "[") {
		// A bracketed IPv6 literal. Not a name, and the caller refuses it for
		// having no dot; take the whole thing so the refusal names it.
		if i := strings.Index(s, "]"); i >= 0 && strings.HasPrefix(s[i+1:], ":") {
			return s[:i+1], true
		}
		return s, false
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, false
	}
	if strings.Contains(s[:i], ":") {
		// An unbracketed IPv6 literal, whose last group can be all digits:
		// "2001:db8::1" would otherwise lose that group to a port that is
		// not there and be refused -- correctly, for having no dot -- under
		// a name the operator never wrote. The check below catches only the
		// literals whose last group is not numeric.
		return s, false
	}
	rest := s[i+1:]
	if rest == "" {
		return s, false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			// Not a port. An IPv6 literal without brackets lands here, and
			// is refused by the caller for having no dot.
			return s, false
		}
	}
	return s[:i], true
}

// domainCandidates offers the suffixes of a name, shortest first, up to how
// deep the deepest entry in the list goes.
//
// The direction is the whole point, and getting it wrong is a bypass. Walking
// from the *name* down -- a.b.c.name, b.c.name, c.name -- has to stop somewhere,
// and a client chooses how many labels it sends: prefix a listed name with more
// labels than the bound and the walk never reaches the entry. Walking from the
// *suffix* up cannot be evaded that way, because a two-label entry is the first
// candidate however long the name is.
//
// And the bound comes from the list rather than from a constant: a list of
// two-label names walks two candidates whatever the client sends. The cost of a
// match is then a property of the feed an operator chose, not of the request an
// attacker composed.
func domainCandidates(name string, depth int, fn func(string) bool) bool {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(name), "."))
	if s == "" || len(s) > maxName || depth < 2 {
		return false
	}
	// The offsets at which a suffix begins, from the right.
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false // one label: nothing can be listed for it
	}
	if depth > maxLabels {
		depth = maxLabels
	}
	for n := 2; n <= depth && n <= len(labels); n++ {
		if fn(strings.Join(labels[len(labels)-n:], ".")) {
			return true
		}
	}
	return false
}

// urlCandidates offers the host-and-path prefixes of a URL at path boundaries,
// shortest first, up to how many segments the deepest entry in the list has --
// plus the whole key first, so an exact entry is the list that gets named.
//
// Shortest-first for the same reason as a domain: walking down from the request
// would let a client append segments past the bound and escape an entry. And
// the boundary is what makes an entry name a resource rather than a string
// prefix -- an entry for /dl must not match /download, which on a shared host
// is somebody else's.
func urlCandidates(rawURL string, segs int, fn func(string) bool) bool {
	key, err := urlKey(rawURL)
	if err != nil {
		return false
	}
	// The whole thing first: the most specific entry is the one worth naming
	// in a status view, even though any match is a match.
	if fn(key) {
		return true
	}
	slash := strings.Index(key, "/")
	if slash < 0 {
		return false
	}
	host, path := key[:slash], key[slash:]
	// A query is part of the exact key above -- a feed may list one -- but not
	// of the boundary walk below: a client that could escape an entry for
	// /dl by asking for /dl?x=1 would have a bypass one character long.
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if path == "/" {
		// The exact key above was the site, so there is nothing else to
		// offer: walking on would ask the list the same question twice more.
		return false
	}
	// The host with no path, which is how a feed lists a whole site.
	if fn(host + "/") {
		return true
	}
	if segs > maxSegments {
		segs = maxSegments
	}
	// path begins with "/", so its segments are the fields between slashes.
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for n := 1; n <= segs && n <= len(parts); n++ {
		if fn(host + "/" + strings.Join(parts[:n], "/")) {
			return true
		}
	}
	return false
}

// domainDepth is the label count of the deepest name in a set of keys, which is
// how far a match has to walk. maxDomainDepth bounds what a list may ask for:
// an entry of two hundred labels would make every request walk two hundred
// candidates, so it is refused at load rather than paid for per request.
const maxDomainDepth = maxLabels

// labelCount counts the labels in a normalised key.
func labelCount(key string) int { return strings.Count(key, ".") + 1 }

// segmentCount counts the path segments in a normalised url key.
func segmentCount(key string) int {
	slash := strings.Index(key, "/")
	if slash < 0 {
		return 0
	}
	trimmed := strings.Trim(key[slash:], "/")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "/") + 1
}
