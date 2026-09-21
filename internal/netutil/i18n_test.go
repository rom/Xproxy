package netutil

import (
	"fmt"
	"strings"
	"testing"
)

// A host name and a path are routing keys. Two spellings of one name
// that the proxy treats as different keys are a way past the route that
// carries the access list, the authentication filter and the WAF
// profile — and two spellings the proxy treats as the same when the
// origin does not are the mirror image. These tests are the Unicode
// half of that contract: what a name may contain, and what it may not.

// TestHostRejectsNonASCII pins the rule that makes homoglyphs a
// non-question here. A name is ASCII or it is not a name: the client
// that wants an internationalised host sends it in its punycode form,
// as every resolver and every browser already does.
func TestHostRejectsNonASCII(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"cyrillic a", "ex\u0430mple.com"},               // U+0430, not 'a'
		{"greek omicron", "g\u03bf\u03bfgle.com"},        // U+03BF
		{"fullwidth", "\uff45xample.com"},                // U+FF45 fullwidth e
		{"combining acute", "cafe\u0301.example.com"},    // e + U+0301
		{"precomposed", "caf\u00e9.example.com"},         // U+00E9
		{"turkish dotless", "\u0131nternal.example"},     // U+0131
		{"turkish dotted capital", "\u0130nternal.test"}, // U+0130, whose lower case is two runes
		{"zero width space", "exa\u200bmple.com"},
		{"zero width joiner", "exa\u200dmple.com"},
		{"bidi override", "exa\u202emple.com"},
		{"left to right mark", "\u200eexample.com"},
		{"ideographic full stop", "example\u3002com"}, // U+3002 resolves like '.'
		{"non breaking space", "exam\u00a0ple.com"},
		{"soft hyphen", "exa\u00adm ple.com"},
		{"emoji", "\U0001f600.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Host(tc.host); got != "" {
				t.Fatalf("Host(%q) = %q; a non-ASCII name must not become a routing key", tc.host, got)
			}
		})
	}
}

// TestHostAcceptsPunycode is the other half: the internationalised name
// in the form it actually travels in.
func TestHostAcceptsPunycode(t *testing.T) {
	for _, h := range []string{"xn--caf-dma.example.com", "xn--80ak6aa92e.com", "xn--p1ai"} {
		if got := Host(h); got != h {
			t.Fatalf("Host(%q) = %q", h, got)
		}
	}
}

// TestHostCaseFolding pins that folding is ASCII only. A Turkish locale
// folds 'I' to '\u0131' and '\u0130' to 'i̇', so a locale-aware fold would give
// one name two keys depending on where the process runs.
func TestHostCaseFolding(t *testing.T) {
	if got := Host("EXAMPLE.COM"); got != "example.com" {
		t.Fatalf("Host(EXAMPLE.COM) = %q", got)
	}
	if got := Host("INTERNAL.TEST"); got != "internal.test" {
		t.Fatalf("Host(INTERNAL.TEST) = %q", got)
	}
	// The same name in every mixed case is one key.
	seen := map[string]bool{}
	for _, h := range []string{"Example.Com", "eXaMpLe.cOm", "EXAMPLE.com", "example.COM"} {
		seen[Host(h)] = true
	}
	if len(seen) != 1 {
		t.Fatalf("mixed case produced %d keys: %v", len(seen), seen)
	}
}

// TestHostOneSpellingPerName covers the spellings that would hand one
// host a second routing key: an extra dot, a trailing dot, a port, an
// empty label. The catch-all route is where a deployment puts its
// permissive default, so a name that misses its own exact entry lands
// exactly where nobody wants it.
func TestHostOneSpellingPerName(t *testing.T) {
	same := []string{"example.com", "example.com.", "example.com:443", "EXAMPLE.COM.", "example.com:0"}
	want := "example.com"
	for _, h := range same {
		if got := Host(h); got != want {
			t.Errorf("Host(%q) = %q, want %q", h, got, want)
		}
	}
	rejected := []string{
		"", ".", "..", ".example.com", "example..com", "example.com..",
		"example.com:", "example.com:https", "example.com:443:443",
		"example.com/path", "example.com?x", "example.com#f", "example com",
		"exam\tple.com", "example.com\r\nX-Evil: 1", "example.com\x00",
		strings.Repeat("a", 254),
	}
	for _, h := range rejected {
		if got := Host(h); got != "" {
			t.Errorf("Host(%q) = %q; it must not be a routing key", h, got)
		}
	}
}

// TestHostIPv6Literals covers the bracketed form, where the interesting
// mistake is accepting a prefix and leaving the rest for the upstream
// to read differently.
func TestHostIPv6Literals(t *testing.T) {
	ok := map[string]string{
		"[::1]":         "[::1]",
		"[::1]:8443":    "[::1]",
		"[2001:db8::1]": "[2001:db8::1]",
		"[2001:DB8::1]": "[2001:db8::1]",
		// A zone identifier is its own address, not a second spelling
		// of the one without it.
		"[fe80::1%25eth0]:443": "[fe80::1%25eth0]",
		"[::ffff:127.0.0.1]":   "[::ffff:127.0.0.1]",
	}
	for in, want := range ok {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
	for _, h := range []string{"[::1", "[::1]junk", "[::1]x:443", "[::1]:", "[::1]:https", "[]", "[not an address]", "[127.0.0.1]"} {
		if got := Host(h); got != "" {
			t.Errorf("Host(%q) = %q; a malformed literal must not route", h, got)
		}
	}
}

// TestCleanPathTraversal covers the path cleaner against the ways a
// request tries to leave the prefix its route matched.
func TestCleanPathTraversal(t *testing.T) {
	cases := map[string]string{
		"":                     "/",
		"/":                    "/",
		"a":                    "/a",
		"/a/../b":              "/b",
		"/a/./b":               "/a/b",
		"/a//b":                "/a/b",
		"/../../../etc/passwd": "/etc/passwd",
		"/a/b/..":              "/a",
		"/a/b/../..":           "/",
		"/a/b/../../..":        "/",
		"/a/":                  "/a/",
		"/a/b/../":             "/a/",
		"///":                  "/",
		"/.":                   "/",
		"/..":                  "/",
		"/...":                 "/...",
		"/a/...":               "/a/...",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q) = %q, want %q", in, got, want)
		}
	}
	// Cleaning is idempotent: a second pass never changes the answer,
	// which is what lets the router compare once.
	for in := range cases {
		once := CleanPath(in)
		if twice := CleanPath(once); twice != once {
			t.Errorf("CleanPath is not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}

// TestCleanPathKeepsBytesItDoesNotUnderstand requires the cleaner to
// leave a path's own characters alone. It resolves segments; it is not
// a decoder, and a cleaner that decoded %2F here would undo the guard
// that refuses an encoded separator.
func TestCleanPathKeepsBytesItDoesNotUnderstand(t *testing.T) {
	for _, p := range []string{
		"/a%2F..%2Fb", "/caf\u00e9", "/cafe\u0301", "/\uff0fetc/passwd",
		"/a b", "/a+b", "/%00", "/\u200b",
	} {
		got := CleanPath(p)
		if !strings.HasPrefix(got, "/") {
			t.Errorf("CleanPath(%q) = %q", p, got)
		}
		if strings.Contains(got, "/../") {
			t.Errorf("CleanPath(%q) left a dot segment: %q", p, got)
		}
		// Nothing was decoded on the way through.
		if strings.Contains(p, "%2F") && !strings.Contains(got, "%2F") {
			t.Errorf("CleanPath decoded an escape in %q: %q", p, got)
		}
	}
}

// TestMediaTypeMatchesTheServersBehindIt pins why this is not
// mime.ParseMediaType: a consumer that threw the type away on a stray
// character would skip its whole policy, while the origin reads the
// body regardless.
func TestMediaTypeMatchesTheServersBehindIt(t *testing.T) {
	cases := map[string]string{
		"application/json":                               "application/json",
		"application/json; charset=utf-8":                "application/json",
		"APPLICATION/JSON":                               "application/json",
		"  application/json  ":                           "application/json",
		"application/json; charset=utf-8; charset=ascii": "application/json",
		"application/json;q":                             "application/json",
		"application/json/x":                             "application/json/x",
		"application/json;":                              "application/json",
		"application/json ;charset=\"":                   "application/json",
		"multipart/form-data; boundary=--x":              "multipart/form-data",
		"":                                               "",
		";charset=utf-8":                                 "",
		"application/vnd.api+json":                       "application/vnd.api+json",
	}
	for in, want := range cases {
		if got := MediaType(in); got != want {
			t.Errorf("MediaType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMediaTypeIsNotFooledByParameters covers the parameter that
// carries a second type: what matters is the token before the first
// semicolon, never a value inside one.
func TestMediaTypeIsNotFooledByParameters(t *testing.T) {
	for _, in := range []string{
		`text/plain; x="application/json"`,
		`text/plain; boundary=application/json`,
		"text/plain;charset=utf-8;type=application/json",
	} {
		if got := MediaType(in); got != "text/plain" {
			t.Errorf("MediaType(%q) = %q", in, got)
		}
	}
}

// TestPathTemplateFoldsIdentifiers covers the inventory's key: two
// requests that differ only by an identifier are one endpoint, and a
// template that folded a real path segment would merge endpoints that
// are not the same.
func TestPathTemplateFoldsIdentifiers(t *testing.T) {
	same := [][]string{
		{"/users/42", "/users/43", "/users/1000000"},
		{"/o/550e8400-e29b-41d4-a716-446655440000", "/o/6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
	}
	for _, group := range same {
		first := PathTemplate(group[0])
		for _, p := range group[1:] {
			if got := PathTemplate(p); got != first {
				t.Errorf("%q and %q gave the templates %q and %q", group[0], p, first, got)
			}
		}
	}
	different := [][2]string{
		{"/users", "/orders"},
		{"/users/42", "/orders/42"},
		{"/v1/users", "/v2/users"},
	}
	for _, pair := range different {
		if PathTemplate(pair[0]) == PathTemplate(pair[1]) {
			t.Errorf("%q and %q folded to the same template %q", pair[0], pair[1], PathTemplate(pair[0]))
		}
	}
	// It is total: anything goes in, a path comes out.
	for _, p := range []string{"", "/", "//", "/a/", strings.Repeat("/a", 500), "/\u00e9", "/%2F"} {
		if got := PathTemplate(p); got == "" && p != "" {
			t.Errorf("PathTemplate(%q) = %q", p, got)
		}
	}
}

// TestHostIsStableUnderRepetition is the determinism property: the same
// header always produces the same key, and normalising twice is the
// same as normalising once.
func TestHostIsStableUnderRepetition(t *testing.T) {
	for _, h := range []string{"Example.COM.", "[::1]:8443", "a.b.c", "xn--caf-dma.example.com"} {
		first := Host(h)
		for i := 0; i < 10; i++ {
			if got := Host(h); got != first {
				t.Fatalf("Host(%q) changed between calls: %q then %q", h, first, got)
			}
		}
		if first != "" {
			if again := Host(first); again != first {
				t.Fatalf("Host is not idempotent for %q: %q then %q", h, first, again)
			}
		}
	}
}

// TestHostLength covers the boundary of the name length limit, where an
// off-by-one decides whether a 253 byte name routes.
func TestHostLength(t *testing.T) {
	label := strings.Repeat("a", 63)
	for _, tc := range []struct {
		n  int
		ok bool
	}{{252, true}, {253, true}, {254, false}, {1000, false}} {
		var parts []string
		for len(strings.Join(parts, ".")) < tc.n {
			parts = append(parts, label)
		}
		h := strings.Join(parts, ".")
		h = h[:tc.n]
		h = strings.TrimSuffix(h, ".")
		got := Host(h)
		if tc.ok && got == "" {
			t.Errorf("a %d byte name was refused", len(h))
		}
		if !tc.ok && got != "" {
			t.Errorf("a %d byte name was accepted as %q", len(h), got)
		}
	}
	if got := Host(fmt.Sprintf("%s.example.com", strings.Repeat("a", 300))); got != "" {
		t.Errorf("an over-long name routed as %q", got)
	}
}
