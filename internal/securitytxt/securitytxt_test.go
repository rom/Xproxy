package securitytxt

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

var epoch = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

func build(t *testing.T, entries ...config.SecurityTxt) *Set {
	t.Helper()
	for i := range entries {
		if entries[i].ValidFor == 0 && entries[i].Expires == "" {
			entries[i].ValidFor = config.Duration(365 * 24 * time.Hour)
		}
	}
	s, err := New(entries, epoch)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestRendersTheFieldsInOrder(t *testing.T) {
	s := build(t, config.SecurityTxt{
		Name:               "public",
		Comment:            "Report responsibly.\n\nWe answer within two working days.",
		Contact:            []string{"mailto:security@example.com", "https://example.com/vdp"},
		ValidFor:           config.Duration(24 * time.Hour),
		Encryption:         []string{"https://example.com/pgp.txt"},
		Acknowledgments:    []string{"https://example.com/thanks"},
		PreferredLanguages: []string{"en", "sv"},
		Canonical:          []string{"https://example.com/.well-known/security.txt"},
		Policy:             []string{"https://example.com/policy"},
		Hiring:             []string{"https://example.com/jobs"},
		CSAF:               []string{"https://example.com/.well-known/csaf/provider-metadata.json"},
		Extra:              map[string][]string{"Zeta": {"last"}, "Alpha": {"first"}},
	})
	got := string(s.Docs()[0].Body())
	want := `# Report responsibly.
#
# We answer within two working days.
Contact: mailto:security@example.com
Contact: https://example.com/vdp
Expires: 2026-09-21T12:00:00Z
Encryption: https://example.com/pgp.txt
Acknowledgments: https://example.com/thanks
Preferred-Languages: en, sv
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/policy
Hiring: https://example.com/jobs
CSAF: https://example.com/.well-known/csaf/provider-metadata.json
Alpha: first
Zeta: last
`
	if got != want {
		t.Fatalf("rendered:\n%s\nwant:\n%s", got, want)
	}
}

// Expires is the one field RFC 9116 makes a parser reject the document
// over, so both ways of setting it are covered.
func TestExpires(t *testing.T) {
	s := build(t, config.SecurityTxt{Contact: []string{"mailto:a@example.com"}, Expires: "2030-01-02T03:04:05Z"})
	if !strings.Contains(string(s.Docs()[0].Body()), "Expires: 2030-01-02T03:04:05Z") {
		t.Fatalf("explicit expires: %s", s.Docs()[0].Body())
	}
	// A non-UTC instant is rendered in UTC, so two nodes in different
	// zones serve the same bytes.
	s = build(t, config.SecurityTxt{Contact: []string{"mailto:a@example.com"}, Expires: "2030-01-02T04:04:05+01:00"})
	if !strings.Contains(string(s.Docs()[0].Body()), "Expires: 2030-01-02T03:04:05Z") {
		t.Fatalf("offset expires: %s", s.Docs()[0].Body())
	}
	if _, err := New([]config.SecurityTxt{{Contact: []string{"mailto:a@example.com"}, Expires: "next tuesday"}}, epoch); err == nil {
		t.Fatal("a nonsense expires was accepted")
	}
}

func TestSelectors(t *testing.T) {
	s := build(t,
		config.SecurityTxt{Name: "internal", ClientCIDRs: []string{"10.0.0.0/8"}, Contact: []string{"mailto:in@example.com"}},
		config.SecurityTxt{Name: "listener", Listeners: []string{"mgmt"}, Contact: []string{"mailto:l@example.com"}},
		config.SecurityTxt{Name: "shop", Hosts: []string{"shop.example.com", "*.shop.example.com"}, Contact: []string{"mailto:s@example.com"}},
		config.SecurityTxt{Name: "numbered", HostRegex: `^api[0-9]+\.example\.com$`, Contact: []string{"mailto:n@example.com"}},
		config.SecurityTxt{Name: "default", Contact: []string{"mailto:d@example.com"}},
	)
	pub := netip.MustParseAddr("203.0.113.7")
	for _, tc := range []struct {
		host, listener string
		client         netip.Addr
		want           string
	}{
		{"anything.test", "main", netip.MustParseAddr("10.1.2.3"), "internal"},
		{"shop.example.com", "mgmt", pub, "listener"},
		{"shop.example.com", "main", pub, "shop"},
		{"eu.shop.example.com", "main", pub, "shop"},
		{"a.b.shop.example.com", "main", pub, "shop"},
		{"example.com", "main", pub, "default"},
		{"api7.example.com", "main", pub, "numbered"},
		{"api.example.com", "main", pub, "default"},
		{"SHOP.EXAMPLE.COM", "main", pub, "shop"},
		{"parked.example.net", "main", pub, "default"},
	} {
		doc := s.Match(tc.host, tc.client, tc.listener)
		if doc == nil || doc.Name() != tc.want {
			name := "<none>"
			if doc != nil {
				name = doc.Name()
			}
			t.Errorf("%s on %s from %s: got %s want %s", tc.host, tc.listener, tc.client, name, tc.want)
		}
	}
}

// A wildcard does not match the bare name, which is the rule the router
// uses; without a fallback entry such a host has no document.
func TestWildcardDoesNotMatchTheBareName(t *testing.T) {
	s := build(t, config.SecurityTxt{Name: "w", Hosts: []string{"*.example.com"}, Contact: []string{"mailto:a@example.com"}})
	if doc := s.Match("example.com", netip.MustParseAddr("203.0.113.1"), "main"); doc != nil {
		t.Fatalf("the bare name matched %s", doc.Name())
	}
	if doc := s.Match("a.example.com", netip.MustParseAddr("203.0.113.1"), "main"); doc == nil {
		t.Fatal("a subdomain did not match")
	}
}

// No entries at all is not an error and answers nothing, so the request
// falls through to routing.
func TestEmptySetMatchesNothing(t *testing.T) {
	s, err := New(nil, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if s != nil && s.Match("example.com", netip.MustParseAddr("203.0.113.1"), "main") != nil {
		t.Fatal("an empty configuration answered")
	}
	// A nil *Set is usable, because that is what the runtime holds when
	// nothing is configured.
	var nilSet *Set
	if nilSet.Match("example.com", netip.MustParseAddr("203.0.113.1"), "main") != nil || nilSet.Docs() != nil {
		t.Fatal("the nil set answered")
	}
}

func TestServe(t *testing.T) {
	s := build(t, config.SecurityTxt{Name: "d", Contact: []string{"mailto:a@example.com"}, CacheFor: config.Duration(2 * time.Hour)})
	doc := s.Docs()[0]
	rec := httptest.NewRecorder()
	doc.Serve(rec, httptest.NewRequest("GET", Path, nil))
	res := rec.Result()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != ContentType {
		t.Fatalf("status %d type %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=7200" {
		t.Fatalf("cache-control %q", got)
	}
	if rec.Body.Len() == 0 || rec.Body.Len() != len(doc.Body()) {
		t.Fatalf("body %d bytes, document %d", rec.Body.Len(), len(doc.Body()))
	}
	// HEAD carries the length and no body.
	rec = httptest.NewRecorder()
	doc.Serve(rec, httptest.NewRequest("HEAD", Path, nil))
	if rec.Body.Len() != 0 || rec.Result().Header.Get("Content-Length") == "" {
		t.Fatalf("HEAD body %d, length %q", rec.Body.Len(), rec.Result().Header.Get("Content-Length"))
	}
	// A security.txt is a file: nothing else is answered.
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		rec = httptest.NewRecorder()
		doc.Serve(rec, httptest.NewRequest(m, Path, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Result().Header.Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s: %d %q", m, rec.Code, rec.Result().Header.Get("Allow"))
		}
	}
	// Zero cache_for sends no Cache-Control at all.
	s = build(t, config.SecurityTxt{Name: "n", Contact: []string{"mailto:a@example.com"}})
	rec = httptest.NewRecorder()
	s.Docs()[0].Serve(rec, httptest.NewRequest("GET", Path, nil))
	if rec.Result().Header.Get("Cache-Control") != "" {
		t.Fatalf("cache-control %q with cache_for 0", rec.Result().Header.Get("Cache-Control"))
	}
}

// A body replaces the whole document, which is what a clear-signed file
// needs; its line endings are normalised, because a file edited on one
// platform and served from another otherwise carries whichever the
// editor left, and a lone CR is not a line ending at all.
func TestVerbatimBodyLineEndings(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Contact: mailto:a@example.com\r\nExpires: 2030-01-01T00:00:00Z\r\n", "Contact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n"},
		{"Contact: mailto:a@example.com\rExpires: 2030-01-01T00:00:00Z\r", "Contact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n"},
		{"Contact: mailto:a@example.com", "Contact: mailto:a@example.com\n"},
		{"already\nfine\n", "already\nfine\n"},
	} {
		s := build(t, config.SecurityTxt{Name: "v", Body: tc.in})
		if got := string(s.Docs()[0].Body()); got != tc.want {
			t.Errorf("%q -> %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	for name, e := range map[string]config.SecurityTxt{
		"no contact":  {Name: "a"},
		"bad regex":   {Name: "b", Contact: []string{"mailto:a@example.com"}, HostRegex: "("},
		"bad cidr":    {Name: "c", Contact: []string{"mailto:a@example.com"}, ClientCIDRs: []string{"10.0.0.0/33"}},
		"empty host":  {Name: "d", Contact: []string{"mailto:a@example.com"}, Hosts: []string{"  "}},
		"oversize":    {Name: "e", Body: strings.Repeat("x", 64<<10+1)},
		"bad expires": {Name: "f", Contact: []string{"mailto:a@example.com"}, Expires: "2030-13-40T00:00:00Z"},
	} {
		if _, err := New([]config.SecurityTxt{e}, epoch); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The first matching entry answers, so order is the whole of the
// precedence rule and a reader can predict it from the file.
func TestFirstMatchWins(t *testing.T) {
	s := build(t,
		config.SecurityTxt{Name: "first", Hosts: []string{"a.example.com"}, Contact: []string{"mailto:1@example.com"}},
		config.SecurityTxt{Name: "second", Hosts: []string{"a.example.com"}, Contact: []string{"mailto:2@example.com"}},
	)
	if doc := s.Match("a.example.com", netip.MustParseAddr("203.0.113.1"), "main"); doc == nil || doc.Name() != "first" {
		t.Fatalf("%v", doc)
	}
}
