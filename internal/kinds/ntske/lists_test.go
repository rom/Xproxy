package ntske

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	ke "github.com/rom/xproxy/internal/ntske"
)

// The two lists this listener decides on before a handshake goes
// anywhere: which addresses may ask, and which server names they may
// ask for.
//
// A key establishment server hands out the keys an NTP client will
// authenticate time with, so "who may ask" is the whole of the access
// control here -- and a deny entry has to win over an allow one, because
// a list that let the broader rule win would be a list an operator
// cannot narrow.
func TestTheClientAndNameListsDecideWhoMayAsk(t *testing.T) {
	pfx := netip.MustParsePrefix
	ip := netip.MustParseAddr

	for _, tc := range []struct {
		name  string
		s     *server
		addr  string
		allow bool
	}{
		{"no lists at all admits anybody", &server{}, "203.0.113.9", true},
		{
			"a denied address is refused even where an allow rule covers it",
			&server{allow: []netip.Prefix{pfx("10.0.0.0/8")}, deny: []netip.Prefix{pfx("10.1.2.0/24")}},
			"10.1.2.3", false,
		},
		{
			"and the rest of the allowed range still gets in",
			&server{allow: []netip.Prefix{pfx("10.0.0.0/8")}, deny: []netip.Prefix{pfx("10.1.2.0/24")}},
			"10.9.9.9", true,
		},
		{
			"an address outside every allow rule is refused",
			&server{allow: []netip.Prefix{pfx("10.0.0.0/8")}},
			"192.0.2.1", false,
		},
		{
			"a deny list on its own refuses only what it names",
			&server{deny: []netip.Prefix{pfx("192.0.2.0/24")}},
			"203.0.113.9", true,
		},
	} {
		if got := tc.s.clientAllowed(ip(tc.addr)); got != tc.allow {
			t.Errorf("%s: clientAllowed(%s) = %v", tc.name, tc.addr, got)
		}
	}

	names := &server{names: []string{"time.example", "*.ntp.example"}}
	for _, tc := range []struct {
		in    string
		allow bool
	}{
		{"time.example", true},
		{"TIME.EXAMPLE", true},     // the list is matched case-insensitively
		{"a.ntp.example", true},    // one label under the wildcard
		{"a.b.ntp.example", false}, // two is not what a wildcard covers
		{"ntp.example", false},     // nor is the bare suffix
		{"other.example", false},
		{"", false},
	} {
		if got := names.nameAllowed(tc.in); got != tc.allow {
			t.Errorf("nameAllowed(%q) = %v, want %v", tc.in, got, tc.allow)
		}
	}
	// An empty list takes any name, including a handshake that named
	// none, which is legal and which a single-server deployment does
	// not need to restrict.
	empty := &server{}
	for _, n := range []string{"", "anything.example"} {
		if !empty.nameAllowed(n) {
			t.Errorf("an empty list refused %q", n)
		}
	}
}

// The idle bound, which is what ends a connection that completed a TLS
// handshake and then said nothing.
func TestTheIdleBoundFallsBackToThirtySeconds(t *testing.T) {
	configured := &server{k: &config.NTSKEListener{IdleTimeout: config.Duration(5 * time.Second)}}
	if got := configured.idle(); got != 5*time.Second {
		t.Errorf("idle = %s, want the configured 5s", got)
	}
	unset := &server{k: &config.NTSKEListener{}}
	if got := unset.idle(); got != 30*time.Second {
		t.Errorf("idle = %s, want the default 30s", got)
	}
}

// Every reason a request is refused has a name of its own, because the
// counters are what an operator reads to tell a client that cannot
// speak the protocol from one that is probing it.
func TestEveryRefusalHasItsOwnName(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errNoRequest, "no_request"},
		{ke.ErrCritical, "unknown_critical_record"},
		{ke.ErrTooLong, "request_too_large"},
		{ke.ErrTruncated, "incomplete_request"},
		{ke.ErrNoEnd, "incomplete_request"},
		{fmt.Errorf("something else"), "bad_request"},
	} {
		if got := refusalFor(tc.err); got != tc.want {
			t.Errorf("refusalFor(%v) = %q, want %q", tc.err, got, tc.want)
		}
		// Wrapped the way the read path wraps them, the answer is the same.
		if got := refusalFor(fmt.Errorf("reading the request: %w", tc.err)); got != tc.want {
			t.Errorf("refusalFor(wrapped %v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	// And the error code a refusal is answered with: a record this build
	// does not know, marked critical, is the one case RFC 8915 answers
	// with its own code rather than a plain bad request.
	if got := errorCodeFor(ke.ErrCritical); got != ke.ErrUnrecognisedCritical {
		t.Errorf("errorCodeFor(critical) = %d", got)
	}
	if got := errorCodeFor(ke.ErrTruncated); got != ke.ErrBadRequest {
		t.Errorf("errorCodeFor(truncated) = %d", got)
	}
}
