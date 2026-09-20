package netutil

import (
	"net/http"
	"net/netip"
	"testing"
)

// TestClientIPDropsZone: an IPv6 zone in X-Forwarded-For would make the
// address miss every prefix match and key its own buckets.
func TestClientIPDropsZone(t *testing.T) {
	trusted := ParsePrefixes([]string{"10.0.0.0/8"})
	r := &http.Request{RemoteAddr: "10.1.2.3:4444", Header: http.Header{"X-Forwarded-For": {"2001:db8::1%eth0"}}}
	ip := ClientIP(r, trusted)
	if ip.Zone() != "" || ip != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("zone kept: %v", ip)
	}
	if !Contains(ParsePrefixes([]string{"2001:db8::/32"}), ip) {
		t.Fatal("prefix match failed")
	}
}

// TestHostBracketSuffix: after a bracketed literal only ":port" may follow.
func TestHostBracketSuffix(t *testing.T) {
	for _, bad := range []string{"[::1]garbage:80", "[::1]:80:90", "[::1]:8x", "[::1].", "[::1]:"} {
		if got := Host(bad); got != "" {
			t.Errorf("Host(%q) = %q, want rejection", bad, got)
		}
	}
	if got := Host("[::1]:8443"); got != "[::1]" {
		t.Errorf("Host([::1]:8443) = %q", got)
	}
}
