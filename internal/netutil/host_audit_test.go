package netutil

import "testing"

// TestHostRejectsResidualPortSyntax: only one port suffix is stripped, and
// whatever remains must be a plain name or a bracketed IPv6 literal, so a
// crafted Host cannot dodge the exact-host route table.
func TestHostRejectsResidualPortSyntax(t *testing.T) {
	ok := map[string]string{
		"API.Example.com:443": "api.example.com",
		"example.com.":        "example.com",
		"[::1]:8443":          "[::1]",
		"[2001:db8::1]":       "[2001:db8::1]",
		"10.0.0.1:80":         "10.0.0.1",
	}
	for in, want := range ok {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"api.example.com:443:x", "a:b:c", "[::1", "[not-an-ip]", "[10.0.0.1]", "ex]ample.com", "a[b"} {
		if got := Host(bad); got != "" {
			t.Errorf("Host(%q) = %q, want rejection", bad, got)
		}
	}
}
