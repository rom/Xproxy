package forward

import (
	"net/netip"
	"testing"
)

// TestForwardPolicy covers the destination matcher and the private
// address set without a network.
func TestForwardPolicy(t *testing.T) {
	rules, err := compileDestRules([]string{"example.test", "*.corp.test", "192.0.2.0/24", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	ip := func(s string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(s)} }
	cases := []struct {
		host string
		ips  []netip.Addr
		want bool
	}{
		{"example.test", ip("203.0.113.1"), true},
		{"sub.example.test", ip("203.0.113.1"), false},
		{"a.corp.test", ip("203.0.113.1"), true},
		{"corp.test", ip("203.0.113.1"), false},
		{"other.test", ip("192.0.2.77"), true},
		{"other.test", ip("2001:db8::1"), true},
		{"other.test", ip("2001:db8::2"), false},
	}
	for _, tc := range cases {
		if got := anyRule(rules, tc.host, tc.ips); got != tc.want {
			t.Errorf("%s %v: got %v", tc.host, tc.ips, got)
		}
	}
	if _, err := compileDestRules([]string{""}); err == nil {
		t.Fatal("empty rule accepted")
	}
	for _, a := range []string{"127.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:10.0.0.1"} {
		if !privateAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s not private", a)
		}
	}
	for _, a := range []string{"203.0.113.1", "8.8.8.8", "2001:db8::1"} {
		if privateAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s private", a)
		}
	}
}

// TestPrivateAddrCoversTransitionRanges: the forward proxy's private-address
// check includes the blocks that embed or alias internal addresses.
func TestPrivateAddrCoversTransitionRanges(t *testing.T) {
	for _, s := range []string{"100.64.1.1", "0.1.2.3", "192.0.0.9", "198.18.0.1", "240.0.0.1", "64:ff9b::a00:1", "2002:c0a8:101::1", "2001:0:53aa:64c:0:bfff:3f57:fefe", "10.1.1.1", "127.0.0.1", "::1"} {
		if !privateAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not treated as private", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700::1111"} {
		if privateAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s wrongly treated as private", s)
		}
	}
}
