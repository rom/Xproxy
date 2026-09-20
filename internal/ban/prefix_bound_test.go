package ban

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// TestPrefixBansBounded: network bans are capped and looked up by prefix
// length, so an attacker rotating source networks can neither grow the
// list without bound nor turn every request into a scan of it.
func TestPrefixBansBounded(t *testing.T) {
	c := cfg()
	c.Triggers = nil
	l, now := newList(t, c)
	for i := 0; i < maxPrefixBans+500; i++ {
		target := fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&0xffff)
		if _, err := l.Ban(target, time.Duration(i+1)*time.Second, "test"); err != nil {
			t.Fatal(err)
		}
	}
	l.mu.RLock()
	n, idx := len(l.prefixes), len(l.prefixIdx)
	l.mu.RUnlock()
	if n > maxPrefixBans || idx != n {
		t.Fatalf("prefixes %d index %d", n, idx)
	}
	// The soonest to expire went; the latest stay and match by lookup.
	if l.Banned(netip.MustParseAddr("2001:db8:0:1::5")) {
		t.Fatal("soonest-expiring prefix kept")
	}
	last := fmt.Sprintf("2001:db8:%x:%x::9", (maxPrefixBans+499)>>16, (maxPrefixBans+499)&0xffff)
	if !l.Banned(netip.MustParseAddr(last)) {
		t.Fatal("latest prefix not found")
	}
	if l.Banned(netip.MustParseAddr("2001:db9::1")) {
		t.Fatal("unbanned network matched")
	}
	// Unban and expiry keep the index in step.
	if err := l.Unban(fmt.Sprintf("2001:db8:%x:%x::/64", (maxPrefixBans+499)>>16, (maxPrefixBans+499)&0xffff)); err != nil {
		t.Fatal(err)
	}
	if l.Banned(netip.MustParseAddr(last)) {
		t.Fatal("unbanned prefix still matches")
	}
	*now = now.Add(2 * time.Hour)
	l.Purge()
	l.mu.RLock()
	n, idx = len(l.prefixes), len(l.prefixIdx)
	l.mu.RUnlock()
	if n != 0 || idx != 0 {
		t.Fatalf("after purge: prefixes %d index %d", n, idx)
	}
}
