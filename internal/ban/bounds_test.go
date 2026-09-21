package ban

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The ban list is a table an attacker writes to: every refusal they
// provoke adds an entry, and the entries are keyed by things they
// choose — an address, a network, a TLS fingerprint. These tests are
// about the bounds on that table and about the state file, which is
// the one part of this package that survives a restart.

// TestFingerprintBansAreBounded covers the fingerprint table, whose key
// is a value the client's own ClientHello decides. Without a bound, a
// client that varies its hello grows the table for as long as it keeps
// getting banned.
func TestFingerprintBansAreBounded(t *testing.T) {
	l, now := newList(t, cfg())
	for i := 0; i < maxFingerprintBans+500; i++ {
		if _, err := l.Ban(fmt.Sprintf("ja4:t13d%04dh2_0000_0000", i), time.Hour, "fingerprint"); err != nil {
			t.Fatalf("ban %d: %v", i, err)
		}
	}
	l.mu.Lock()
	n := len(l.fps)
	l.mu.Unlock()
	if n > maxFingerprintBans {
		t.Fatalf("the fingerprint table holds %d entries, the bound is %d", n, maxFingerprintBans)
	}
	// The most recent ban survived the eviction: a bound that dropped
	// the newest entry would make the last attacker the one who gets in.
	last := fmt.Sprintf("ja4:t13d%04dh2_0000_0000", maxFingerprintBans+499)
	found := false
	for _, e := range l.Entries() {
		if e.Target == last {
			found = true
		}
	}
	if !found {
		t.Fatal("the newest fingerprint ban was evicted")
	}
	// An expired entry is what eviction prefers to drop.
	*now = now.Add(2 * time.Hour)
	l.Purge()
	l.mu.Lock()
	after := len(l.fps)
	l.mu.Unlock()
	if after != 0 {
		t.Fatalf("%d fingerprint bans survived their expiry", after)
	}
}

// TestPrefixBansAreBounded is the same question for network bans, which
// an aggregate trigger creates from traffic spread across a range.
func TestPrefixBansAreBounded(t *testing.T) {
	l, now := newList(t, cfg())
	for i := 0; i < maxPrefixBans+200; i++ {
		target := fmt.Sprintf("%d.%d.0.0/16", 100+i/256, i%256)
		if _, err := l.Ban(target, time.Hour, "net"); err != nil {
			t.Fatalf("ban %d (%s): %v", i, target, err)
		}
	}
	l.mu.Lock()
	n := len(l.prefixes)
	l.mu.Unlock()
	if n > maxPrefixBans {
		t.Fatalf("the prefix table holds %d entries, the bound is %d", n, maxPrefixBans)
	}
	// Banning the same network again extends it rather than adding a
	// second entry, and counts the repeat.
	before := n
	if _, err := l.Ban("100.0.0.0/16", 2*time.Hour, "net"); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	after := len(l.prefixes)
	l.mu.Unlock()
	if after > before {
		t.Fatalf("re-banning a network grew the table from %d to %d", before, after)
	}
	*now = now.Add(3 * time.Hour)
	l.Purge()
	l.mu.Lock()
	left := len(l.prefixes)
	l.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d prefix bans survived their expiry", left)
	}
}

// TestPurgeSweepsEveryTable requires a purge to clear addresses,
// networks, fingerprints and the trigger windows together. A table that
// kept its expired entries would eventually refuse a live client on the
// strength of a ban that ended.
func TestPurgeSweepsEveryTable(t *testing.T) {
	l, now := newList(t, cfg())
	if _, err := l.Ban("192.0.2.1", time.Minute, "addr"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("198.51.100.0/24", time.Minute, "net"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("ja4:t13d1516h2_8daaf6152771_02713d6af862", time.Minute, "fp"); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	l.Observe(ip, "waf")
	l.Observe(ip, "waf")
	if got := len(l.Entries()); got != 3 {
		t.Fatalf("%d bans before the purge", got)
	}

	// Before expiry a purge changes nothing.
	l.Purge()
	if got := len(l.Entries()); got != 3 {
		t.Fatalf("%d bans after an early purge", got)
	}

	*now = now.Add(2 * time.Minute)
	l.Purge()
	if got := len(l.Entries()); got != 0 {
		t.Fatalf("%d bans survived their expiry: %v", got, l.Entries())
	}
	if l.Banned(netip.MustParseAddr("192.0.2.1")) || l.Banned(netip.MustParseAddr("198.51.100.5")) {
		t.Fatal("an expired ban still refuses a client")
	}
	// The trigger window went with it: two more observations must not
	// complete a threshold of three.
	l.Observe(ip, "waf")
	l.Observe(ip, "waf")
	if l.Banned(ip) {
		t.Fatal("observations from before the window expired still counted")
	}
}

// TestStateFilePath covers the accessor the status view prints, which
// is how an operator finds the file to back up or remove.
func TestStateFilePath(t *testing.T) {
	l, _ := newList(t, cfg())
	if got := l.StateFile(); got != "" {
		t.Fatalf("a list with no state file reports %q", got)
	}
	c := cfg()
	c.StateFile = filepath.Join(t.TempDir(), "bans.db")
	withFile, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer withFile.Close()
	if got := withFile.StateFile(); got != c.StateFile {
		t.Fatalf("StateFile is %q, want %q", got, c.StateFile)
	}
}

// TestStateFileFailures covers the paths a state file cannot be opened
// at. A ban list that cannot persist must still be a ban list: the
// alternative is a proxy that refuses to start because a disk is full,
// with every ban it would have enforced going unenforced instead.
func TestStateFileFailures(t *testing.T) {
	dir := t.TempDir()
	c := cfg()
	c.StateFile = filepath.Join(dir, "no", "such", "dir", "bans.db")
	l, err := New(c, nolog)
	if err == nil {
		defer l.Close()
		// It started: then it must work in memory.
		if _, err := l.Ban("192.0.2.1", time.Hour, "x"); err != nil {
			t.Fatalf("a list without a usable state file cannot ban: %v", err)
		}
		if !l.Banned(netip.MustParseAddr("192.0.2.1")) {
			t.Fatal("the in-memory ban did not take")
		}
		return
	}
	// Or it refused, and said which file it could not open.
	if !contains(err.Error(), "bans.db") {
		t.Fatalf("the error does not name the file: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestPersistedEntriesSurviveManyWrites drives enough bans through the
// write queue to make it fall back to the synchronous path, then
// reopens the file. Every live ban must be there: the queue exists to
// keep writes off the request path, not to lose them.
func TestPersistedEntriesSurviveManyWrites(t *testing.T) {
	c := cfg()
	c.MaxEntries = 100000
	c.StateFile = filepath.Join(t.TempDir(), "bans.db")
	l, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	const n = 2000
	for i := 0; i < n; i++ {
		if _, err := l.Ban(fmt.Sprintf("192.0.%d.%d", i/256, i%256), time.Hour, "bulk"); err != nil {
			t.Fatalf("ban %d: %v", i, err)
		}
	}
	l.Close() // the writer drains the queue before this returns

	reopened, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	missing := 0
	for i := 0; i < n; i++ {
		if !reopened.Banned(netip.MustParseAddr(fmt.Sprintf("192.0.%d.%d", i/256, i%256))) {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("%d of %d bans were lost across a restart", missing, n)
	}
}

// TestCloseIsIdempotent covers the shutdown path, which runs on a
// reload as well as on a stop.
func TestCloseIsIdempotent(t *testing.T) {
	c := cfg()
	c.StateFile = filepath.Join(t.TempDir(), "bans.db")
	l, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("192.0.2.1", time.Hour, "x"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l.Close()
	l.Close()
}

// TestBanTargetsThatAreNotTargets covers the strings that reach Ban
// from the management socket, where an operator types them.
func TestBanTargetsThatAreNotTargets(t *testing.T) {
	l, _ := newList(t, cfg())
	for _, target := range []string{
		"", " ", "not-an-address", "192.0.2", "192.0.2.1/33", "192.0.2.256",
		"2001:db8::/129", "ja4:", "ja4:" + string(make([]byte, 300)),
		"192.0.2.1;DROP",
	} {
		if _, err := l.Ban(target, time.Hour, "manual"); err == nil {
			t.Errorf("Ban(%q) was accepted", target)
		}
	}
	// And the ones that are, including the forms an operator types with
	// a stray space or a trailing newline on a command line: those are
	// trimmed to one spelling rather than becoming a second key.
	for _, target := range []string{
		"192.0.2.1", "2001:db8::1", "198.51.100.0/24", "2001:db8::/32",
		"ja4:t13d1516h2_8daaf6152771_02713d6af862",
		"203.0.113.1 ", " 203.0.113.2", "203.0.113.3\n",
	} {
		if _, err := l.Ban(target, time.Hour, "manual"); err != nil {
			t.Errorf("Ban(%q): %v", target, err)
		}
	}
}

// TestExemptBeatsEverything requires an exempt range to survive every
// path into the list: a manual ban, a trigger, and a restart that
// restores one from the state file.
func TestExemptBeatsEverything(t *testing.T) {
	c := cfg()
	c.ExemptCIDRs = []string{"10.0.0.0/8", "192.0.2.0/24"}
	c.StateFile = filepath.Join(t.TempDir(), "bans.db")
	l, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("192.0.2.1", time.Hour, "manual"); err == nil {
		t.Fatal("an exempt address was banned by hand")
	}
	ip := netip.MustParseAddr("10.1.2.3")
	for i := 0; i < 10; i++ {
		l.Observe(ip, "waf")
	}
	if l.Banned(ip) {
		t.Fatal("a trigger banned an exempt address")
	}
	// A ban recorded before the exemption existed must not come back
	// to life when the file is reloaded under the new configuration.
	if _, err := l.Ban("203.0.113.1", time.Hour, "manual"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	c2 := cfg()
	c2.StateFile = c.StateFile
	c2.ExemptCIDRs = []string{"203.0.113.0/24"}
	l2, err := New(c2, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if l2.Banned(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("a ban on a now-exempt address was restored from the state file")
	}
}

// TestObserveIsSafeConcurrently drives the list from many goroutines:
// every deny in the proxy calls Observe, from every listener's
// goroutines at once.
func TestObserveIsSafeConcurrently(t *testing.T) {
	l, _ := newList(t, cfg())
	done := make(chan struct{})
	for g := 0; g < 16; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				ip := netip.MustParseAddr(fmt.Sprintf("203.0.%d.%d", g, i%256))
				l.Observe(ip, "waf")
				l.Banned(ip)
				if i%50 == 0 {
					l.Entries()
					l.Purge()
				}
			}
		}(g)
	}
	for g := 0; g < 16; g++ {
		<-done
	}
}

var _ = config.Bans{}
