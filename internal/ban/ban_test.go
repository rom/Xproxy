package ban

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

func cfg() *config.Bans {
	return &config.Bans{
		MaxEntries: 1000, Action: "drop", ExemptCIDRs: []string{"10.0.0.0/8"},
		Triggers: []config.BanTrigger{{
			Name: "t", Reasons: []string{"waf", "rate_limit"}, Threshold: 3,
			Window: config.Duration(time.Minute), Duration: config.Duration(time.Minute),
			Escalation: 2, MaxDuration: config.Duration(5 * time.Minute),
		}},
	}
}

func newList(t *testing.T, c *config.Bans) (*List, *time.Time) {
	t.Helper()
	l, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	t.Cleanup(l.Close)
	return l, &now
}

func TestTriggerAndEscalation(t *testing.T) {
	l, now := newList(t, cfg())
	ip := netip.MustParseAddr("203.0.113.5")
	for i := 0; i < 3; i++ {
		if l.Observe(ip, "acl") != nil {
			t.Fatal("acl is not a configured reason")
		}
	}
	if l.Observe(ip, "waf") != nil || l.Observe(ip, "rate_limit") != nil {
		t.Fatal("banned too early")
	}
	e := l.Observe(ip, "waf")
	if e == nil || e.Count != 1 || e.Until.Sub(*now) != time.Minute {
		t.Fatalf("first ban: %+v", e)
	}
	if !l.Banned(ip) || l.Banned(netip.MustParseAddr("203.0.113.6")) {
		t.Fatal("Banned lookup")
	}
	// Expiry.
	*now = now.Add(2 * time.Minute)
	if l.Banned(ip) {
		t.Fatal("ban did not expire")
	}
	// Second ban escalates to 2 minutes, third to 4, fourth capped at 5.
	for i, want := range []time.Duration{2 * time.Minute, 4 * time.Minute, 5 * time.Minute} {
		var e *Entry
		for j := 0; j < 3; j++ {
			e = l.Observe(ip, "waf")
		}
		if e == nil || e.Until.Sub(*now) != want {
			t.Fatalf("ban %d: %+v want %v", i+2, e, want)
		}
		*now = now.Add(want + time.Second)
	}
	active, total := l.Stats()
	if active != 0 || total != 4 {
		t.Fatalf("stats %d %d", active, total)
	}
}

func TestWindowReset(t *testing.T) {
	l, now := newList(t, cfg())
	ip := netip.MustParseAddr("203.0.113.7")
	l.Observe(ip, "waf")
	l.Observe(ip, "waf")
	*now = now.Add(2 * time.Minute)
	if l.Observe(ip, "waf") != nil {
		t.Fatal("window did not reset")
	}
}

func TestExemptAndManual(t *testing.T) {
	l, _ := newList(t, cfg())
	ex := netip.MustParseAddr("10.1.2.3")
	for i := 0; i < 10; i++ {
		if l.Observe(ex, "waf") != nil {
			t.Fatal("exempt address banned")
		}
	}
	if _, err := l.Ban("10.1.2.3", time.Hour, "x"); err == nil {
		t.Fatal("manual ban of exempt address accepted")
	}
	if _, err := l.Ban("127.0.0.1", time.Hour, "x"); err == nil {
		t.Fatal("loopback ban accepted")
	}
	if _, err := l.Ban("0.0.0.0/0", time.Hour, "x"); err == nil {
		t.Fatal("wide prefix accepted")
	}
	if _, err := l.Ban("garbage", time.Hour, "x"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := l.Ban("198.51.100.0/24", 0, "x"); err == nil {
		t.Fatal("zero duration accepted")
	}
	e, err := l.Ban("198.51.100.0/24", time.Hour, "scanner")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Banned(netip.MustParseAddr("198.51.100.77")) || l.Banned(netip.MustParseAddr("198.51.101.1")) {
		t.Fatal("prefix ban")
	}
	if _, err := l.Ban("192.0.2.1", time.Hour, "manual"); err != nil {
		t.Fatal(err)
	}
	// IPv4-mapped lookups normalise.
	if !l.Banned(netip.MustParseAddr("::ffff:192.0.2.1")) {
		t.Fatal("mapped lookup")
	}
	es := l.Entries()
	if len(es) != 2 || es[0].Source != "manual" {
		t.Fatalf("entries: %+v", es)
	}
	if err := l.Unban(e.Target); err != nil {
		t.Fatal(err)
	}
	if err := l.Unban(e.Target); !errors.Is(err, ErrNotFound) {
		t.Fatal("second unban should be not found")
	}
	if l.Banned(netip.MustParseAddr("198.51.100.77")) {
		t.Fatal("still banned")
	}
}

func TestBound(t *testing.T) {
	c := cfg()
	c.MaxEntries = 100
	l, _ := newList(t, c)
	for i := 0; i < 300; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)})
		if _, err := l.Ban(ip.String(), time.Duration(i+1)*time.Second, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(l.addrs); n > 100 {
		t.Fatalf("table grew to %d", n)
	}
}

func TestPersistence(t *testing.T) {
	c := cfg()
	c.StateFile = filepath.Join(t.TempDir(), "bans.db")
	l, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("192.0.2.9", time.Hour, "persist"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("192.0.2.10", time.Millisecond, "short"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ban("198.51.100.0/24", time.Hour, "net"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	time.Sleep(5 * time.Millisecond)
	l2, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if !l2.Banned(netip.MustParseAddr("192.0.2.9")) || !l2.Banned(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("bans not restored")
	}
	if l2.Banned(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("expired ban restored")
	}
	if err := l2.Unban("192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	l3, _ := New(c, nolog)
	defer l3.Close()
	if l3.Banned(netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("unban not persisted")
	}
}

func TestOnChangeAndApply(t *testing.T) {
	l, now := newList(t, cfg())
	type ev struct {
		target  string
		removed bool
	}
	var events []ev
	l.OnChange(func(e Entry, removed bool) { events = append(events, ev{e.Target, removed}) })
	if _, err := l.Ban("192.0.2.30", time.Hour, "x"); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.30")
	for i := 0; i < 3; i++ {
		l.Observe(ip, "waf")
	}
	if err := l.Unban("192.0.2.30"); err != nil {
		t.Fatal(err)
	}
	// Peer applied bans do not echo.
	if err := l.Apply(Entry{Target: "192.0.2.31", Until: now.Add(time.Hour), Reason: "r"}, false, "nodeB"); err != nil {
		t.Fatal(err)
	}
	if err := l.Apply(Entry{Target: "192.0.2.32", Until: now.Add(-time.Hour)}, false, "nodeB"); err != nil {
		t.Fatal(err)
	}
	if err := l.Apply(Entry{Target: "10.1.1.1", Until: now.Add(time.Hour)}, false, "nodeB"); err != nil {
		t.Fatal(err)
	}
	if err := l.Apply(Entry{Target: "garbage"}, false, "nodeB"); err == nil {
		t.Fatal("garbage applied")
	}
	if len(events) != 3 || events[0] != (ev{"192.0.2.30", false}) || events[1] != (ev{"203.0.113.30", false}) || events[2] != (ev{"192.0.2.30", true}) {
		t.Fatalf("events %+v", events)
	}
	if !l.Banned(netip.MustParseAddr("192.0.2.31")) || l.Banned(netip.MustParseAddr("192.0.2.32")) || l.Banned(netip.MustParseAddr("10.1.1.1")) {
		t.Fatal("apply semantics")
	}
	var src string
	for _, e := range l.Entries() {
		if e.Target == "192.0.2.31" {
			src = e.Source
		}
	}
	if src != "peer:nodeB" {
		t.Fatalf("source %q", src)
	}
	if err := l.Apply(Entry{Target: "192.0.2.31"}, true, "nodeB"); err != nil || l.Banned(netip.MustParseAddr("192.0.2.31")) {
		t.Fatal("peer unban")
	}
}

func TestReconfigure(t *testing.T) {
	l, _ := newList(t, cfg())
	ip := netip.MustParseAddr("203.0.113.9")
	if _, err := l.Ban(ip.String(), time.Hour, "x"); err != nil {
		t.Fatal(err)
	}
	c := cfg()
	c.Triggers = nil
	c.Action = "reject"
	l.Reconfigure(c)
	if !l.Banned(ip) || l.DropsConnections() {
		t.Fatal("reconfigure lost state or action")
	}
	for i := 0; i < 5; i++ {
		if l.Observe(netip.MustParseAddr("203.0.113.10"), "waf") != nil {
			t.Fatal("trigger still active")
		}
	}
}

func TestAggregates(t *testing.T) {
	c := cfg()
	c.Triggers = []config.BanTrigger{
		{Name: "net", Reasons: []string{"rate_limit"}, Threshold: 6, MinSources: 3, Aggregate: "net", NetV4: 24, NetV6: 48,
			Window: config.Duration(time.Minute), Duration: config.Duration(time.Minute), Escalation: 2, MaxDuration: config.Duration(5 * time.Minute)},
		{Name: "tool", Reasons: []string{"waf"}, Threshold: 4, MinSources: 2, Aggregate: "ja4",
			Window: config.Duration(time.Minute), Duration: config.Duration(time.Minute), Escalation: 2, MaxDuration: config.Duration(5 * time.Minute)},
	}
	l, now := newList(t, c)
	// Six denies from one address do not reach three sources: no ban.
	one := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 6; i++ {
		if l.Observe(one, "rate_limit") != nil {
			t.Fatal("single source banned the network")
		}
	}
	// Two more addresses of the same /24 complete the sources: the
	// network is banned and a fresh address in it is refused.
	l.Observe(netip.MustParseAddr("203.0.113.10"), "rate_limit")
	e := l.Observe(netip.MustParseAddr("203.0.113.11"), "rate_limit")
	if e == nil || e.Target != "203.0.113.0/24" || e.Source != "trigger:net" {
		t.Fatalf("network ban: %+v", e)
	}
	if !l.Banned(netip.MustParseAddr("203.0.113.200")) || l.Banned(netip.MustParseAddr("203.0.114.1")) {
		t.Fatal("prefix lookup")
	}
	// IPv6 aggregates on the /48.
	for i := 0; i < 5; i++ {
		l.Observe(netip.MustParseAddr("2001:db8:1:"+string(rune('a'+i))+"::1"), "rate_limit")
	}
	if e := l.Observe(netip.MustParseAddr("2001:db8:1:f::9"), "rate_limit"); e == nil || e.Target != "2001:db8:1::/48" {
		t.Fatalf("ipv6 network ban: %+v", e)
	}
	// A network overlapping an exempt range is never banned.
	for i := 0; i < 6; i++ {
		l.Observe(netip.MustParseAddr("10.0.0."+string(rune('1'+i))), "rate_limit")
	}
	if l.Banned(netip.MustParseAddr("10.0.0.99")) {
		t.Fatal("exempt network banned")
	}
	// Fingerprint bans: plaintext clients (no ja4) do not count; two
	// addresses sharing a fingerprint reach the threshold; the
	// fingerprint is then refused from any address except exempt ones.
	fp := "t13d0403h1_000000000000_000000000000"
	for i := 0; i < 4; i++ {
		if l.ObserveClient(netip.MustParseAddr("198.51.100.1"), "", "waf") != nil {
			t.Fatal("plaintext client counted for ja4")
		}
	}
	l.ObserveClient(netip.MustParseAddr("198.51.100.1"), fp, "waf")
	l.ObserveClient(netip.MustParseAddr("198.51.100.1"), fp, "waf")
	l.ObserveClient(netip.MustParseAddr("198.51.100.1"), fp, "waf")
	e = l.ObserveClient(netip.MustParseAddr("198.51.100.2"), fp, "waf")
	if e == nil || e.Target != FingerprintPrefix+fp || e.Count != 1 {
		t.Fatalf("fingerprint ban: %+v", e)
	}
	if !l.BannedFingerprint(fp) || l.BannedFingerprint("other") || !l.BannedClient(netip.MustParseAddr("192.0.2.77"), fp) {
		t.Fatal("fingerprint lookup")
	}
	if l.BannedClient(netip.MustParseAddr("10.2.3.4"), fp) || l.BannedClient(netip.MustParseAddr("192.0.2.77"), "") {
		t.Fatal("exempt address or plaintext client refused by a fingerprint ban")
	}
	// Entries and stats include every kind; the fingerprint entry can be
	// listed, unbanned, banned manually and refused when malformed.
	if es := l.Entries(); len(es) != 3 {
		t.Fatalf("entries %+v", es)
	}
	if active, _ := l.Stats(); active != 3 {
		t.Fatalf("active %d", active)
	}
	if err := l.Unban(FingerprintPrefix + fp); err != nil || l.BannedFingerprint(fp) || l.hasFP.Load() {
		t.Fatalf("unban fingerprint: %v", err)
	}
	if _, err := l.Ban(FingerprintPrefix+"t13d1516h2_8daaf6152771_b0da82dd1658", time.Hour, "tool"); err != nil {
		t.Fatal(err)
	}
	if !l.BannedFingerprint("t13d1516h2_8daaf6152771_b0da82dd1658") {
		t.Fatal("manual fingerprint ban")
	}
	for _, bad := range []string{FingerprintPrefix, FingerprintPrefix + "short", FingerprintPrefix + "UPPER_CASE_123456", FingerprintPrefix + "has space here_x"} {
		if _, err := l.Ban(bad, time.Hour, "x"); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// Escalation follows the fingerprint target; expiry purges it.
	*now = now.Add(2 * time.Hour)
	l.Purge()
	if l.hasFP.Load() || l.BannedFingerprint("t13d1516h2_8daaf6152771_b0da82dd1658") {
		t.Fatal("expired fingerprint ban still active")
	}
	// A peer's fingerprint ban applies; a network ban touching an exempt
	// range does not.
	if err := l.Apply(Entry{Target: FingerprintPrefix + fp, Until: now.Add(time.Hour), Reason: "peer"}, false, "n2"); err != nil || !l.BannedFingerprint(fp) {
		t.Fatalf("peer fingerprint ban: %v", err)
	}
	if err := l.Apply(Entry{Target: "10.0.0.0/24", Until: now.Add(time.Hour)}, false, "n2"); err != nil || l.Banned(netip.MustParseAddr("10.0.0.5")) {
		t.Fatalf("peer exempt network ban: %v", err)
	}
	if err := l.Apply(Entry{Target: FingerprintPrefix + fp}, true, "n2"); err != nil || l.BannedFingerprint(fp) {
		t.Fatalf("peer fingerprint unban: %v", err)
	}
}

func TestFingerprintPersistence(t *testing.T) {
	c := cfg()
	c.StateFile = filepath.Join(t.TempDir(), "bans.db")
	l, now := newList(t, c)
	*now = time.Now() // the reloading list checks expiry against the wall clock
	fp := "t13d0403h1_000000000000_000000000000"
	if _, err := l.Ban(FingerprintPrefix+fp, time.Hour, "tool"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l2, err := New(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	l2.now = func() time.Time { return *now }
	defer l2.Close()
	if !l2.BannedFingerprint(fp) {
		t.Fatal("fingerprint ban not persisted")
	}
}

// A ban used to cost one synchronous db.Update — one fsync — on the
// request goroutine, and a full history table was scanned on every
// trigger. Both are work a flood of distinct clients drives.
func TestTriggerBansAreBatchedAndHistoryIsBounded(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Bans{
		Action:     "reject",
		StateFile:  filepath.Join(dir, "bans.db"),
		MaxEntries: 4096,
		Triggers: []config.BanTrigger{{
			Name: "deny", Reasons: []string{"acl"}, Threshold: 1,
			Window: config.Duration(time.Minute), Duration: config.Duration(time.Minute),
			MaxDuration: config.Duration(time.Hour), Escalation: 2,
		}},
	}
	l, err := New(cfg, nolog)
	if err != nil {
		t.Fatal(err)
	}
	l.max = 64 // a small history table, so the bound is reached
	const clients = 500
	for i := 0; i < clients; i++ {
		l.Observe(netip.MustParseAddr(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)), "acl")
	}
	l.mu.Lock()
	hist, lru := len(l.history), l.histLRU.Len()
	l.mu.Unlock()
	if hist > l.max || hist != lru {
		t.Fatalf("history %d, lru %d, bound %d", hist, lru, l.max)
	}
	// Close drains the write queue, so every ban is on disk afterwards.
	l.Close()
	l2, err := New(cfg, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if n := len(l2.Entries()); n != clients {
		t.Fatalf("%d bans survived the restart, want %d", n, clients)
	}
}
