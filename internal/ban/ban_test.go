package ban

import (
	"errors"
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
