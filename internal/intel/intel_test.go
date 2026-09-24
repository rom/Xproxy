package intel

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The forms a feed is actually written in, and the order that decides.
func TestAListIsReadAsAFeedIsWritten(t *testing.T) {
	dir := t.TempDir()
	cidr := write(t, dir, "nets.txt", `# a comment
; another
// and another

10.0.0.0/8
192.0.2.7
2001:db8::/32
198.51.100.0/24   # trailing comment
203.0.113.5	tab and a note
`)
	ja4 := write(t, dir, "fp.txt", "t13d1516h2_8daaf6152771_02713d6af862\n")
	s, err := New([]Spec{
		{Name: "nets", Kind: KindCIDR, Action: ActionBlock, File: cidr},
		{Name: "fingerprints", Kind: KindJA4, Action: ActionChallenge, File: ja4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); len(st) != 2 || st[0].Entries != 5 || st[1].Entries != 1 {
		t.Fatalf("entries read as %+v", st)
	}
	for _, tc := range []struct {
		ip, ja4, list string
		want          bool
	}{
		{"10.1.2.3", "", "nets", true},
		{"192.0.2.7", "", "nets", true},
		{"192.0.2.8", "", "", false},
		{"2001:db8::1", "", "nets", true},
		{"198.51.100.200", "", "nets", true},
		{"203.0.113.5", "", "nets", true},
		{"203.0.113.6", "", "", false},
		// An IPv4-mapped IPv6 address is the same client as the IPv4 one.
		{"::ffff:10.1.2.3", "", "nets", true},
		// A fingerprint matches its own list and nothing else.
		{"8.8.8.8", "t13d1516h2_8daaf6152771_02713d6af862", "fingerprints", true},
		{"8.8.8.8", "t13d1516h2_other_fingerprint", "", false},
		{"8.8.8.8", "", "", false},
	} {
		ip, err := netip.ParseAddr(tc.ip)
		if err != nil {
			t.Fatal(err)
		}
		hit, ok := s.Match(ip, tc.ja4)
		if ok != tc.want || hit.List != tc.list {
			t.Errorf("Match(%s, %q) = %+v %v, want %q %v", tc.ip, tc.ja4, hit, ok, tc.list, tc.want)
		}
	}
	// The action comes from the list that matched, not from the set.
	if hit, _ := s.Match(netip.MustParseAddr("10.0.0.1"), ""); hit.Action != ActionBlock {
		t.Errorf("action %q, want %q", hit.Action, ActionBlock)
	}
	if s.Matches.Load() == 0 {
		t.Error("matches were not counted")
	}
}

// The order is the policy: the first list that matches decides.
func TestTheFirstListThatMatchesDecides(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.txt", "10.0.0.0/8\n")
	b := write(t, dir, "b.txt", "10.1.0.0/16\n")
	s, err := New([]Spec{
		{Name: "broad", Kind: KindCIDR, Action: ActionBlock, File: a},
		{Name: "narrow", Kind: KindCIDR, Action: ActionChallenge, File: b},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hit, _ := s.Match(netip.MustParseAddr("10.1.2.3"), ""); hit.List != "broad" {
		t.Errorf("%+v, want the first list", hit)
	}
}

// A list that cannot be read is a load error, not a list that matches
// nothing: the operator believes an imported list works.
func TestAListThatCannotBeReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := New([]Spec{{Name: "missing", File: filepath.Join(dir, "nope.txt")}}); err == nil {
		t.Error("a missing file was accepted")
	}
	bad := write(t, dir, "bad.txt", "10.0.0.0/8\nnot-an-address\n")
	_, err := New([]Spec{{Name: "bad", File: bad}})
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %v, want one naming the line", err)
	}
	// A network with host bits set is masked rather than refused: feeds
	// are written both ways and both mean the same network.
	masked := write(t, dir, "masked.txt", "10.1.2.3/8\n")
	s, err := New([]Spec{{Name: "masked", File: masked}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Match(netip.MustParseAddr("10.9.9.9"), ""); !ok {
		t.Error("a network with host bits set did not match its own range")
	}
	// A fingerprint list refuses a line no fingerprint could be.
	long := write(t, dir, "long.txt", strings.Repeat("x", 200)+"\n")
	if _, err := New([]Spec{{Name: "long", Kind: KindJA4, File: long}}); err == nil {
		t.Error("a 200 character fingerprint was accepted")
	}
}

// A feed changes; the proxy re-reads it without a reload of the whole
// configuration, and only the files that changed.
func TestOnlyAChangedFileIsReRead(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.txt", "10.0.0.0/8\n")
	b := write(t, dir, "b.txt", "192.0.2.0/24\n")
	s, err := New([]Spec{
		{Name: "a", File: a}, {Name: "b", File: b},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reload(); n != 0 || err != nil {
		t.Errorf("an unchanged set re-read %d lists: %v", n, err)
	}
	// Rewrite one of them, far enough from the first write that the
	// modification time differs on a coarse clock.
	time.Sleep(10 * time.Millisecond)
	write(t, dir, "a.txt", "10.0.0.0/8\n203.0.113.0/24\n")
	n, err := s.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d lists re-read, want 1", n)
	}
	if _, ok := s.Match(netip.MustParseAddr("203.0.113.9"), ""); !ok {
		t.Error("the new entry does not match")
	}
	if s.Reloads.Load() != 1 {
		t.Errorf("reloads counted: %d", s.Reloads.Load())
	}
	// A file that changed into something unreadable reports the error and
	// keeps what was loaded: a feed with a bad line in it must not empty
	// the policy either, and the error is how anybody finds out.
	time.Sleep(10 * time.Millisecond)
	write(t, dir, "a.txt", "10.0.0.0/8\nnot-an-address\n")
	n, err = s.Reload()
	if err == nil || !strings.Contains(err.Error(), "not-an-address") {
		t.Errorf("a malformed re-read reported %v, want the bad line", err)
	}
	if n != 0 {
		t.Errorf("%d lists counted as re-read, want 0", n)
	}
	if _, ok := s.Match(netip.MustParseAddr("203.0.113.9"), ""); !ok {
		t.Error("the entries were dropped for a file that stopped parsing")
	}
	if s.Reloads.Load() != 1 {
		t.Errorf("a failed re-read was counted: %d", s.Reloads.Load())
	}

	// A file being rewritten in place is unreadable for a moment, and
	// that moment must not empty the policy.
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reload(); err == nil {
		t.Error("a missing file should be reported")
	}
	if _, ok := s.Match(netip.MustParseAddr("203.0.113.9"), ""); !ok {
		t.Error("the entries were dropped when the file went away")
	}
}

// A nil set is the shape a listener with no section has, and nothing
// about it may panic.
func TestANilSetMatchesNothing(t *testing.T) {
	var s *Set
	if _, ok := s.Match(netip.MustParseAddr("10.0.0.1"), "x"); ok {
		t.Error("a nil set matched")
	}
	if n, err := s.Reload(); n != 0 || err != nil {
		t.Errorf("reload of a nil set: %d %v", n, err)
	}
	if s.Status() != nil || s.Len() != 0 {
		t.Error("a nil set reported lists")
	}
	// And an empty set is the same thing with a section present.
	empty, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := empty.Match(netip.MustParseAddr("10.0.0.1"), ""); ok {
		t.Error("an empty set matched")
	}
}

// The refresh loop picks up a feed that changed on its own schedule,
// which is the alternative to an operator reloading the proxy for it.
func TestTheRefreshLoopReReadsAChangedFile(t *testing.T) {
	dir := t.TempDir()
	f := write(t, dir, "a.txt", "10.0.0.0/8\n")
	s, err := New([]Spec{{Name: "a", File: f}})
	if err != nil {
		t.Fatal(err)
	}
	var errs int
	s.Refresh(5*time.Millisecond, func(error) { errs++ })
	defer s.Stop()
	time.Sleep(10 * time.Millisecond)
	write(t, dir, "a.txt", "10.0.0.0/8\n203.0.113.0/24\n")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.Match(netip.MustParseAddr("203.0.113.9"), ""); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refresh loop did not pick up the new entry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !s.Refreshing() {
		t.Error("the set does not report that it is refreshing")
	}

	// Stopping twice, and stopping a set that never refreshed, are both
	// fine: a reload replaces the set and stops the old one.
	s.Stop()
	s.Stop()
	quiet, err := New([]Spec{{Name: "a", File: f}})
	if err != nil {
		t.Fatal(err)
	}
	quiet.Stop()
	if s.Refreshing() {
		t.Error("a stopped set still reports that it is refreshing")
	}
	// A refresh with no interval and a refresh of an empty set start
	// nothing at all.
	quiet.Refresh(0, nil)
	empty, _ := New(nil)
	empty.Refresh(time.Millisecond, nil)
	if quiet.Refreshing() || empty.Refreshing() {
		t.Error("a set with nothing to refresh started a loop")
	}
	empty.Stop()
	var none *Set
	if none.Refreshing() {
		t.Error("a nil set reports a refresh loop")
	}
}
