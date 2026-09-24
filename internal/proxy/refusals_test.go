package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/rom/xproxy/internal/listener"
)

// The reason a kind logs and the label an operator queries are the same
// word, with the kind's own prefix taken off: the kind label already
// says "vnc", so a reason of "vnc_version" would read as vnc twice.
func TestRefusalReasonDropsTheKindsOwnPrefix(t *testing.T) {
	var s Stats
	s.Refuse("vnc", "vnc_version")
	s.Refuse("rdp", "rdp_negotiate")
	s.Refuse("ssh", "auth_failed") // already unprefixed
	s.Refuse("ftp", "")            // a caller with no reason at all
	got := s.RefusalCounts()
	for _, c := range []struct{ kind, reason string }{
		{"vnc", "version"}, {"rdp", "negotiate"}, {"ssh", "auth_failed"}, {"ftp", "unspecified"},
	} {
		if got[c.kind][c.reason] != 1 {
			t.Errorf("%s/%s counted %d, want 1 (have %v)", c.kind, c.reason, got[c.kind][c.reason], got[c.kind])
		}
	}
	// The prefix is only stripped when it is the kind's own: a udp
	// listener refusing "udp_denied" is one thing, an ssh listener
	// whose reason happens to start with "udpsomething" is another.
	s.Refuse("ssh", "udp_thing")
	if got := s.RefusalCounts(); got["ssh"]["udp_thing"] != 1 {
		t.Errorf("a reason prefixed with another kind's name was rewritten: %v", got["ssh"])
	}
}

// A reason must not be attributable to a kind the roster does not have:
// that is the only way a caller could grow the outer map. It is counted
// rather than dropped, because a refusal nobody can see is worse than
// one with no label.
func TestRefuseRejectsAKindTheRosterDoesNotHave(t *testing.T) {
	var s Stats
	s.Refuse("gopher", "whatever")
	s.Refuse("", "whatever")
	if got := s.RefusalCounts(); len(got) != 0 {
		t.Errorf("an unknown kind reached the table: %v", got)
	}
	if n := s.RefusalsUntracked.Load(); n != 2 {
		t.Errorf("untracked counted %d, want 2", n)
	}
}

// One kind's reason set is bounded. Reasons are string literals in the
// kinds, so the bound is a guard against this repository outgrowing it
// rather than against a client, and reaching it counts the refusal
// somewhere rather than losing it.
func TestRefusalReasonsAreBounded(t *testing.T) {
	var s Stats
	for i := 0; i < maxRefusalReasons+10; i++ {
		s.Refuse("ssh", "reason_"+strings.Repeat("x", i))
	}
	got := s.RefusalCounts()
	if len(got["ssh"]) != maxRefusalReasons {
		t.Errorf("held %d reasons, want the bound %d", len(got["ssh"]), maxRefusalReasons)
	}
	if n := s.RefusalsUntracked.Load(); n != 10 {
		t.Errorf("untracked counted %d, want the 10 past the bound", n)
	}
	// A reason already in the table still counts after the bound is
	// reached: the bound stops the table growing, not the counting.
	before := got["ssh"]["reason_"]
	s.Refuse("ssh", "reason_")
	if after := s.RefusalCounts()["ssh"]["reason_"]; after != before+1 {
		t.Errorf("a known reason went from %d to %d after the bound", before, after)
	}
}

// The counting path is taken from every connection goroutine at once.
func TestRefuseIsConcurrent(t *testing.T) {
	var s Stats
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s.Refuse("ftp", "command_refused")
				s.Refuse("ftp", "path_refused")
				s.Refuse("ssh", "auth_failed")
			}
		}(i)
	}
	wg.Wait()
	got := s.RefusalCounts()
	for _, c := range []struct {
		kind, reason string
		want         uint64
	}{{"ftp", "command_refused", 1600}, {"ftp", "path_refused", 1600}, {"ssh", "auth_failed", 1600}} {
		if got[c.kind][c.reason] != c.want {
			t.Errorf("%s/%s counted %d, want %d", c.kind, c.reason, got[c.kind][c.reason], c.want)
		}
	}
}

// The snapshot carries the breakdown, so xproxyctl and the management
// API see what the metrics endpoint sees.
func TestSnapshotCarriesRefusals(t *testing.T) {
	var s Stats
	if sn := s.snapshot(); sn.Refusals != nil {
		t.Errorf("a process that refused nothing reported %v", sn.Refusals)
	}
	s.Refuse("mqtt", "publish_topic_refused")
	sn := s.snapshot()
	if sn.Refusals["mqtt"]["publish_topic_refused"] != 1 {
		t.Errorf("snapshot refusals %v", sn.Refusals)
	}
	if sn.RefusalsUntracked != 0 {
		t.Errorf("untracked %d in a healthy snapshot", sn.RefusalsUntracked)
	}
}

// Every listener kind reports its refusals, and reports them under its
// own name. A kind added without this is a protocol whose refusals are
// one aggregate number again, which is the thing this family exists to
// stop; a kind that passes a sibling's name is a label nobody can read.
//
// http is exempt: its refusals are the twenty-two named counters on this
// struct, exported as xproxy_denied_total, which this family is the
// other protocols' equivalent of rather than a replacement for.
func TestEveryKindReportsItsRefusals(t *testing.T) {
	const kindsDir = "../kinds"
	exempt := map[string]bool{"http": true}
	entries, err := os.ReadDir(kindsDir)
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`Refuse\("([a-z0-9_]*)"`)
	for _, e := range entries {
		if !e.IsDir() || exempt[e.Name()] {
			continue
		}
		kind := e.Name()
		if _, known := listener.RoleOf(kind); !known {
			t.Errorf("internal/kinds/%s is not a kind the roster names", kind)
			continue
		}
		files, err := filepath.Glob(filepath.Join(kindsDir, kind, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		reported := false
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range call.FindAllStringSubmatch(string(src), -1) {
				if m[1] != kind {
					t.Errorf("%s reports a refusal as kind %q", f, m[1])
					continue
				}
				reported = true
			}
		}
		if !reported {
			t.Errorf("kind %s refuses connections without naming a reason: no Counters().Refuse(%q, ...) in internal/kinds/%s", kind, kind, kind)
		}
	}
}
