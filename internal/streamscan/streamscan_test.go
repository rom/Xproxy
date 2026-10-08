package streamscan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/testutil"
)

// The shared stream scanner, on its own.
//
// Four kinds relay through this -- layer 4, SFTP writes, FTP transfers and the
// plaintext inside an intercepted tunnel -- and each had its own end-to-end test
// of a match closing a connection. What none of them reach is the shape of the
// thing: which directions a guard builds a stream for, where the byte bound
// stops the scanning, and what a nil stream does when a caller that has no
// policy feeds it anyway. Those are properties of this package, so they are
// tested here rather than four times through four protocols.

const marker = "TOP-SECRET-MARKER"

func guard(t *testing.T, c *config.YARAPolicy) *streamscan.Guard {
	t.Helper()
	if c.RulesFile == "" && c.RulesDir == "" {
		c.RulesFile = testutil.YARARules(t)
	}
	if c.MaxWindow == 0 {
		c.MaxWindow = 65536
	}
	g, err := streamscan.New(c)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return g
}

// A policy naming no rules is a listener that would scan nothing while looking
// as though it scanned, so it is refused at load rather than accepted empty.
func TestAPolicyWithNoRulesIsRefused(t *testing.T) {
	if _, err := streamscan.New(&config.YARAPolicy{}); err == nil ||
		!strings.Contains(err.Error(), "rules_file or rules_dir") {
		t.Fatalf("a policy with neither: %v", err)
	}
}

// A rules file that is not there, and a directory that is not there: the error
// says which, because the two are different configuration mistakes.
func TestRulesThatCannotBeReadAreReported(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yar")
	if _, err := streamscan.New(&config.YARAPolicy{RulesFile: missing}); err == nil {
		t.Error("a rules_file that does not exist was accepted")
	}
	if _, err := streamscan.New(&config.YARAPolicy{RulesDir: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Error("a rules_dir that does not exist was accepted")
	}
}

// A directory is one rule set, taken in name order.
func TestADirectoryIsOneRuleSet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yar"), []byte(testutil.YARARuleSet), 0o600); err != nil {
		t.Fatal(err)
	}
	g := guard(t, &config.YARAPolicy{RulesDir: dir, Directions: []string{"client"}})
	s := g.Stream("client")
	if s == nil {
		t.Fatal("no stream for the direction the policy names")
	}
	if !s.Feed([]byte(marker)) {
		t.Error("the rule from the directory did not fire")
	}
}

// directions decides which sides get a stream at all, which is how a listener
// halves the work where only one side carries what the rules are about.
func TestOnlyTheNamedDirectionsAreScanned(t *testing.T) {
	for _, c := range []struct {
		name       string
		directions []string
		client     bool
		upstream   bool
	}{
		{"client only", []string{"client"}, true, false},
		{"upstream only", []string{"upstream"}, false, true},
		{"both", []string{"client", "upstream"}, true, true},
		{"neither named", nil, false, false},
		{"a direction this proxy has no name for", []string{"sideways"}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := guard(t, &config.YARAPolicy{Directions: c.directions})
			if got := g.Stream("client") != nil; got != c.client {
				t.Errorf("client stream = %v, want %v", got, c.client)
			}
			if got := g.Stream("upstream") != nil; got != c.upstream {
				t.Errorf("upstream stream = %v, want %v", got, c.upstream)
			}
		})
	}
}

// What fired is carried for the record, and the policy comes back with it so
// the caller can find out what a match should lead to without holding the
// configuration itself.
func TestAMatchCarriesTheRuleAndThePolicy(t *testing.T) {
	g := guard(t, &config.YARAPolicy{Directions: []string{"client"}, Action: "close"})
	s := g.Stream("client")
	if !s.Feed([]byte("before " + marker + " after")) {
		t.Fatal("the rule did not fire")
	}
	ms := s.Matches()
	if len(ms) == 0 || ms[0].Rule != "secret_marker" {
		t.Fatalf("matches = %+v, want secret_marker", ms)
	}
	if p := s.Policy(); p == nil || p.Action != "close" {
		t.Fatalf("policy = %+v, want the one the guard was built from", p)
	}
	// Once a rule has fired the stream is stopped: the decision has been
	// made and the bytes after it are the caller's business, not the
	// scanner's.
	if s.Feed([]byte(marker)) {
		t.Error("a stopped stream fired a second time")
	}
}

// A match that straddles two reads is still found, which is what the window
// overlap is for: one read from the socket is where the stream paused, not
// where the data ends.
func TestAMatchAcrossTwoReadsIsStillFound(t *testing.T) {
	g := guard(t, &config.YARAPolicy{Directions: []string{"client"}})
	s := g.Stream("client")
	half := len(marker) / 2
	if s.Feed([]byte(marker[:half])) {
		t.Fatal("half a marker fired")
	}
	if !s.Feed([]byte(marker[half:])) {
		t.Error("the marker split across two reads did not fire")
	}
}

// max_bytes stops the scanning and lets the connection carry on, which is
// stated in the configuration rather than left to be noticed: past the bound
// the bytes are forwarded unscanned.
func TestPastMaxBytesTheStreamCarriesOnUnscanned(t *testing.T) {
	g := guard(t, &config.YARAPolicy{Directions: []string{"client"}, MaxBytes: 8})
	s := g.Stream("client")
	// Eight bytes of something harmless exhausts the bound.
	if s.Feed([]byte("........")) {
		t.Fatal("harmless bytes fired")
	}
	if s.Feed([]byte(marker)) {
		t.Error("the scanner was still reading past max_bytes")
	}
}

// The bound can fall inside one read, and then only the part under it is
// scanned -- the marker is cut in half by the bound and does not fire.
func TestTheBoundCanFallInsideOneRead(t *testing.T) {
	g := guard(t, &config.YARAPolicy{Directions: []string{"client"}, MaxBytes: 4})
	s := g.Stream("client")
	if s.Feed([]byte(marker)) {
		t.Error("a marker cut by max_bytes fired on the part under the bound")
	}
}

// A nil guard and a nil stream are what a listener with no yara section has,
// and every relay path feeds them unconditionally rather than testing first.
func TestNoPolicyIsFedWithoutCeremony(t *testing.T) {
	var g *streamscan.Guard
	s := g.Stream("client")
	if s != nil {
		t.Fatal("a nil guard made a stream")
	}
	if s.Feed([]byte(marker)) {
		t.Error("a nil stream fired")
	}
	if ms := s.Matches(); ms != nil {
		t.Errorf("a nil stream has matches: %+v", ms)
	}
	if p := s.Policy(); p != nil {
		t.Errorf("a nil stream has a policy: %+v", p)
	}
	// An empty read is not a read: it must not count against the bound or
	// be mistaken for the end of anything.
	real := guard(t, &config.YARAPolicy{Directions: []string{"client"}}).Stream("client")
	if real.Feed(nil) {
		t.Error("an empty read fired")
	}
}
