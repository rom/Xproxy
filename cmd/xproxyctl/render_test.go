package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The control tool prints two kinds of thing: the proxy's own state,
// and values that arrived from somewhere else — a peer's node name, an
// upstream's error, a ban's reason typed by whoever asked for it. These
// tests cover the renderers directly, including the cases the running
// proxy in the other tests never produces.

// TestPrintChanges covers every branch of the configuration comparison
// an operator reads before a reload, which is the last chance to notice
// that a change does more than it says.
func TestPrintChanges(t *testing.T) {
	var out bytes.Buffer
	printChanges(&out, &config.Changes{From: "active", To: "file", Same: true})
	if !strings.Contains(out.String(), "active and file are identical") {
		t.Fatalf("identical: %q", out.String())
	}

	out.Reset()
	printChanges(&out, &config.Changes{
		From: "active", To: "file",
		Summary: []string{"1 route added", "1 upstream changed"},
		Changes: []config.Change{
			{Kind: "added", Section: "routes", Name: "api"},
			{Kind: "removed", Section: "routes", Name: "old"},
			{Kind: "changed", Section: "server.limits"},
		},
		RestartNeeded: []string{"listener main (udp socket)"},
		Drains:        []string{"listener web"},
		Text:          "--- active\n+++ file\n@@\n-a\n+b\n",
	})
	s := out.String()
	for _, want := range []string{
		"active -> file", "1 route added", "added    routes api", "removed  routes old",
		"changed  server.limits", "restart needed for:", "listener main (udp socket)",
		"applied on reload with a connection drain:", "listener web", "+++ file",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the comparison does not mention %q:\n%s", want, s)
		}
	}

	// A comparison too large to diff says so rather than printing
	// nothing, which would read as "no textual difference".
	out.Reset()
	printChanges(&out, &config.Changes{From: "a", To: "b", Truncated: true, Summary: []string{"x"}})
	if !strings.Contains(out.String(), "text diff omitted") {
		t.Fatalf("truncated: %q", out.String())
	}
}

// TestSmallRenderers covers the cells of the tables, each of which has
// an empty, a zero and an error form.
func TestSmallRenderers(t *testing.T) {
	if ago(time.Time{}) != "-" {
		t.Fatal("a zero time must render as a dash, not as 55 years ago")
	}
	if got := ago(time.Now().Add(-90 * time.Second)); !strings.HasSuffix(got, " ago") {
		t.Fatalf("ago: %q", got)
	}
	if onOff(true) != "on" || onOff(false) != "off" {
		t.Fatal("onOff")
	}
	if dash("") != "-" || dash("x") != "x" {
		t.Fatal("dash")
	}
	if originProbeCell(200, "") != "200" {
		t.Fatal("a successful probe must render its status")
	}
	if got := originProbeCell(0, "connection refused"); got != "err:connection refused" {
		t.Fatalf("a failed probe rendered as %q", got)
	}
	// An error wins over a status: a probe that failed has no status
	// worth printing, and printing 0 would read as a real answer.
	if got := originProbeCell(502, "timeout"); got != "err:timeout" {
		t.Fatalf("a probe with both gave %q", got)
	}
}

// TestParseDays covers the duration argument of the api key commands,
// in both of its spellings and in the ways it can be wrong. Zero and
// negative must be refused: an api key that expires the moment it is
// made, or in the past, is a key nobody can use and an operator who
// does not know why.
func TestParseDays(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"90d", 90 * 24 * time.Hour},
		{"1d", 24 * time.Hour},
		{"24h", 24 * time.Hour},
		{"1h30m", 90 * time.Minute},
		{"", 0},
		{"0d", 0},
		{"-5d", 0},
		{"d", 0},
		{"90", 0},
		{"90days", 0},
		{"1.5d", 0},
		{"0", 0},
		{"-1h", 0},
		{"nonsense", 0},
		{" 90d", 0},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseDays(tc.in)
			if tc.want == 0 {
				if err == nil {
					t.Fatalf("accepted %q as %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("%q produced %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestTimeOrNever is the other side of ago: an absolute instant, or a
// dash when there is none.
func TestTimeOrNever(t *testing.T) {
	if timeOrNever(time.Time{}) != "-" {
		t.Fatal("a zero time must render as a dash")
	}
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	if got := timeOrNever(at); got != "2026-09-20T10:00:00Z" {
		t.Fatalf("timeOrNever: %q", got)
	}
}

// TestTailRejectsBadInput covers the log follower's argument handling
// and the configurations it cannot follow. The success path blocks
// forever by design, so it is not exercised here.
func TestTailRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	cfg := "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n" +
		"logging:\n  directory: " + dir + "\n  access: {enabled: true}\n" +
		"upstreams:\n  - name: u\n    endpoints: [{address: \"127.0.0.1:1\"}]\n" +
		"routes:\n  - {name: r, upstream: u}\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := tail(cfgPath, "bogus", &out, &errOut); code != 2 {
		t.Fatalf("an unknown stream gave code %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown stream") {
		t.Fatalf("errors: %q", errOut.String())
	}
	errOut.Reset()
	// The stream is configured but the file does not exist yet.
	if code := tail(cfgPath, "access", &out, &errOut); code != 1 {
		t.Fatalf("a missing log file gave code %d", code)
	}
	errOut.Reset()
	if code := tail(filepath.Join(dir, "absent.yaml"), "access", &out, &errOut); code != 1 {
		t.Fatalf("a missing configuration gave code %d", code)
	}
	if !strings.Contains(errOut.String(), "error:") {
		t.Fatalf("it failed without saying why: %q", errOut.String())
	}
}

// TestHtpasswdEdges covers the users file's remaining paths: the names
// that must be refused, the comments and blank lines that must survive
// a rewrite, and the failures of the write itself. The file is what a
// basic_auth route trusts, so a rewrite that loses a line silently
// unlocks or locks out whoever was on it.
func TestHtpasswdEdges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "users")
	var out, errOut bytes.Buffer

	// A name with a colon or a newline would forge a second entry.
	for _, name := range []string{"", "a:b", "a\nb", "a\rb"} {
		errOut.Reset()
		if code := htpasswd(file, name, strings.NewReader("correct horse battery\n"), &out, &errOut); code != 2 {
			t.Fatalf("the name %q gave code %d", name, code)
		}
	}

	// Comments and other users survive a rewrite.
	existing := "# the operators\nalice:$2a$10$oldhash\n\nbob:$2a$10$bobhash\n"
	if err := os.WriteFile(file, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := htpasswd(file, "alice", strings.NewReader("a new long password\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "# the operators") {
		t.Fatalf("the comment was dropped:\n%s", s)
	}
	if !strings.Contains(s, "bob:$2a$10$bobhash") {
		t.Fatalf("another user was dropped:\n%s", s)
	}
	if strings.Contains(s, "$2a$10$oldhash") {
		t.Fatalf("the old hash survived:\n%s", s)
	}
	if strings.Count(s, "alice:") != 1 {
		t.Fatalf("alice appears %d times:\n%s", strings.Count(s, "alice:"), s)
	}

	// An empty password is still a password the hasher judges; whatever
	// it decides, the file must not be left half written.
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := htpasswd(file, "carol", strings.NewReader(""), &out, &errOut); code == 0 {
		t.Fatal("an empty password was accepted")
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused password still rewrote the file")
	}

	// A path whose directory does not exist fails before anything is
	// written, and says so.
	errOut.Reset()
	if code := htpasswd(filepath.Join(dir, "no-such-dir", "users"), "alice",
		strings.NewReader("a long enough password\n"), &out, &errOut); code != 1 {
		t.Fatalf("a missing directory gave code %d", code)
	}
	if !strings.Contains(errOut.String(), "error:") {
		t.Fatalf("it failed without saying why: %q", errOut.String())
	}

	// A path that is a directory fails on the read, not on a rename
	// that would have replaced it.
	errOut.Reset()
	if code := htpasswd(dir, "alice", strings.NewReader("a long enough password\n"), &out, &errOut); code == 0 {
		t.Fatal("a directory was accepted as a users file")
	}
}
