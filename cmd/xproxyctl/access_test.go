package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// Just-in-time access from the command line. The ledger itself and the socket
// are tested where they live; what is tested here is the half an operator
// touches -- the four commands that change a grant, and the two that read one.
//
// Four eyes is the property worth driving from this side rather than from the
// server's: `-by` defaults to the account running the command, so the ordinary
// invocation has no flag in it at all, and whether the trail names a person
// depends on that default being right. A refusal here is a refusal to grant
// access, so the words it comes back with are part of the feature.

const accessYAML = `
version: 1
access:
  ledger: %s
  approvals: 1
  max_duration: 4h
  max_lead: 24h
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`

// accessHarness is harness with an access section, which is what puts a ledger
// behind the socket: without one every call here is a 404, and that is its own
// case below.
func accessHarness(t *testing.T) (sock string) {
	t.Helper()
	dir := t.TempDir()
	yaml := strings.Replace(accessYAML, "%s", filepath.Join(dir, "access.log"), 1)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "m.sock")
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return sock
}

// accessRun drives the command through a client on the socket, the way run
// does.
func accessRun(t *testing.T, sock string, asJSON bool, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	fs := flag.NewFlagSet("xproxyctl", flag.ContinueOnError)
	fs.SetOutput(&errOut)
	_ = fs.Parse(append([]string{"access"}, args...))
	code := accessCommand(mgmt.NewClient(sock), fs, &out, &errOut, asJSON)
	return code, out.String(), errOut.String()
}

// askID pulls the grant id out of what ask printed.
func askID(t *testing.T, out string) string {
	t.Helper()
	for _, f := range strings.Fields(out) {
		if len(f) >= 8 && !strings.ContainsAny(f, ":/") && strings.Trim(f, "0123456789abcdef") == "" {
			return f
		}
	}
	t.Fatalf("no grant id in:\n%s", out)
	return ""
}

// TestAGrantIsAskedForApprovedAndListed is the ordinary path, and the only one
// an estate uses every day: somebody asks, somebody else approves, and the
// list shows the window.
func TestAGrantIsAskedForApprovedAndListed(t *testing.T) {
	sock := accessHarness(t)

	// An empty ledger is said in words rather than as an empty table, because
	// a table with no rows reads as a question nobody answered.
	code, out, errOut := accessRun(t, sock, false)
	if code != 0 || !strings.Contains(out, "no grant matched") {
		t.Fatalf("empty list: %d %q %q", code, out, errOut)
	}

	code, out, errOut = accessRun(t, sock, false, "ask",
		"-subject", "alice", "-listener", "bastion", "-target", "prod-hosts",
		"-reason", "ticket 4213: replace the failed disk", "-for", "2h", "-by", "bob")
	if code != 0 {
		t.Fatalf("ask: %d %q %q", code, out, errOut)
	}
	id := askID(t, out)
	// What an ask prints is the next step, naming the two people who may not
	// be the approver -- which is the rule, said where somebody will read it.
	if !strings.Contains(out, "approval(s) from somebody other than bob and alice") {
		t.Errorf("the ask does not say who may approve it:\n%s", out)
	}
	if !strings.Contains(out, "xproxyctl access approve "+id) {
		t.Errorf("the ask does not print the command to approve it:\n%s", out)
	}

	// The list carries what an approver needs to decide: who, where, why, and
	// how many approvals it still wants.
	code, out, errOut = accessRun(t, sock, false)
	if code != 0 {
		t.Fatalf("list: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"alice", "bastion", "prod-hosts", "ticket 4213", "0/1", "bob"} {
		if !strings.Contains(out, want) {
			t.Errorf("the list has no %q:\n%s", want, out)
		}
	}

	// Four eyes: the person who asked may not approve their own ask. This is
	// the refusal the whole feature exists for.
	if code, _, errOut := accessRun(t, sock, false, "approve", id, "-by", "bob"); code == 0 {
		t.Error("the asker approved their own ask")
	} else if !strings.Contains(errOut, "error:") {
		t.Errorf("the refusal says nothing: %q", errOut)
	}

	code, out, errOut = accessRun(t, sock, false, "approve", id, "-by", "carol", "-note", "disk is dead, agreed")
	if code != 0 {
		t.Fatalf("approve: %d %q %q", code, out, errOut)
	}
	// show reports the approval and who gave it, which is the record somebody
	// reads afterwards.
	code, out, errOut = accessRun(t, sock, false, "show", id)
	if code != 0 {
		t.Fatalf("show: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"alice", "carol", "disk is dead"} {
		if !strings.Contains(out, want) {
			t.Errorf("show has no %q:\n%s", want, out)
		}
	}
	// The state filter narrows to what it names and excludes what it does not.
	if code, out, _ := accessRun(t, sock, false, "-state", "denied"); code != 0 || !strings.Contains(out, "no grant matched") {
		t.Errorf("a filter on denied: %d %q", code, out)
	}
	// And -json is the same report for a program rather than a person.
	if code, out, _ := accessRun(t, sock, true); code != 0 || !strings.Contains(out, `"subject"`) {
		t.Errorf("json list: %d %q", code, out)
	}
	if code, out, _ := accessRun(t, sock, true, "show", id); code != 0 || !strings.Contains(out, `"approvals"`) {
		t.Errorf("json show: %d %q", code, out)
	}
}

// TestADeniedAskAndARevokedGrantAreBothRecorded: a window somebody took back
// has to read differently from one that was never granted, because the two
// mean different things to whoever reads the trail.
func TestADeniedAskAndARevokedGrantAreBothRecorded(t *testing.T) {
	sock := accessHarness(t)
	ask := func(reason string) string {
		t.Helper()
		code, out, errOut := accessRun(t, sock, false, "ask",
			"-subject", "alice", "-listener", "bastion", "-target", "prod",
			"-reason", reason, "-for", "1h", "-by", "bob")
		if code != 0 {
			t.Fatalf("ask: %d %q %q", code, out, errOut)
		}
		return askID(t, out)
	}

	denied := ask("one nobody agreed to")
	if code, out, errOut := accessRun(t, sock, false, "deny", denied, "-by", "carol", "-note", "no change window"); code != 0 {
		t.Fatalf("deny: %d %q %q", code, out, errOut)
	} else if !strings.Contains(out, "denied") {
		t.Errorf("deny said %q", out)
	}

	revoked := ask("one taken back")
	if code, _, errOut := accessRun(t, sock, false, "approve", revoked, "-by", "carol"); code != 0 {
		t.Fatalf("approve: %s", errOut)
	}
	if code, out, errOut := accessRun(t, sock, false, "revoke", revoked, "-by", "dave", "-note", "work finished early"); code != 0 {
		t.Fatalf("revoke: %d %q %q", code, out, errOut)
	} else if !strings.Contains(out, "revoked") {
		t.Errorf("revoke said %q", out)
	}

	code, out, _ := accessRun(t, sock, false, "-state", "denied")
	if code != 0 || !strings.Contains(out, "one nobody agreed to") || strings.Contains(out, "one taken back") {
		t.Errorf("the denied filter: %d %q", code, out)
	}
	code, out, _ = accessRun(t, sock, false, "-state", "revoked")
	if code != 0 || !strings.Contains(out, "one taken back") || strings.Contains(out, "one nobody agreed to") {
		t.Errorf("the revoked filter: %d %q", code, out)
	}
}

// TestTheActorDefaultsToTheAccountRunningTheCommand: `-by` is the name the
// trail records, and the ordinary invocation does not pass it. A default that
// came out as root, or as nothing, would make four eyes unenforceable -- two
// acts by "root" are two acts by the same name, which is what the rule is
// about.
func TestTheActorDefaultsToTheAccountRunningTheCommand(t *testing.T) {
	sock := accessHarness(t)
	// SUDO_USER first, because somebody who reached the socket through sudo is
	// still a person and root is not a name.
	t.Setenv("SUDO_USER", "alice-at-the-keyboard")
	code, out, errOut := accessRun(t, sock, false, "ask",
		"-subject", "svc", "-listener", "bastion", "-target", "prod", "-reason", "why", "-for", "1h")
	if code != 0 {
		t.Fatalf("ask: %d %q %q", code, out, errOut)
	}
	if _, list, _ := accessRun(t, sock, false); !strings.Contains(list, "alice-at-the-keyboard") {
		t.Errorf("the trail does not name the account that asked:\n%s", list)
	}
	// Without SUDO_USER it is still a name rather than empty.
	if err := os.Unsetenv("SUDO_USER"); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = accessRun(t, sock, false, "ask",
		"-subject", "svc2", "-listener", "bastion", "-target", "prod", "-reason", "why", "-for", "1h")
	if code != 0 {
		t.Fatalf("ask without SUDO_USER: %d %q %q", code, out, errOut)
	}
	id := askID(t, out)
	_, shown, _ := accessRun(t, sock, false, "show", id)
	if strings.Contains(shown, "asked by \n") || strings.Contains(shown, "by: \n") {
		t.Errorf("the ask has no actor:\n%s", shown)
	}
}

// TestTheWindowIsBoundedByTheEstatesOwnLimits: max_duration and max_lead are
// the estate's, and a command line asking past either is refused here rather
// than granted and then not honoured.
func TestTheWindowIsBoundedByTheEstatesOwnLimits(t *testing.T) {
	sock := accessHarness(t)
	cases := []struct {
		name string
		args []string
	}{
		{"longer than max_duration", []string{"ask", "-subject", "a", "-listener", "l", "-target", "t", "-reason", "r", "-for", "8h", "-by", "bob"}},
		{"further ahead than max_lead", []string{"ask", "-subject", "a", "-listener", "l", "-target", "t", "-reason", "r", "-for", "1h",
			"-start", time.Now().Add(48 * time.Hour).Format(time.RFC3339), "-by", "bob"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, out, errOut := accessRun(t, sock, false, c.args...); code == 0 {
				t.Errorf("accepted: %q %q", out, errOut)
			}
		})
	}
}

// TestAccessRefusesWhatItCannotActon: the usage errors, which on this command
// are worth a test because every one of them is somebody trying to grant or
// take away access and getting no grant either way.
func TestAccessRefusesWhatItCannotActOn(t *testing.T) {
	sock := accessHarness(t)
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"show with no id", []string{"show"}, 2, "usage: xproxyctl access"},
		{"show with two ids", []string{"show", "a", "b"}, 2, "usage: xproxyctl access"},
		{"an id nobody issued", []string{"show", "0123456789abcdef"}, 1, "error:"},
		{"approve with no id", []string{"approve"}, 2, "one grant id"},
		{"approve an id nobody issued", []string{"approve", "0123456789abcdef", "-by", "bob"}, 1, "error:"},
		{"revoke an id nobody issued", []string{"revoke", "0123456789abcdef", "-by", "bob"}, 1, "error:"},
		{"ask with no subject", []string{"ask", "-listener", "l", "-target", "t", "-reason", "r", "-for", "1h"}, 2, "are all required"},
		{"ask with no reason", []string{"ask", "-subject", "a", "-listener", "l", "-target", "t", "-for", "1h"}, 2, "are all required"},
		{"ask with no window", []string{"ask", "-subject", "a", "-listener", "l", "-target", "t", "-reason", "r"}, 2, "are all required"},
		{"an unparseable start", []string{"ask", "-subject", "a", "-listener", "l", "-target", "t", "-reason", "r", "-for", "1h", "-start", "tuesday"}, 1, "start:"},
		// A typo in the filter is refused rather than answered with an empty
		// list, because "no grant matched" reads as "nobody has access".
		{"a state nothing is in", []string{"-state", "nonsense"}, 2, "is not a state"},
		{"approve with the id twice", []string{"approve", "0123456789abcdef", "fedcba9876543210"}, 2, "one grant id"},
		{"a word that is not a subcommand", []string{"bogus"}, 2, "usage: xproxyctl access"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := accessRun(t, sock, false, c.args...)
			if code != c.code {
				t.Fatalf("code %d, want %d (%q %q)", code, c.code, out, errOut)
			}
			if !strings.Contains(errOut, c.want) {
				t.Errorf("stderr %q does not mention %q", errOut, c.want)
			}
		})
	}
}

// TestWithoutAnAccessSectionEveryCallSaysSo: an estate with no ledger is not
// an estate with an empty one, and the difference matters to somebody who
// thinks they configured just-in-time access and did not.
func TestWithoutAnAccessSectionEveryCallSaysSo(t *testing.T) {
	sock, _ := harness(t) // the ordinary harness has no access section
	for _, args := range [][]string{
		{},
		{"show", "0123456789abcdef"},
		{"ask", "-subject", "a", "-listener", "l", "-target", "t", "-reason", "r", "-for", "1h", "-by", "bob"},
		{"approve", "0123456789abcdef", "-by", "bob"},
	} {
		code, out, errOut := accessRun(t, sock, false, args...)
		if code != 1 {
			t.Errorf("%v: code %d (%q)", args, code, out)
		}
		if !strings.Contains(errOut, "not configured") {
			t.Errorf("%v: stderr %q does not say the section is missing", args, errOut)
		}
	}
}
