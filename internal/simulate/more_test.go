package simulate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// The rest of the capture reader's refusals, the comment fields read out of
// a flow, the differential's error handling, and what Offline does with
// state it cannot copy.
//
// These are the edges of a tool whose whole value is that its answer can be
// trusted: a capture file half understood, a decision nobody got, or a state
// file quietly skipped would each produce a report about traffic nobody sent.

// shbLE and shbBE are the two spellings of a pcapng section header: the
// magic at offset 8 is what says which, and the block's own length has to be
// read in that order or every offset after it is wrong.
const (
	shbLE = "\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00"
	shbBE = "\x0a\x0d\x0d\x0a\x00\x00\x00\x1c\x1a\x2b\x3c\x4d\x00\x01\x00\x00" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x1c"
)

// errReader fails part way through, the way a truncated download or a
// filesystem error does.
type errReader struct{ n int }

func (r *errReader) Read(p []byte) (int, error) {
	if r.n > 0 {
		r.n--
		p[0] = 'x'
		return 1, nil
	}
	return 0, errors.New("the disk went away")
}

func TestTheCaptureReaderRefusesTheRestOfWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		// Four octets: the magic is there and the block is not.
		{"a block header past the end", "\x0a\x0d\x0d\x0a", "past the end of the file"},
		// Twelve octets: enough for a block header, not enough for the
		// section header's own fields, and the byte order is in the part
		// that is missing.
		{"a truncated section header", "\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a",
			"truncated section header"},
		// A length that is not a whole number of four-octet words is not a
		// length this format can have, and trusting it would walk the
		// offsets off the end.
		{"a block length that cannot be right", shbLE + "\x06\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00",
			"a block of 7 bytes"},
	} {
		_, err := ReadCapture(strings.NewReader(tc.in))
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", tc.name, err, tc.want)
		}
	}

	// A big-endian section: read in the wrong order its length is enormous,
	// so a reader that ignored the magic would refuse this file. It carries
	// no packets, which is not an error -- an empty capture is a capture.
	flows, err := ReadCapture(strings.NewReader(shbBE))
	if err != nil {
		t.Errorf("a big-endian section header: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("flows out of an empty section: %d", len(flows))
	}

	// And a read that fails part way through is the reader's error, not a
	// file this reader does not understand.
	if _, err := ReadCapture(&errReader{n: 4}); err == nil ||
		!strings.Contains(err.Error(), "the disk went away") {
		t.Errorf("a failed read: %v", err)
	}
}

// The comment is the capture's own note on the exchange and the reason a
// capture is worth simulating over rather than generating traffic. It is
// text, written by a different version of this project than the one reading
// it, so every field read out of it has to cope with not being there.
func TestTheCommentFieldsCopeWithACommentThatHasNone(t *testing.T) {
	var none Flow
	if none.RequestID() != "" || none.Route() != "" || none.Denied() != "" || none.Status() != 0 {
		t.Errorf("a flow with no comment: %+v", none)
	}
	// A status that is not a number is no status rather than a part of one:
	// reporting 4 for "4xx" would be a status the proxy never answered.
	odd := Flow{Comment: "request_id=01J route=shop status=4xx"}
	if odd.Status() != 0 {
		t.Errorf("status %d, want 0", odd.Status())
	}
	if odd.RequestID() != "01J" || odd.Route() != "shop" {
		t.Errorf("the fields around it did not read: %+v", odd)
	}
}

// An input one side could not decide at all is reported as no decision, not
// folded into either column. The distinction is the one this whole package
// rests on: a question nobody answered is not an agreement, and it is
// certainly not a refusal.
func TestADecisionNobodyGotIsNotAnAgreement(t *testing.T) {
	// The same failure on both sides is not a change: the proposal did not
	// cause it, and reporting it would bury the changes that matter.
	same := Compare(
		[]Outcome{{Input: "a", Decision: Errored, Err: "no listener named edge"}},
		[]Outcome{{Input: "a", Decision: Errored, Err: "no listener named edge"}})
	if same.Differs() {
		t.Errorf("the same failure on both sides was reported as a change: %+v", same.Changes)
	}
	if same.Same != 1 {
		t.Errorf("same %d", same.Same)
	}

	// A failure on one side only, and a different failure on both, are both
	// something to look at.
	for _, tc := range []struct {
		name          string
		before, after Outcome
	}{
		{"one side failed", Outcome{Input: "a", Decision: Allowed, Status: 200},
			Outcome{Input: "a", Decision: Errored, Err: "the sink refused the connection"}},
		{"both failed differently", Outcome{Input: "a", Decision: Errored, Err: "one thing"},
			Outcome{Input: "a", Decision: Errored, Err: "another"}},
	} {
		d := Compare([]Outcome{tc.before}, []Outcome{tc.after})
		if len(d.Changes) != 1 || d.Changes[0].How != Unanswerable {
			t.Errorf("%s: %+v", tc.name, d.Changes)
		}
	}

	// The error is what describe() says about such an outcome, because
	// there is no reason and no status to say instead.
	if got := describe(Outcome{Decision: Errored, Err: "the sink refused the connection"}); got !=
		"error (the sink refused the connection)" {
		t.Errorf("describe: %q", got)
	}
	// And a class this version does not know sorts last rather than first,
	// so a reader of an older report is not told a hole is the worst thing
	// in a list that contains something else.
	if r := rank("something a later version added"); r != 5 {
		t.Errorf("rank of an unknown class = %d, want 5", r)
	}
}

// The configuration a simulation runs is a copy, down to the maps. A map
// shared with the caller is the one that would not show up in a test of the
// pointers: the simulation rewrites paths and switches sections off, and an
// estate holding its real configuration should not find it altered by having
// asked a question about it.
func TestTheMapsInAConfigurationAreCopiedTheSameAsThePointers(t *testing.T) {
	cfg := parse(t, `version: 1
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - name: all
    paths: ["/"]
    upstream: app
    request_headers: {set: {X-Estate: "real"}}
`)
	out, _, err := Offline(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	set := out.Routes[0].RequestHeaders.Set
	if set["X-Estate"] != "real" {
		t.Fatalf("the map did not survive the copy: %v", set)
	}
	set["X-Estate"] = "simulated"
	delete(set, "X-Estate")
	set["X-Added-By-The-Simulation"] = "1"
	if got := cfg.Routes[0].RequestHeaders.Set; got["X-Estate"] != "real" || len(got) != 1 {
		t.Errorf("the caller's map was written through: %v", got)
	}
}

// State the engine reads is copied into the simulation's directory, and a
// state file that cannot be read stops the run rather than being skipped.
// Starting from state that is not the estate's would answer a different
// question: a ban that vanished changes a decision.
func TestStateThatCannotBeCopiedStopsTheSimulation(t *testing.T) {
	dir := t.TempDir()
	// A real ban state file, with something in it, so the copy runs rather
	// than noting that there was nothing to copy.
	bans := filepath.Join(dir, "bans.db")
	if err := os.WriteFile(bans, []byte("203.0.113.9 reason=waf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parse(t, `version: 1
bans: {action: reject, state_file: `+bans+`}
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`)
	simDir := t.TempDir()
	out, rep, err := Offline(cfg, simDir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out.Bans.StateFile)
	if err != nil {
		t.Fatalf("the copy is not there: %v", err)
	}
	if !strings.Contains(string(b), "203.0.113.9") {
		t.Errorf("the copy does not have the estate's bans in it: %q", b)
	}
	if len(rep.Copied) != 1 || !strings.Contains(rep.Copied[0], bans) {
		t.Errorf("the report does not name what it copied: %v", rep.Copied)
	}

	// A state path that is a directory is not a state file, and reading it
	// fails with something other than "it is not there". Each section that
	// carries state has to stop on it, so each one is asked.
	for _, tc := range []struct{ name, yaml string }{
		{"bans", "bans: {action: reject, state_file: DIR}"},
		{"access", "access: {ledger: DIR, approvals: 1}"},
		{"asset_inventory", "asset_inventory: {enabled: true, state_file: DIR}"},
		{"api_inventory", "api_inventory: {enabled: true, state_file: DIR}"},
	} {
		sub := filepath.Join(dir, tc.name+"-is-a-directory")
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		c, perr := config.Parse([]byte("version: 1\n" +
			strings.ReplaceAll(tc.yaml, "DIR", sub) + `
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`))
		if perr != nil {
			t.Errorf("%s: %v", tc.name, perr)
			continue
		}
		if _, _, err := Offline(c, t.TempDir()); err == nil {
			t.Errorf("%s: a state path that is a directory was copied", tc.name)
		} else if !strings.Contains(err.Error(), "for the simulation") {
			t.Errorf("%s: %v does not say what it was doing", tc.name, err)
		}
	}
}

// The remaining outward sections, each on its own. The table in offline.go
// is this package's security argument and the test above checks the table;
// this checks the code that reads it, because a section listed as switched
// off and never cleared would reach the estate from a simulation.
func TestTheRestOfWhatReachesOutsideIsSwitchedOff(t *testing.T) {
	scimDir := t.TempDir()
	token := filepath.Join(scimDir, "scim.token")
	if err := os.WriteFile(token, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ section, yaml string }{
		{"acme", `acme: {directory: "https://acme.example.com/directory", email: ops@example.com, accept_terms: true, state_dir: /var/lib/xproxy/acme}`},
		{"scim", `scim: {token_file: ` + token + `, state_file: ` + filepath.Join(scimDir, "scim.json") +
			`, mfa_users_file: ` + filepath.Join(scimDir, "mfa.json") + `}`},
		{"ingress", `ingress: {enabled: true, api_server: "https://10.0.0.7:6443", cert_dir: /var/lib/xproxy/ingress}`},
		{"metrics", `metrics: {otlp: {endpoint: "https://10.0.0.8:4318/v1/metrics"}}`},
		{"sandbox", `sandbox: {enabled: true}`},
	} {
		c, err := config.Parse([]byte("version: 1\n" + tc.yaml + `
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`))
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		out, rep, err := Offline(c, t.TempDir())
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		found := false
		for _, s := range rep.SwitchedOff {
			if s == tc.section {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was present and is not in %v", tc.section, rep.SwitchedOff)
		}
		// And it is actually gone from the configuration that would run,
		// which is the half the report cannot tell anybody.
		switch tc.section {
		case "acme":
			if out.ACME != nil {
				t.Error("acme is still there")
			}
		case "scim":
			if out.SCIM != nil {
				t.Error("scim is still there")
			}
		case "ingress":
			if out.Ingress != nil {
				t.Error("ingress is still there")
			}
		case "metrics":
			if out.Metrics.OTLP != nil {
				t.Error("the otlp exporter is still there")
			}
		case "sandbox":
			if out.Sandbox.Enabled != nil && *out.Sandbox.Enabled {
				t.Error("the sandbox would still be applied")
			}
		}
	}
}
