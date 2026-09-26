package mgmt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/telnet" // a gate kind that can require a grant
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// accessServer starts a proxy whose telnet gate requires a grant, with the
// management socket in front of it and the trail in a file the test can read.
func accessServer(t *testing.T) (*proxy.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	mfaFile := filepath.Join(dir, "mfa")
	if err := os.WriteFile(mfaFile, []byte("alice:JBSWY3DPEHPK3PXPJBSWY3DPEH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(dir, "access.log")
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: kit
      address: "127.0.0.1:0"
      kind: telnet
      telnet: {upstream: u, require_grant: true, mfa: {file: ` + mfaFile + `}}
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
access:
  ledger: ` + ledger + `
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	sock := filepath.Join(dir, "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Shutdown(context.Background()) })
	return p, sock, ledger
}

// The round trip an operator actually does: ask, have somebody else approve,
// see it active.
func TestTheFourEyesRoundTripOverTheSocket(t *testing.T) {
	_, sock, ledger := accessServer(t)

	code, body := call(t, sock, "POST", "/v1/access", map[string]any{
		"subject": "alice", "listener": "kit", "target": "u",
		"reason": "switch upgrade", "by": "carol", "duration": "1h",
	})
	if code != 200 {
		t.Fatalf("ask: %d %s", code, body)
	}
	var g access.Grant
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	if g.ID == "" || g.NeedApprovals != 1 {
		t.Fatalf("grant %+v", g)
	}

	// The requester cannot approve, and neither can the subject.
	for _, who := range []string{"carol", "alice"} {
		code, body := call(t, sock, "POST", "/v1/access/approve", map[string]any{"id": g.ID, "by": who})
		if code != 403 {
			t.Errorf("approval by %s: %d %s, want 403", who, code, body)
		}
	}
	// Somebody else can.
	if code, body := call(t, sock, "POST", "/v1/access/approve",
		map[string]any{"id": g.ID, "by": "bob", "note": "spoke to carol"}); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	// And not twice.
	if code, _ := call(t, sock, "POST", "/v1/access/approve", map[string]any{"id": g.ID, "by": "BOB"}); code != 403 {
		t.Errorf("a second approval by the same person: %d, want 403", code)
	}

	code, body = call(t, sock, "GET", "/v1/access?state=active", nil)
	if code != 200 {
		t.Fatalf("list: %d %s", code, body)
	}
	var rep AccessReport
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Grants) != 1 || rep.Grants[0].ID != g.ID || rep.Grants[0].State != access.Active {
		t.Fatalf("the active grant is not there: %+v", rep.Grants)
	}
	if rep.Stats.Requests != 1 || rep.Stats.Approvals != 1 {
		t.Errorf("counters %+v", rep.Stats)
	}

	// The trail on disk carries both acts and the note.
	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	trail := string(raw)
	for _, want := range []string{`"kind":"request"`, `"kind":"approve"`, "spoke to carol", "switch upgrade"} {
		if !strings.Contains(trail, want) {
			t.Errorf("the trail does not carry %q:\n%s", want, trail)
		}
	}
}

// The refusals a client has to tell apart: a grant that does not exist, one it
// is too late to act on, and a window the policy will not allow.
func TestTheRefusalsCarryTheirOwnStatus(t *testing.T) {
	_, sock, _ := accessServer(t)

	if code, _ := call(t, sock, "POST", "/v1/access/approve",
		map[string]any{"id": "0123456789abcdef", "by": "bob"}); code != 404 {
		t.Errorf("approving a grant that does not exist: %d, want 404", code)
	}
	// A window longer than max_duration is refused when it is asked for,
	// rather than left for an approver to notice.
	if code, body := call(t, sock, "POST", "/v1/access", map[string]any{
		"subject": "alice", "listener": "kit", "target": "u", "reason": "all week",
		"by": "carol", "duration": "72h",
	}); code != 400 || !strings.Contains(string(body), "max_duration") {
		t.Errorf("a window past the bound: %d %s", code, body)
	}
	// A denial is final, so acting on it afterwards is a conflict rather
	// than a bad request.
	_, body := call(t, sock, "POST", "/v1/access", map[string]any{
		"subject": "alice", "listener": "kit", "target": "u", "reason": "later",
		"by": "carol", "duration": "1h",
	})
	var g access.Grant
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, sock, "POST", "/v1/access/deny", map[string]any{"id": g.ID, "by": "bob"}); code != 200 {
		t.Fatal("deny")
	}
	if code, _ := call(t, sock, "POST", "/v1/access/approve", map[string]any{"id": g.ID, "by": "erin"}); code != 409 {
		t.Errorf("approving a denied grant: %d, want 409", code)
	}
	// And a body with a field nobody defined is refused rather than
	// silently ignored: a typo in "duration" must not become a grant with
	// somebody else's default window.
	if code, _ := call(t, sock, "POST", "/v1/access", map[string]any{
		"subject": "alice", "listener": "kit", "target": "u", "reason": "typo",
		"by": "carol", "duratoin": "1h",
	}); code != 400 {
		t.Errorf("a misspelt field: %d, want 400", code)
	}
}

// A daemon with no access section answers 404 rather than pretending: an
// operator asking for grants on the wrong daemon has to be told.
func TestWithoutTheSectionTheCallsSayThereIsNoLedger(t *testing.T) {
	_, sock, _ := mfaServer(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/access"},
		{"POST", "/v1/access"},
		{"POST", "/v1/access/approve"},
		{"POST", "/v1/access/deny"},
		{"POST", "/v1/access/revoke"},
	} {
		code, body := call(t, sock, c.method, c.path, map[string]any{"id": "x", "by": "bob"})
		if code != 404 || !strings.Contains(string(body), "not configured") {
			t.Errorf("%s %s: %d %s", c.method, c.path, code, body)
		}
	}
}

// Revoking is not slowed down by four eyes -- taking access away is not the
// decision the requirement guards -- and it takes effect on a grant in force.
func TestRevocationNeedsNobodyElse(t *testing.T) {
	p, sock, _ := accessServer(t)
	_, body := call(t, sock, "POST", "/v1/access", map[string]any{
		"subject": "alice", "listener": "kit", "target": "u", "reason": "incident",
		"by": "carol", "duration": "1h",
	})
	var g access.Grant
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, sock, "POST", "/v1/access/approve", map[string]any{"id": g.ID, "by": "bob"}); code != 200 {
		t.Fatal("approve")
	}
	if got, reason := p.Access().Admit("alice", "kit", []string{"u"}); got == nil {
		t.Fatalf("the approved grant did not admit: %q", reason)
	}
	// Carol asked for it and carol can take it back, with no second person.
	if code, body := call(t, sock, "POST", "/v1/access/revoke",
		map[string]any{"id": g.ID[:8], "by": "carol", "note": "laptop stolen"}); code != 200 {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if _, reason := p.Access().Admit("alice", "kit", []string{"u"}); reason != access.ReasonRevoked {
		t.Errorf("after revocation: %q, want %q", reason, access.ReasonRevoked)
	}
}
