package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
)

// accessProxy is a server with an access ledger and nothing else interesting.
func accessProxy(t *testing.T) *Server {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "access.log")
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
access:
  ledger: ` + ledger + `
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Access().Close() })
	if _, err := os.Stat(ledger); err != nil {
		t.Fatalf("the ledger was not created: %v", err)
	}
	return s
}

// The numbers an operator alerts on: a queue of requests nobody has answered,
// and sessions turned away for want of a grant. Both have to be in the
// exposition, and the states have to be there at zero as well -- a gauge that
// disappears when it reaches zero is a gauge an alert cannot be written
// against.
func TestAccessMetricsCarryTheQueueAndTheRefusals(t *testing.T) {
	s := accessProxy(t)
	l := s.Access()

	pending, err := l.Request(access.Request{Subject: "alice", Listener: "bastion", Target: "hosts",
		Reason: "incident", By: "carol", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	live, err := l.Request(access.Request{Subject: "dave", Listener: "bastion", Target: "hosts",
		Reason: "change 9", By: "carol", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(live.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	// One session turned away, so the refusal counter has something in it.
	l.Admit("eve", "bastion", []string{"hosts"})

	body := exposition(t, s)
	for _, want := range []string{
		`xproxy_access_grants{state="pending"} 1`,
		`xproxy_access_grants{state="active"} 1`,
		`xproxy_access_grants{state="revoked"} 0`,
		"xproxy_access_requests_total 2",
		"xproxy_access_approvals_total 1",
		`xproxy_access_refusals_total{reason="no_grant"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the exposition lacks %q", want)
		}
	}

	// And the summary the status view reads agrees with it.
	sum := s.Stats().Access
	if sum == nil || sum.ByState["pending"] != 1 || sum.ByState["active"] != 1 || sum.Requests != 2 {
		t.Errorf("summary %+v", sum)
	}
	if _, err := l.Revoke(pending.ID, "dave", ""); err != nil {
		t.Fatal(err)
	}
	if sum := s.Stats().Access; sum.ByState["pending"] != 0 || sum.ByState["revoked"] != 1 {
		t.Errorf("after the revocation: %+v", sum.ByState)
	}
}

// A proxy with no access section says nothing about grants, rather than
// reporting zeros that would look like an estate whose approvals had all
// vanished.
func TestWithoutTheSectionThereAreNoAccessMetrics(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if s.Stats().Access != nil {
		t.Error("a proxy with no access section reported a summary")
	}
	if body := exposition(t, s); strings.Contains(body, "xproxy_access_") {
		t.Error("the exposition carries access metrics with no ledger")
	}
}

// exposition renders the Prometheus text the daemon serves.
func exposition(t *testing.T, s *Server) string {
	t.Helper()
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
