package postgres

import (
	"fmt"
	"io"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// authzRelay is a relay under the estate's authorisation policy.
func authzRelay(t *testing.T, section, serverAddr, policy string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(pgYAML, section, serverAddr)+"authorization:\n"+policy)
	return s, proxytest.Addr(t, s, "db")
}

// The startup packet is the first and only place a role appears -- this relay
// never sees the password -- so it is where the policy is asked, and it is
// before the server is dialled. A role no rule covers never reaches it.
func TestAPolicyRefusesBeforeTheServerIsDialled(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := authzRelay(t, base, fake.addr(), `  rules:
    - {name: reporting, allow: true, users: [reporter]}
`)
	cl := dial(t, addr, "user", "alice", "database", "app")
	// The relay answers with a fatal error and closes.
	_, _ = io.Copy(io.Discard, cl.c)
	if got := fake.got(); len(got) != 0 {
		t.Errorf("the server saw %q from a role no rule covers", got)
	}
	if n := s.Stats().Refusals["postgres"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["postgres"])
	}
}

// And the role a rule does name gets through to the server.
func TestAPolicyAdmitsTheRoleItNames(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := authzRelay(t, base, fake.addr(), `  rules:
    - {name: app, allow: true, users: [alice], targets: [pg], actions: [connect]}
`)
	cl := dial(t, addr, "user", "alice", "database", "app")
	_ = cl.waitReady(t)
	if e := cl.query(t, "SELECT 1"); e != "" {
		t.Fatalf("a statement was refused: %s", e)
	}
	if got := fake.got(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Errorf("the server saw %q", got)
	}
}

// A policy in shadow mode records and admits -- and records it as a would-be
// refusal only, on a listener that is otherwise enforcing. The two shadow
// switches are separate, and this is the one an estate uses to read a new policy
// against a database that is already under its own statement policy.
func TestAShadowedPolicyRecordsAndAdmitsOnPostgres(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := authzRelay(t, base, fake.addr(), `  shadow: true
  rules:
    - {name: not-alice, users: [alice]}
`)
	cl := dial(t, addr, "user", "alice", "database", "app")
	_ = cl.waitReady(t)
	if e := cl.query(t, "SELECT 1"); e != "" {
		t.Fatalf("a shadowed policy refused a statement: %s", e)
	}
	if got := fake.got(); len(got) != 1 {
		t.Errorf("the server saw %q, so the session was not really admitted", got)
	}
	st := s.Stats()
	if n := st.Refusals["postgres"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
	if n := st.WouldRefusals["postgres"]["authorization"]; n != 1 {
		t.Errorf("would-be refusals %d, want 1: %v", n, st.WouldRefusals["postgres"])
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "postgres" && e.Reason == "authorization" && e.Rule == "not-alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
}
