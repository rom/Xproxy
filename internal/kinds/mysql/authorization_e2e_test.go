package mysql

import (
	"fmt"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// authzRelay is a relay under the estate's authorisation policy.
func authzRelay(t *testing.T, section, serverAddr, policy string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(myYAML, section, serverAddr)+"authorization:\n"+policy)
	return s, proxytest.Addr(t, s, "db")
}

// The login packet is the first place an account appears, so it is where the
// policy is asked -- and before the login is forwarded, so an account no rule
// covers never reaches the server.
func TestAPolicyRefusesTheLoginBeforeItIsForwarded(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := authzRelay(t, base, fake.addr(), `  rules:
    - {name: reporting, allow: true, users: [reporter]}
`)
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e == "" {
		t.Error("a login no rule covers was accepted")
	}
	if got := fake.sawStmts(); len(got) != 0 {
		t.Errorf("the server saw %q from an account no rule covers", got)
	}
	if n := s.Stats().Refusals["mysql"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["mysql"])
	}
}

// And the account a rule does name gets through and can run a statement.
func TestAPolicyAdmitsTheAccountItNames(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := authzRelay(t, base, fake.addr(), `  rules:
    - {name: app, allow: true, users: [app], targets: [my], actions: [connect]}
`)
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e != "" {
		t.Fatalf("login: %s", e)
	}
	if e := cl.send(t, 3 /* ComQuery */, "SELECT 1"); e != "" {
		t.Fatalf("select: %s", e)
	}
	if got := fake.sawStmts(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Errorf("the server saw %q", got)
	}
}

// A policy in shadow mode records and admits, and records it as a would-be
// refusal only on a listener that is otherwise enforcing.
func TestAShadowedPolicyRecordsAndAdmitsOnMySQL(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := authzRelay(t, base, fake.addr(), `  shadow: true
  rules:
    - {name: not-app, users: [app]}
`)
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e != "" {
		t.Fatalf("a shadowed policy refused a login: %s", e)
	}
	st := s.Stats()
	if n := st.Refusals["mysql"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
	if n := st.WouldRefusals["mysql"]["authorization"]; n != 1 {
		t.Errorf("would-be refusals %d, want 1: %v", n, st.WouldRefusals["mysql"])
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "mysql" && e.Reason == "authorization" && e.Rule == "not-app" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
}
