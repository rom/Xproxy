package tds

import (
	"fmt"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/tdswire"
)

// authzRelay is a relay under the estate's authorisation policy.
func authzRelay(t *testing.T, section, serverAddr, policy string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(tdsYAML, section, serverAddr)+"authorization:\n"+policy)
	return s, proxytest.Addr(t, s, "db")
}

// The Login7 packet is the first place an account appears, so it is where the
// policy is asked -- and before it is forwarded, so an account no rule covers
// never reaches the server.
func TestAPolicyRefusesTheLoginBeforeItIsForwarded(t *testing.T) {
	fake := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	s, addr := authzRelay(t, base, fake.addr(), `  rules:
    - {name: reporting, allow: true, users: [reporter]}
`)
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	types, _, _ := fake.saw()
	if len(types) != 0 {
		t.Errorf("the server saw %v from an account no rule covers", types)
	}
	if n := s.Stats().Refusals["tds"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["tds"])
	}
}

// And the account a rule does name gets through and can run a batch.
func TestAPolicyAdmitsTheAccountItNames(t *testing.T) {
	fake := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := authzRelay(t, base, fake.addr(), `  rules:
    - {name: app, allow: true, users: [app], targets: [sql], actions: [connect]}
`)
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	cl.batch(t, "SELECT 1")
	types, _, stmts := fake.saw()
	if len(types) != 2 || types[0] != wire.TypeLogin7 || types[1] != wire.TypeSQLBatch {
		t.Fatalf("the server saw %v", types)
	}
	if len(stmts) != 1 || stmts[0] != "SELECT 1" {
		t.Errorf("statements: %v", stmts)
	}
}

// A policy in shadow mode records and admits, and records it as a would-be
// refusal only on a listener that is otherwise enforcing.
func TestAShadowedPolicyRecordsAndAdmitsOnTDS(t *testing.T) {
	fake := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	s, addr := authzRelay(t, base, fake.addr(), `  shadow: true
  rules:
    - {name: not-app, users: [app]}
`)
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	cl.batch(t, "SELECT 1")
	types, _, _ := fake.saw()
	if len(types) != 2 {
		t.Errorf("the server saw %v, so the session was not really admitted", types)
	}
	st := s.Stats()
	if n := st.Refusals["tds"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
	if n := st.WouldRefusals["tds"]["authorization"]; n != 1 {
		t.Errorf("would-be refusals %d, want 1: %v", n, st.WouldRefusals["tds"])
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "tds" && e.Reason == "authorization" && e.Rule == "not-app" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
}
