package ldap

import (
	"fmt"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// authzServer is a relay under the estate's authorisation policy, in the shape
// the other end-to-end tests here use: implicit TLS to the client, because a
// simple bind carries a password and this relay refuses one in the clear, which
// would refuse every bind below before the policy was reached.
func authzServer(t *testing.T, addr, policy string) (*proxy.Server, string, *testutil.CA) {
	t.Helper()
	ca, cert, key := certs(t)
	section := `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        rules:
          - {name: everything, action: allow}` + tlsSection(cert, key)
	s := proxytest.Start(t, fmt.Sprintf(ldapYAML, section, addr)+"authorization:\n"+policy)
	return s, proxytest.Addr(t, s, "dir"), ca
}

// A bind is the one request that names an identity, so it is where the policy is
// asked -- and before the bind is forwarded, so a DN no rule covers never reaches
// the directory. Which matters here more than in most places: a bind that reaches
// a directory is a password guess against it.
func TestAPolicyRefusesABindBeforeTheDirectorySeesIt(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr, ca := authzServer(t, d.addr(), `  rules:
    - {name: apps, allow: true, users: ["cn=app1,ou=services,dc=example,dc=com"]}
`)

	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=intruder,dc=example,dc=com", "guess"))
	if got := cl.next(3 * time.Second); got != nil && got.Result != nil &&
		got.Result.Code == wire.ResultSuccess {
		t.Error("a bind no rule covers was answered with success")
	}
	for _, m := range d.seen() {
		if m.Bind != nil {
			t.Errorf("the bind reached the directory as %q", m.Bind.Name)
		}
	}
	if n := s.Stats().Refusals["ldap"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["ldap"])
	}
}

// And the DN a rule does name reaches the directory.
func TestAPolicyAdmitsTheBindItNames(t *testing.T) {
	d := startDirectory(t, &directory{})
	_, addr, ca := authzServer(t, d.addr(), `  rules:
    - {name: apps, allow: true, users: ["cn=app1,ou=services,dc=example,dc=com"], targets: [directories]}
`)

	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result == nil ||
		got.Result.Code != wire.ResultSuccess {
		t.Fatalf("a bind the policy allows was refused: %+v", got)
	}
	found := false
	for _, m := range d.seen() {
		if m.Bind != nil && m.Bind.Name == "cn=app1,ou=services,dc=example,dc=com" {
			found = true
		}
	}
	if !found {
		t.Error("the bind did not reach the directory")
	}
}

// A policy in shadow mode records and admits.
func TestAShadowedPolicyRecordsAndAdmitsOnLDAP(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr, ca := authzServer(t, d.addr(), `  shadow: true
  rules:
    - {name: not-app1, users: ["cn=app1,ou=services,dc=example,dc=com"]}
`)

	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result == nil ||
		got.Result.Code != wire.ResultSuccess {
		t.Fatalf("a shadowed policy refused a bind: %+v", got)
	}
	st := s.Stats()
	if n := st.Refusals["ldap"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
	if n := st.WouldRefusals["ldap"]["authorization"]; n != 1 {
		t.Errorf("would-be refusals %d, want 1: %v", n, st.WouldRefusals["ldap"])
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "ldap" && e.Reason == "authorization" && e.Rule == "not-app1" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
}
