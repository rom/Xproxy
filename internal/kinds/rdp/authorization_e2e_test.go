package rdp_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rdp"
)

// authzGateway is an RDP gateway under the estate's authorisation policy.
func authzGateway(t *testing.T, d *desktop, extra, policy string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desks
      address: "127.0.0.1:0"
      kind: rdp
      rdp:
        upstream: farm
%s
logging: {access: {enabled: false}}
upstreams:
  - name: farm
    endpoints: [{address: %s}]
authorization:
%s
`, extra, d.addr(), policy))
	return s, proxytest.Addr(t, s, "desks")
}

// A client-info name is only a claim. When the gateway replaces the supplied
// credential with its own, the desktop cannot authenticate that claim, so it
// must not satisfy a user rule by itself.
func TestAPolicyDoesNotTrustANameReplacedByTheGateway(t *testing.T) {
	cert, key, pool := certs(t)
	pw := filepath.Join(t.TempDir(), "svc.pw")
	write(t, pw, "service-secret")
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := authzGateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        upstream_user: svc\n"+
		"        upstream_password_file: "+pw+"\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}",
		`  rules:
    - {name: app-team, allow: true, users: [alice]}
`)

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "not-alices-password")
	waitFor(t, "the unverified name to be refused", func() bool {
		return s.Stats().Refusals["rdp"]["authorization"] == 1
	})
	if info := d.credential(); info != nil {
		t.Errorf("the gateway credential reached the desktop for an unverified name as %q", info.Username)
	}
}

// RDP carries the person in one packet, once, and that packet arrives after the
// desktop has been dialled -- so the policy cannot be asked before the target is
// reached. What it does instead is refuse before the credential goes any
// further: the desktop sees a connection and never the person's name or
// password.
func TestAPolicyRefusesBeforeTheCredentialTravels(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := authzGateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}",
		`  rules:
    - {name: app-team, allow: true, users: [bob]}
`)

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "her-password")
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().Refusals["rdp"]["authorization"] == 1 })
	if info := d.credential(); info != nil {
		t.Errorf("the credential reached the desktop as %q", info.Username)
	}
}

// And for the person a rule does name, the credential goes through.
func TestAPolicyAdmitsThePersonItNamesOnRDP(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := authzGateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}",
		`  rules:
    - {name: app-team, allow: true, users: [alice], targets: [farm]}
`)

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "her-password")
	waitFor(t, "the credential to arrive", func() bool { return d.credential() != nil })
}
