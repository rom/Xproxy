package ssh_test

// The target's own credential: a host certificate signed by an authority
// the known_hosts file trusts with an @cert-authority line.
//
// Without this the file's own vocabulary is only half read. An estate that
// rebuilds machines signs each new host key with a host CA exactly so
// that nobody has to edit known_hosts everywhere, and a bastion reading
// plain entries alone refuses every one of those hosts.

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// certSigner signs a certificate for host with ca and returns the signer
// a target would present.
func certSigner(t *testing.T, ca, host cssh.Signer, typ uint32, principals []string, from, to time.Time) cssh.Signer {
	t.Helper()
	cert := &cssh.Certificate{
		Key:             host.PublicKey(),
		CertType:        typ,
		KeyId:           "target",
		ValidPrincipals: principals,
		ValidAfter:      uint64(from.Unix()), //nolint:gosec // test times are positive
		ValidBefore:     uint64(to.Unix()),   //nolint:gosec // test times are positive
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	signer, err := cssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// bastionKnowing starts a target presenting hostSigner and a bastion whose
// known_hosts holds lines, built from the target's address.
func bastionKnowing(t *testing.T, hostSigner cssh.Signer, lines func(target string) string) (string, cssh.Signer) {
	t.Helper()
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, clientSigner, clientAuthorized := sshKey(t, dir, "client")
	tg := startTargetSSH(t, hostSigner)
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(clientAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, []byte(lines(tg.addr())), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
        upstream_user: operator
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, authorized, upKeyPath, known, tg.addr())
	s := proxytest.Start(t, yaml)
	return s.Addrs()["bastion"], clientSigner
}

// authority is an @cert-authority line for 127.0.0.1.
func authority(authorized string) string {
	return "@cert-authority 127.0.0.1 " + strings.TrimSpace(authorized) + "\n"
}

// runs reports whether a session through the bastion reached the target.
func runs(t *testing.T, addr string, client cssh.Signer) bool {
	t.Helper()
	c := dialBastion(t, addr, client)
	sess, err := c.NewSession()
	if err != nil {
		return false
	}
	out, err := sess.Output("uptime")
	return err == nil && string(out) == "ran uptime"
}

// A host certificate signed by an authority the file trusts is accepted,
// and the target's own key is nowhere in known_hosts.
func TestAHostCertificateFromATrustedAuthorityIsAccepted(t *testing.T) {
	dir := t.TempDir()
	_, hostKey, _ := sshKey(t, dir, "target_host")
	_, ca, caAuthorized := sshKey(t, dir, "host_ca")
	signer := certSigner(t, ca, hostKey, cssh.HostCert, []string{"127.0.0.1"},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	addr, client := bastionKnowing(t, signer, func(string) string { return authority(caAuthorized) })
	if !runs(t, addr, client) {
		t.Error("a session through a certificate-authenticated host did not run")
	}
}

// And everything about such a certificate that must not be accepted.
func TestAHostCertificateIsRefusedWhenItDoesNotHold(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name       string
		principals []string
		from, to   time.Time
		otherCA    bool
		userCert   bool
	}{
		{name: "another authority signed it", principals: []string{"127.0.0.1"}, from: now.Add(-time.Hour), to: now.Add(time.Hour), otherCA: true},
		{name: "has expired", principals: []string{"127.0.0.1"}, from: now.Add(-2 * time.Hour), to: now.Add(-time.Hour)},
		{name: "is not valid yet", principals: []string{"127.0.0.1"}, from: now.Add(time.Hour), to: now.Add(2 * time.Hour)},
		{name: "names another host", principals: []string{"other.example.net"}, from: now.Add(-time.Hour), to: now.Add(time.Hour)},
		{name: "is a user certificate", principals: []string{"127.0.0.1"}, from: now.Add(-time.Hour), to: now.Add(time.Hour), userCert: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, hostKey, _ := sshKey(t, dir, "target_host")
			_, ca, caAuthorized := sshKey(t, dir, "host_ca")
			_, other, _ := sshKey(t, dir, "other_ca")
			signing := ca
			if tc.otherCA {
				signing = other
			}
			typ := uint32(cssh.HostCert)
			if tc.userCert {
				typ = cssh.UserCert
			}
			signer := certSigner(t, signing, hostKey, typ, tc.principals, tc.from, tc.to)
			addr, client := bastionKnowing(t, signer, func(string) string { return authority(caAuthorized) })
			if runs(t, addr, client) {
				t.Errorf("a host certificate that %s was accepted", tc.name)
			}
		})
	}
}

// A revoked line refuses the key it names whatever else the file says,
// which is the case the marker exists for. It covers the authority too:
// one line takes back every certificate that CA ever signed.
func TestARevokedHostKeyOrAuthorityIsRefused(t *testing.T) {
	for _, what := range []string{"host", "authority"} {
		t.Run(what, func(t *testing.T) {
			dir := t.TempDir()
			_, hostKey, hostAuthorized := sshKey(t, dir, "target_host")
			_, ca, caAuthorized := sshKey(t, dir, "host_ca")
			signer := certSigner(t, ca, hostKey, cssh.HostCert, []string{"127.0.0.1"},
				time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			revoked := hostAuthorized
			if what == "authority" {
				revoked = caAuthorized
			}
			addr, client := bastionKnowing(t, signer, func(string) string {
				return authority(caAuthorized) + "@revoked 127.0.0.1 " + strings.TrimSpace(revoked) + "\n"
			})
			if runs(t, addr, client) {
				t.Errorf("a session ran although the %s was revoked", what)
			}
		})
	}
}

// A plain key still works, and a revocation of it refuses it although the
// same key is listed as trusted elsewhere in the file.
func TestARevocationBeatsATrustedPlainKey(t *testing.T) {
	dir := t.TempDir()
	_, hostKey, hostAuthorized := sshKey(t, dir, "target_host")
	plain := func(target string) string {
		return target + " " + strings.TrimSpace(hostAuthorized) + "\n"
	}
	addr, client := bastionKnowing(t, hostKey, plain)
	if !runs(t, addr, client) {
		t.Fatal("a plain known_hosts entry stopped working")
	}
	addr, client = bastionKnowing(t, hostKey, func(target string) string {
		return plain(target) + "@revoked 127.0.0.1 " + strings.TrimSpace(hostAuthorized) + "\n"
	})
	if runs(t, addr, client) {
		t.Error("a revoked key was accepted because another line trusted it")
	}
}

// A file that trusts nothing says so when the listener is built, rather
// than refusing every session later.
func TestAKnownHostsFileWithNoTrustedKeysIsRefusedAtBind(t *testing.T) {
	dir := t.TempDir()
	_, _, authorized := sshKey(t, dir, "target_host")
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, []byte("@revoked 127.0.0.1 "+strings.TrimSpace(authorized)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, _, clientAuthorized := sshKey(t, dir, "client")
	authorizedPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorizedPath, []byte(clientAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: "127.0.0.1:22"}]
`, hostKeyPath, authorizedPath, upKeyPath, known)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := s.Start(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		t.Error("a known_hosts file holding only a revocation was accepted")
	}
}

// An authority is trusted for the hosts its line names, and for no
// others: a CA that signs for one estate is not a CA for another.
func TestAnAuthorityIsTrustedOnlyForTheHostsItsLineNames(t *testing.T) {
	dir := t.TempDir()
	_, hostKey, _ := sshKey(t, dir, "target_host")
	_, ca, caAuthorized := sshKey(t, dir, "host_ca")
	signer := certSigner(t, ca, hostKey, cssh.HostCert, []string{"127.0.0.1"},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	addr, client := bastionKnowing(t, signer, func(string) string {
		// The authority is trusted for another host entirely, and the
		// certificate is otherwise perfectly good.
		return "@cert-authority other.example.net " + strings.TrimSpace(caAuthorized) + "\n"
	})
	if runs(t, addr, client) {
		t.Error("an authority trusted for another host signed this one's certificate and it was accepted")
	}
}
