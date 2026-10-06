package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// run with no arguments, an unknown one, and version: the three answers a
// command gives before it does anything.
func TestUsageAndVersion(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, "usage: xproxy-admin"},
		{[]string{"nope"}, 2, "usage: xproxy-admin"},
		{[]string{"version"}, 0, "xproxy-admin"},
		{[]string{"-version"}, 0, "xproxy-admin"},
		{[]string{"user"}, 2, "usage: xproxy-admin user"},
	} {
		var out, errOut bytes.Buffer
		if code := run(tc.args, strings.NewReader(""), &out, &errOut); code != tc.code {
			t.Errorf("%v: exit %d, want %d (%s%s)", tc.args, code, tc.code, out.String(), errOut.String())
		}
		if got := out.String() + errOut.String(); !strings.Contains(got, tc.want) {
			t.Errorf("%v: %q does not contain %q", tc.args, got, tc.want)
		}
	}
}

// The users file is the credential store, so the round trip through the command
// line is worth asserting: a user added as an operator comes back as one, a
// certificate-only user comes back with no password, and a deleted user is gone.
func TestUserLifecycle(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	do := func(args ...string) (string, int) {
		var out, errOut bytes.Buffer
		code := run(args, strings.NewReader(""), &out, &errOut)
		return out.String() + errOut.String(), code
	}
	if got, code := do("user", "add", "alice", "-users", users, "-role", "operator", "-cert-only"); code != 0 {
		t.Fatalf("add: %d %s", code, got)
	}
	if got, code := do("user", "add", "bob", "-users", users, "-role", "nonsense"); code == 0 {
		t.Errorf("an unknown role was accepted: %s", got)
	}
	got, code := do("user", "list", "-users", users)
	if code != 0 || !strings.Contains(got, "alice") || !strings.Contains(got, "operator") {
		t.Fatalf("list: %d %q", code, got)
	}
	if got, code := do("user", "del", "alice", "-users", users); code != 0 {
		t.Fatalf("del: %d %s", code, got)
	}
	if got, _ := do("user", "list", "-users", users); strings.Contains(got, "alice") {
		t.Errorf("a deleted user is still listed: %q", got)
	}
}

// -validate is the check an operator runs before the GUI binds anything, so what
// it must catch is every file it would otherwise touch for the first time during
// an incident.
func TestValidate(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	if err := os.WriteFile(users, []byte("alice:operator:x509\nbob:viewer:$x$1$aa$bb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfg, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key := writeKeyPair(t, dir, "gui")
	other, _ := writeKeyPair(t, dir, "other")

	do := func(args ...string) (string, int) {
		var out, errOut bytes.Buffer
		code := run(append([]string{"serve", "-validate"}, args...), strings.NewReader(""), &out, &errOut)
		return out.String() + errOut.String(), code
	}

	// The whole set, valid.
	got, code := do("-users", users, "-config", cfg, "-listen", "10.0.0.5:8443",
		"-tls-cert", cert, "-tls-key", key, "-client-ca", other)
	if code != 0 {
		t.Fatalf("a valid set was refused: %d %s", code, got)
	}
	for _, want := range []string{"2 users", "1 operator", "1 viewer", "1 certificate only", "mutual TLS"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not say %q: %s", want, got)
		}
	}
	// And nothing was bound: a second validate on the same address succeeds.
	if _, code := do("-users", users, "-config", cfg, "-listen", "10.0.0.5:8443",
		"-tls-cert", cert, "-tls-key", key, "-client-ca", other); code != 0 {
		t.Error("the first validate left something listening")
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a certificate and key that do not pair",
			[]string{"-users", users, "-config", cfg, "-tls-cert", cert, "-tls-key", filepath.Join(dir, "other-key.pem")},
			"tls:"},
		{"a client CA that is not a certificate",
			[]string{"-users", users, "-config", cfg, "-tls-cert", cert, "-tls-key", key, "-client-ca", users},
			"holds no certificate"},
		{"a configuration file this process cannot read",
			[]string{"-users", users, "-config", filepath.Join(dir, "nope.yaml")},
			"config:"},
		{"a restart command that is not on the system",
			[]string{"-users", users, "-config", cfg, "-restart-cmd", filepath.Join(dir, "nope") + " restart"},
			"restart-cmd:"},
		{"a users file that will not parse",
			[]string{"-users", cfg, "-config", cfg},
			"expected name:role:hash"},
		{"a non-loopback address without mutual TLS",
			[]string{"-users", users, "-config", cfg, "-listen", "10.0.0.5:8443"},
			"non-loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, code := do(tc.args...)
			if code == 0 {
				t.Fatalf("accepted: %s", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("%q does not name the problem (%q)", got, tc.want)
			}
		})
	}

	// The two notes an operator should see rather than find out later.
	got, _ = do("-users", users, "-config", "")
	if !strings.Contains(got, "cannot edit the configuration") {
		t.Errorf("no warning for a GUI without -config: %s", got)
	}
	if !strings.Contains(got, "restart action is disabled") {
		t.Errorf("no note for a GUI without -restart-cmd: %s", got)
	}
}

// writeKeyPair writes a self-signed certificate and its key, and returns both
// paths.
func writeKeyPair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	write := func(path, kind string, b []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(certPath, "CERTIFICATE", der)
	write(keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}
