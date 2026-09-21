package config

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/testutil"
)

// TestKeyExchangeValidation: an unknown group is a typo that would
// otherwise silently narrow the offered set, and a list with no
// post-quantum group loads with advice rather than an error — a fleet
// that cannot negotiate the hybrid exists, and the operator, not the
// proxy, decides what to do about it.
func TestKeyExchangeValidation(t *testing.T) {
	base := `version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:8443"
      tls:
        certificates: [{cert_file: CERT, key_file: KEY}]
        key_exchange: [GROUPS]
upstreams:
  - name: app
    endpoints: [{address: "10.0.0.1:80"}]
routes:
  - name: app
    paths: [/]
    upstream: app
`
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "a.test")
	yaml := func(groups string) []byte {
		s := strings.ReplaceAll(base, "CERT", cert)
		s = strings.ReplaceAll(s, "KEY", key)
		return []byte(strings.ReplaceAll(s, "GROUPS", groups))
	}
	if _, err := Parse(yaml("X25519MLKEM768, X25519")); err != nil {
		t.Fatalf("valid groups refused: %v", err)
	}
	if _, err := Parse(yaml("X25519, Curve25519")); err == nil {
		t.Error("unknown group accepted")
	} else if !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Errorf("the error does not list the known groups: %v", err)
	}
	if _, err := Parse(yaml("X25519, X25519")); err == nil {
		t.Error("duplicate group accepted")
	}
	c, err := Parse(yaml("X25519, P-256"))
	if err != nil {
		t.Fatalf("classical-only list refused: %v", err)
	}
	advice := strings.Join(c.Advice(), "\n")
	if !strings.Contains(advice, "post-quantum") {
		t.Errorf("no advice about a classical-only list: %q", advice)
	}
	// The default list says nothing, because it is already hybrid.
	c, err = Parse([]byte(strings.ReplaceAll(strings.ReplaceAll(
		strings.ReplaceAll(base, "CERT", cert), "KEY", key),
		"        key_exchange: [GROUPS]\n", "")))
	if err != nil {
		t.Fatal(err)
	}
	if a := strings.Join(c.Advice(), "\n"); strings.Contains(a, "post-quantum") {
		t.Errorf("the default list produced advice: %q", a)
	}
}
