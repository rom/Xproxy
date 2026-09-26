package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/fipsmode"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/testutil"
)

// custodyProxy builds a server whose three certificates are held three
// different ways, so the report has something to count.
func custodyProxy(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	diskCert, diskKey := testutil.WriteCert(t, dir, "disk.test")
	refCert, refKey := testutil.WriteCert(t, dir, "ref.test")
	hsmCert, _ := testutil.WriteCert(t, dir, "hsm.test")
	keyPEM, err := os.ReadFile(refKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XPROXY_TEST_REF_KEY", string(keyPEM))
	// The vault's token is read when the client is built, so a vault
	// configured with a token that is not there fails at start rather than at
	// the first secret somebody needs.
	t.Setenv("XPROXY_TEST_VAULT_TOKEN", "s.not-a-real-token")
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: edge
      address: "127.0.0.1:0"
      tls:
        min_version: "1.3"
        certificates:
          - {cert_file: ` + diskCert + `, key_file: ` + diskKey + `}
          - {cert_file: ` + refCert + `, key: "env:XPROXY_TEST_REF_KEY"}
          - cert_file: ` + hsmCert + `
            signer: {socket: ` + filepath.Join(dir, "signer.sock") + `, key: edge}
logging: {access: {enabled: false}}
secrets:
  vault:
    address: https://vault.invalid:8200
    token_env: XPROXY_TEST_VAULT_TOKEN
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// What an auditor asks is how many private keys an attacker who reads this
// machine's file system gets, and the report has to answer it without them
// having to read the configuration.
func TestTheReportSaysWhereTheKeysAre(t *testing.T) {
	s := custodyProxy(t)
	cu := s.CustodyReport()
	if cu.KeysOnDisk != 1 || cu.KeysReferenced != 1 || cu.KeysExternal != 1 {
		t.Errorf("counts %+v, want one of each", cu)
	}
	if !cu.Vault {
		t.Error("a vault is configured and the report does not say so")
	}
	// The whole thing is on the snapshot, because a status page that shows it
	// only when something is wrong is a status page nobody can audit.
	if got := s.Stats().Custody; got.KeysOnDisk != 1 {
		t.Errorf("the snapshot does not carry the report: %+v", got)
	}
}

// Every number is in the exposition at rest, at zero where it has to be: a
// gauge that appears only once something is wrong cannot be alerted on, because
// there is nothing to compare against.
func TestCustodyIsInTheExposition(t *testing.T) {
	s := custodyProxy(t)
	var buf bytes.Buffer
	s.WriteMetrics(&buf)
	out := buf.String()
	for _, want := range []string{
		`xproxy_private_keys{custody="file"} 1`,
		`xproxy_private_keys{custody="reference"} 1`,
		`xproxy_private_keys{custody="signer"} 1`,
		`xproxy_secrets_vault 1`,
		`xproxy_secrets_stale 0`,
		`xproxy_fips_required 0`,
		`xproxy_fips_refused_algorithms 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition lacks %q", want)
		}
	}
	// fips_enabled reports the truth about this process either way, so it is
	// checked for presence rather than for a value: the same test has to pass
	// on a FIPS build and an ordinary one.
	if !strings.Contains(out, "xproxy_fips_enabled ") {
		t.Error("exposition lacks xproxy_fips_enabled")
	}
}

// Without a secrets section there is still a resolver, so no kind has to test
// for nil -- and it answers paths and the environment while refusing a vault
// reference, which is what a configuration written before this existed needs.
func TestThereIsAlwaysAResolver(t *testing.T) {
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
	res := s.Secrets()
	if res == nil {
		t.Fatal("no resolver without a secrets section")
	}
	t.Setenv("XPROXY_TEST_PLAIN", "material")
	if v, err := res.StringValue("env:XPROXY_TEST_PLAIN"); err != nil || v != "material" {
		t.Errorf("env reference resolved to %q, %v", v, err)
	}
	if _, err := res.Bytes("vault:secret/x#y"); err == nil {
		t.Error("a vault reference resolved with no vault configured")
	}
	if cu := s.CustodyReport(); cu.Vault {
		t.Error("the report claims a vault with no secrets section")
	}
}

// required: true on a binary where the module is not active is a refusal to
// start, not a warning. The value of the setting is precisely that a deployment
// which must be FIPS cannot quietly stop being it after a rebuild.
func TestFIPSRequiredWithoutTheModuleRefusesToStart(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
fips: {required: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(cfg, logging.Discard())
	if fipsmode.Enabled() {
		// On a FIPS build the requirement is met, so the server comes up
		// and there is nothing to assert beyond that.
		if err != nil {
			t.Fatalf("fips is active and the server still refused: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("fips required on a build without the module and the server started")
	}
	// The message has to say what to do about it. A refusal that does not
	// name GODEBUG=fips140=on is a refusal an operator cannot act on.
	if !strings.Contains(err.Error(), "fips140=on") {
		t.Errorf("error %q does not say how to turn it on", err)
	}
}

// What the FIPS probe asks about, and what it deliberately does not.
//
// Cipher suites are a TLS 1.2 matter: 1.3's are not configurable and a listener
// at min_version 1.3 never offers one. Probing them there would warn about
// ChaCha20 -- which a FIPS module does refuse -- on an estate that does not
// offer it, and a warning an operator cannot act on is one they learn to
// ignore.
func TestTheProbeAsksAboutWhatTheListenersOffer(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "probe.test")
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: modern
      address: "127.0.0.1:0"
      tls:
        min_version: "1.3"
        key_exchange: [X25519MLKEM768, P-256]
        certificates: [{cert_file: ` + certPath + `, key_file: ` + keyPath + `}]
logging: {access: {enabled: false}}
`))
	if err != nil {
		t.Fatal(err)
	}
	groups, suites := fipsProbeSubjects(cfg)
	if len(groups) != 2 {
		t.Errorf("groups %v, want the two named", groups)
	}
	if len(suites) != 0 {
		t.Errorf("suites %v, want none from a 1.3-only listener", suites)
	}

	// A 1.2 listener that names nothing still has the default suites probed,
	// because the default is what it actually offers.
	cfg12, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      tls:
        min_version: "1.2"
        certificates: [{cert_file: ` + certPath + `, key_file: ` + keyPath + `}]
logging: {access: {enabled: false}}
`))
	if err != nil {
		t.Fatal(err)
	}
	groups12, suites12 := fipsProbeSubjects(cfg12)
	if len(groups12) == 0 {
		t.Error("a listener that names no groups had none probed; the default is what it offers")
	}
	if len(suites12) == 0 {
		t.Error("a 1.2 listener that names no suites had none probed; the default is what it offers")
	}

	// A listener with no TLS at all contributes nothing, and neither does a
	// configuration with no TLS listener: no goroutine, no handshakes, no
	// warnings about algorithms nobody offers.
	plain, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: plain, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
`))
	if err != nil {
		t.Fatal(err)
	}
	if g, s := fipsProbeSubjects(plain); len(g) != 0 || len(s) != 0 {
		t.Errorf("a configuration with no TLS listener probed %v %v", g, s)
	}
}
