package proxy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/testutil"
	"github.com/rom/xproxy/internal/tlsconf"
)

// What this process does about its own key custody while it is running: a key
// rotated at its source reaching the listener serving with it, and the probe
// that says which of the configured algorithms the module in this process
// will actually do.
//
// A certificate is read once at load. Without the refresh loop below, a key
// rotated in a vault would reach the listener only at the next reload, and
// "rotate it and the running proxy picks it up" would be a claim rather than
// a behaviour -- so what is asserted here is the certificate the listener
// serves afterwards, not that a function was called.

// built parses yaml and builds the server from it. The listeners are not
// started: this package links no listener kind, so there is nothing to serve
// with, and everything below is about what the engine settles at build time.
func built(t *testing.T, yaml string) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

// copyOver replaces the file at dst with the contents of src, which is the
// shape a rotation arrives in: the path stays and what is behind it changes.
func copyOver(t *testing.T, dst, src string) {
	t.Helper()
	b, err := os.ReadFile(src) //nolint:gosec // a path this test wrote
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// listenerServing is a bound listener serving one certificate, which is what
// the refresh loop walks. It is assembled here rather than started, because
// the loop asks the listener's own certificate holder and nothing else.
func listenerServing(t *testing.T, name string, cert config.Certificate, res *keysource.Resolver) *boundListener {
	t.Helper()
	_, rl, err := tlsconf.Server(&config.TLS{
		Certificates: []config.Certificate{cert},
		MinVersion:   "1.3", ClientAuth: "none",
	}, []config.Protocol{config.ProtocolH1}, tlsconf.WithSecrets(res))
	if err != nil {
		t.Fatalf("listener %s: %v", name, err)
	}
	return &boundListener{cfg: config.Listener{Name: name}, tlsReload: rl}
}

// serving is the subject of the certificate a listener is serving now.
func serving(t *testing.T, bl *boundListener) string {
	t.Helper()
	certs := bl.tlsReload.Certificates()
	if len(certs) != 1 {
		t.Fatalf("listener %s serves %d certificates", bl.cfg.Name, len(certs))
	}
	return certs[0].Subject
}

func TestARotatedKeyReachesTheListenerServingWithIt(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "ref.test")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// The key this listener serves with is reached through a reference,
	// which is the only arrangement the loop has anything to do for.
	ref := filepath.Join(dir, "serving.key")
	if err := os.WriteFile(ref, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// The resolver holds a resolved value for the refresh interval, so the
	// clock has to move before a rotation is visible at all -- which is the
	// behaviour worth having: a vault is not asked once per handshake.
	var ahead atomic.Int64
	res := keysource.New(nil, time.Minute, nil)
	res.SetClockForTest(func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) })

	referenced := listenerServing(t, "referenced", config.Certificate{CertFile: certPath, Key: "file:" + ref}, res)
	diskCert, diskKey := testutil.WriteCert(t, dir, "disk.test")
	ondisk := listenerServing(t, "ondisk", config.Certificate{CertFile: diskCert, KeyFile: diskKey}, res)
	if !referenced.tlsReload.HasReferencedKeys() {
		t.Fatal("a certificate whose key is a reference does not say so")
	}
	if ondisk.tlsReload.HasReferencedKeys() {
		t.Fatal("a certificate whose key is a file claims a reference")
	}
	all := func() []*boundListener { return []*boundListener{referenced, ondisk} }

	// An interval that was never set is the default rather than no ticker:
	// a deployment with references and no secrets section still rotates.
	r := newSecretRefresh(0, logging.Discard(), all)
	if r.every != config.DefaultSecretRefresh {
		t.Errorf("an unset interval became %v, want %v", r.every, config.DefaultSecretRefresh)
	}
	if got := newSecretRefresh(time.Minute, logging.Discard(), all).every; got != time.Minute {
		t.Errorf("a configured interval became %v", got)
	}

	// Nothing has rotated, so a pass over the listeners changes nothing. The
	// listener whose key is a file is not asked at all.
	r.once()
	if r.rotations.Load() != 0 || r.failures.Load() != 0 {
		t.Errorf("a pass with nothing rotated: %d rotations, %d failures", r.rotations.Load(), r.failures.Load())
	}

	// A key that is not this certificate's is a change the listener will not
	// take. The pair in force stays, which is the rule the whole arrangement
	// holds to: a bad refresh must not take a working certificate away from a
	// proxy that is serving with it.
	_, strange := testutil.WriteCert(t, t.TempDir(), "strange.test")
	copyOver(t, ref, strange)
	ahead.Store(int64(2 * time.Minute))
	r.once()
	if r.failures.Load() != 1 {
		t.Errorf("refresh failures %d, want 1", r.failures.Load())
	}
	if r.rotations.Load() != 0 {
		t.Error("a key that does not match the certificate was counted as a rotation")
	}
	if got := serving(t, referenced); got != "ref.test" {
		t.Errorf("the listener is serving %q after a refusal, want the pair it started with", got)
	}

	// The pair rotated together is carried into the listener.
	newCert, newKey := testutil.WriteCert(t, t.TempDir(), "rotated.test")
	copyOver(t, certPath, newCert)
	copyOver(t, ref, newKey)
	ahead.Store(int64(4 * time.Minute))
	r.once()
	if r.rotations.Load() != 1 {
		t.Errorf("rotations %d, want 1", r.rotations.Load())
	}
	if got := serving(t, referenced); got != "rotated.test" {
		t.Errorf("the listener is serving %q, want the rotated pair", got)
	}
	if got := serving(t, ondisk); got != "disk.test" {
		t.Errorf("the listener with a file key is serving %q; nothing asked it to change", got)
	}

	t.Run("and the loop does it without being asked", func(t *testing.T) {
		loop := newSecretRefresh(20*time.Millisecond, logging.Discard(), all)
		loop.start()
		defer loop.stop()
		againCert, againKey := testutil.WriteCert(t, t.TempDir(), "again.test")
		copyOver(t, certPath, againCert)
		copyOver(t, ref, againKey)
		ahead.Store(int64(6 * time.Minute))
		for deadline := time.Now().Add(10 * time.Second); loop.rotations.Load() == 0; {
			if time.Now().After(deadline) {
				t.Fatal("the loop did not carry the rotation")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if got := serving(t, referenced); got != "again.test" {
			t.Errorf("the listener is serving %q, want the pair the loop found", got)
		}
	})
}

// The probe is not the requirement. It says which of the configured
// algorithms the module in this process will actually do, which is worth
// knowing at start rather than from the first client that cannot handshake
// with a listener whose key exchange list the module refuses.
func TestTheFIPSProbeSaysWhatTheModuleWillDo(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "probe.test")
	s := built(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      tls:
        min_version: "1.2"
        key_exchange: [X25519, P-256]
        cipher_suites: [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
        certificates: [{cert_file: %s, key_file: %s}]
logging: {access: {enabled: false}}
fips: {probe: true}
`, certPath, keyPath))

	// Every algorithm named there is one this runtime does, module or no
	// module, so nothing is refused and the probe does not hold the proxy
	// back. The assertion is that it ran and answered, not that this build
	// is a FIPS build.
	cu := s.CustodyReport()
	if len(cu.FIPSRefused) != 0 {
		t.Errorf("the probe refused %v, on algorithms every build does", cu.FIPSRefused)
	}
	if cu.FIPSRequired {
		t.Error("the report claims fips is required where only the probe was asked for")
	}
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "xproxy_fips_refused_algorithms 0") {
		t.Error("exposition lacks xproxy_fips_refused_algorithms 0")
	}
}

// An imported list is only as good as its last read, so every list gets its
// own series: a feed whose fetches have stopped while its failures climb
// still matches, on entries nobody has refreshed. A list read from a file
// fetches nothing, and its fetch counters are left out rather than published
// as three zeroes that would never move.
func TestAnImportedListIsInTheExpositionPerList(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "blocked.txt")
	if err := os.WriteFile(listPath, []byte("198.51.100.0/24\n203.0.113.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := built(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
threat_intel:
  lists:
    - {name: blocked-networks, file: %s, action: block}
`, listPath))

	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`xproxy_threat_list_entries{kind="cidr",list="blocked-networks"} 2`,
		`xproxy_threat_list_hits_total{list="blocked-networks"} 0`,
		`xproxy_threat_list_skipped{list="blocked-networks"} 0`,
		"xproxy_threat_list_age_seconds{",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition lacks %q", want)
		}
	}
	if strings.Contains(out, "xproxy_threat_feed_fetches_total") {
		t.Error("a list read from a file published fetch counters")
	}
}
