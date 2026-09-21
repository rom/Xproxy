package tlsconf

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/ech"
	"github.com/rom/xproxy/internal/testutil"
)

// echFixture writes a key pair to disk and returns the listener section
// that serves it, plus the config list a client would learn from DNS.
func echFixture(t *testing.T, publicName string, id uint8, require bool) (*config.TLS, []byte) {
	t.Helper()
	dir := t.TempDir()
	cfg, priv, err := ech.Generate(publicName, id)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "ech.config")
	keyPath := filepath.Join(dir, "ech.key")
	if err := os.WriteFile(cfgPath, enc, 0o644); err != nil { //nolint:gosec // public by design
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	// The certificate covers both the public name and the inner one, as
	// a real deployment's must.
	crt, key := testutil.WriteCert(t, dir, publicName)
	list, err := ech.MarshalList([]ech.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	return &config.TLS{
		Certificates: []config.Certificate{{CertFile: crt, KeyFile: key}},
		MinVersion:   "1.3", ClientAuth: "none",
		ECH: &config.ECH{Keys: []config.ECHKey{{ConfigFile: cfgPath, KeyFile: keyPath}}, Require: require},
	}, list
}

// serveECH starts a listener from a tls section and returns its address
// and the Reloadable, so a test can read the counters afterwards.
func serveECH(t *testing.T, cfg *config.TLS) (string, *Reloadable) {
	t.Helper()
	tc, r, err := Server(cfg, []config.Protocol{config.ProtocolH1})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String(), r
}

// echWhen waits for the server's side of the count to catch up. In TLS
// 1.3 the client's Dial returns once it has the server's Finished, and
// the server is still finishing its own handshake, so the counters are
// a moment behind the connection the client already has. Reading them
// once is reading a race; this reads them until they say what the
// client's own connection state already said, or gives up.
func echWhen(t *testing.T, r *Reloadable, ok func(*ECHStatus) bool) *ECHStatus {
	t.Helper()
	var st *ECHStatus
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if st = r.ECH(); st != nil && ok(st) {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the listener never reported it: %+v", st)
	return nil
}

// TestECHAccepted is the end to end proof: a client that learned the
// config encrypts its hello, the server decrypts it, and the inner name
// — the one that matters — never appears on the wire.
func TestECHAccepted(t *testing.T) {
	cfg, list := echFixture(t, "ech.example.com", 1, false)
	addr, r := serveECH(t, cfg)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify:             true, //nolint:gosec // self-signed test certificate
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example.com",
		EncryptedClientHelloConfigList: list,
	})
	if err != nil {
		t.Fatalf("dial with ech: %v", err)
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	if !st.ECHAccepted {
		t.Fatal("the server did not accept ECH")
	}
	if st.ServerName != "secret.example.com" {
		t.Fatalf("inner server name = %q", st.ServerName)
	}
	status := echWhen(t, r, func(st *ECHStatus) bool { return st.Accepted == 1 })
	if !status.Enabled || status.Rejected != 0 {
		t.Fatalf("status = %+v", status)
	}
	if len(status.Keys) != 1 || status.Keys[0].ConfigID != 1 || status.Keys[0].PublicName != "ech.example.com" || !status.Keys[0].Retry {
		t.Fatalf("keys = %+v", status.Keys)
	}
	// The list the listener says it serves is the list a record should
	// publish, so the two cannot drift apart unnoticed.
	if status.ConfigList == "" {
		t.Fatal("no config list reported")
	}
	if _, err := ech.ParseList(mustBase64(t, status.ConfigList)); err != nil {
		t.Fatalf("reported config list does not parse: %v", err)
	}
}

// TestECHFallbackStillWorks: a client that never learned the key gets
// an ordinary handshake with the public name. This is the case that
// makes rotation safe, and the one `require` gives up.
func TestECHFallbackStillWorks(t *testing.T) {
	cfg, _ := echFixture(t, "ech.example.com", 1, false)
	addr, r := serveECH(t, cfg)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		ServerName:         "ech.example.com",
	})
	if err != nil {
		t.Fatalf("dial without ech: %v", err)
	}
	if conn.ConnectionState().ECHAccepted {
		t.Fatal("a client that sent no ECH was reported as accepted")
	}
	_ = conn.Close()
	if st := echWhen(t, r, func(st *ECHStatus) bool { return st.Rejected == 1 }); st.Accepted != 0 || st.Refused != 0 {
		t.Fatalf("status = %+v", st)
	}
}

// TestECHRequireRefuses: with require set, the fallback is refused
// rather than served — which is the point and the danger.
func TestECHRequireRefuses(t *testing.T) {
	cfg, list := echFixture(t, "ech.example.com", 1, true)
	addr, r := serveECH(t, cfg)
	// In TLS 1.3 the client's Dial returns before the server has had
	// its say, so the refusal surfaces on the first read. That is the
	// client's experience of `require`: a connection that appears to
	// open and then dies with an alert.
	conn0, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		ServerName:         "ech.example.com",
	})
	if err == nil {
		buf := make([]byte, 1)
		_ = conn0.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn0.Read(buf)
		_ = conn0.Close()
	}
	if err == nil {
		t.Fatal("a handshake without ECH was accepted on a listener that requires it")
	}
	// And the ECH client still gets through.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify:             true, //nolint:gosec // self-signed test certificate
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example.com",
		EncryptedClientHelloConfigList: list,
	})
	if err != nil {
		t.Fatalf("dial with ech on a requiring listener: %v", err)
	}
	// The client's Dial returns before the server has finished with the
	// handshake, so the counter it keeps is waited for rather than read
	// once: the same reason the refusal above surfaces on a read.
	var st *ECHStatus
	for i := 0; i < 200; i++ {
		if st = r.ECH(); st.Accepted == 1 && st.Refused == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = conn.Close()
	if st.Accepted != 1 || st.Refused != 1 {
		t.Fatalf("status = %+v", st)
	}
	if !errors.Is(ErrECHRequired, ErrECHRequired) {
		t.Fatal("sentinel")
	}
}

// TestECHStaleKeyIsRetried: a client holding a config the server does
// not have is told the current one during the handshake it fails, which
// is how a rotation heals itself without an outage.
func TestECHStaleKeyIsRetried(t *testing.T) {
	cfg, _ := echFixture(t, "ech.example.com", 1, false)
	addr, _ := serveECH(t, cfg)
	stale, _, err := ech.Generate("ech.example.com", 9)
	if err != nil {
		t.Fatal(err)
	}
	list, err := ech.MarshalList([]ech.Config{stale})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tls.Dial("tcp", addr, &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example.com",
		EncryptedClientHelloConfigList: list,
		// When ECH is rejected, crypto/tls verifies the provider's
		// certificate and ignores InsecureSkipVerify, so the test
		// certificate is accepted here instead.
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	})
	if err == nil {
		t.Fatal("a stale config was accepted")
	}
	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) {
		t.Fatalf("error is %T (%v), want an ECH rejection carrying retry configs", err, err)
	}
	if len(rej.RetryConfigList) == 0 {
		t.Fatal("no retry config was offered; a rotation would never heal")
	}
	cs, err := ech.ParseList(rej.RetryConfigList)
	if err != nil {
		t.Fatalf("the retry list does not parse: %v", err)
	}
	if len(cs) != 1 || cs[0].ID != 1 {
		t.Fatalf("retry configs = %+v", cs)
	}
}

// TestECHKeyMismatchIsRefusedAtLoad: a config served with the wrong
// private key fails every ECH handshake and falls back silently, so the
// site looks healthy while encrypting nothing. It has to be caught at
// load or it is never caught.
func TestECHKeyMismatchIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	a, _, err := ech.Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ech.Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "ech.config")
	keyPath := filepath.Join(dir, "ech.key")
	if err := os.WriteFile(cfgPath, enc, 0o644); err != nil { //nolint:gosec // public by design
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, otherPriv, 0o600); err != nil {
		t.Fatal(err)
	}
	crt, key := testutil.WriteCert(t, dir, "ech.example.com")
	_, _, err = Server(&config.TLS{
		Certificates: []config.Certificate{{CertFile: crt, KeyFile: key}},
		MinVersion:   "1.3", ClientAuth: "none",
		ECH: &config.ECH{Keys: []config.ECHKey{{ConfigFile: cfgPath, KeyFile: keyPath}}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "public keys differ") {
		t.Fatalf("mismatched pair: %v", err)
	}
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64Decode(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}
