package signerd_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/signerd"
)

// start runs a helper on a socket in a temporary directory and returns its path.
func start(t *testing.T, keys ...signerd.Key) (string, *signerd.Server) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "signer.sock")
	srv, err := signerd.New(keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Close()
		_ = ln.Close()
	})
	return sock, srv
}

// selfSigned makes a certificate for a key and returns its PEM.
func selfSigned(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "helper.test"},
		DNSNames:     []string{"helper.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The whole point, end to end and over a real TLS connection: a client
// handshakes with a server whose private key is in another process.
//
// Every key type gets its own run, because the algorithms differ in exactly the
// places a signing protocol gets wrong -- Ed25519 signs a message rather than a
// digest, and RSA-PSS needs the salt length on the wire or a correct signature
// is rejected.
func TestAHandshakeWithTheKeyInAnotherProcess(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		key  crypto.Signer
		// tls13 says whether to pin TLS 1.3, which is the version that uses
		// PSS for RSA; 1.2 exercises PKCS#1 v1.5 for the same key.
		tls13 bool
	}{
		{name: "ECDSA P-256, TLS 1.3", key: ecKey, tls13: true},
		{name: "ECDSA P-256, TLS 1.2", key: ecKey},
		{name: "RSA 2048 with PSS, TLS 1.3", key: rsaKey, tls13: true},
		{name: "RSA 2048 with PKCS#1, TLS 1.2", key: rsaKey},
		{name: "Ed25519, TLS 1.3", key: edKey, tls13: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM := selfSigned(t, tc.key)
			sock, srv := start(t, signerd.Key{Name: "edge", Signer: tc.key})

			// CertificateFor proves the helper holds the matching key before
			// anything is served, so reaching here is already one signature.
			cert, err := keysource.CertificateFor(certPEM, keysource.SignerConfig{Socket: sock, Key: "edge"})
			if err != nil {
				t.Fatal(err)
			}
			min := uint16(tls.VersionTLS12)
			max := uint16(tls.VersionTLS12)
			if tc.tls13 {
				min, max = tls.VersionTLS13, tls.VersionTLS13
			}
			ts := &http.Server{
				Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
				ReadHeaderTimeout: 5 * time.Second,
				TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: min, MaxVersion: max},
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			go func() { _ = ts.ServeTLS(ln, "", "") }()
			defer func() { _ = ts.Close() }()

			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(certPEM) {
				t.Fatal("the certificate did not go into a pool")
			}
			client := &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "helper.test", MinVersion: min, MaxVersion: max},
			}}
			resp, err := client.Get("https://" + ln.Addr().String() + "/")
			if err != nil {
				t.Fatalf("the handshake failed with the key outside the process: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != "ok" {
				t.Errorf("body %q", body)
			}
			if n := srv.Signatures.Load(); n < 2 {
				t.Errorf("the helper signed %d times, want the proof and the handshake", n)
			}
			if n := srv.Refusals.Load() + srv.Malformed.Load(); n != 0 {
				t.Errorf("the helper refused %d requests during a good handshake", n)
			}
		})
	}
}

// A request is refused rather than answered wrongly, and the refusal never says
// more than it has to.
func TestWhatTheHelperRefuses(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sock, srv := start(t,
		signerd.Key{Name: "ec", Signer: ecKey},
		signerd.Key{Name: "rsa", Signer: rsaKey})

	ask := func(t *testing.T, raw string) map[string]any {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write([]byte(raw + "\n")); err != nil {
			t.Fatal(err)
		}
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.NewDecoder(c).Decode(&out); err != nil {
			t.Fatalf("no answer: %v", err)
		}
		return out
	}
	errOf := func(t *testing.T, m map[string]any) string {
		t.Helper()
		s, _ := m["error"].(string)
		if s == "" {
			t.Fatalf("answered without an error: %v", m)
		}
		if _, ok := m["sig"]; ok {
			t.Errorf("an error carried a signature too: %v", m)
		}
		return s
	}

	// A digest of the right length for the cases that get that far.
	digest := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" // sha256 of nothing

	for _, tc := range []struct{ name, req, wants string }{
		{"not JSON at all", `{`, "not this protocol"},
		{"a version from the future", `{"v":2,"key":"ec","alg":"ECDSA-SHA256","digest":"` + digest + `"}`, "version 2"},
		{"a key it does not hold", `{"v":1,"key":"nope","alg":"ECDSA-SHA256","digest":"` + digest + `"}`, "the key is not loaded"},
		{"a digest that is not base64", `{"v":1,"key":"ec","alg":"ECDSA-SHA256","digest":"!!!"}`, "not base64"},
		{"an empty digest", `{"v":1,"key":"ec","alg":"ECDSA-SHA256","digest":""}`, "empty"},
		{"a hash nobody names", `{"v":1,"key":"ec","alg":"ECDSA-MD5","digest":"` + digest + `"}`, "hash \"MD5\""},
		{"an algorithm nobody names", `{"v":1,"key":"ec","alg":"GOST","digest":"` + digest + `"}`, "not one this protocol names"},
		// The interesting one: the right shape of request for the wrong key.
		// Signing it anyway with whatever the key does produces a signature
		// the verifier rejects, three layers away from the cause.
		{"PSS asked of an ECDSA key", `{"v":1,"key":"ec","alg":"RSA-PSS-SHA256","digest":"` + digest + `"}`, "asked of a ECDSA key"},
		{"ECDSA asked of an RSA key", `{"v":1,"key":"rsa","alg":"ECDSA-SHA256","digest":"` + digest + `"}`, "asked of a RSA key"},
		{"Ed25519 asked of an RSA key", `{"v":1,"key":"rsa","alg":"Ed25519","digest":"` + digest + `"}`, "asked of a RSA key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := errOf(t, ask(t, tc.req))
			if !strings.Contains(msg, tc.wants) {
				t.Errorf("error %q, want %q", msg, tc.wants)
			}
		})
	}

	// A refusal for an unknown key must not list the keys this helper holds: a
	// caller that can enumerate them learns which certificates this machine
	// serves, and it is not needed to fix a typo.
	msg := errOf(t, ask(t, `{"v":1,"key":"nope","alg":"ECDSA-SHA256","digest":"`+digest+`"}`))
	for _, name := range srv.Names() {
		if strings.Contains(msg, name) {
			t.Errorf("the refusal named a key this helper holds: %q", msg)
		}
	}
}

// A digest too long to be a digest is refused. The bound is what stops the
// socket being a general-purpose signing oracle for documents.
func TestADocumentIsNotADigest(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := start(t, signerd.Key{Name: "ec", Signer: ecKey})
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Base64 of about 6 KB: over the digest bound, well under the frame bound,
	// so the helper answers rather than hanging up.
	big := strings.Repeat("A", 8192)
	req := `{"v":1,"key":"ec","alg":"ECDSA-SHA256","digest":"` + big + `"}` + "\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.NewDecoder(c).Decode(&out); err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if s, _ := out["error"].(string); !strings.Contains(s, "too long to be a digest") {
		t.Errorf("error %q", s)
	}
}

// One connection carries many signatures, because the proxy pools them: a helper
// that answered once and hung up would make every handshake pay for a socket.
func TestOneConnectionAnswersManyRequests(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sock, srv := start(t, signerd.Key{Name: "ec", Signer: ecKey})
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	dec := json.NewDecoder(c)
	digest := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	for i := 0; i < 5; i++ {
		if _, err := c.Write([]byte(`{"v":1,"key":"ec","alg":"ECDSA-SHA256","digest":"` + digest + `"}` + "\n")); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		var out map[string]any
		if err := dec.Decode(&out); err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
		if s, _ := out["sig"].(string); s == "" {
			t.Fatalf("answer %d carried no signature: %v", i, out)
		}
	}
	if n := srv.Signatures.Load(); n != 5 {
		t.Errorf("signatures %d, want 5 on one connection", n)
	}
}

// A helper with no keys, a key with no name and a name twice are all refused at
// build. Each of them would otherwise be a helper that accepts connections and
// refuses requests, which from the proxy's side looks like a key that is loaded
// and wrong.
func TestWhatAHelperRefusesToBe(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		keys  []signerd.Key
		wants string
	}{
		{"no keys", nil, "no keys"},
		{"a key with no name", []signerd.Key{{Signer: ecKey}}, "no name"},
		{"a key with no signer", []signerd.Key{{Name: "ec"}}, "no signer"},
		{"one name twice", []signerd.Key{{Name: "ec", Signer: ecKey}, {Name: " ec ", Signer: ecKey}}, "defined twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signerd.New(tc.keys, nil)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error %q, want %q", err, tc.wants)
			}
		})
	}
}

// A client that can reach the socket can send refusable requests as fast as it
// likes. A line per refusal would be that client's write amplification on this
// machine's journal -- which is the failure SIGNER.md tells a helper's author to
// avoid, so this one had better not have it.
//
// The counters stay exact; only the log is bounded.
func TestAFloodOfRefusalsIsOneLogLine(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var buf lockedBuffer
	srv, err := signerd.New([]signerd.Key{{Name: "ec", Signer: ecKey}},
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "signer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close(); _ = ln.Close() })

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	dec := json.NewDecoder(c)
	digest := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	const n = 200
	for i := 0; i < n; i++ {
		if _, err := c.Write([]byte(`{"v":1,"key":"nope","alg":"ECDSA-SHA256","digest":"` + digest + `"}` + "\n")); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		var out map[string]any
		if err := dec.Decode(&out); err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
		if s, _ := out["error"].(string); s == "" {
			t.Fatalf("answer %d was not a refusal: %v", i, out)
		}
	}
	// Every one of them is counted -- the bound is on the log, not on the
	// truth, because a counter that stopped counting under a flood would hide
	// exactly the flood it was there to show.
	if got := srv.Refusals.Load(); got != n {
		t.Errorf("refusals counted %d, want %d", got, n)
	}
	lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	if buf.String() == "" {
		lines = 0
	}
	if lines == 0 {
		t.Error("a flood of refusals produced no log line at all")
	}
	if lines > 3 {
		t.Errorf("%d refusals produced %d log lines; the notice is not bounding them", n, lines)
	}
}

// lockedBuffer is a bytes.Buffer safe for the writer goroutine and the test to
// share, which slog needs because the session runs in its own goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
