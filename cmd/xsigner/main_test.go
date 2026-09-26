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
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/keysource"
)

// proveOverSocket builds the proxy's own signer against the socket, which both
// exercises the real client and performs one signature: CertificateFor proves
// the helper holds the key matching the certificate before anything is served.
func proveOverSocket(certPEM []byte, socket string) error {
	_, err := keysource.CertificateFor(certPEM, keysource.SignerConfig{Socket: socket, Key: "edge"})
	return err
}

// writeKey writes a PEM private key in the encoding named and returns its path.
func writeKey(t *testing.T, dir, name, encoding string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	switch encoding {
	case "sec1":
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	case "pkcs8":
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	default:
		t.Fatalf("encoding %q", encoding)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func write(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// -validate loads every key before the socket is bound, so a helper that could
// not answer for one of its keys is found out by an operator rather than by a
// handshake.
func TestValidateLoadsEveryKey(t *testing.T) {
	dir := t.TempDir()
	sec1, _ := writeKey(t, dir, "a.key", "sec1")
	pkcs8, _ := writeKey(t, dir, "b.key", "pkcs8")
	cfg := write(t, filepath.Join(dir, "xsigner.yaml"), `
socket: /run/xsigner/signer.sock
keys:
  - {name: edge, key: `+sec1+`}
  - {name: pay, key: file:`+pkcs8+`}
`)
	var out, errOut bytes.Buffer
	if code := run([]string{"-config", cfg, "-validate"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if got := out.String(); !strings.Contains(got, "2 key(s): edge, pay") {
		t.Errorf("output %q", got)
	}
}

// -print-keys is the answer to the one question the protocol cannot answer from
// the proxy's side without a certificate in hand: which key is behind this name.
func TestPrintKeysNamesWhatLoaded(t *testing.T) {
	dir := t.TempDir()
	keyPath, key := writeKey(t, dir, "a.key", "sec1")
	cfg := write(t, filepath.Join(dir, "xsigner.yaml"),
		"socket: /run/xsigner/signer.sock\nkeys:\n  - {name: edge, key: "+keyPath+"}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"-config", cfg, "-print-keys"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "# edge (ECDSA P-256)") {
		t.Errorf("output does not name the key and its type: %q", got)
	}
	// The public key printed must be the one that loaded, not a different key
	// of the same shape.
	at := strings.Index(got, "-----BEGIN")
	if at < 0 {
		t.Fatalf("no PEM in %q", got)
	}
	block, _ := pem.Decode([]byte(got[at:]))
	if block == nil {
		t.Fatalf("no PEM in %q", got)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || !ec.Equal(&key.PublicKey) {
		t.Error("the public key printed is not the key that loaded")
	}
	// And the private half must not be anywhere in the output.
	if strings.Contains(got, "PRIVATE") {
		t.Error("the output carries private key material")
	}
}

// What the configuration refuses. Each of these would otherwise be a helper that
// starts and then behaves in a way nobody meant.
func TestWhatTheConfigurationRefuses(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeKey(t, dir, "a.key", "sec1")
	base := "socket: /run/xsigner/signer.sock\n"
	for _, tc := range []struct{ name, body, wants string }{
		{
			name:  "a relative socket",
			body:  "socket: run/signer.sock\nkeys:\n  - {name: edge, key: " + keyPath + "}\n",
			wants: "absolute path",
		},
		{
			// A socket anything on the machine can write to is a signing
			// oracle for every key this helper holds. There is no deployment
			// where it is right, so it is refused rather than warned about.
			name:  "a world writable socket",
			body:  base + "socket_mode: \"0666\"\nkeys:\n  - {name: edge, key: " + keyPath + "}\n",
			wants: "signing oracle",
		},
		{
			name:  "no keys",
			body:  base,
			wants: "keys: at least one",
		},
		{
			name:  "a key with no name",
			body:  base + "keys:\n  - {key: " + keyPath + "}\n",
			wants: "name: required",
		},
		{
			name:  "one name twice",
			body:  base + "keys:\n  - {name: edge, key: " + keyPath + "}\n  - {name: edge, key: " + keyPath + "}\n",
			wants: "appears twice",
		},
		{
			name:  "a relative key path",
			body:  base + "keys:\n  - {name: edge, key: file:a.key}\n",
			wants: "must be an absolute path",
		},
		{
			name:  "a vault reference with no vault",
			body:  base + "keys:\n  - {name: edge, key: \"vault:secret/tls/edge#key\"}\n",
			wants: "no secrets.vault section",
		},
		{
			// Unlike the proxy's own vault client there is no insecure escape
			// hatch: this process exists to hold private keys, and reading
			// them over plain HTTP would undo the reason it exists.
			name: "a vault over plain HTTP",
			body: base + "secrets:\n  vault:\n    address: http://127.0.0.1:8200\n    token_env: T\n" +
				"keys:\n  - {name: edge, key: \"vault:secret/tls/edge#key\"}\n",
			wants: "must be an https:// URL",
		},
		{
			name: "a vault with both token sources",
			body: base + "secrets:\n  vault:\n    address: https://v:8200\n    token_env: T\n    token_file: /etc/t\n" +
				"keys:\n  - {name: edge, key: \"vault:secret/tls/edge#key\"}\n",
			wants: "exactly one of token_file or token_env",
		},
		{
			name:  "a key that is not a key",
			body:  base + "keys:\n  - {name: edge, key: " + write(t, filepath.Join(dir, "not.pem"), "hello\n") + "}\n",
			wants: "no private key in the PEM",
		},
		{
			name:  "a mistyped setting",
			body:  base + "socketmode: \"0600\"\nkeys:\n  - {name: edge, key: " + keyPath + "}\n",
			wants: "field socketmode not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := write(t, filepath.Join(t.TempDir(), "xsigner.yaml"), tc.body)
			var out, errOut bytes.Buffer
			if code := run([]string{"-config", cfg, "-validate"}, &out, &errOut); code == 0 {
				t.Fatalf("accepted: %s", out.String())
			}
			if got := errOut.String(); !strings.Contains(got, tc.wants) {
				t.Errorf("error %q, want %q", got, tc.wants)
			}
		})
	}
}

// An encrypted legacy PEM is refused rather than prompted for: a helper started
// by systemd has nowhere to prompt, and a passphrase in the configuration is not
// a passphrase.
func TestAnEncryptedKeyIsRefusedWithAnAnswer(t *testing.T) {
	dir := t.TempDir()
	body := "-----BEGIN EC PRIVATE KEY-----\n" +
		"Proc-Type: 4,ENCRYPTED\n" +
		"DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\n" +
		"AAAA\n-----END EC PRIVATE KEY-----\n"
	keyPath := write(t, filepath.Join(dir, "enc.key"), body)
	cfg := write(t, filepath.Join(dir, "xsigner.yaml"),
		"socket: /run/xsigner/signer.sock\nkeys:\n  - {name: edge, key: "+keyPath+"}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"-config", cfg, "-validate"}, &out, &errOut); code == 0 {
		t.Fatal("an encrypted key was accepted")
	}
	got := errOut.String()
	if !strings.Contains(got, "the key is encrypted") || !strings.Contains(got, "vault") {
		t.Errorf("error %q does not say what to do about it", got)
	}
}

// The helper runs, answers, and shuts down on a signal -- driven through the
// real entry point, because the socket binding and the signal handling are only
// in there.
func TestTheHelperRunsAndStops(t *testing.T) {
	dir := t.TempDir()
	keyPath, key := writeKey(t, dir, "a.key", "sec1")
	sock := filepath.Join(dir, "signer.sock")
	cfg := write(t, filepath.Join(dir, "xsigner.yaml"),
		"socket: "+sock+"\nkeys:\n  - {name: edge, key: "+keyPath+"}\n")

	// The helper logs from the goroutine running it, and this test reads what
	// it logged, so the buffer has to be safe for both. A bytes.Buffer here is
	// a data race the detector finds -- and one worth having found, since the
	// same mistake in the product would be a log writer shared between
	// sessions.
	var out bytes.Buffer
	var errOut lockedBuffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"-config", cfg}, &out, &errOut) }()

	// Wait for the socket, then use it through the client the proxy uses.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the socket never appeared: %s", errOut.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	certPEM := selfSignedFor(t, key)
	if err := proveOverSocket(certPEM, sock); err != nil {
		t.Fatalf("the helper did not sign for its own key: %v", err)
	}

	// The start line has to name the keys and the socket's mode: an operator
	// who cannot see them cannot tell a typo in a name from a key that failed
	// to load.
	if got := errOut.String(); !strings.Contains(got, `"keys":"edge"`) || !strings.Contains(got, `"mode":"0600"`) {
		t.Errorf("start line %q", got)
	}
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d: %s", code, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the helper did not stop on a signal")
	}
	if got := errOut.String(); !strings.Contains(got, `"signatures":1`) {
		t.Errorf("the shutdown line does not count the signature: %q", got)
	}
}

// selfSignedFor is a certificate for the key, which is what the proxy's client
// needs to prove the helper holds the matching private key.
func selfSignedFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "helper.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// lockedBuffer is a bytes.Buffer safe for the goroutine running the helper and
// the test to share, which the helper's own log writer needs.
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
