package keysource

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// helper is a stand-in for the process that holds the key: it speaks the
// protocol and signs with whatever key the test gave it. A real one would reach
// a PKCS#11 module, a TPM or a smartcard, which is exactly the point of the
// socket being in between.
type helper struct {
	t    *testing.T
	ln   net.Listener
	key  crypto.Signer
	name string
	// behave replaces the answer, for the cases where the helper is the thing
	// under test.
	behave   func(req request) (response, bool)
	requests atomic.Int64
	conns    atomic.Int64
}

func startHelper(t *testing.T, key crypto.Signer, name string) *helper {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "signer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	h := &helper{t: t, ln: ln, key: key, name: name}
	t.Cleanup(func() { _ = ln.Close() })
	go h.serve()
	return h
}

func (h *helper) addr() string { return h.ln.Addr().String() }

func (h *helper) serve() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.conns.Add(1)
		go h.session(c)
	}
}

// session answers every request on one connection, which is what a helper has
// to do for the proxy's pool to be worth anything.
func (h *helper) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		line, err := readFrame(c)
		if err != nil {
			return
		}
		h.requests.Add(1)
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			return
		}
		resp := h.answer(req)
		out, _ := json.Marshal(resp)
		if _, err := c.Write(append(out, '\n')); err != nil {
			return
		}
	}
}

func (h *helper) answer(req request) response {
	if h.behave != nil {
		if r, done := h.behave(req); done {
			return r
		}
	}
	if req.Key != h.name {
		return response{V: 1, Error: "no key called " + req.Key}
	}
	digest, err := base64.StdEncoding.DecodeString(req.Digest)
	if err != nil {
		return response{V: 1, Error: "the digest is not base64"}
	}
	var opts crypto.SignerOpts = crypto.SHA256
	switch {
	case req.Alg == "Ed25519":
		opts = crypto.Hash(0)
	case strings.HasPrefix(req.Alg, "RSA-PSS-"):
		opts = &rsa.PSSOptions{SaltLength: req.SaltLen, Hash: crypto.SHA256}
	}
	sig, err := h.key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return response{V: 1, Error: err.Error()}
	}
	return response{V: 1, Sig: base64.StdEncoding.EncodeToString(sig)}
}

func signerFor(t *testing.T, h *helper, pub crypto.PublicKey, key string) *Signer {
	t.Helper()
	s, err := NewSigner(SignerConfig{Socket: h.addr(), Key: key, Timeout: 2 * time.Second}, pub)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The property the whole arrangement exists for: the proxy signs without ever
// holding the private key, and what comes back verifies against the
// certificate's public key.
func TestTheProxySignsWithoutHoldingTheKey(t *testing.T) {
	for name, key := range map[string]crypto.Signer{
		"ecdsa":   mustECDSA(t),
		"rsa":     mustRSA(t),
		"ed25519": mustEd25519(t),
	} {
		t.Run(name, func(t *testing.T) {
			h := startHelper(t, key, "edge")
			s := signerFor(t, h, key.Public(), "edge")

			msg := []byte("what the handshake is signing")
			var (
				digest []byte
				opts   crypto.SignerOpts = crypto.SHA256
			)
			if _, ed := key.Public().(ed25519.PublicKey); ed {
				digest, opts = msg, crypto.Hash(0)
			} else {
				sum := sha256.Sum256(msg)
				digest = sum[:]
			}
			sig, err := s.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := verify(key.Public(), digest, sig, opts); err != nil {
				t.Errorf("the signature does not verify: %v", err)
			}
			if s.Signatures.Load() == 0 {
				t.Error("no signature was counted")
			}
		})
	}
}

// A helper that answers and a helper that holds the right key are different
// questions, and the second is the one an operator gets wrong. It is settled
// when the signer is built, so a wrong key fails the load rather than every
// handshake.
func TestAHelperWithTheWrongKeyFailsAtBuild(t *testing.T) {
	right, other := mustECDSA(t), mustECDSA(t)
	h := startHelper(t, other, "edge")
	if _, err := NewSigner(SignerConfig{Socket: h.addr(), Key: "edge"}, right.Public()); err == nil {
		t.Fatal("a helper signing with another key was accepted")
	} else if !strings.Contains(err.Error(), "not the certificate's") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}

	// And a helper that does not hold the named key at all.
	h2 := startHelper(t, right, "other-key")
	if _, err := NewSigner(SignerConfig{Socket: h2.addr(), Key: "edge"}, right.Public()); err == nil {
		t.Fatal("a helper with no such key was accepted")
	}
}

// What the signer refuses to be built with, and what a missing helper looks
// like: all three are configuration mistakes that must not wait for traffic.
func TestTheSignerRefusesAnImpossibleConfiguration(t *testing.T) {
	key := mustECDSA(t)
	for name, cfg := range map[string]SignerConfig{
		"no socket":                  {Key: "edge"},
		"no key name":                {Socket: "/run/xproxy/signer.sock"},
		"a socket that is not there": {Socket: filepath.Join(t.TempDir(), "absent.sock"), Key: "edge"},
	} {
		if _, err := NewSigner(cfg, key.Public()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The wire names the scheme, because a verifier that assumes the wrong one
// rejects a correct signature. PSS carries its salt length for the same reason.
func TestTheWireNamesTheScheme(t *testing.T) {
	rsaKey, ecKey, edKey := mustRSA(t), mustECDSA(t), mustEd25519(t)
	for name, c := range map[string]struct {
		key     crypto.Signer
		opts    crypto.SignerOpts
		wantAlg string
		wantLen int
	}{
		"ecdsa sha256": {ecKey, crypto.SHA256, "ECDSA-SHA256", 0},
		"ecdsa sha384": {ecKey, crypto.SHA384, "ECDSA-SHA384", 0},
		"rsa pkcs1":    {rsaKey, crypto.SHA256, "RSA-PKCS1-SHA256", 0},
		"rsa pss":      {rsaKey, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}, "RSA-PSS-SHA256", 32},
		"rsa pss auto": {rsaKey, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}, "RSA-PSS-SHA256", 32},
		"ed25519":      {edKey, crypto.Hash(0), "Ed25519", 0},
	} {
		h := startHelper(t, c.key, "edge")
		var got request
		h.behave = func(req request) (response, bool) {
			got = req
			return response{}, false
		}
		s := signerFor(t, h, c.key.Public(), "edge")
		sum := sha256.Sum256([]byte("x"))
		digest := sum[:]
		if c.wantAlg == "Ed25519" {
			digest = []byte("the whole message")
		}
		if _, err := s.Sign(rand.Reader, digest, c.opts); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Alg != c.wantAlg || got.SaltLen != c.wantLen {
			t.Errorf("%s: alg %q salt %d, want %q %d", name, got.Alg, got.SaltLen, c.wantAlg, c.wantLen)
		}
		if got.V != 1 || got.Key != "edge" {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// Every way a helper can answer badly has to be an error rather than a
// signature: a proxy that accepted nonsense from its signer would be serving
// handshakes that fail at the client, which is the worst place to find out.
func TestAnAnswerThatIsNotASignature(t *testing.T) {
	key := mustECDSA(t)
	for name, c := range map[string]struct {
		resp response
		says error
	}{
		"an error of its own": {response{V: 1, Error: "the token is locked"}, ErrSignerRefused},
		"not base64":          {response{V: 1, Sig: "not base64!!"}, ErrSignerProtocol},
		"an empty signature":  {response{V: 1, Sig: ""}, ErrSignerProtocol},
	} {
		h := startHelper(t, key, "edge")
		s := signerFor(t, h, key.Public(), "edge")
		h.behave = func(request) (response, bool) { return c.resp, true }
		sum := sha256.Sum256([]byte("x"))
		_, err := s.Sign(rand.Reader, sum[:], crypto.SHA256)
		if !errors.Is(err, c.says) {
			t.Errorf("%s: %v, want %v", name, err, c.says)
		}
		if s.Failures.Load() == 0 {
			t.Errorf("%s: the failure was not counted", name)
		}
	}

	// A helper that answers with a megabyte cannot fill memory or a log line.
	h := startHelper(t, key, "edge")
	s := signerFor(t, h, key.Public(), "edge")
	h.behave = func(request) (response, bool) {
		return response{V: 1, Sig: strings.Repeat("A", maxSignerFrame)}, true
	}
	sum := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(rand.Reader, sum[:], crypto.SHA256); err == nil {
		t.Error("an oversize answer was accepted")
	}
}

// A helper that hangs must fail the handshake rather than hold it: the timeout
// is on the connection, so a helper that accepts and says nothing is bounded.
func TestAHelperThatHangsTimesOut(t *testing.T) {
	key := mustECDSA(t)
	h := startHelper(t, key, "edge")
	s := signerFor(t, h, key.Public(), "edge")
	s.cfg.Timeout = 150 * time.Millisecond
	h.behave = func(request) (response, bool) {
		time.Sleep(2 * time.Second)
		return response{V: 1, Error: "too late"}, true
	}
	sum := sha256.Sum256([]byte("x"))
	start := time.Now()
	if _, err := s.Sign(rand.Reader, sum[:], crypto.SHA256); err == nil {
		t.Error("a hanging helper produced a signature")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the call took %s, so the timeout did not hold", took)
	}
}

// Connections are reused, because a socket connect per handshake is a cost on
// the path that matters -- and a pooled connection the helper closed must not
// fail a handshake, which is what a restarted helper looks like.
func TestConnectionsAreReusedAndARestartIsSurvived(t *testing.T) {
	key := mustECDSA(t)
	h := startHelper(t, key, "edge")
	s := signerFor(t, h, key.Public(), "edge")
	sum := sha256.Sum256([]byte("x"))

	for range 5 {
		if _, err := s.Sign(rand.Reader, sum[:], crypto.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	// One connection for the proof and the five signatures, because each is
	// returned to the pool.
	if got := h.conns.Load(); got != 1 {
		t.Errorf("%d connections for six requests, want one reused", got)
	}

	// The helper restarts: the pooled connection is dead, and the next
	// signature still works.
	if err := closeIdle(s); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(rand.Reader, sum[:], crypto.SHA256); err != nil {
		t.Errorf("after the pooled connection died: %v", err)
	}
}

// closeIdle closes the pooled connections from underneath the signer, which is
// what a restarted helper does to them.
func closeIdle(s *Signer) error {
	for {
		select {
		case c := <-s.conns:
			if err := c.Close(); err != nil {
				return err
			}
			// Put a closed connection back, so the next request finds it in
			// the pool and has to recover.
			s.conns <- c
			return nil
		default:
			return nil
		}
	}
}

// The signer is a crypto.Signer, so it goes into a tls.Certificate and a real
// handshake completes with the key on the other side of a socket. This is the
// test that would catch a scheme this protocol names wrongly, because the client
// verifies the signature for itself.
func TestARealHandshakeWithTheKeyOutsideTheProcess(t *testing.T) {
	key := mustECDSA(t)
	certDER, pool := selfSigned(t, key)
	h := startHelper(t, key, "edge")
	s := signerFor(t, h, key.Public(), "edge")

	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: s,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("hello"))
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool,
		ServerName: "signer.test", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = client.Close() }()
	buf := make([]byte, 5)
	if _, err := client.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q", buf)
	}
	if s.Signatures.Load() < 2 { // the proof at build, and the handshake
		t.Errorf("%d signatures, want the proof and the handshake", s.Signatures.Load())
	}
}

func mustECDSA(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustRSA(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustEd25519(t *testing.T) crypto.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// selfSigned makes a certificate for the key, so a real TLS stack can be handed
// the pair.
func selfSigned(t *testing.T, key crypto.Signer) ([]byte, *x509.CertPool) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signer.test"},
		DNSNames:              []string{"signer.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return der, pool
}

// CertificateFor is what a listener uses: the chain from the PEM, the public key
// from its leaf, the private key on the other side of a socket -- and the proof
// that the two belong together before anything is served.
func TestACertificateWhoseKeyIsElsewhere(t *testing.T) {
	key := mustECDSA(t)
	certDER, _ := selfSigned(t, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	h := startHelper(t, key, "edge")

	cert, err := CertificateFor(certPEM, SignerConfig{Socket: h.addr(), Key: "edge"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 || cert.Leaf == nil {
		t.Fatalf("chain %d leaf %v", len(cert.Certificate), cert.Leaf)
	}
	if _, ok := cert.PrivateKey.(*Signer); !ok {
		t.Errorf("private key is %T, want the external signer", cert.PrivateKey)
	}

	// A PEM with no certificate in it, and a helper holding another key, are
	// both load-time errors rather than handshake-time ones.
	if _, err := CertificateFor([]byte("not a pem"), SignerConfig{Socket: h.addr(), Key: "edge"}); err == nil {
		t.Error("a PEM with no certificate was accepted")
	}
	other := mustECDSA(t)
	otherDER, _ := selfSigned(t, other)
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER})
	if _, err := CertificateFor(otherPEM, SignerConfig{Socket: h.addr(), Key: "edge"}); err == nil {
		t.Error("a certificate the helper cannot sign for was accepted")
	}
}
