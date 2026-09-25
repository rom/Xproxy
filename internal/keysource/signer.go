package keysource

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// An external signer: the private key never enters this process.
//
// A vault reference improves custody -- one master copy, one place that decides
// who may read it -- but the material still ends up in the proxy's memory, which
// is what a core dump, a debugger or a read primitive in this process can reach.
// The arrangement that does not have that property is the one where the proxy
// never holds the key at all: it sends a digest to a helper that holds the key
// and gets a signature back.
//
// That is what this is. The helper may keep its key in an HSM through PKCS#11,
// in a TPM, in a smartcard, or in a file with different ownership; none of that
// is this package's business, and deliberately so. PKCS#11 in particular needs
// cgo to dlopen a vendor module, and this proxy is built without cgo on purpose
// -- so the cgo, the vendor library and the blast radius of both live in a
// separate process behind a socket, which is a better place for them than inside
// the thing that terminates TLS for the estate.
//
// The protocol is one JSON object each way over a Unix socket, newline framed,
// because a helper is something an operator writes:
//
//	-> {"v":1,"key":"edge","alg":"ECDSA-SHA256","digest":"<base64>"}
//	<- {"v":1,"sig":"<base64>"}
//	<- {"v":1,"error":"the key is not loaded"}
//
// Ed25519 signs a message rather than a digest, so for alg "Ed25519" the digest
// field carries the whole message; every other algorithm carries the hash. A
// PSS signature carries salt_len as well, because a verifier that assumes the
// wrong salt length rejects a correct signature.

// signerTimeout bounds one signature. It is on the handshake path: a helper that
// hangs must fail the handshake rather than hold a connection open for ever.
const signerTimeout = 3 * time.Second

// maxSignerFrame bounds one answer. A signature is at most a few hundred bytes;
// a megabyte is a helper answering with something else.
const maxSignerFrame = 64 << 10

// maxSignerConns bounds the connections held to a helper. Each carries one
// request at a time, so this is the parallelism of signing.
const maxSignerConns = 8

var (
	// ErrSignerRefused is the helper answering with an error of its own.
	ErrSignerRefused = errors.New("signer: the helper refused")
	// ErrSignerProtocol is an answer this package cannot read.
	ErrSignerProtocol = errors.New("signer: the helper's answer is not the protocol")
)

// SignerConfig is what an external signer needs.
type SignerConfig struct {
	// Socket is the Unix socket the helper listens on.
	Socket string
	// Key names which key the helper should use, since one helper may hold
	// several.
	Key string
	// Timeout bounds one signature; 0 is the default.
	Timeout time.Duration
	// MaxConns bounds the connections held; 0 is the default.
	MaxConns int
}

// Signer is a crypto.Signer backed by a helper process.
type Signer struct {
	cfg SignerConfig
	pub crypto.PublicKey
	// conns is the idle pool. A connection carries one request at a time, so
	// a full pool is the bound on signing in parallel; a caller that finds it
	// empty opens one of its own rather than waiting, because a handshake
	// waiting on a socket pool is a handshake that has already failed.
	conns chan net.Conn
	// dial is the dialler, replaced in tests.
	dial func() (net.Conn, error)

	Signatures atomic.Uint64
	Failures   atomic.Uint64

	closeOnce sync.Once
}

// NewSigner builds a signer for the public key in a certificate and proves the
// helper holds the matching private key before anything is served.
//
// The proof matters: a socket that answers and a key that matches are different
// questions, and the second one is the one an operator gets wrong. Finding out
// at load beats finding out on every handshake.
func NewSigner(cfg SignerConfig, pub crypto.PublicKey) (*Signer, error) {
	if strings.TrimSpace(cfg.Socket) == "" {
		return nil, errors.New("signer: socket is required")
	}
	if strings.TrimSpace(cfg.Key) == "" {
		return nil, errors.New("signer: key is required, because a helper may hold several")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = signerTimeout
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = maxSignerConns
	}
	s := &Signer{cfg: cfg, pub: pub, conns: make(chan net.Conn, cfg.MaxConns)}
	s.dial = func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
		d := net.Dialer{Timeout: cfg.Timeout}
		return d.DialContext(ctx, "unix", cfg.Socket)
	}
	if err := s.prove(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetDialForTest replaces the dialler.
func (s *Signer) SetDialForTest(f func() (net.Conn, error)) { s.dial = f }

// Public is the certificate's public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign asks the helper for a signature.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, saltLen, err := s.algorithm(opts)
	if err != nil {
		s.Failures.Add(1)
		return nil, err
	}
	sig, err := s.request(request{V: 1, Key: s.cfg.Key, Alg: alg,
		Digest: base64.StdEncoding.EncodeToString(digest), SaltLen: saltLen})
	if err != nil {
		s.Failures.Add(1)
		return nil, err
	}
	s.Signatures.Add(1)
	return sig, nil
}

// algorithm names the scheme for the wire, from the key type and the options the
// TLS stack passed.
func (s *Signer) algorithm(opts crypto.SignerOpts) (string, int, error) {
	switch s.pub.(type) {
	case ed25519.PublicKey:
		// Ed25519 hashes internally, so the "digest" is the message and there
		// is no hash to name.
		return "Ed25519", 0, nil
	case *ecdsa.PublicKey:
		h, err := hashName(opts.HashFunc())
		if err != nil {
			return "", 0, err
		}
		return "ECDSA-" + h, 0, nil
	case *rsa.PublicKey:
		h, err := hashName(opts.HashFunc())
		if err != nil {
			return "", 0, err
		}
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			salt := pss.SaltLength
			if salt == rsa.PSSSaltLengthAuto || salt == rsa.PSSSaltLengthEqualsHash {
				salt = opts.HashFunc().Size()
			}
			return "RSA-PSS-" + h, salt, nil
		}
		return "RSA-PKCS1-" + h, 0, nil
	}
	return "", 0, fmt.Errorf("signer: %T is not a key this protocol names", s.pub)
}

// hashName is the hash as the wire spells it.
func hashName(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	case crypto.SHA1:
		// TLS 1.2 with an old client can still ask for it. Naming it is
		// honest; whether to offer such a client anything is the listener's
		// own policy, not this layer's.
		return "SHA1", nil
	}
	return "", fmt.Errorf("signer: hash %v is not one this protocol names", h)
}

// request is one exchange.
type request struct {
	V       int    `json:"v"`
	Key     string `json:"key"`
	Alg     string `json:"alg"`
	Digest  string `json:"digest"`
	SaltLen int    `json:"salt_len,omitempty"`
}

type response struct {
	V     int    `json:"v"`
	Sig   string `json:"sig"`
	Error string `json:"error"`
}

// request sends one request and reads one answer, on a pooled connection.
func (s *Signer) request(req request) ([]byte, error) {
	conn, pooled, err := s.take()
	if err != nil {
		return nil, err
	}
	sig, err := s.exchange(conn, req)
	if err != nil {
		_ = conn.Close()
		if pooled {
			// A pooled connection the helper closed underneath us is not a
			// signing failure: try once on a fresh one, which is what every
			// pool has to do and what a restarted helper looks like.
			fresh, _, derr := s.take()
			if derr != nil {
				return nil, err
			}
			sig, err = s.exchange(fresh, req)
			if err != nil {
				_ = fresh.Close()
				return nil, err
			}
			s.put(fresh)
			return sig, nil
		}
		return nil, err
	}
	s.put(conn)
	return sig, nil
}

// take returns a connection, saying whether it came from the pool.
func (s *Signer) take() (net.Conn, bool, error) {
	select {
	case c := <-s.conns:
		return c, true, nil
	default:
	}
	c, err := s.dial()
	if err != nil {
		return nil, false, fmt.Errorf("signer %s: %w", s.cfg.Socket, err)
	}
	return c, false, nil
}

// put returns a connection to the pool, closing it when the pool is full.
func (s *Signer) put(c net.Conn) {
	select {
	case s.conns <- c:
	default:
		_ = c.Close()
	}
}

// exchange writes the request and reads the answer on one connection.
func (s *Signer) exchange(conn net.Conn, req request) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(s.cfg.Timeout)); err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	answer, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	var resp response
	if err := json.Unmarshal(answer, &resp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignerProtocol, err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrSignerRefused, clip([]byte(resp.Error)))
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Sig)
	if err != nil {
		return nil, fmt.Errorf("%w: the signature is not base64", ErrSignerProtocol)
	}
	if len(sig) == 0 {
		return nil, fmt.Errorf("%w: an empty signature", ErrSignerProtocol)
	}
	return sig, nil
}

// readFrame reads one newline terminated answer, bounded.
func readFrame(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 0, 512)
	one := make([]byte, 1)
	for len(buf) < maxSignerFrame {
		n, err := conn.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return buf, nil
			}
			buf = append(buf, one[0])
			continue
		}
		if err != nil {
			if len(buf) > 0 && errors.Is(err, io.EOF) {
				// A helper that answered and closed without a newline is
				// answering, so the frame stands.
				return buf, nil
			}
			return nil, fmt.Errorf("signer: %w", err)
		}
	}
	return nil, fmt.Errorf("%w: the answer is longer than %d bytes", ErrSignerProtocol, maxSignerFrame)
}

// prove asks for one signature over random bytes and verifies it against the
// public key, so a helper holding the wrong key fails the load.
func (s *Signer) prove() error {
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	var (
		digest []byte
		opts   crypto.SignerOpts = crypto.SHA256
	)
	switch s.pub.(type) {
	case ed25519.PublicKey:
		digest, opts = msg, crypto.Hash(0)
	default:
		sum := sha256.Sum256(msg)
		digest = sum[:]
	}
	sig, err := s.Sign(rand.Reader, digest, opts)
	if err != nil {
		return fmt.Errorf("signer %s: the helper could not sign with key %q: %w", s.cfg.Socket, s.cfg.Key, err)
	}
	if err := verify(s.pub, digest, sig, opts); err != nil {
		return fmt.Errorf("signer %s: the helper signed with a key that is not the certificate's: %w",
			s.cfg.Socket, err)
	}
	return nil
}

// verify checks a signature against a public key, which is the half that proves
// the helper holds what it claims.
func verify(pub crypto.PublicKey, digest, sig []byte, opts crypto.SignerOpts) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest, sig) {
			return errors.New("the signature does not verify")
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("the signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			return rsa.VerifyPSS(k, opts.HashFunc(), digest, sig, pss)
		}
		return rsa.VerifyPKCS1v15(k, opts.HashFunc(), digest, sig)
	}
	return fmt.Errorf("%T is not a key this package verifies", pub)
}

// Close releases the pooled connections.
func (s *Signer) Close() error {
	s.closeOnce.Do(func() {
		for {
			select {
			case c := <-s.conns:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

// CertificateFor builds a tls.Certificate whose private key lives in the
// helper: the chain comes from the certificate PEM, the public key from its
// leaf, and every signature goes over the socket.
//
// It is here rather than in the TLS package because the interesting part is the
// proof -- NewSigner verifies that the helper's key matches this certificate --
// and that belongs beside the signer it is about.
func CertificateFor(certPEM []byte, cfg SignerConfig) (tls.Certificate, error) {
	var chain [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return tls.Certificate{}, errors.New("signer: no certificate in the PEM")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("signer: %w", err)
	}
	s, err := NewSigner(cfg, leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: chain, PrivateKey: s, Leaf: leaf}, nil
}
