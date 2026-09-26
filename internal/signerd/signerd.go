// Package signerd is the helper side of the external signer protocol: it holds
// private keys and answers signature requests over a Unix socket.
//
// Why a separate process at all. A TLS private key in the proxy's memory is
// reachable by anything that can read that memory -- a core dump, a debugger, a
// read primitive in a bug. Moving the key out means the proxy never holds it:
// it sends a digest and gets a signature back, and what an attacker who owns the
// proxy can then do is ask for signatures while they own it, which is bounded in
// time and is not the same as walking away with the key.
//
// It is also where cgo goes. A PKCS#11 module is a vendor C library, and the
// daemons are built with CGO_ENABLED=0 on purpose; a helper is the right place
// for that library, its bugs and its dlopen. This package does not itself speak
// PKCS#11 -- it serves keys it can read as PEM, from a file, the environment or
// a vault -- but it is the process a PKCS#11 build would extend, and the
// protocol is documented so that an operator can write their own helper in
// whatever language their HSM has bindings for.
//
// What this package deliberately does not do:
//
//   - It never sends a key anywhere. There is no "give me the key" request in
//     the protocol; there is only "sign this".
//   - It answers a digest, not a document. It cannot tell a TLS handshake from
//     anything else, so a client that can reach the socket can have anything
//     signed by the keys this helper holds. That is what the socket's
//     permissions are for, and why the helper's socket belongs to one user.
//   - It does not log a digest or a signature. A digest is not secret, but a log
//     of every handshake's digest is a side channel nobody asked for.
package signerd

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
)

// Limits on one exchange. A request is a digest and a few field names; anything
// larger is a client that is not speaking this protocol, and reading it would be
// the helper's own memory bound rather than the client's.
const (
	maxFrame     = 64 << 10
	readTimeout  = 30 * time.Second
	writeTimeout = 5 * time.Second
	// maxDigest bounds the digest a request may carry. SHA-512 is 64 bytes;
	// Ed25519 signs a message rather than a digest, and a TLS 1.3 CertificateVerify
	// transcript is a little over a hundred, so the bound is generous and still
	// nowhere near a document.
	maxDigest = 4 << 10
)

// A Key is one private key this helper will sign with.
type Key struct {
	// Name is what a request names it by. One helper may hold several.
	Name string
	// Signer is the key itself. It may be an in-memory key parsed from PEM or
	// anything else implementing crypto.Signer -- a PKCS#11 session, a TPM
	// handle -- which is the seam a different build extends.
	Signer crypto.Signer
}

// A Server answers signature requests on a listener.
type Server struct {
	keys map[string]crypto.Signer
	log  *slog.Logger

	// Counters for the status line: what was signed, what was refused, and
	// what could not be read as a request at all. The three are separate
	// because they mean different things -- refusals are a misconfigured
	// proxy, unreadable requests are something else on the socket.
	Signatures atomic.Uint64
	Refusals   atomic.Uint64
	Malformed  atomic.Uint64

	// Notices bound the log. A client that can reach the socket can send a
	// refusable request as fast as it likes, and a line per refusal would be
	// that client's write amplification on this machine's journal -- which
	// is exactly the failure SIGNER.md tells a helper's author to avoid, so
	// this one had better not have it. Each notice counts every occurrence
	// and warns at most once a minute with the number since the last
	// warning, so a flood stays one line a minute and the counters stay
	// exact.
	unknownKey bound.Notice
	badAlg     bound.Notice
	badFrame   bound.Notice
	signFailed bound.Notice

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// New builds a server over the keys given. A helper with no keys is refused:
// it would accept connections and refuse every request, which reads from the
// outside exactly like a key that is loaded and wrong.
func New(keys []Key, log *slog.Logger) (*Server, error) {
	if len(keys) == 0 {
		return nil, errors.New("signerd: no keys; a helper with nothing to sign with refuses every request")
	}
	m := make(map[string]crypto.Signer, len(keys))
	for _, k := range keys {
		name := strings.TrimSpace(k.Name)
		switch {
		case name == "":
			return nil, errors.New("signerd: a key with no name cannot be asked for")
		case k.Signer == nil:
			return nil, fmt.Errorf("signerd: key %q has no signer", name)
		case m[name] != nil:
			return nil, fmt.Errorf("signerd: key %q is defined twice", name)
		}
		m[name] = k.Signer
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{keys: m, log: log, conns: map[net.Conn]struct{}{}}, nil
}

// Names lists the keys this helper holds, for the start-up line. A name is not a
// secret and an operator who cannot see which keys loaded cannot tell a typo in
// a name from a key that failed to load.
func (s *Server) Names() []string {
	out := make([]string, 0, len(s.keys))
	for n := range s.keys {
		out = append(out, n)
	}
	return out
}

// PublicKey is the public half of one of this helper's keys, so that an
// operator can check what loaded against the certificate that will use it.
func (s *Server) PublicKey(name string) (crypto.PublicKey, bool) {
	k, ok := s.keys[strings.TrimSpace(name)]
	if !ok {
		return nil, false
	}
	return k.Public(), true
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		s.track(c)
		go func() {
			defer s.untrack(c)
			s.session(c)
		}()
	}
}

// Close drops every connection in progress, which is what a shutdown needs: a
// handshake waiting on a signature should fail now rather than hang.
func (s *Server) Close() {
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

// session answers every request on one connection.
//
// The proxy keeps connections open and reuses them, so this loops rather than
// answering once: a new connection per signature would make every handshake pay
// for a socket.
func (s *Server) session(c net.Conn) {
	// The buffer is the frame bound: ReadSlice fills it and refuses, so
	// sizing it to maxFrame is what makes that constant true rather than
	// decorative.
	br := bufio.NewReaderSize(c, maxFrame)
	for {
		if err := c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return
		}
		line, err := readFrame(br)
		if err != nil {
			// A closed connection is the ordinary end of a session, not an
			// event. Anything else is one, because something on this socket
			// is not speaking the protocol.
			if !errors.Is(err, errClosed) {
				s.Malformed.Add(1)
				s.badFrame.Hit(s.log, "a request could not be read", "error", err.Error())
			}
			return
		}
		resp := s.answer(line)
		if err := s.write(c, resp); err != nil {
			return
		}
	}
}

// answer turns one request into one response. It never returns an error: a
// refusal is a response, because a helper that hung up on a bad request would
// cost the proxy a connection and tell it nothing.
func (s *Server) answer(line []byte) response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		s.Malformed.Add(1)
		return response{V: 1, Error: "the request is not this protocol"}
	}
	if req.V != 1 {
		s.Malformed.Add(1)
		return response{V: 1, Error: fmt.Sprintf("version %d is not supported", req.V)}
	}
	key, ok := s.keys[strings.TrimSpace(req.Key)]
	if !ok {
		// The name is echoed and the names this helper holds are not: a
		// caller that can enumerate the keys learns which certificates this
		// machine serves, and it is not needed to fix a typo.
		s.Refusals.Add(1)
		s.unknownKey.Hit(s.log, "a request named a key this helper does not hold", "key", clip(req.Key))
		return response{V: 1, Error: "the key is not loaded"}
	}
	digest, err := base64.StdEncoding.DecodeString(req.Digest)
	switch {
	case err != nil:
		s.Malformed.Add(1)
		return response{V: 1, Error: "the digest is not base64"}
	case len(digest) == 0:
		s.Malformed.Add(1)
		return response{V: 1, Error: "the digest is empty"}
	case len(digest) > maxDigest:
		// A digest this large is a client trying to have a document signed
		// rather than a hash of one.
		s.Malformed.Add(1)
		return response{V: 1, Error: "the digest is too long to be a digest"}
	}
	opts, err := optsFor(req.Alg, req.SaltLen, key.Public())
	if err != nil {
		s.Refusals.Add(1)
		s.badAlg.Hit(s.log, "a request named an algorithm this helper will not sign with",
			"key", clip(req.Key), "alg", clip(req.Alg), "error", err.Error())
		return response{V: 1, Error: err.Error()}
	}
	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		s.Refusals.Add(1)
		// The error may come from an HSM and is the operator's only clue, so
		// it is logged; it is also sent back, because the proxy's own log is
		// where somebody will look first.
		// Bounded like the rest: a device that has come unplugged fails every
		// request, and the hundredth line says nothing the first did not.
		s.signFailed.Hit(s.log, "signing failed", "key", clip(req.Key), "alg", clip(req.Alg), "error", err.Error())
		return response{V: 1, Error: "signing failed: " + err.Error()}
	}
	s.Signatures.Add(1)
	return response{V: 1, Sig: base64.StdEncoding.EncodeToString(sig)}
}

func (s *Server) write(c net.Conn, resp response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if err := c.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err = c.Write(append(b, '\n'))
	return err
}

// request and response are the wire, and they have to match
// internal/keysource/signer.go exactly. They are duplicated rather than shared
// because that file is the *client* and this is the specification an operator's
// own helper is written against: a shared struct would make a change here look
// local when it is a protocol change.
type request struct {
	V       int    `json:"v"`
	Key     string `json:"key"`
	Alg     string `json:"alg"`
	Digest  string `json:"digest"`
	SaltLen int    `json:"salt_len,omitempty"`
}

type response struct {
	V     int    `json:"v"`
	Sig   string `json:"sig,omitempty"`
	Error string `json:"error,omitempty"`
}

var errClosed = errors.New("signerd: the connection ended")

// readFrame reads one newline-terminated request, bounded by the reader's buffer.
//
// A frame larger than the bound ends the connection rather than drawing a
// refusal. That is deliberate: a client sending megabytes without a newline is
// not mis-configured, it is not speaking this protocol, and answering it would
// mean reading the rest of whatever it is sending.
func readFrame(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, fmt.Errorf("a request longer than %d bytes", maxFrame)
	case err != nil:
		return nil, errClosed
	}
	return line, nil
}

// optsFor turns the algorithm the wire named into the options crypto.Signer
// takes, refusing anything the key cannot do.
//
// The check against the key type is the point: a request naming RSA-PSS for an
// ECDSA key is a misconfiguration, and signing it anyway with whatever the key
// does produces a signature the verifier rejects -- a failure three layers away
// from its cause.
func optsFor(alg string, saltLen int, pub crypto.PublicKey) (crypto.SignerOpts, error) {
	name := strings.TrimSpace(alg)
	switch {
	case name == "Ed25519":
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return nil, fmt.Errorf("alg Ed25519 was asked of a %s key", keyKind(pub))
		}
		// Ed25519 hashes internally: the "digest" is the message, and the
		// options say no pre-hash.
		return crypto.Hash(0), nil
	case strings.HasPrefix(name, "ECDSA-"):
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("alg %s was asked of a %s key", name, keyKind(pub))
		}
		return hashFor(strings.TrimPrefix(name, "ECDSA-"))
	case strings.HasPrefix(name, "RSA-PSS-"):
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("alg %s was asked of a %s key", name, keyKind(pub))
		}
		h, err := hashFor(strings.TrimPrefix(name, "RSA-PSS-"))
		if err != nil {
			return nil, err
		}
		hash := h.(crypto.Hash)
		// The salt length is on the wire because a verifier that assumes the
		// wrong one rejects a correct signature. An absent or negative value
		// means "equal to the hash", which is what TLS 1.3 requires anyway.
		if saltLen <= 0 {
			saltLen = hash.Size()
		}
		if saltLen > 512 {
			return nil, fmt.Errorf("salt_len %d is not a salt length", saltLen)
		}
		return &rsa.PSSOptions{SaltLength: saltLen, Hash: hash}, nil
	case strings.HasPrefix(name, "RSA-PKCS1-"):
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("alg %s was asked of a %s key", name, keyKind(pub))
		}
		return hashFor(strings.TrimPrefix(name, "RSA-PKCS1-"))
	}
	return nil, fmt.Errorf("alg %q is not one this protocol names", clip(alg))
}

// hashFor is the hash the wire spells.
func hashFor(h string) (crypto.SignerOpts, error) {
	switch h {
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	case "SHA1":
		// A TLS 1.2 client can still ask for it. Refusing here would be this
		// helper deciding a listener's policy from behind a socket, which is
		// the wrong place: the listener's min_version and cipher_suites are
		// where that decision is written down.
		return crypto.SHA1, nil
	}
	return nil, fmt.Errorf("hash %q is not one this protocol names", clip(h))
}

// keyKind names a key type for an error, without saying anything about the key.
func keyKind(pub crypto.PublicKey) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

// clip bounds a value that came off the socket before it reaches a log line. A
// client can send a megabyte of field and a log that carried it would be the
// client's own write amplification.
func clip(s string) string {
	const max = 64
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
