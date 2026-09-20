// Package originsig signs proxied requests so that an origin can refuse
// traffic that did not pass through the proxy: a bypass protection that
// works where network filtering is not enough (shared hosting, a cloud
// origin reachable from the internet) and complements mutual TLS.
//
// The proxy sets one header on every forwarded request:
//
//	X-Xproxy-Signature: v1;t=<unix seconds>;kid=<key id>;sig=<base64url HMAC-SHA256>
//
// The MAC covers, as newline separated lines: the literal "v1", the
// method, the Host header sent upstream, the path, the raw query, the
// timestamp, the client address (X-Real-Ip), the request id, and the
// values of the configured extra headers in order. The origin computes
// the same MAC with the shared key, compares in constant time, and
// refuses a signature older than the TTL (replays) or with an unknown
// key id. The key file is a keyring: xproxyctl rotate-secret adds a new
// primary while the previous key stays valid for verification, so the
// origin can be updated within the grace period.
package originsig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultHeader is the signature header name.
const DefaultHeader = "X-Xproxy-Signature"

// Version is the current signature format.
const Version = "v1"

// MaxDigestBody bounds the request body a body digest covers. A larger
// bodied request is refused rather than signed without one, because a
// signature that stops at the headers lets anything past the origin
// check replace the body.
const MaxDigestBody = 8 << 20

// BodyDigest is the digest a signature covers, in the RFC 9530
// spelling. The proxy also sends it as Content-Digest, so an origin
// that verifies by hand can compare the header it already parses.
func BodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// ErrBodyDigest is returned by Verify when the body does not match the
// digest the signature covers.
var ErrBodyDigest = errors.New("origin signature body digest mismatch")

// KeyID returns the identifier of a key: the first eight hex digits of
// its SHA-256, enough to pick the right key from a ring.
func KeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// Signer signs outbound requests with the primary key of a ring.
type Signer struct {
	Header  string
	Include []string
	// Digest makes the signature cover the request body as well, for
	// the methods that carry one. Without it a signature proves a
	// request passed through the proxy, not what it carried: anything
	// that can reach the origin can replay a captured header set with
	// a body of its own for as long as the timestamp is inside the TTL.
	Digest bool
	keys   [][]byte
	kid    string
}

// New builds a signer; keys are primary first (verification accepts all).
func New(header string, include []string, keys [][]byte) (*Signer, error) {
	if len(keys) == 0 || len(keys[0]) < 16 {
		return nil, errors.New("origin signature key must be at least 16 bytes")
	}
	if header == "" {
		header = DefaultHeader
	}
	canon := make([]string, len(include))
	for i, h := range include {
		canon[i] = http.CanonicalHeaderKey(h)
	}
	return &Signer{Header: header, Include: canon, keys: keys, kid: KeyID(keys[0])}, nil
}

// Keys returns the ring, primary first.
func (s *Signer) Keys() [][]byte { return s.keys }

// canonical builds the signed string for a request with the given time,
// client address and request id.
func canonical(method, host, path, query string, ts int64, client, requestID string, include []string, hdr http.Header, digest string) string {
	var b strings.Builder
	b.WriteString(Version)
	b.WriteByte('\n')
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(host))
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(query)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('\n')
	b.WriteString(client)
	b.WriteByte('\n')
	b.WriteString(requestID)
	for _, h := range include {
		b.WriteByte('\n')
		b.WriteString(strings.Join(hdr.Values(h), ","))
	}
	if digest != "" {
		b.WriteByte('\n')
		b.WriteString(digest)
	}
	return b.String()
}

func mac(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Sign sets the signature header on an outbound request. host is the
// Host the upstream will see, client the address forwarded in
// X-Real-Ip, requestID the X-Request-Id value. digest is the body
// digest from BodyDigest, or "" for a request with no body or a signer
// that does not cover one; when it is set the header carries bd=1 so
// the origin knows to check the body, and stripping that marker breaks
// the signature rather than the check.
func (s *Signer) Sign(out *http.Request, now time.Time, client, requestID, digest string) {
	ts := now.Unix()
	msg := canonical(out.Method, out.Host, out.URL.Path, out.URL.RawQuery, ts, client, requestID, s.Include, out.Header, digest)
	sig := fmt.Sprintf("%s;t=%d;kid=%s;sig=%s", Version, ts, s.kid, mac(s.keys[0], msg))
	if digest != "" {
		out.Header.Set("Content-Digest", digest)
		sig += ";bd=1"
	}
	out.Header.Set(s.Header, sig)
}

// Errors of Verify.
var (
	ErrMissing    = errors.New("origin signature missing")
	ErrMalformed  = errors.New("origin signature malformed")
	ErrUnknownKey = errors.New("origin signature key unknown")
	ErrExpired    = errors.New("origin signature expired")
	ErrMismatch   = errors.New("origin signature mismatch")
)

// Verify checks the signature on an inbound request at an origin: the
// header, the request as received (method, Host, path, query), the
// client address and request id the proxy set, and the ttl. It is what
// an origin written in Go calls; the documentation gives the same steps
// for other languages.
func Verify(r *http.Request, header string, include []string, keys [][]byte, ttl time.Duration, now time.Time) error {
	if header == "" {
		header = DefaultHeader
	}
	v := r.Header.Get(header)
	if v == "" {
		return ErrMissing
	}
	parts := strings.Split(v, ";")
	if (len(parts) != 4 && len(parts) != 5) || parts[0] != Version {
		return ErrMalformed
	}
	fields := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, "=")
		if !ok {
			return ErrMalformed
		}
		fields[k] = val
	}
	ts, err := strconv.ParseInt(fields["t"], 10, 64)
	if err != nil || fields["sig"] == "" || fields["kid"] == "" {
		return ErrMalformed
	}
	age := now.Unix() - ts
	if age > int64(ttl/time.Second) || age < -60 {
		return ErrExpired
	}
	canon := make([]string, len(include))
	for i, h := range include {
		canon[i] = http.CanonicalHeaderKey(h)
	}
	digest := ""
	if fields["bd"] == "1" {
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxDigestBody+1))
		if err != nil || int64(len(body)) > MaxDigestBody {
			return ErrBodyDigest
		}
		// The handler still needs the body.
		r.Body = io.NopCloser(bytes.NewReader(body))
		digest = BodyDigest(body)
	}
	msg := canonical(r.Method, r.Host, r.URL.Path, r.URL.RawQuery, ts, r.Header.Get("X-Real-Ip"), r.Header.Get("X-Request-Id"), canon, r.Header, digest)
	for _, key := range keys {
		if KeyID(key) != fields["kid"] {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(mac(key, msg)), []byte(fields["sig"])) == 1 {
			return nil
		}
		return ErrMismatch
	}
	return ErrUnknownKey
}
