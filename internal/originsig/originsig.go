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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultHeader is the signature header name.
const DefaultHeader = "X-Xproxy-Signature"

// Version is the current signature format.
const Version = "v1"

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
	keys    [][]byte
	kid     string
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
func canonical(method, host, path, query string, ts int64, client, requestID string, include []string, hdr http.Header) string {
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
	return b.String()
}

func mac(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Sign sets the signature header on an outbound request. host is the
// Host the upstream will see, client the address forwarded in
// X-Real-Ip, requestID the X-Request-Id value.
func (s *Signer) Sign(out *http.Request, now time.Time, client, requestID string) {
	ts := now.Unix()
	msg := canonical(out.Method, out.Host, out.URL.Path, out.URL.RawQuery, ts, client, requestID, s.Include, out.Header)
	out.Header.Set(s.Header, fmt.Sprintf("%s;t=%d;kid=%s;sig=%s", Version, ts, s.kid, mac(s.keys[0], msg)))
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
	if len(parts) != 4 || parts[0] != Version {
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
	msg := canonical(r.Method, r.Host, r.URL.Path, r.URL.RawQuery, ts, r.Header.Get("X-Real-Ip"), r.Header.Get("X-Request-Id"), canon, r.Header)
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
