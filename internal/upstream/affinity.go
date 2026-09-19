package upstream

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/secret"
)

// affinity issues and verifies signed session cookies. The cookie value is
// base64url(index:uint16 || expiry:int64 || hmac-sha256[:16]). The backend
// address is never exposed; only an index that is meaningless without the
// configuration, and the signature stops a client from steering itself to
// a chosen backend.
type affinity struct {
	keys   [][]byte // primary first; every key verifies
	ttl    time.Duration
	cookie string
}

const macLen = 16

// newAffinity loads the secret (a raw key or a keyring, see
// internal/secret); an empty path makes an ephemeral key that survives
// reloads (the pool keeps it) but not restarts.
func newAffinity(cookie string, ttl time.Duration, secretFile string) (*affinity, error) {
	ring, err := secret.LoadOrCreate(secretFile)
	if err != nil {
		return nil, fmt.Errorf("affinity secret: %w", err)
	}
	return &affinity{keys: ring.All(), ttl: ttl, cookie: cookie}, nil
}

func signWith(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:macLen]
}

func (a *affinity) sign(msg []byte) []byte { return signWith(a.keys[0], msg) }

// verifyMAC accepts a signature by any key of the ring, so cookies issued
// before a rotation stay valid until the old key is dropped.
func (a *affinity) verifyMAC(msg, mac []byte) bool {
	ok := 0
	for _, k := range a.keys {
		ok |= subtle.ConstantTimeCompare(signWith(k, msg), mac)
	}
	return ok == 1
}

// issue creates a cookie value for endpoint index.
func (a *affinity) issue(index int, now time.Time) string {
	buf := make([]byte, 2+8, 2+8+macLen)
	binary.BigEndian.PutUint16(buf, uint16(index))                     //nolint:gosec // endpoint count is validated far below 65535
	binary.BigEndian.PutUint64(buf[2:], uint64(now.Add(a.ttl).Unix())) //nolint:gosec // positive unix time
	buf = append(buf, a.sign(buf)...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// verify returns the endpoint index encoded in value, or -1.
func (a *affinity) verify(value string, now time.Time) int {
	if len(value) > 64 {
		return -1
	}
	buf, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(buf) != 2+8+macLen {
		return -1
	}
	if !a.verifyMAC(buf[:10], buf[10:]) {
		return -1
	}
	exp := binary.BigEndian.Uint64(buf[2:])
	if exp > 1<<62 || int64(exp) < now.Unix() { //nolint:gosec // range checked
		return -1
	}
	return int(binary.BigEndian.Uint16(buf))
}
