package upstream

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

// affinity issues and verifies signed session cookies. The cookie value is
// base64url(index:uint16 || expiry:int64 || hmac-sha256[:16]). The backend
// address is never exposed; only an index that is meaningless without the
// configuration, and the signature stops a client from steering itself to
// a chosen backend.
type affinity struct {
	key    []byte
	ttl    time.Duration
	cookie string
}

const macLen = 16

func newAffinity(cookie string, ttl time.Duration, secretFile string) (*affinity, error) {
	key, err := loadOrCreateSecret(secretFile)
	if err != nil {
		return nil, err
	}
	return &affinity{key: key, ttl: ttl, cookie: cookie}, nil
}

func loadOrCreateSecret(path string) ([]byte, error) {
	if path == "" {
		// Ephemeral key: affinity survives reloads (the pool keeps the key)
		// but not restarts, which is acceptable for a single instance.
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		return k, nil
	}
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // operator configured path
		if len(b) < 32 {
			return nil, fmt.Errorf("affinity secret %s is shorter than 32 bytes", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read affinity secret: %w", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, fmt.Errorf("create affinity secret: %w", err)
	}
	return k, nil
}

func (a *affinity) sign(msg []byte) []byte {
	m := hmac.New(sha256.New, a.key)
	m.Write(msg)
	return m.Sum(nil)[:macLen]
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
	if subtle.ConstantTimeCompare(a.sign(buf[:10]), buf[10:]) != 1 {
		return -1
	}
	exp := binary.BigEndian.Uint64(buf[2:])
	if exp > 1<<62 || int64(exp) < now.Unix() { //nolint:gosec // range checked
		return -1
	}
	return int(binary.BigEndian.Uint16(buf))
}
