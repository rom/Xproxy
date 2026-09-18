// Package secret loads the symmetric keys the proxy signs and seals with
// (affinity cookies, challenge cookies and nonces, OIDC sessions, log
// pseudonyms) and rotates them without invalidating what was issued
// under the previous key.
//
// A secret file is either raw bytes (32 or more, the original format,
// one key) or a keyring:
//
//	xproxy-keyring v1
//	2026-09-18T10:00:00Z base64url-key
//	2026-06-01T09:00:00Z base64url-key
//
// The first key signs and seals; every key verifies and opens. Rotate
// prepends a fresh key and keeps a bounded number of old ones, so a
// cookie sealed yesterday still opens today, and after the retention
// period the old key is gone. Files are written 0600 through a rename.
package secret

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Header is the first line of a keyring file.
const Header = "xproxy-keyring v1"

// Limits.
const (
	MinKeyBytes = 32
	MaxKeys     = 16
	KeyBytes    = 32 // size of generated keys
)

// Key is one entry: its bytes and when it became primary.
type Key struct {
	Bytes []byte
	Since time.Time
}

// Keyring is the ordered key set; index 0 is the primary.
type Keyring struct {
	keys []Key
	path string
}

// Primary returns the signing key.
func (k *Keyring) Primary() []byte { return k.keys[0].Bytes }

// All returns every key, primary first, for verification.
func (k *Keyring) All() [][]byte {
	out := make([][]byte, len(k.keys))
	for i, e := range k.keys {
		out[i] = e.Bytes
	}
	return out
}

// Keys returns the entries with their dates.
func (k *Keyring) Keys() []Key { return append([]Key(nil), k.keys...) }

// Len returns the number of keys.
func (k *Keyring) Len() int { return len(k.keys) }

// Path returns the file the ring came from ("" for an ephemeral ring).
func (k *Keyring) Path() string { return k.path }

// Ephemeral returns a ring with one random key that lives in memory.
func Ephemeral() (*Keyring, error) {
	b, err := random()
	if err != nil {
		return nil, err
	}
	return &Keyring{keys: []Key{{Bytes: b, Since: time.Now()}}}, nil
}

func random() ([]byte, error) {
	b := make([]byte, KeyBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Load reads a keyring or raw key file.
func Load(path string) (*Keyring, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator configured path
	if err != nil {
		return nil, err
	}
	return parse(path, data)
}

// LoadOrCreate reads the file, or creates it with one fresh key when it
// does not exist. An empty path yields an ephemeral ring.
func LoadOrCreate(path string) (*Keyring, error) {
	if path == "" {
		return Ephemeral()
	}
	k, err := Load(path)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b, err := random()
	if err != nil {
		return nil, err
	}
	k = &Keyring{keys: []Key{{Bytes: b, Since: time.Now().UTC()}}, path: path}
	if err := k.write(); err != nil {
		return nil, err
	}
	return k, nil
}

func parse(path string, data []byte) (*Keyring, error) {
	if !strings.HasPrefix(string(data), Header+"\n") {
		if len(data) < MinKeyBytes {
			return nil, fmt.Errorf("secret %s is shorter than %d bytes", path, MinKeyBytes)
		}
		return &Keyring{keys: []Key{{Bytes: append([]byte(nil), data...)}}, path: path}, nil
	}
	k := &Keyring{path: path}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Scan() // header
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		when, enc, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("secret %s: malformed line", path)
		}
		since, err := time.Parse(time.RFC3339, when)
		if err != nil {
			return nil, fmt.Errorf("secret %s: bad date %q", path, when)
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(enc))
		if err != nil || len(b) < MinKeyBytes {
			return nil, fmt.Errorf("secret %s: bad key on line dated %s", path, when)
		}
		k.keys = append(k.keys, Key{Bytes: b, Since: since})
		if len(k.keys) > MaxKeys {
			return nil, fmt.Errorf("secret %s: more than %d keys", path, MaxKeys)
		}
	}
	if len(k.keys) == 0 {
		return nil, fmt.Errorf("secret %s: keyring without keys", path)
	}
	return k, nil
}

// write stores the ring in the keyring format.
func (k *Keyring) write() error {
	var sb strings.Builder
	sb.WriteString(Header + "\n")
	for _, e := range k.keys {
		since := e.Since
		if since.IsZero() {
			since = time.Now().UTC()
		}
		sb.WriteString(since.UTC().Format(time.RFC3339) + " " + base64.RawURLEncoding.EncodeToString(e.Bytes) + "\n")
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	if err := os.Rename(tmp, k.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}

// Rotate prepends a fresh primary key to the file at path (creating the
// file when absent, converting a raw key file to a keyring) and keeps at
// most keep previous keys. It returns the resulting ring.
func Rotate(path string, keep int) (*Keyring, error) {
	if keep < 0 || keep > MaxKeys-1 {
		return nil, fmt.Errorf("keep must be between 0 and %d", MaxKeys-1)
	}
	k, err := Load(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		k = &Keyring{path: path}
	}
	b, err := random()
	if err != nil {
		return nil, err
	}
	keys := append([]Key{{Bytes: b, Since: time.Now().UTC()}}, k.keys...)
	if len(keys) > keep+1 {
		keys = keys[:keep+1]
	}
	k.keys = keys
	if err := k.write(); err != nil {
		return nil, err
	}
	return k, nil
}
