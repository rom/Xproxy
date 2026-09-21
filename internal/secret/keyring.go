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
	"io"
	"os"
	"path/filepath"
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

// Primary returns the signing key, or nil for a ring with no keys (a
// ring loaded from a file always has one; the guard keeps a caller from
// panicking on a zero value).
func (k *Keyring) Primary() []byte {
	if k == nil || len(k.keys) == 0 {
		return nil
	}
	return k.keys[0].Bytes
}

// All returns a copy of every key, primary first, for verification. The
// bytes are copied because they are the signing material: a caller that
// worked in place would change what the proxy signs with.
func (k *Keyring) All() [][]byte {
	if k == nil {
		return nil
	}
	out := make([][]byte, len(k.keys))
	for i, e := range k.keys {
		out[i] = append([]byte(nil), e.Bytes...)
	}
	return out
}

// Keys returns a copy of the entries with their dates.
func (k *Keyring) Keys() []Key {
	if k == nil {
		return nil
	}
	out := make([]Key, len(k.keys))
	for i, e := range k.keys {
		out[i] = Key{Bytes: append([]byte(nil), e.Bytes...), Since: e.Since}
	}
	return out
}

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
//
// The file's permissions are part of its contents being secret: these
// keys sign challenge and affinity cookies, seal OIDC sessions and
// pseudonymise logs, so anybody who can read the file can mint any of
// them. A file other accounts can read, or the group can write, is
// refused rather than loaded — the same rule the proxy already applies
// to password and client-secret files. The stat is taken from the open
// descriptor, so a file swapped between the check and the read cannot
// slip past it.
func Load(path string) (*Keyring, error) {
	f, err := os.Open(path) //nolint:gosec // operator configured path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkMode(path, fi.Mode().Perm()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxFileBytes {
		return nil, fmt.Errorf("secret %s is larger than %d bytes", path, maxFileBytes)
	}
	return parse(path, data)
}

// maxFileBytes bounds a secret file: a keyring of MaxKeys entries is a
// few kilobytes, and a raw key is one key.
const maxFileBytes = 1 << 20

// checkMode refuses permissions that let another account read the keys.
// Group read is allowed: a deployment that runs the proxy and its tools
// under one group is ordinary. Group write is not, because it lets
// somebody else choose the keys.
func checkMode(path string, m os.FileMode) error {
	if m&0o007 != 0 {
		return fmt.Errorf("secret %s is readable or writable by other (mode %04o); run chmod 640 %s", path, m, path)
	}
	if m&0o020 != 0 {
		return fmt.Errorf("secret %s is writable by its group (mode %04o); run chmod 640 %s", path, m, path)
	}
	return nil
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
	if err := sc.Err(); err != nil {
		// A line too long for the scanner, or a read that failed: the
		// keys after it would be dropped silently, and a cookie sealed
		// under one of them would stop opening for no visible reason.
		return nil, fmt.Errorf("secret %s: %w", path, err)
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
	// A fresh O_EXCL temp file in the same directory: a pre-planted name or
	// symlink can neither receive the key nor choose its permissions.
	f, err := os.CreateTemp(filepath.Dir(k.path), filepath.Base(k.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write secret: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.WriteString(sb.String()); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
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
