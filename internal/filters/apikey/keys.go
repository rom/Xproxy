// Package apikey is a built-in filter kind that authenticates API clients
// with keys managed through their whole life: issued with `xproxyctl
// apikey add` (the plaintext is shown once, the file keeps a SHA-256),
// scoped, expiring, rotated with a grace period for the previous secret
// and revoked. The filter re-reads the file when it changes.
//
//	filters:
//	  - name: partners
//	    kind: api_key
//	    options:
//	      keys_file: /etc/xproxy/api-keys          # managed by xproxyctl apikey
//	      source: header:X-Api-Key                 # default; or bearer, query:<name>
//	      required_scopes: [orders:read]           # every listed scope; default none
//	      forward_id_header: X-Api-Key-Id          # default; "" disables
//	      forward_scopes_header: X-Api-Key-Scopes  # default; "" disables
//	      strip: true                              # remove the key upstream; default true
//	      reload: 30s                              # how often the file's change time is checked
//	      expiry_warning: 168h                     # log keys expiring within this window
package apikey

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Key is one entry of the keys file.
type Key struct {
	ID      string
	State   string // active or revoked
	Expires time.Time
	Scopes  []string
	Hash    string // hex SHA-256 of the plaintext key
	// PrevHash and PrevUntil keep the secret before a rotation valid
	// for a grace period.
	PrevHash  string
	PrevUntil time.Time
	Note      string
	Created   time.Time
}

// File format: one key per line, eight fields separated by "|":
// id|state|expires|scopes|sha256|prev_sha256|prev_until|note, with "-"
// for an empty field and "," between scopes. Lines starting with # are
// comments.
const (
	fieldCount = 9
	// KeyPrefix starts every plaintext key so that a leaked one is
	// recognisable by scanners.
	KeyPrefix = "xpk_"
)

// Load reads the keys file. Malformed lines are errors: a key file is
// written by the tool and edited rarely, so a typo must not silently
// drop a key (or its revocation).
func Load(path string) ([]Key, error) {
	data, err := os.ReadFile(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse decodes the keys file contents; path names it in errors.
func Parse(data []byte, path string) ([]Key, error) {
	var keys []Key
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("%s:%d: duplicate key id %s", path, n, k.ID)
		}
		seen[k.ID] = true
		keys = append(keys, k)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func parseLine(line string) (Key, error) {
	parts := strings.Split(line, "|")
	if len(parts) != fieldCount {
		return Key{}, fmt.Errorf("expected %d fields, got %d", fieldCount, len(parts))
	}
	k := Key{ID: parts[0], State: parts[1], Hash: parts[4], PrevHash: dash(parts[5]), Note: dash(parts[7])}
	if !idOK(k.ID) {
		return Key{}, fmt.Errorf("bad key id %q", k.ID)
	}
	if k.State != "active" && k.State != "revoked" {
		return Key{}, fmt.Errorf("bad state %q", k.State)
	}
	var err error
	if k.Expires, err = parseTime(parts[2]); err != nil {
		return Key{}, fmt.Errorf("expires: %w", err)
	}
	if s := dash(parts[3]); s != "" {
		k.Scopes = strings.Split(s, ",")
	}
	if len(k.Hash) != 64 || !isHex(k.Hash) {
		return Key{}, errors.New("hash is not a hex SHA-256")
	}
	if k.PrevHash != "" && (len(k.PrevHash) != 64 || !isHex(k.PrevHash)) {
		return Key{}, errors.New("previous hash is not a hex SHA-256")
	}
	if k.PrevUntil, err = parseTime(parts[6]); err != nil {
		return Key{}, fmt.Errorf("prev_until: %w", err)
	}
	if k.Created, err = parseTime(parts[8]); err != nil {
		return Key{}, fmt.Errorf("created: %w", err)
	}
	return k, nil
}

func (k Key) line() string {
	scopes := strings.Join(k.Scopes, ",")
	return strings.Join([]string{k.ID, k.State, fmtTime(k.Expires), orDash(scopes), k.Hash, orDash(k.PrevHash), fmtTime(k.PrevUntil), orDash(strings.ReplaceAll(k.Note, "|", "/")), fmtTime(k.Created)}, "|")
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func parseTime(s string) (time.Time, error) {
	if s == "-" || s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func idOK(id string) bool {
	if len(id) < 1 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// HashKey returns the stored digest of a plaintext key.
func HashKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Generate returns a fresh plaintext key for id: the prefix, the id and
// 32 random bytes, so the id is recoverable from the key for lookups.
func Generate(id string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return KeyPrefix + id + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// IDOf extracts the id from a plaintext key ("" when the key does not
// have the expected shape).
func IDOf(plain string) string {
	rest, ok := strings.CutPrefix(plain, KeyPrefix)
	if !ok {
		return ""
	}
	id, _, ok := strings.Cut(rest, "_")
	if !ok || !idOK(id) {
		return ""
	}
	return id
}

// Save writes the keys atomically (a temporary file renamed over path,
// mode 0600).
func Save(path string, keys []Key) error {
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	var b strings.Builder
	b.WriteString("# xproxy API keys: id|state|expires|scopes|sha256|prev_sha256|prev_until|note|created\n")
	b.WriteString("# managed by xproxyctl apikey; the plaintext keys are never stored\n")
	for _, k := range keys {
		b.WriteString(k.line())
		b.WriteByte('\n')
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Add issues a key: it appends the entry and returns the plaintext,
// which is shown once and never stored.
func Add(path, id string, scopes []string, expires time.Time, note string) (string, error) {
	if !idOK(id) {
		return "", fmt.Errorf("key id %q: use 1 to 32 characters from a-z, 0-9, - and _", id)
	}
	keys, err := Load(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	for _, k := range keys {
		if k.ID == id {
			return "", fmt.Errorf("key %s exists; rotate or revoke it", id)
		}
	}
	plain, err := Generate(id)
	if err != nil {
		return "", err
	}
	keys = append(keys, Key{ID: id, State: "active", Expires: expires, Scopes: scopes, Hash: HashKey(plain), Note: note, Created: time.Now().UTC().Truncate(time.Second)})
	return plain, Save(path, keys)
}

// Rotate gives id a new secret and keeps the previous one valid for
// grace; it returns the new plaintext.
func Rotate(path, id string, grace time.Duration) (string, error) {
	keys, err := Load(path)
	if err != nil {
		return "", err
	}
	for i := range keys {
		if keys[i].ID != id {
			continue
		}
		if keys[i].State != "active" {
			return "", fmt.Errorf("key %s is %s", id, keys[i].State)
		}
		plain, err := Generate(id)
		if err != nil {
			return "", err
		}
		keys[i].PrevHash, keys[i].PrevUntil = keys[i].Hash, time.Time{}
		if grace > 0 {
			keys[i].PrevUntil = time.Now().UTC().Add(grace).Truncate(time.Second)
		} else {
			keys[i].PrevHash = ""
		}
		keys[i].Hash = HashKey(plain)
		return plain, Save(path, keys)
	}
	return "", fmt.Errorf("no key %s", id)
}

// Revoke marks id revoked (kept in the file so the id is never reused
// and the revocation is visible).
func Revoke(path, id string) error {
	keys, err := Load(path)
	if err != nil {
		return err
	}
	for i := range keys {
		if keys[i].ID == id {
			keys[i].State = "revoked"
			keys[i].PrevHash, keys[i].PrevUntil = "", time.Time{}
			return Save(path, keys)
		}
	}
	return fmt.Errorf("no key %s", id)
}

// Remove deletes id from the file (a revoked key that is old enough).
func Remove(path, id string) error {
	keys, err := Load(path)
	if err != nil {
		return err
	}
	out := keys[:0]
	found := false
	for _, k := range keys {
		if k.ID == id {
			found = true
			continue
		}
		out = append(out, k)
	}
	if !found {
		return fmt.Errorf("no key %s", id)
	}
	return Save(path, out)
}
