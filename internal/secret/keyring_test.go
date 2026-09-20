package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	k, err := LoadOrCreate(path)
	if err != nil || k.Len() != 1 || len(k.Primary()) != KeyBytes {
		t.Fatalf("create: %v %v", err, k)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	again, err := LoadOrCreate(path)
	if err != nil || !bytes.Equal(again.Primary(), k.Primary()) {
		t.Fatal("reload changed the key")
	}
	// Rotation keeps the old key for verification.
	old := k.Primary()
	r, err := Rotate(path, 2)
	if err != nil || r.Len() != 2 || bytes.Equal(r.Primary(), old) || !bytes.Equal(r.All()[1], old) {
		t.Fatalf("rotate: %v %v", err, r)
	}
	for i := 0; i < 5; i++ {
		if r, err = Rotate(path, 2); err != nil {
			t.Fatal(err)
		}
	}
	if r.Len() != 3 {
		t.Fatalf("keep bound: %d keys", r.Len())
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), Header+"\n") || strings.Count(string(data), "\n") != 4 {
		t.Fatalf("file:\n%s", data)
	}
	// Raw key files still load and convert on rotation.
	raw := filepath.Join(dir, "raw")
	rawKey := bytes.Repeat([]byte{7}, 40)
	_ = os.WriteFile(raw, rawKey, 0o600)
	k, err = Load(raw)
	if err != nil || k.Len() != 1 || !bytes.Equal(k.Primary(), rawKey) {
		t.Fatalf("raw: %v", err)
	}
	r, err = Rotate(raw, 1)
	if err != nil || r.Len() != 2 || !bytes.Equal(r.All()[1], rawKey) {
		t.Fatalf("raw rotate: %v %v", err, r)
	}
	// Errors: short raw key, bad lines, too many keys, missing file.
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("tooshort"), 0o600)
	if _, err := Load(short); err == nil {
		t.Fatal("short key accepted")
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte(Header+"\nnot-a-date AAAA\n"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("bad line accepted")
	}
	_ = os.WriteFile(bad, []byte(Header+"\n"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("empty ring accepted")
	}
	if _, err := Load(filepath.Join(dir, "none")); err == nil {
		t.Fatal("missing file loaded")
	}
	if _, err := Rotate(path, MaxKeys); err == nil {
		t.Fatal("keep beyond the bound accepted")
	}
	e, err := Ephemeral()
	if err != nil || e.Path() != "" || e.Len() != 1 {
		t.Fatalf("ephemeral: %v", err)
	}
	if k, err := LoadOrCreate(""); err != nil || k.Path() != "" {
		t.Fatalf("empty path: %v", err)
	}
}

// A keyring any local account can read is as good as published: it signs
// challenge and affinity cookies and seals OIDC sessions.
func TestWorldReadableKeyringIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ring")
	if _, err := Rotate(path, 2); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode os.FileMode
		want string
	}{
		{0o644, "readable or writable by other"},
		{0o604, "readable or writable by other"},
		{0o660, "writable by its group"},
	} {
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("mode %04o: %v", tc.mode, err)
		}
	}
	// Owner-only and owner plus group read are both fine.
	for _, mode := range []os.FileMode{0o600, 0o640} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Fatalf("mode %04o: %v", mode, err)
		}
	}
}

// A line the scanner cannot hold used to end the loop silently, dropping
// every key after it: cookies sealed under those keys stopped opening
// with nothing in the logs to say why.
func TestKeyringLineTooLongIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ring")
	long := Header + "\n2026-01-01T00:00:00Z " + strings.Repeat("A", 128<<10) + "\n"
	if err := os.WriteFile(path, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("an over-long keyring line was accepted")
	}
}
