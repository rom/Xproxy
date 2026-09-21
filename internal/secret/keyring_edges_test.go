package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The keyring signs challenge and affinity cookies, seals OIDC sessions
// and pseudonymises logs. Its file is the secret; these are the edges
// where one is created, rotated or refused.

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	// An empty path is an ephemeral ring: one key, no file, and a
	// different key every time.
	a, err := LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	if a.Len() != 1 || a.Path() != "" {
		t.Fatalf("ephemeral ring: %d keys, path %q", a.Len(), a.Path())
	}
	b, err := LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Primary()) == string(b.Primary()) {
		t.Error("two ephemeral rings share a key")
	}
	if len(a.Primary()) != KeyBytes {
		t.Errorf("a generated key is %d bytes", len(a.Primary()))
	}

	// A path that does not exist yet is created, with one key and a
	// mode nobody else can read.
	path := filepath.Join(dir, "sub", "secret.key")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	k, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 1 || k.Path() != path {
		t.Fatalf("created ring: %d keys, path %q", k.Len(), k.Path())
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("the key file is mode %v", st.Mode().Perm())
	}
	// Loading it again gives the same key: a restart must not invalidate
	// every cookie the proxy has issued.
	again, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Primary()) != string(k.Primary()) {
		t.Error("the key changed between loads")
	}
	// A file that cannot be created is an error, not an ephemeral ring:
	// an operator who asked for a file must not get cookies that stop
	// opening after a restart.
	if _, err := LoadOrCreate(filepath.Join(dir, "nope", "secret.key")); err == nil {
		t.Error("a key file in a missing directory was created")
	}
	// A file that exists but cannot be read is an error too.
	if os.Geteuid() != 0 {
		bad := filepath.Join(dir, "unreadable.key")
		if err := os.WriteFile(bad, []byte(strings.Repeat("k", 32)), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(bad); err == nil {
			t.Error("an unreadable key file was loaded")
		}
	}
	// A directory in place of the file.
	if _, err := LoadOrCreate(dir); err == nil {
		t.Error("a directory was loaded as a keyring")
	}
	// No temporary files are left behind by a create.
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file %q left behind", e.Name())
		}
	}
}

func TestRotateEdges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	// A keep count outside the range is refused before anything is
	// written: a mistake here would throw away every previous key.
	for _, keep := range []int{-1, MaxKeys, MaxKeys + 1, 1 << 20} {
		if _, err := Rotate(path, keep); err == nil {
			t.Errorf("keep %d was accepted", keep)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a refused rotation created the file")
	}

	// Rotating a file that does not exist creates it with one key.
	k, err := Rotate(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 1 {
		t.Fatalf("%d keys after the first rotation", k.Len())
	}
	first := string(k.Primary())

	// Each rotation prepends a key and keeps at most keep previous ones.
	for i := 0; i < 6; i++ {
		k, err = Rotate(path, 3)
		if err != nil {
			t.Fatal(err)
		}
		if k.Len() > 4 {
			t.Fatalf("rotation %d left %d keys", i, k.Len())
		}
	}
	if string(k.Primary()) == first {
		t.Error("the primary key did not change")
	}
	// The keys are newest first, so a cookie sealed under the previous
	// key still opens.
	entries := k.Keys()
	for i := 1; i < len(entries); i++ {
		if entries[i].Since.After(entries[i-1].Since) {
			t.Errorf("key %d is newer than key %d", i, i-1)
		}
	}
	// keep 0 drops every previous key at once, which is the emergency
	// path after a leak.
	k, err = Rotate(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 1 {
		t.Fatalf("keep 0 left %d keys", k.Len())
	}
	// A raw key file is converted to a keyring, keeping the old key as
	// the secondary.
	raw := filepath.Join(dir, "raw.key")
	if err := os.WriteFile(raw, []byte(strings.Repeat("r", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err = Rotate(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 2 || string(k.All()[1]) != strings.Repeat("r", 32) {
		t.Fatalf("a converted raw file: %d keys", k.Len())
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), Header) {
		t.Errorf("the converted file does not start with the header:\n%s", data)
	}
	if st, _ := os.Stat(raw); st.Mode().Perm() != 0o600 {
		t.Errorf("the rotated file is mode %v", st.Mode().Perm())
	}
	// A rotation that cannot write reports it rather than losing the
	// ring in memory.
	if _, err := Rotate(filepath.Join(dir, "nope", "x.key"), 1); err == nil {
		t.Error("a rotation into a missing directory succeeded")
	}
	if _, err := Rotate(dir, 1); err == nil {
		t.Error("a directory was rotated")
	}
	// A file that is not a keyring at all is refused rather than
	// silently replaced.
	broken := filepath.Join(dir, "broken.key")
	if err := os.WriteFile(broken, []byte(Header+"\nnot a line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(broken, 1); err == nil {
		t.Error("a malformed keyring was rotated")
	}
	if data, _ := os.ReadFile(broken); !strings.Contains(string(data), "not a line") {
		t.Error("a refused rotation changed the file")
	}
}

func TestKeyringAccessors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	k, err := Rotate(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Primary()) != KeyBytes {
		t.Errorf("the primary key is %d bytes", len(k.Primary()))
	}
	if k.Path() != path || k.Len() != 1 {
		t.Errorf("path %q, %d keys", k.Path(), k.Len())
	}
	// All returns the keys in order and does not hand out the ring's own
	// slice for a caller to change.
	all := k.All()
	if len(all) != 1 {
		t.Fatalf("%d keys", len(all))
	}
	all[0][0] ^= 0xff
	if string(k.Primary()) == string(all[0]) {
		t.Error("All returned the ring's own key material")
	}
	entries := k.Keys()
	entries[0].Bytes[0] ^= 0xff
	if string(k.Primary()) == string(entries[0].Bytes) {
		t.Error("Keys returned the ring's own key material")
	}
	// A ring with no keys has no primary rather than panicking.
	empty := &Keyring{}
	if empty.Len() != 0 || empty.Primary() != nil || empty.All() != nil && len(empty.All()) != 0 {
		t.Errorf("an empty ring: %d keys, primary %v", empty.Len(), empty.Primary())
	}
	var nilRing *Keyring
	if nilRing.Primary() != nil || nilRing.All() != nil || nilRing.Keys() != nil {
		t.Error("a nil ring answered with key material")
	}
	// Since is set on a created key, so an operator can see the age of
	// the material.
	if k.Keys()[0].Since.IsZero() || time.Since(k.Keys()[0].Since) > time.Hour {
		t.Errorf("the key is dated %v", k.Keys()[0].Since)
	}
}
