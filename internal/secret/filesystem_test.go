package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A keyring file is the material behind every session cookie, every
// signed origin header and every device identifier this proxy issues.
// It lives on a file system an operator shares with other accounts, a
// backup tool, an editor that writes through a temporary file, and a
// configuration management system that may put it in place while the
// proxy is reading it. These tests are about the file rather than the
// cryptography.

// write writes a keyring file with the given mode.
func write(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // beat the umask
		t.Fatal(err)
	}
	return p
}

// ring renders a keyring document with n keys.
func ring(n int) string {
	var sb strings.Builder
	sb.WriteString(Header + "\n")
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		for j := range key {
			key[j] = byte(i + 1)
		}
		// Newest first, which is the order the file is written in: the
		// primary is the key a new cookie is sealed with.
		fmt.Fprintf(&sb, "2026-09-%02dT10:00:00Z %s\n", 28-i, base64.RawURLEncoding.EncodeToString(key))
	}
	return sb.String()
}

// TestPermissions covers the modes a keyring may and may not have.
// Group read is ordinary — the proxy and its tools under one group —
// but anything world readable or group writable means somebody else
// can read the keys or choose them.
func TestPermissions(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true},
		{0o640, true},
		{0o400, true},
		{0o644, false},
		{0o604, false},
		{0o606, false},
		{0o660, false},
		{0o666, false},
		{0o777, false},
		{0o002, false},
		{0o620, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%04o", uint32(tc.mode)), func(t *testing.T) {
			p := write(t, dir, fmt.Sprintf("k%04o", uint32(tc.mode)), ring(1), tc.mode)
			_, err := Load(p)
			if tc.ok && err != nil {
				t.Fatalf("mode %04o was refused: %v", uint32(tc.mode), err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("mode %04o was accepted", uint32(tc.mode))
				}
				// The message has to say what to do about it.
				if !strings.Contains(err.Error(), "chmod") {
					t.Fatalf("the error does not say how to fix it: %v", err)
				}
			}
		})
	}
}

// TestCreatedFilesAreNotReadable requires a keyring the proxy creates
// itself to be 0600 whatever the process umask is.
func TestCreatedFilesAreNotReadable(t *testing.T) {
	old := syscallUmaskForTest(0)
	defer syscallUmaskForTest(old)
	dir := t.TempDir()
	p := filepath.Join(dir, "created.key")
	if _, err := LoadOrCreate(p); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("a created keyring is mode %04o with a zero umask", uint32(st.Mode().Perm()))
	}
	// And it loads back.
	k, err := Load(p)
	if err != nil || k.Len() != 1 {
		t.Fatalf("reload: %v %v", k, err)
	}
	if len(k.Keys()) != 1 || len(k.Keys()[0].Bytes) < MinKeyBytes {
		t.Fatalf("the created key is %v", k.Keys())
	}
	// Keys returns a copy: a caller that edits it must not reach the
	// ring every request verifies against.
	k.Keys()[0].Bytes[0] ^= 0xff
	if k.Keys()[0].Bytes[0] == k.Primary()[0]^0xff {
		t.Fatal("Keys handed out the ring's own slice header")
	}
}

// TestTruncatedAndCorrupt covers files that are not what they claim.
// Each must be an error naming the file; the one thing that must never
// happen is a ring that silently holds fewer keys than the file does,
// because a cookie sealed under a dropped key stops opening for no
// visible reason.
func TestTruncatedAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	full := ring(3)
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"header only", Header + "\n"},
		{"header without newline", Header},
		{"no date", Header + "\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"},
		{"bad date", Header + "\nyesterday " + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "\n"},
		{"bad base64", Header + "\n2026-09-20T10:00:00Z !!!!\n"},
		{"short key", Header + "\n2026-09-20T10:00:00Z " + base64.RawURLEncoding.EncodeToString(make([]byte, 4)) + "\n"},
		{"truncated mid line", full[:len(full)-20]},
		{"only comments", Header + "\n# nothing here\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := write(t, dir, "corrupt-"+strings.ReplaceAll(tc.name, " ", "-"), tc.content, 0o600)
			k, err := Load(p)
			if err == nil {
				// A truncated last line may leave a valid prefix; what
				// it must not do is produce a ring that claims keys it
				// does not have.
				for _, key := range k.Keys() {
					if len(key.Bytes) < MinKeyBytes {
						t.Fatalf("%s produced a %d byte key", tc.name, len(key.Bytes))
					}
				}
				return
			}
			if !strings.Contains(err.Error(), p) {
				t.Fatalf("the error does not name the file: %v", err)
			}
		})
	}
}

// TestRawKeyFile covers the other accepted shape: a file that is just
// key material, which is how an operator hands over a secret generated
// elsewhere.
func TestRawKeyFile(t *testing.T) {
	dir := t.TempDir()
	raw := strings.Repeat("k", 32)
	p := write(t, dir, "raw", raw, 0o600)
	k, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 1 || string(k.Primary()) != raw {
		t.Fatalf("a raw key file: %v", k.Keys())
	}
	// Too short is refused rather than used: a 4 byte key is not a key.
	short := write(t, dir, "short", "abcd", 0o600)
	if _, err := Load(short); err == nil {
		t.Fatal("a four byte secret was accepted")
	}
	// Rotating a raw key file converts it to a keyring and keeps the
	// original as a previous key, so what it sealed still opens.
	if _, err := Rotate(p, 2); err != nil {
		t.Fatal(err)
	}
	k, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 2 {
		t.Fatalf("after rotation the ring holds %d keys", k.Len())
	}
	if string(k.All()[1]) != raw {
		t.Fatal("rotation dropped the original key")
	}
}

// TestOversizeFile covers a path that is not a keyring at all: a log, a
// core dump, a disk image pointed at by a typo in the configuration.
func TestOversizeFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "big", strings.Repeat("x", maxFileBytes+1), 0o600)
	_, err := Load(p)
	if err == nil {
		t.Fatal("a file over the ceiling was loaded")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

// TestLongLine covers a keyring whose line is longer than the scanner's
// buffer. The keys after it would otherwise be dropped in silence.
func TestLongLine(t *testing.T) {
	dir := t.TempDir()
	long := Header + "\n2026-09-20T10:00:00Z " + strings.Repeat("A", 200000) + "\n" + strings.TrimPrefix(ring(1), Header+"\n")
	p := write(t, dir, "long", long, 0o600)
	k, err := Load(p)
	if err == nil && k.Len() < 2 {
		t.Fatal("a line the scanner could not read dropped the keys after it in silence")
	}
}

// TestTooManyKeys covers the ring's own bound.
func TestTooManyKeys(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "many", ring(MaxKeys+1), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatalf("a ring of %d keys was loaded", MaxKeys+1)
	}
	ok := write(t, dir, "max", ring(MaxKeys), 0o600)
	k, err := Load(ok)
	if err != nil || k.Len() != MaxKeys {
		t.Fatalf("a ring of exactly %d keys: %v %v", MaxKeys, k, err)
	}
}

// TestMissingAndUnreadable covers the paths that are not a file.
func TestMissingAndUnreadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing file gave %v", err)
	}
	// A directory where a file belongs.
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sub); err == nil {
		t.Fatal("a directory was loaded as a keyring")
	}
	// LoadOrCreate into a directory that does not exist fails rather
	// than running on an ephemeral ring nobody can rotate.
	if _, err := LoadOrCreate(filepath.Join(dir, "no", "such", "dir", "k")); err == nil {
		t.Fatal("a keyring in a missing directory was created")
	}
	// An empty path is the documented way to ask for an ephemeral ring.
	k, err := LoadOrCreate("")
	if err != nil || k.Len() != 1 || k.Path() != "" {
		t.Fatalf("an ephemeral ring: %v %v", k, err)
	}
}

// TestSymlink covers a keyring reached through a link. Following one
// inside a directory the operator controls is ordinary; what matters is
// that a rotation does not write through it and leave the key somewhere
// else, and that the permission check applies to the file the
// descriptor actually refers to.
func TestSymlink(t *testing.T) {
	dir := t.TempDir()
	real := write(t, dir, "real.key", ring(1), 0o600)
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Load(link); err != nil {
		t.Fatalf("a keyring through a symlink: %v", err)
	}
	// A link to a world readable file is refused, though the link
	// itself is 0777 as links always are.
	bad := write(t, dir, "bad.key", ring(1), 0o644)
	badLink := filepath.Join(dir, "bad-link.key")
	if err := os.Symlink(bad, badLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badLink); err == nil {
		t.Fatal("a symlink to a world readable keyring was loaded")
	}
	// Rotation replaces the link's target atomically; the key never
	// exists at a name another account could have planted.
	before, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(link, 1); err != nil {
		t.Fatal(err)
	}
	k, err := Load(link)
	if err != nil || k.Len() != 2 {
		t.Fatalf("after rotating through a link: %v %v", k, err)
	}
	if after, err := os.Readlink(link); err == nil && after != before {
		t.Fatalf("rotation repointed the link from %q to %q", before, after)
	}
	st, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the rotated file is mode %04o", uint32(st.Mode().Perm()))
	}
}

// TestLongAndUnusualNames covers file names an operator may actually
// use: a very long one, one with spaces, one with non-ASCII characters,
// one that looks like an option.
func TestLongAndUnusualNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		strings.Repeat("k", 200) + ".key",
		"a key with spaces.key",
		"nyckel-öäå.key",
		"-not-an-option.key",
		".hidden.key",
		"key.with.many.dots.key",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if _, err := LoadOrCreate(p); err != nil {
				t.Fatalf("create: %v", err)
			}
			if _, err := Load(p); err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := Rotate(p, 1); err != nil {
				t.Fatalf("rotate: %v", err)
			}
		})
	}
}

// TestRotationKeepsTheRingUsable rotates many times and requires the
// ring to stay within its bound, keep the newest key first, and remain
// loadable after every step. A ring that lost its order would verify
// against the wrong key first on every request.
func TestRotationKeepsTheRingUsable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rotating.key")
	var previous []byte
	for i := 0; i < 20; i++ {
		k, err := Rotate(p, 3)
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if k.Len() > 4 {
			t.Fatalf("rotation %d left %d keys with -keep 3", i, k.Len())
		}
		if previous != nil && len(k.All()) > 1 && string(k.All()[1]) != string(previous) {
			t.Fatalf("rotation %d did not keep the previous primary as the second key", i)
		}
		previous = append([]byte(nil), k.Primary()...)
		reloaded, err := Load(p)
		if err != nil {
			t.Fatalf("rotation %d left an unloadable file: %v", i, err)
		}
		if string(reloaded.Primary()) != string(k.Primary()) {
			t.Fatalf("rotation %d: the file's primary differs from the returned one", i)
		}
		// Every key in the ring is distinct: a rotation that repeated
		// one would not be a rotation.
		seen := map[string]bool{}
		for _, key := range reloaded.All() {
			if seen[string(key)] {
				t.Fatalf("rotation %d produced a duplicate key", i)
			}
			seen[string(key)] = true
		}
	}
	if _, err := Rotate(p, -1); err == nil {
		t.Fatal("a negative keep was accepted")
	}
	if _, err := Rotate(p, MaxKeys); err == nil {
		t.Fatalf("keep %d was accepted", MaxKeys)
	}
}

// TestConcurrentLoads reads one keyring from many goroutines. The proxy
// builds a generation per reload and several filters may load the same
// file at once.
func TestConcurrentLoads(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "shared.key", ring(3), 0o600)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := Load(p)
			if err != nil {
				errs <- err
				return
			}
			if k.Len() != 3 {
				errs <- fmt.Errorf("loaded %d keys", k.Len())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestEphemeralRingsDiffer requires two ephemeral rings to hold
// different keys. One process restarting must not reproduce the keys of
// the last one, which is the whole difference between an ephemeral ring
// and a hard-coded secret.
func TestEphemeralRingsDiffer(t *testing.T) {
	a, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Primary()) == string(b.Primary()) {
		t.Fatal("two ephemeral rings share a key")
	}
	if len(a.Primary()) < MinKeyBytes {
		t.Fatalf("an ephemeral key is %d bytes", len(a.Primary()))
	}
	if a.Path() != "" {
		t.Fatalf("an ephemeral ring has the path %q", a.Path())
	}
}

// TestKeyOrderIsByAge pins the order the ring hands its keys out in:
// the newest first, because that is the one a new cookie is sealed
// with, and the rest in the order they were rotated out.
func TestKeyOrderIsByAge(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "ordered.key", ring(3), 0o600)
	k, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	keys := k.Keys()
	if len(keys) != 3 {
		t.Fatalf("%d keys", len(keys))
	}
	if string(k.Primary()) != string(keys[0].Bytes) {
		t.Fatal("the primary is not the first key")
	}
	for i := 1; i < len(keys); i++ {
		if keys[i].Since.After(keys[i-1].Since) {
			t.Fatalf("key %d is newer than key %d", i, i-1)
		}
	}
	if !keys[0].Since.Equal(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("the primary is dated %v", keys[0].Since)
	}
}

// TestWriteFailures covers what happens when the file system says no.
// A rotation that half wrote the ring would leave the proxy unable to
// open anything it had sealed, so every failure must leave the old file
// exactly as it was and leave no temporary file behind.
func TestWriteFailures(t *testing.T) {
	dir := t.TempDir()

	// The destination is a directory: the rename cannot replace it.
	asDir := filepath.Join(dir, "adir")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(asDir, 1); err == nil {
		t.Fatal("a rotation onto a directory succeeded")
	}
	if leftovers(t, dir) > 1 {
		t.Fatal("a failed rotation left a temporary file behind")
	}

	if os.Geteuid() == 0 {
		// The rest is about permissions, which do not apply to root.
		return
	}
	// The directory is not writable: the temporary file cannot be made.
	ro := filepath.Join(dir, "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if _, err := Rotate(filepath.Join(ro, "k"), 1); err == nil {
		t.Fatal("a rotation into a read-only directory succeeded")
	}
	if _, err := LoadOrCreate(filepath.Join(ro, "k2")); err == nil {
		t.Fatal("a keyring was created in a read-only directory")
	}

	// An existing ring survives a failed rotation: the file the proxy
	// is verifying against is never the casualty of a write that could
	// not finish.
	p := write(t, dir, "survivor.key", ring(2), 0o600)
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	_, rotErr := Rotate(p, 1)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if rotErr == nil {
		t.Skip("the directory stayed writable")
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a failed rotation changed the keyring")
	}
}

// leftovers counts the entries in a directory, so a test can notice a
// temporary file that was not cleaned up.
func leftovers(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			n++
		}
	}
	return n
}
