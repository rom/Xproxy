package keysource

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every configuration written before references existed says a path, so a bare
// path has to keep meaning exactly what it meant.
func TestABarePathIsStillAPath(t *testing.T) {
	for _, in := range []string{"/etc/xproxy/tls/edge.key", "file:/etc/xproxy/tls/edge.key"} {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got.Scheme != SchemeFile || got.Target != "/etc/xproxy/tls/edge.key" {
			t.Errorf("%s parsed as %+v", in, got)
		}
		if !got.IsFile() {
			t.Errorf("%s is not a file reference", in)
		}
	}
	// A relative path is still a path -- whether it is a *good* path is the
	// configuration's business, not this parser's.
	if got, err := Parse("tls/edge.key"); err != nil || got.Scheme != SchemeFile {
		t.Errorf("relative path: %+v %v", got, err)
	}
}

// A typo in a scheme must not become a path nobody meant: "vult:secret/x" is an
// error rather than a file called "vult:secret/x".
func TestAReferenceIsParsedOrRefused(t *testing.T) {
	for name, in := range map[string]string{
		"an unknown scheme":         "vult:secret/tls#key",
		"nothing at all":            "  ",
		"file with no path":         "file:",
		"env with no variable":      "env:",
		"vault with no path":        "vault:",
		"vault with no field":       "vault:secret/tls/edge",
		"vault with an empty field": "vault:secret/tls/edge#",
	} {
		if got, err := Parse(in); err == nil {
			t.Errorf("%s (%q) parsed as %+v", name, in, got)
		}
	}
	v, err := Parse("vault:secret/tls/edge#key")
	if err != nil {
		t.Fatal(err)
	}
	if v.Scheme != SchemeVault || v.Target != "secret/tls/edge" || v.Field != "key" {
		t.Errorf("%+v", v)
	}
	if v.String() != "vault:secret/tls/edge#key" {
		t.Errorf("String() = %q", v.String())
	}
	if v.IsFile() {
		t.Error("a vault reference reported itself as a file")
	}
}

// The two sources that need no server, and the bounds on both.
func TestFilesAndTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.key")
	if err := os.WriteFile(path, []byte("material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(nil, 0, nil)

	if got, err := r.Bytes(path); err != nil || string(got) != "material\n" {
		t.Errorf("file: %q %v", got, err)
	}
	// StringValue trims, because an editor's trailing newline is not part of a
	// token.
	if got, err := r.StringValue(path); err != nil || got != "material" {
		t.Errorf("trimmed: %q %v", got, err)
	}

	t.Setenv("EDGE_KEY", "from-the-environment")
	if got, err := r.StringValue("env:EDGE_KEY"); err != nil || got != "from-the-environment" {
		t.Errorf("env: %q %v", got, err)
	}
	if _, err := r.StringValue("env:NOT_SET_ANYWHERE"); err == nil {
		t.Error("a variable that is not set resolved")
	}

	// An empty secret is an error rather than a key of length zero reaching a
	// TLS stack.
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Bytes(empty); !errors.Is(err, ErrEmpty) {
		t.Errorf("an empty file: %v, want ErrEmpty", err)
	}
	// And something far too large is a wrong path, said as such.
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxSecretBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := r.Bytes(big)
	if err == nil || !strings.Contains(err.Error(), "right path") {
		t.Errorf("an oversize file: %v", err)
	}
}

// A vault reference with no vault configured is an error, not a fallback: a
// proxy that quietly read a file called "vault:secret/x" would be worse than
// one that refused to start.
func TestAVaultReferenceNeedsAVault(t *testing.T) {
	r := New(nil, 0, nil)
	if _, err := r.Bytes("vault:secret/tls/edge#key"); !errors.Is(err, ErrNoVault) {
		t.Errorf("%v, want ErrNoVault", err)
	}
}

// Nothing here ever puts the material in an error, because errors are logged.
func TestAnErrorNeverCarriesTheMaterial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	const material = "SUPER-SECRET-KEY-MATERIAL"
	if err := os.WriteFile(path, []byte(material+strings.Repeat("x", maxSecretBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(nil, 0, nil)
	_, err := r.Bytes(path)
	if err == nil {
		t.Fatal("an oversize secret resolved")
	}
	if strings.Contains(err.Error(), material) {
		t.Errorf("the error carries the material: %v", err)
	}
}

// The TTL is what makes a rotation reach a running proxy: within it the cached
// value is used, past it the source is asked again.
func TestTheValueIsCachedUntilTheTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	r := New(nil, time.Minute, nil)
	r.SetClockForTest(func() time.Time { return now })

	if got, _ := r.StringValue(path); got != "first" {
		t.Fatalf("got %q", got)
	}
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.StringValue(path); got != "first" {
		t.Errorf("within the TTL: %q, want the cached value", got)
	}
	now = now.Add(2 * time.Minute)
	if got, _ := r.StringValue(path); got != "second" {
		t.Errorf("past the TTL: %q, want the rotated value", got)
	}
}

// A source that stops answering must not take a key away from a proxy that is
// already serving with it -- and the operator has to be told, once, rather than
// once per handshake.
func TestAFailedRefreshKeepsTheOldValueAndWarnsOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("in-use"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var warned []string
	r := New(nil, time.Minute, func(ref string, err error) { warned = append(warned, ref) })
	r.SetClockForTest(func() time.Time { return now })
	if got, _ := r.StringValue(path); got != "in-use" {
		t.Fatalf("got %q", got)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	for range 3 {
		got, err := r.StringValue(path)
		if err != nil || got != "in-use" {
			t.Fatalf("after the source went away: %q %v", got, err)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "key") {
		t.Errorf("warnings %v, want exactly one naming the reference", warned)
	}
	if stale := r.Stale(); len(stale) != 1 {
		t.Errorf("stale %v, want the one reference", stale)
	}
	// And a reference that never resolved at all is an error rather than a
	// silent empty value: there is nothing to fall back to.
	if _, err := r.Bytes(filepath.Join(dir, "never-existed")); err == nil {
		t.Error("a reference that never resolved returned no error")
	}
}

// The caller gets a copy, so nothing it does to the slice reaches the cache --
// a handshake that scribbled on a key would otherwise break every later one.
func TestTheCallerCannotEditTheCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("material"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(nil, time.Hour, nil)
	// The first read fills the cache and the second is served from it, and
	// both hand out a copy: a handshake that scribbled on a key it was given
	// would otherwise break every later one.
	for i := range 2 {
		got, err := r.Bytes(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "material" {
			t.Fatalf("read %d: %q", i, got)
		}
		for j := range got {
			got[j] = 'x'
		}
	}
	if got, _ := r.StringValue(path); got != "material" {
		t.Errorf("the cache was edited through the caller's slice: %q", got)
	}
}
