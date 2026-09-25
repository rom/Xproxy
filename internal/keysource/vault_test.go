package keysource

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubVault is enough of the Vault KV API to drive the client: it records the
// paths and tokens it was asked with, and answers what a test told it to.
type stubVault struct {
	*httptest.Server
	mu       chan struct{}
	requests atomic.Int64
	// token is what the stub accepts; anything else is a 403, which is what a
	// rotated token looks like from here.
	token   atomic.Value
	paths   []string
	tokens  []string
	answer  func(path string) (int, string)
	version int
}

func newStubVault(t *testing.T, kv int) *stubVault {
	t.Helper()
	s := &stubVault{mu: make(chan struct{}, 1), version: kv}
	s.mu <- struct{}{}
	s.token.Store("root-token")
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		<-s.mu
		s.paths = append(s.paths, r.URL.Path)
		s.tokens = append(s.tokens, r.Header.Get("X-Vault-Token"))
		answer := s.answer
		s.mu <- struct{}{}
		if r.Header.Get("X-Vault-Token") != s.token.Load().(string) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		if answer != nil {
			code, body := answer(r.URL.Path)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
			return
		}
		fields := map[string]any{"key": "-----BEGIN PRIVATE KEY-----", "note": "beside it", "count": 7.0}
		var body []byte
		if s.version == 1 {
			body, _ = json.Marshal(map[string]any{"data": fields})
		} else {
			body, _ = json.Marshal(map[string]any{"data": map[string]any{"data": fields,
				"metadata": map[string]any{"version": 3}}})
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *stubVault) seen() ([]string, []string) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	return append([]string(nil), s.paths...), append([]string(nil), s.tokens...)
}

// tokenFile writes a token file, which is where a token belongs: the
// configuration is dumped, kept in the history and diffed.
func tokenFile(t *testing.T, dir, token string) string {
	t.Helper()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func vaultFor(t *testing.T, s *stubVault, cfg VaultConfig) *Vault {
	t.Helper()
	dir := t.TempDir()
	if cfg.Address == "" {
		cfg.Address = s.URL
	}
	if cfg.TokenRef == "" {
		cfg.TokenRef = tokenFile(t, dir, "root-token")
	}
	cfg.Insecure = true // the stub speaks http
	v, err := NewVault(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The ordinary case: a field of a KV v2 secret, at the path the API uses.
func TestReadingAFieldOfASecret(t *testing.T) {
	s := newStubVault(t, 2)
	v := vaultFor(t, s, VaultConfig{})
	r := New(v, 0, nil)

	got, err := r.StringValue("vault:secret/tls/edge#key")
	if err != nil {
		t.Fatal(err)
	}
	if got != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("got %q", got)
	}
	paths, tokens := s.seen()
	if len(paths) != 1 || paths[0] != "/v1/secret/data/tls/edge" {
		t.Errorf("paths %v, want the KV v2 data path", paths)
	}
	if tokens[0] != "root-token" {
		t.Errorf("token %q, want the one from the file with the newline trimmed", tokens[0])
	}
	// A non-string field is rendered rather than refused, because a port or a
	// count in a secret is a legitimate thing to reference.
	if got, err := r.StringValue("vault:secret/tls/edge#count"); err != nil || got != "7" {
		t.Errorf("a number: %q %v", got, err)
	}
	// A field that is not there names the ones that are, since an operator
	// who wrote the wrong field needs to know which exist -- and the names
	// are not the values.
	_, err = r.StringValue("vault:secret/tls/edge#private")
	if err == nil || !strings.Contains(err.Error(), "note") {
		t.Errorf("a missing field: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "BEGIN PRIVATE KEY") {
		t.Errorf("the error carries a value: %v", err)
	}
}

// KV v1 is a different path and a different shape, and guessing between them
// answers "not found" for a secret that is there.
func TestKVVersionOne(t *testing.T) {
	s := newStubVault(t, 1)
	v := vaultFor(t, s, VaultConfig{KVVersion: 1})
	if got, err := New(v, 0, nil).StringValue("vault:secret/tls/edge#key"); err != nil ||
		got != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("%q %v", got, err)
	}
	paths, _ := s.seen()
	if len(paths) != 1 || paths[0] != "/v1/secret/tls/edge" {
		t.Errorf("paths %v, want the KV v1 path", paths)
	}
}

// A token rotated underneath the process is what a 403 usually means, so the
// token is read again and the request retried once -- and only once, because a
// bad token must not become a loop against somebody else's server.
func TestARotatedTokenIsPickedUpOnce(t *testing.T) {
	s := newStubVault(t, 2)
	dir := t.TempDir()
	path := tokenFile(t, dir, "old-token")
	v := vaultFor(t, s, VaultConfig{TokenRef: path})
	r := New(v, 0, nil)

	// The stub now expects a token this client does not have.
	s.token.Store("new-token")
	if _, err := r.Bytes("vault:secret/tls/edge#key"); err == nil {
		t.Fatal("a stale token read the secret")
	}
	// Exactly two requests: the original and one retry. The bound matters more
	// than it looks -- a retry loop against a token that will never be right
	// is a loop against somebody else's server, and the mutation that removes
	// the bound does not fail this assertion so much as never reach it.
	if before := s.requests.Load(); before != 2 {
		t.Errorf("%d requests for one read, want the original and one retry", before)
	}

	// The operator rotates the file; the next read picks it up.
	if err := os.WriteFile(path, []byte("new-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Bytes("vault:secret/tls/edge#key"); err != nil {
		t.Fatalf("after the rotation: %v", err)
	}
}

// What the client refuses to be built with at all, because each one is a way to
// hand every secret to somebody else.
func TestTheVaultClientRefusesAnUnsafeConfiguration(t *testing.T) {
	dir := t.TempDir()
	token := tokenFile(t, dir, "root-token")
	for name, cfg := range map[string]VaultConfig{
		"no address":                {TokenRef: token},
		"http without the opt-in":   {Address: "http://vault.example:8200", TokenRef: token},
		"a scheme that is not http": {Address: "vault://vault.example", TokenRef: token, Insecure: true},
		"no token":                  {Address: "https://vault.example:8200"},
		"a token file that is not there": {Address: "https://vault.example:8200",
			TokenRef: filepath.Join(dir, "missing")},
		"an empty token file": {Address: "https://vault.example:8200",
			TokenRef: tokenFile(t, t.TempDir(), "  ")},
		"a kv version that does not exist": {Address: "https://vault.example:8200",
			TokenRef: token, KVVersion: 3},
		"a ca file that is not there": {Address: "https://vault.example:8200",
			TokenRef: token, CAFile: filepath.Join(dir, "no-ca.pem")},
		"a ca file with no certificate in it": {Address: "https://vault.example:8200",
			TokenRef: token, CAFile: token},
		"a token from somewhere that is not a file or the environment": {
			Address: "https://vault.example:8200", TokenRef: "vault:secret/token#token"},
	} {
		if _, err := NewVault(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// And http with the opt-in is allowed, because a test estate and a
	// sidecar on loopback both need it.
	if _, err := NewVault(VaultConfig{Address: "http://127.0.0.1:8200", TokenRef: token, Insecure: true}); err != nil {
		t.Errorf("http with the opt-in: %v", err)
	}
}

// What the server can answer wrongly, and what each one has to say.
func TestTheAnswersThatAreNotASecret(t *testing.T) {
	s := newStubVault(t, 2)
	v := vaultFor(t, s, VaultConfig{})
	r := New(v, 0, nil)

	for name, c := range map[string]struct {
		code, want int
		body, says string
	}{
		"not found":             {code: 404, body: `{"errors":[]}`, says: "not found"},
		"sealed":                {code: 503, body: `{"errors":["Vault is sealed"]}`, says: "503"},
		"not json":              {code: 200, body: `<html>a proxy in the middle</html>`, says: "JSON"},
		"a field that is a map": {code: 200, body: `{"data":{"data":{"key":{"nested":1}}}}`, says: "not a string"},
	} {
		s.answer = func(string) (int, string) { return c.code, c.body }
		_, err := r.Bytes("vault:secret/tls/edge#key")
		if err == nil {
			t.Errorf("%s: read a secret", name)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want it to mention %q", name, err, c.says)
		}
	}
	// An enormous error body cannot fill a log line.
	s.answer = func(string) (int, string) { return 500, strings.Repeat("x", 4096) }
	_, err := r.Bytes("vault:secret/tls/edge#key")
	if err == nil || len(err.Error()) > 512 {
		t.Errorf("an enormous error body: %d characters", len(err.Error()))
	}
}

// A path may name its own mount or take the configured one, because an operator
// writes it both ways and neither should be a 404.
func TestThePathMayNameTheMountOrNot(t *testing.T) {
	s := newStubVault(t, 2)
	v := vaultFor(t, s, VaultConfig{Mount: "kv"})
	r := New(v, 0, nil)
	for _, ref := range []string{"vault:kv/tls/edge#key", "vault:tls/edge#key"} {
		if _, err := r.Bytes(ref); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	paths, _ := s.seen()
	for _, p := range paths {
		if p != "/v1/kv/data/tls/edge" {
			t.Errorf("path %s, want the mount once", p)
		}
	}
}

// A vault that stops answering keeps the proxy serving with what it has, which
// is the property the whole arrangement stands on: the estate keeps working
// while somebody fixes the vault.
func TestAVaultOutageDoesNotTakeTheKeyAway(t *testing.T) {
	s := newStubVault(t, 2)
	v := vaultFor(t, s, VaultConfig{})
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var warnings int
	r := New(v, time.Minute, func(string, error) { warnings++ })
	r.SetClockForTest(func() time.Time { return now })

	if _, err := r.Bytes("vault:secret/tls/edge#key"); err != nil {
		t.Fatal(err)
	}
	s.Close() // the vault goes away
	now = now.Add(2 * time.Minute)
	got, err := r.StringValue("vault:secret/tls/edge#key")
	if err != nil || got != "-----BEGIN PRIVATE KEY-----" {
		t.Fatalf("during the outage: %q %v", got, err)
	}
	if warnings != 1 {
		t.Errorf("%d warnings, want one", warnings)
	}
	if stale := r.Stale(); len(stale) != 1 {
		t.Errorf("stale %v", stale)
	}
}

// A namespace is a header, and an estate that uses them needs it on every
// request or every read is a 404 in the root namespace.
func TestTheNamespaceIsSent(t *testing.T) {
	var ns atomic.Value
	ns.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns.Store(r.Header.Get("X-Vault-Namespace"))
		_, _ = w.Write([]byte(`{"data":{"data":{"key":"v"}}}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	v, err := NewVault(VaultConfig{Address: srv.URL, TokenRef: tokenFile(t, dir, "t"),
		Namespace: "team-a", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(v, 0, nil).Bytes("vault:secret/x#key"); err != nil {
		t.Fatal(err)
	}
	if got := ns.Load().(string); got != "team-a" {
		t.Errorf("namespace %q", got)
	}
}

// errForbidden is the one error the client tells apart internally; a caller sees
// an ordinary error rather than something it might match on by accident.
func TestForbiddenIsNotLeakedAsASentinel(t *testing.T) {
	s := newStubVault(t, 2)
	v := vaultFor(t, s, VaultConfig{})
	s.token.Store("another-token")
	_, err := New(v, 0, nil).Bytes("vault:secret/x#key")
	if err == nil {
		t.Fatal("read with a wrong token")
	}
	if !errors.Is(err, errForbidden) {
		t.Logf("a caller sees: %v", err)
	}
}
