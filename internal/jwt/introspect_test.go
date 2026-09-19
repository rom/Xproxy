package jwt

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func TestIntrospection(t *testing.T) {
	var calls atomic.Int64
	active := map[string]bool{"opaque-good": true, "opaque-revoked": false}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "rp" || pass != "s3cret" || r.Method != http.MethodPost {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		tok := strings.TrimPrefix(string(body), "token=")
		if tok == "boom" {
			w.WriteHeader(500)
			return
		}
		resp := map[string]any{"active": active[tok]}
		if active[tok] {
			resp["sub"] = "alice"
			resp["scope"] = "read"
			resp["aud"] = "api"
			resp["iss"] = "https://as.test"
			resp["exp"] = time.Now().Add(time.Hour).Unix()
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	certPEM := srv.Certificate().Raw
	if err := os.WriteFile(ca, pemEncode(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JWTProvider{Name: "as", Issuer: "https://as.test", Audiences: []string{"api"}, ClockSkew: config.Duration(30 * time.Second),
		RequiredClaims: []string{"sub"},
		Introspection: &config.TokenIntrospection{URL: srv.URL + "/introspect", ClientID: "rp", ClientSecretFile: secret, CAFile: ca,
			CacheTTL: config.Duration(time.Minute), Timeout: config.Duration(2 * time.Second)}}
	p, err := NewProvider(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Introspects("a.b.c") {
		t.Fatal("a provider without keys introspects every token")
	}
	claims, err := p.Verify("opaque-good")
	if err != nil || ClaimString(claims["sub"]) != "alice" {
		t.Fatalf("good token: %v %v", claims, err)
	}
	if _, err := p.Verify("opaque-good"); err != nil || calls.Load() != 1 {
		t.Fatalf("second verification not served from the cache: calls %d err %v", calls.Load(), err)
	}
	if _, err := p.Verify("opaque-revoked"); !errors.Is(err, ErrInactive) || category(err) != "inactive" {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := p.Verify("opaque-revoked"); calls.Load() != 2 {
		t.Fatalf("negative answer not cached: %d %v", calls.Load(), err)
	}
	if _, err := p.Verify("boom"); !errors.Is(err, ErrIntrospection) {
		t.Fatalf("endpoint failure: %v", err)
	}
	_, _ = p.Verify("boom")
	if calls.Load() != 4 {
		t.Fatal("an unavailable endpoint was cached")
	}
	c, e, h, n := p.IntrospectionStats()
	if c != 4 || e != 2 || h != 2 || n != 2 {
		t.Fatalf("stats calls=%d errors=%d hits=%d cached=%d", c, e, h, n)
	}
	// Audience and issuer rules apply to introspected claims.
	cfg.Audiences = []string{"other"}
	p2, _ := NewProvider(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := p2.Verify("opaque-good"); !errors.Is(err, ErrAudience) {
		t.Fatalf("audience: %v", err)
	}
	// With keys and without always, only opaque tokens are introspected.
	cfg.Audiences = []string{"api"}
	cfg.HMACSecretFile = secret
	if err := os.WriteFile(secret, []byte(strings.Repeat("k", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Algorithms = []string{"HS256"}
	p3, err := NewProvider(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p3.Introspects("a.b.c") || !p3.Introspects("opaque") {
		t.Fatal("introspection selection with keys")
	}
	cfg.Introspection.Always = true
	p4, _ := NewProvider(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !p4.Introspects("a.b.c") {
		t.Fatal("always must introspect signed tokens")
	}
}

func pemEncode(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
