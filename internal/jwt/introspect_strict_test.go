package jwt

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// RFC 7662 lets an authorization server answer with nothing but
// {"active": true}. Treating a missing issuer or audience as a pass
// accepted every live token of that server, including one minted for
// another client, another audience or another tenant. The JWT path
// always failed closed on both, and the introspection path now matches
// it: absence is not acceptance.
func TestIntrospectionRequiresIssuerAndAudience(t *testing.T) {
	answers := map[string]map[string]any{
		"bare":        {"active": true, "sub": "alice"},
		"no-audience": {"active": true, "sub": "alice", "iss": "https://as.test"},
		"other-tenant": {"active": true, "sub": "alice", "iss": "https://as.test",
			"aud": "another-relying-party"},
		"complete": {"active": true, "sub": "alice", "iss": "https://as.test", "aud": "api"},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tok := string(body)[len("token="):]
		resp, ok := answers[tok]
		if !ok {
			resp = map[string]any{"active": false}
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
	if err := os.WriteFile(ca, pemEncode(srv.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JWTProvider{Name: "as", Issuer: "https://as.test", Audiences: []string{"api"},
		ClockSkew: config.Duration(30 * time.Second),
		Introspection: &config.TokenIntrospection{URL: srv.URL + "/introspect", ClientID: "rp",
			ClientSecretFile: secret, CAFile: ca, CacheTTL: config.Duration(time.Minute),
			Timeout: config.Duration(2 * time.Second)}}
	p, err := NewProvider(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"bare", "no-audience", "other-tenant"} {
		if _, err := p.Verify(token); err == nil {
			t.Errorf("an active answer with token %q was accepted without a matching issuer and audience", token)
		}
	}
	if _, err := p.Verify("complete"); err != nil {
		t.Fatalf("a complete answer was refused: %v", err)
	}
}
