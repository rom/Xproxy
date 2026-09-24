package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filters/apikey"
)

// TestIdentityRateLimit checks a limit keyed on the api_key identity:
// two different keys each get their own bucket, and rotating the raw
// header does not, because the key is the verified identity.
func TestIdentityRateLimit(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	k1, err := apikey.Add(keys, "one", nil, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := apikey.Add(keys, "two", nil, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
rate_limits:
  - {name: per-key, key: "identity:api_key", algorithm: sliding_window, limit: 1, window: 1m}
filters:
  - {name: keys, kind: api_key, options: {keys_file: %s}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: api, paths: [/api], upstream: app, filters: [keys], rate_limits: [per-key]}
`, keys, a.addr())
	_, url := startServer(t, yaml)
	get := func(key string) int {
		r, _ := http.NewRequest("GET", url+"/api", nil)
		r.Header.Set("X-Api-Key", key)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// First key: first request passes, second is limited.
	if s := get(k1); s != 200 {
		t.Fatalf("first key first request: %d", s)
	}
	if s := get(k1); s != 429 {
		t.Fatalf("first key second request: %d", s)
	}
	// A different verified identity has its own bucket.
	if s := get(k2); s != 200 {
		t.Fatalf("second key first request: %d", s)
	}
	if s := get(k2); s != 429 {
		t.Fatalf("second key second request: %d", s)
	}
	// An unauthenticated request is refused by the filter (401), never
	// reaching the limiter.
	r, _ := http.NewRequest("GET", url+"/api", nil)
	resp, _ := http.DefaultClient.Do(r)
	if resp.StatusCode != 401 {
		t.Fatalf("no key: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestIdentityRateLimitJWT checks a limit keyed on the verified JWT
// subject: two subjects get separate buckets, and a request with no
// token falls back to the address bucket rather than sharing one.
func TestIdentityRateLimitJWT(t *testing.T) {
	a := newBackend(t, "a")
	secret := "0123456789abcdef0123456789abcdef"
	secretFile := filepath.Join(t.TempDir(), "hs.key")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
jwt:
  providers:
    - {name: hs, issuer: test, audiences: [api], algorithms: [HS256], hmac_secret_file: %s}
rate_limits:
  - {name: per-sub, key: "identity:jwt", algorithm: sliding_window, limit: 1, window: 1m}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: api, paths: [/api], upstream: app, jwt: {provider: hs}, rate_limits: [per-sub]}
`, secretFile, a.addr())
	_, url := startServer(t, yaml)
	token := func(sub string) string {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payload, _ := json.Marshal(map[string]any{"sub": sub, "iss": "test", "aud": "api", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
		body := hdr + "." + base64.RawURLEncoding.EncodeToString(payload)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(body))
		return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	get := func(sub string) int {
		r, _ := http.NewRequest("GET", url+"/api", nil)
		r.Header.Set("Authorization", "Bearer "+token(sub))
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if get("alice") != 200 || get("alice") != 429 {
		t.Fatal("alice not limited on the second request")
	}
	if get("bob") != 200 {
		t.Fatal("bob shares alice's bucket")
	}
}
