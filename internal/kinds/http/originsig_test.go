package http

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/originsig"
	"github.com/rom/xproxy/internal/secret"
)

func TestOriginSignature(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "origin.key")
	var verified, failed atomic.Int64
	var mu sync.Mutex
	var keys [][]byte
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		k := keys
		mu.Unlock()
		if err := originsig.Verify(r, "X-Origin-Sig", []string{"X-Tenant"}, k, 5*time.Minute, time.Now()); err != nil {
			failed.Add(1)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		verified.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(origin.Close)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: %s}]
    origin_signature: {header: X-Origin-Sig, secret_file: %s, ttl: 5m, include: [X-Tenant]}
routes:
  - {name: app, upstream: app, request_headers: {set: {X-Tenant: acme}}}
`, origin.Listener.Addr().String(), keyFile)
	_, url := startServer(t, yaml)
	ring, err := secret.Load(keyFile)
	if err != nil {
		t.Fatalf("secret file not created: %v", err)
	}
	mu.Lock()
	keys = ring.All()
	mu.Unlock()
	// A client supplied signature header is replaced, never trusted.
	resp, body := get(t, url+"/api/items?x=1", "X-Origin-Sig", "v1;t=1;kid=deadbeef;sig=forged")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("signed request: %d %q", resp.StatusCode, body)
	}
	if verified.Load() != 1 || failed.Load() != 0 {
		t.Fatalf("verified %d failed %d", verified.Load(), failed.Load())
	}
	// Traffic that bypasses the proxy is refused by the origin.
	direct, err := http.Get(origin.URL + "/api/items") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = direct.Body.Close()
	if direct.StatusCode != 403 || failed.Load() != 1 {
		t.Fatalf("direct request: %d", direct.StatusCode)
	}
	// After a key rotation the origin holding both keys still verifies
	// what the running proxy signs with the previous primary.
	if _, err := secret.Rotate(keyFile, 2); err != nil {
		t.Fatal(err)
	}
	ring, _ = secret.Load(keyFile)
	mu.Lock()
	keys = ring.All()
	mu.Unlock()
	if resp, _ := get(t, url+"/api/items"); resp.StatusCode != 200 {
		t.Fatalf("after rotation before reload: %d", resp.StatusCode)
	}
}
