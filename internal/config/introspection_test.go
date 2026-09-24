package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntrospectionConfig(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
jwt:
  providers:
    - name: as
      issuer: https://as.test
      audiences: [api]
      %s
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u, jwt: {provider: as}}
`
	ok, err := parseNoFiles([]byte(strings.Replace(base, "%s", "introspection: {url: https://as.test/introspect, client_id: rp, client_secret_file: "+secret+"}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	in := ok.JWT.Providers[0].Introspection
	if in.CacheTTL.D().Seconds() != 60 || in.Timeout.D().Seconds() != 3 {
		t.Fatalf("defaults %+v", in)
	}
	bad := map[string]string{
		"": "jwks_file, jwks_url, hmac_secret_file or introspection is required",
		"introspection: {url: http://as.test/i, client_id: rp, client_secret_file: " + secret + "}":                 "introspection.url: must be an https URL",
		"introspection: {url: https://as.test/i, client_secret_file: " + secret + "}":                               "client_id and an absolute client_secret_file",
		"introspection: {url: https://as.test/i, client_id: rp, client_secret_file: " + secret + ", cache_ttl: 2h}": "cache_ttl: must be between 0 and 1h",
		"introspection: {url: https://as.test/i, client_id: rp, client_secret_file: " + secret + ", timeout: 1ms}":  "timeout: must be between 100ms and 30s",
	}
	for c, want := range bad {
		_, err := parseNoFiles([]byte(strings.Replace(base, "%s", c, 1)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v want %q", c, err, want)
		}
	}
	withoutAudience := strings.Replace(base, "      audiences: [api]\n", "", 1)
	_, err = parseNoFiles([]byte(strings.Replace(withoutAudience, "%s", "introspection: {url: https://as.test/introspect, client_id: rp, client_secret_file: "+secret+"}", 1)))
	if err == nil || !strings.Contains(err.Error(), "audiences: at least one audience is required") {
		t.Fatalf("missing audiences: got %v", err)
	}
}
