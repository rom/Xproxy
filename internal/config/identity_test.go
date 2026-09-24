package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// identityConfig is a provider with keys and whatever section a case is
// about.
func identityConfig(t *testing.T, section string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(jwks, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
jwt:
  providers:
    - name: as
      issuer: https://as.test
      audiences: [api]
      jwks_file: ` + jwks + `
` + section + `
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u, jwt: {provider: as}}
`, secret
}

// An exchange that names neither an audience nor a resource asks the
// authorization server for a token as broad as the one it replaces. The
// configuration reads as if the control were on, so it is refused at load
// rather than left to look right.
func TestAnExchangeMustNarrowSomething(t *testing.T) {
	cfg, secret := identityConfig(t, `      token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET}`)
	_, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
	if err == nil || !strings.Contains(err.Error(), "audience or resource is required") {
		t.Fatalf("error %v, want one about naming an audience", err)
	}
	cfg, secret = identityConfig(t, `      token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: orders}`)
	out, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
	if err != nil {
		t.Fatalf("a narrowed exchange was refused: %v", err)
	}
	tx := out.JWT.Providers[0].TokenExchange
	if tx.CacheTTL.D() != time.Minute || tx.Timeout.D() != 3*time.Second {
		t.Fatalf("defaults %+v", tx)
	}
	if !tx.Requires() {
		t.Fatal("required defaulted to false")
	}
}

func TestExchangeSettingsAreChecked(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`token_exchange: {url: http://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a}`, "url: must be an https URL"},
		{`token_exchange: {url: https://as.test/token, client_secret_file: SECRET, audience: a}`, "client_id and an absolute client_secret_file are required"},
		{`token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, resource: "not a uri"}`, "must be an absolute URI"},
		{`token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a, requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token"}`, "would be forwarded as an access token"},
		{`token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a, header: "Host"}`, "cannot carry a token"},
		{`token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a, cache_ttl: 2h}`, "cache_ttl: must be between 0 and 1h"},
		{`token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a, timeout: 1m}`, "timeout: must be between 100ms and 30s"},
		{`token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a, scopes: ["with space"]}`, "a scope is a non-empty token"},
	} {
		cfg, secret := identityConfig(t, "      "+tc.section)
		_, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", tc.section, err, tc.want)
		}
	}
}

// An exchange that fails open reaches the backend with no token at all, on
// exactly the requests where the control went wrong. It loads, and it says
// so.
func TestFailingOpenOnAnExchangeIsWarnedAbout(t *testing.T) {
	cfg, secret := identityConfig(t, `      token_exchange: {url: https://as.test/token, client_id: gw, client_secret_file: SECRET, audience: a, required: false}`)
	out, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range out.Advice() {
		if strings.Contains(w, "no token at all") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no warning about failing open: %v", out.Advice())
	}
}

// A symmetric algorithm in a DPoP policy is a policy that verifies proofs
// the verifier could have written itself.
func TestDPoPSettingsAreChecked(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`dpop: {mode: maybe}`, "mode: must be off, allow or require"},
		{`dpop: {mode: allow, algorithms: [HS256]}`, "is not an asymmetric JWS algorithm"},
		{`dpop: {mode: allow, max_age: 1h}`, "max_age: must be between 0 and 10m"},
		{`dpop: {mode: allow, external_url: "not a url"}`, "external_url: must be an absolute URL"},
	} {
		cfg, secret := identityConfig(t, "      "+tc.section)
		_, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", tc.section, err, tc.want)
		}
	}
	// The defaults, and the warning for a provider whose token does not
	// travel where RFC 9449 puts the proof.
	cfg, secret := identityConfig(t, "      dpop: {mode: allow}\n      source: \"cookie:session\"")
	out, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
	if err != nil {
		t.Fatal(err)
	}
	d := out.JWT.Providers[0].DPoP
	if d.MaxAge.D() != time.Minute || d.ReplayEntries != 65536 {
		t.Fatalf("defaults %+v", d)
	}
	found := false
	for _, w := range out.Advice() {
		if strings.Contains(w, "Authorization header") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no warning about the token source: %v", out.Advice())
	}
}

// The certificate binding has two ways to be configured so that it loads
// and can never fire, and both are worse than an error: the operator
// believes the control is on. Both are warnings an operator sees at every
// load, and both are asserted by their words here.
func TestCertificateBindingSettingsAreChecked(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`certificate_binding: {mode: maybe}`, "mode: must be off, allow or require"},
	} {
		cfg, secret := identityConfig(t, "      "+tc.section)
		_, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", tc.section, err, tc.want)
		}
	}
	for _, tc := range []struct{ name, section, want string }{
		{"no listener asks for a certificate", `certificate_binding: {mode: require}`,
			"no listener asks for a client certificate"},
		{"a forwarded certificate with nothing trusted", `certificate_binding: {mode: allow, trust_forwarded_header: true}`,
			"needs trusted_proxies"},
		{"a forwarded certificate with the binding off", `certificate_binding: {mode: off, trust_forwarded_header: true}`,
			"no certificate is ever compared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, secret := identityConfig(t, "      "+tc.section)
			out, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
			if err != nil {
				t.Fatalf("a configuration that should only warn was refused: %v", err)
			}
			found := false
			for _, w := range out.Advice() {
				if strings.Contains(w, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no advice containing %q: %v", tc.want, out.Advice())
			}
		})
	}
	// And the configuration that can fire warns about nothing: a listener
	// asking for a certificate, and a binding that compares it.
	cfg, secret := identityConfig(t, "      certificate_binding: {mode: require}")
	cfg = strings.Replace(cfg,
		`  listeners: [{name: main, address: "127.0.0.1:0"}]`,
		"  listeners:\n    - name: main\n      address: \"127.0.0.1:0\"\n      tls:\n        client_auth: require\n        client_ca_file: CA\n        certificates: [{cert_file: CERT, key_file: KEY}]", 1)
	dir := t.TempDir()
	for name, target := range map[string]string{"CA": "ca.pem", "CERT": "cert.pem", "KEY": "key.pem"} {
		p := filepath.Join(dir, target)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg = strings.Replace(cfg, name, p, 1)
	}
	out, err := parseNoFiles([]byte(strings.ReplaceAll(cfg, "SECRET", secret)))
	if err != nil {
		t.Fatalf("a binding on a listener that asks for a certificate: %v", err)
	}
	for _, w := range out.Advice() {
		if strings.Contains(w, "certificate_binding") {
			t.Errorf("unexpected advice: %s", w)
		}
	}
}
