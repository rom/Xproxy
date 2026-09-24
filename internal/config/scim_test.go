package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scimConfig writes the files a provisioning section needs and returns a
// configuration with the section spliced in. TOKEN, USERS, KEYS and
// STATE are replaced with paths.
func scimConfig(t *testing.T, section string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	token := write("token", "a-provisioning-token-0123\n")
	users := write("mfa.users", "# enrolments\n")
	keys := write("api-keys", "# keys\n")
	base := `
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.5:8080"}]}
routes:
  - {name: app, upstream: app}
`
	s := section
	for from, to := range map[string]string{
		"TOKEN": token, "USERS": users, "KEYS": keys,
		"STATE": filepath.Join(dir, "scim-users"),
	} {
		s = strings.ReplaceAll(s, from, to)
	}
	return base + s
}

// The section that loads, with every default filled in.
func TestSCIMDefaults(t *testing.T) {
	cfg, err := ParseWith([]byte(scimConfig(t, `
scim:
  token_file: TOKEN
  state_file: STATE
  keys_file: KEYS
  client_cidrs: [10.0.0.0/8]
`)), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.SCIM.Base(); got != SCIMPath {
		t.Errorf("path %q, want the default %q", got, SCIMPath)
	}
	if got := cfg.SCIM.Results(); got != 100 {
		t.Errorf("max_results %d, want 100", got)
	}
	if cfg.SCIM.Secrets() {
		t.Error("secrets are returned by default")
	}
	if got := cfg.SCIM.TTL(); got != 0 {
		t.Errorf("key_ttl %v, want none", got)
	}
}

// What a file cannot say is checked at load. Each of these is a
// provisioning endpoint with a lock missing.
func TestSCIMIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"scim: {state_file: STATE, keys_file: KEYS}", "token_file: required"},
		{"scim: {token_file: TOKEN, keys_file: KEYS}", "state_file: required"},
		{"scim: {token_file: TOKEN, state_file: STATE}", "name at least one"},
		{"scim: {token_file: TOKEN, state_file: relative/state, keys_file: KEYS}", "state_file: must be an absolute path"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: relative/keys}", "keys_file: must be an absolute path"},
		{"scim: {path: scim, token_file: TOKEN, state_file: STATE, keys_file: KEYS}", "must start with /"},
		{"scim: {path: /, token_file: TOKEN, state_file: STATE, keys_file: KEYS}", "cannot be the root"},
		{"scim: {path: /scim/v2/, token_file: TOKEN, state_file: STATE, keys_file: KEYS}", "must not end with /"},
		{"scim: {path: \"/scim?v=2\", token_file: TOKEN, state_file: STATE, keys_file: KEYS}", "is a path, not a URL"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, listeners: [nope]}", "unknown listener"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, hosts: [\"not a host\"]}", "not a valid host pattern"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, client_cidrs: [10.0.0.0]}", "is not a CIDR"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, max_results: 5000}", "between 1 and 1000"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, key_ttl: 1m}", "between 1h and 10 years"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, issuer: \"a=b\"}", "scim.issuer"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, key_scopes: [\"a b\"]}", "is not a scope name"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, external_url: admin.example.com}", "must begin with https://"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, external_url: \"https://a/x?y=1\"}", "no query or fragment"},
	} {
		_, err := ParseWith([]byte(scimConfig(t, tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\nerror %v, want one about %q", tc.section, err, tc.want)
		}
	}
}

// The advice. A provisioning endpoint with no selectors loads, because
// somebody may mean it, and says what it is.
func TestSCIMAdvice(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS}", "answers on every listener and every host"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, client_cidrs: [10.0.0.0/8], return_secrets: true}", "return_secrets is on"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, client_cidrs: [10.0.0.0/8]}", "key_scopes is empty"},
		{"scim: {token_file: TOKEN, state_file: STATE, keys_file: KEYS, client_cidrs: [10.0.0.0/8], external_url: \"http://a\"}", "in the clear"},
	} {
		cfg, err := ParseWith([]byte(scimConfig(t, tc.section)), false)
		if err != nil {
			t.Fatalf("%s: %v", tc.section, err)
		}
		if !strings.Contains(strings.Join(cfg.Advice(), "\n"), tc.want) {
			t.Errorf("%s\nadvice %v, want one about %q", tc.section, cfg.Advice(), tc.want)
		}
	}
}

// A credential file that does not exist yet is advice, not an error: the
// first provisioning creates it, and a typo is the other way to get one.
func TestSCIMCredentialFilesNeedNotExistYet(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("a-provisioning-token-0123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.5:8080"}]}
routes:
  - {name: app, upstream: app}
scim:
  token_file: ` + token + `
  state_file: ` + filepath.Join(dir, "scim-users") + `
  mfa_users_file: ` + filepath.Join(dir, "mfa.users") + `
  keys_file: ` + filepath.Join(dir, "api-keys") + `
  key_scopes: [orders:read]
  client_cidrs: [10.0.0.0/8]
`
	cfg, err := ParseWith([]byte(yaml), true)
	if err != nil {
		t.Fatalf("a configuration whose credential files are not there yet did not load: %v", err)
	}
	advice := strings.Join(cfg.Advice(), "\n")
	for _, want := range []string{"mfa_users_file", "keys_file", "does not exist yet"} {
		if !strings.Contains(advice, want) {
			t.Errorf("advice %q does not mention %q", advice, want)
		}
	}
	// The token file is not one of them: a missing token is an endpoint
	// nobody can authenticate to.
	bad := strings.Replace(yaml, token, filepath.Join(dir, "no-token"), 1)
	if _, err := ParseWith([]byte(bad), true); err == nil {
		t.Error("a missing token file loaded")
	}
}
