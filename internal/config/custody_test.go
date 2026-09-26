package config

import (
	"strings"
	"testing"
	"time"
)

// tlsCustody builds a configuration with one TLS listener whose single
// certificate carries whatever custody keys the test is about, plus an optional
// top-level section.
func tlsCustody(certExtra, top string) string {
	return `
version: 1
server:
  listeners:
    - name: edge
      address: "127.0.0.1:0"
      kind: http
      tls:
        certificates:
          - cert_file: /etc/xproxy/tls/edge.pem
` + certExtra + `
upstreams:
  - name: app
    endpoints: [{address: "127.0.0.1:9000"}]
routes:
  - name: all
    upstream: app
` + top
}

// A certificate says where its private key comes from exactly once. Nought is a
// certificate with no key; two is a certificate whose key nobody can name by
// reading the file, and a precedence rule would only move the confusion.
func TestACertificateNamesOneKeySource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		keys  string
		top   string
		wants string // "" means it must load
	}{
		{name: "key_file as before", keys: "            key_file: /etc/xproxy/tls/edge.key"},
		{
			name: "a file reference",
			keys: "            key: file:/etc/xproxy/tls/edge.key",
		},
		{
			name: "the environment",
			keys: "            key: env:EDGE_KEY",
		},
		{
			name: "a vault, with a vault configured",
			keys: "            key: vault:secret/tls/edge#key",
			top: `
secrets:
  vault:
    address: https://vault.internal:8200
    token_file: /etc/xproxy/vault-token
`,
		},
		{
			name: "a signer",
			keys: "            signer: {socket: /run/xproxy/signer.sock, key: edge}",
		},
		{
			// cert_file alone: the certificate is there and nothing says
			// where its key is.
			name:  "nothing at all",
			keys:  "",
			wants: "one of key_file, key or signer is required",
		},
		{
			name: "a file and a reference",
			keys: "            key_file: /etc/xproxy/tls/edge.key\n" +
				"            key: env:EDGE_KEY",
			wants: "key_file, key are all set",
		},
		{
			name: "a file and a signer",
			keys: "            key_file: /etc/xproxy/tls/edge.key\n" +
				"            signer: {socket: /run/xproxy/signer.sock, key: edge}",
			wants: "key_file, signer are all set",
		},
		{
			name:  "a vault reference with no vault",
			keys:  "            key: vault:secret/tls/edge#key",
			wants: "there is no secrets.vault section",
		},
		{
			name:  "a vault reference with no field",
			keys:  "            key: vault:secret/tls/edge",
			wants: "needs a field",
		},
		{
			name:  "a scheme that does not exist",
			keys:  "            key: kms:arn/whatever",
			wants: "unknown reference scheme",
		},
		{
			name:  "a relative path",
			keys:  "            key: file:tls/edge.key",
			wants: "must be an absolute path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(tlsCustody(tc.keys, tc.top)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// The signer's bounds are on the handshake path, so they are bounded rather than
// left to an operator's arithmetic: a signature that may take an hour is a
// listener that holds connections open until somebody notices.
func TestSignerDefaultsAndBounds(t *testing.T) {
	ok, err := parseNoFiles([]byte(tlsCustody(
		"            signer: {socket: /run/xproxy/signer.sock, key: edge}", "")))
	if err != nil {
		t.Fatal(err)
	}
	sg := ok.Server.Listeners[0].TLS.Certificates[0].Signer
	if sg.Timeout.D() != DefaultSignerTimeout || sg.MaxConns != DefaultSignerConns {
		t.Errorf("defaults %v %d, want %v %d", sg.Timeout.D(), sg.MaxConns, DefaultSignerTimeout, DefaultSignerConns)
	}
	for _, tc := range []struct{ keys, wants string }{
		{"            signer: {key: edge}", "socket: required"},
		{"            signer: {socket: run/signer.sock, key: edge}", "socket: must be an absolute path"},
		{"            signer: {socket: /run/signer.sock}", "key: required"},
		{"            signer: {socket: /run/signer.sock, key: edge, timeout: 1h}", "timeout: must be between"},
		{"            signer: {socket: /run/signer.sock, key: edge, timeout: 1ms}", "timeout: must be between"},
		{"            signer: {socket: /run/signer.sock, key: edge, max_conns: 9999}", "max_conns: must be between"},
	} {
		_, err := parseNoFiles([]byte(tlsCustody(tc.keys, "")))
		if err == nil || !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: error %v, want %q", tc.keys, err, tc.wants)
		}
	}
}

// Plain HTTP to a vault puts the token and every secret it reads in clear on the
// wire. It stays possible, for a development vault on the loopback, and it takes
// two settings: one typo must not do it.
func TestPlainHTTPToAVaultTakesTwoDecisions(t *testing.T) {
	vault := func(body string) string {
		return tlsCustody("            key_file: /etc/xproxy/tls/edge.key", "secrets:\n  vault:\n"+body)
	}
	for _, tc := range []struct{ name, body, wants string }{
		{
			name:  "http with neither",
			body:  "    address: http://127.0.0.1:8200\n    token_file: /etc/xproxy/vault-token\n",
			wants: "use https://",
		},
		{
			name:  "http with only insecure",
			body:  "    address: http://127.0.0.1:8200\n    insecure: true\n    token_file: /etc/xproxy/vault-token\n",
			wants: "allow_insecure must also be true",
		},
		{
			name: "http with both loads",
			body: "    address: http://127.0.0.1:8200\n    insecure: true\n    allow_insecure: true\n" +
				"    token_file: /etc/xproxy/vault-token\n",
		},
		{
			// The other direction, and the more dangerous one: skipping
			// verification on an https:// address means anything on the
			// path can hand this proxy its secrets, and it looks secure
			// in the file.
			name:  "insecure on https is refused outright",
			body:  "    address: https://vault.internal:8200\n    insecure: true\n    token_file: /etc/xproxy/vault-token\n",
			wants: "Set ca_file instead",
		},
		{
			name:  "no scheme at all",
			body:  "    address: vault.internal:8200\n    token_file: /etc/xproxy/vault-token\n",
			wants: "must be an http:// or https:// URL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(vault(tc.body)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil || !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// There is no anonymous read of a vault, and two token sources is as ambiguous
// as two key sources.
func TestAVaultNeedsExactlyOneToken(t *testing.T) {
	vault := func(body string) string {
		return tlsCustody("            key_file: /etc/xproxy/tls/edge.key",
			"secrets:\n  vault:\n    address: https://vault.internal:8200\n"+body)
	}
	for _, tc := range []struct{ body, wants string }{
		{"", "one of token_file or token_env is required"},
		{"    token_file: /etc/xproxy/vault-token\n    token_env: VAULT_TOKEN\n", "exactly one says where the token comes from"},
		{"    token_file: etc/vault-token\n", "token_file: must be an absolute path"},
		{"    token_file: /etc/xproxy/vault-token\n", ""},
		{"    token_env: VAULT_TOKEN\n", ""},
	} {
		_, err := parseNoFiles([]byte(vault(tc.body)))
		switch {
		case tc.wants == "" && err != nil:
			t.Errorf("%q did not load: %v", tc.body, err)
		case tc.wants == "":
		case err == nil || !strings.Contains(err.Error(), tc.wants):
			t.Errorf("%q: error %v, want %q", tc.body, err, tc.wants)
		}
	}
}

// The refresh interval and the KV version are bounded, and the defaults are the
// ones an estate almost always wants.
func TestSecretsDefaultsAndBounds(t *testing.T) {
	ok, err := parseNoFiles([]byte(tlsCustody("            key_file: /etc/xproxy/tls/edge.key",
		"secrets:\n  vault:\n    address: https://vault.internal:8200\n    token_file: /etc/xproxy/vault-token\n")))
	if err != nil {
		t.Fatal(err)
	}
	sec := ok.Secrets
	if sec.RefreshInterval.D() != DefaultSecretRefresh {
		t.Errorf("refresh_interval %v, want %v", sec.RefreshInterval.D(), DefaultSecretRefresh)
	}
	if sec.Vault.Mount != "secret" || sec.Vault.KVVersion != 2 {
		t.Errorf("vault defaults %q %d", sec.Vault.Mount, sec.Vault.KVVersion)
	}
	for _, tc := range []struct{ body, wants string }{
		{"secrets:\n  refresh_interval: 1s\n", "refresh_interval: must be between"},
		{"secrets:\n  refresh_interval: 48h\n", "refresh_interval: must be between"},
		{"secrets:\n  vault:\n    address: https://v:8200\n    token_env: T\n    kv_version: 3\n", "kv_version: must be 1 or 2"},
	} {
		_, err := parseNoFiles([]byte(tlsCustody("            key_file: /etc/xproxy/tls/edge.key", tc.body)))
		if err == nil || !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%q: error %v, want %q", tc.body, err, tc.wants)
		}
	}
	// A secrets section with no vault is legitimate -- it sets the refresh
	// interval for file: and env: references -- and says so rather than
	// reading as if a vault had been configured and mistyped.
	warned, err := parseNoFiles([]byte(tlsCustody("            key_file: /etc/xproxy/tls/edge.key",
		"secrets:\n  refresh_interval: 10m\n")))
	if err != nil {
		t.Fatal(err)
	}
	if warned.Secrets.RefreshInterval.D() != 10*time.Minute {
		t.Errorf("refresh_interval %v", warned.Secrets.RefreshInterval.D())
	}
	if !hasAdvice(warned, "only file: and env: references resolve") {
		t.Errorf("no advice about a secrets section with no vault: %v", warned.Advice())
	}
}

// probe_fails without a probe, and probe_fails without required, are both
// configurations that read as if they enforced something and do not.
func TestFIPSSectionCombinations(t *testing.T) {
	for _, tc := range []struct{ body, wants string }{
		{"fips:\n  probe_fails: true\n", "only makes sense with required: true"},
		{"fips:\n  required: true\n  probe: false\n  probe_fails: true\n", "there is no probe to fail"},
		{"fips:\n  required: true\n", ""},
		{"fips:\n  probe: true\n", ""},
	} {
		_, err := parseNoFiles([]byte(tlsCustody("            key_file: /etc/xproxy/tls/edge.key", tc.body)))
		switch {
		case tc.wants == "" && err != nil:
			t.Errorf("%q did not load: %v", tc.body, err)
		case tc.wants == "":
		case err == nil || !strings.Contains(err.Error(), tc.wants):
			t.Errorf("%q: error %v, want %q", tc.body, err, tc.wants)
		}
	}
	// probe follows required, so an estate that says "required" gets the
	// report without having to know the probe exists.
	on, err := parseNoFiles([]byte(tlsCustody("            key_file: /etc/xproxy/tls/edge.key", "fips:\n  required: true\n")))
	if err != nil {
		t.Fatal(err)
	}
	if on.FIPS.Probe == nil || !*on.FIPS.Probe {
		t.Errorf("probe %v, want true beside required", on.FIPS.Probe)
	}
	off, err := parseNoFiles([]byte(tlsCustody("            key_file: /etc/xproxy/tls/edge.key", "fips:\n  required: false\n")))
	if err != nil {
		t.Fatal(err)
	}
	if off.FIPS.Probe == nil || *off.FIPS.Probe {
		t.Errorf("probe %v, want false without required", off.FIPS.Probe)
	}
}
