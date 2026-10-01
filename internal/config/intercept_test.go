package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// interceptConfig wraps an intercept section in the smallest valid
// configuration that carries a forward listener.
func interceptConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: main
      address: ":8080"
    - name: fwd
      address: ":3128"
      kind: forward
      forward:
        intercept:
` + section + `
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: r
    hosts: [example.test]
    upstream: app
`
}

const interceptKeys = `          ca_cert_file: /etc/xproxy/mitm.pem
          ca_key_file: /etc/xproxy/mitm-key.pem
`

// TestInterceptDefaults pins what an intercept section means when it
// says the least. The two that matter are that upstream verification is
// on unless it was turned off in writing, and that ALPN is http/1.1
// alone — a stream the proxy relays is one it has to be able to read.
func TestInterceptDefaults(t *testing.T) {
	cfg, err := ParseWith([]byte(interceptConfig(interceptKeys)), false)
	if err != nil {
		t.Fatal(err)
	}
	ic := cfg.Server.Listeners[1].Forward.Intercept
	if ic == nil {
		t.Fatal("no intercept section")
	}
	if ic.VerifyUpstream == nil || !*ic.VerifyUpstream {
		t.Fatalf("verify_upstream defaulted to %v, want true", ic.VerifyUpstream)
	}
	if ic.MinVersion != "1.2" || ic.MaxCache != 1024 || ic.LeafTTL.D() != 24*time.Hour {
		t.Fatalf("defaults: %+v", ic)
	}
	if len(ic.ALPN) != 1 || ic.ALPN[0] != "http/1.1" {
		t.Fatalf("alpn: %v", ic.ALPN)
	}
	// hosts empty is a large decision to leave implicit, so it is said
	// out loud rather than left to be discovered.
	if !hasAdvice(cfg, "hosts: empty") {
		t.Fatalf("no warning about an empty hosts list: %v", cfg.Advice())
	}
}

// TestInterceptWarnsAboutNotVerifying: an interception proxy that does
// not check the destination hands every client behind it a padlock it
// did not earn. It is allowed, because somebody may have a reason, and
// it is never quiet.
func TestInterceptWarnsAboutNotVerifying(t *testing.T) {
	cfg, err := ParseWith([]byte(interceptConfig(interceptKeys+
		"          hosts: [\"*.example.test\"]\n          verify_upstream: false\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "verify_upstream") {
		t.Fatalf("no warning: %v", cfg.Advice())
	}
	if hasAdvice(cfg, "hosts: empty") {
		t.Fatalf("warned about a hosts list that was set: %v", cfg.Advice())
	}
	// h2 is offered but not parsed, which is also said out loud.
	cfg, err = ParseWith([]byte(interceptConfig(interceptKeys+
		"          hosts: [a.test]\n          alpn: [http/1.1, h2]\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "alpn: h2") {
		t.Fatalf("no h2 warning: %v", cfg.Advice())
	}
}

// TestInterceptRefusals lists what does not load at all.
func TestInterceptRefusals(t *testing.T) {
	cases := []struct {
		name, section, want string
	}{
		{"no certificate", "          ca_key_file: /k.pem\n", "ca_cert_file: required"},
		{"no key", "          ca_cert_file: /c.pem\n", "ca_key_file: required"},
		{"relative certificate", "          ca_cert_file: mitm.pem\n          ca_key_file: /k.pem\n", "must be an absolute path"},
		{"bad host", interceptKeys + "          hosts: [\"a*b\"]\n", "intercept.hosts"},
		{"bad bypass", interceptKeys + "          bypass_hosts: [\"10.0.0.0/33\"]\n", "intercept.bypass_hosts"},
		{"relative ca_file", interceptKeys + "          ca_file: roots.pem\n", "ca_file: must be an absolute path"},
		{"min version", interceptKeys + "          min_version: \"1.1\"\n", "min_version: must be 1.2 or 1.3"},
		{"leaf ttl", interceptKeys + "          leaf_ttl: 1000h\n", "leaf_ttl"},
		{"max cache", interceptKeys + "          max_cache: -1\n", "max_cache"},
		{"unknown alpn", interceptKeys + "          alpn: [spdy/3]\n", "alpn[0]"},
		{"alpn twice", interceptKeys + "          alpn: [h2, h2]\n", "listed twice"},
		{"yara without rules", interceptKeys + "          yara: {}\n", "rules_file or rules_dir is required"},
	}
	for _, tc := range cases {
		_, err := ParseWith([]byte(interceptConfig(tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestInterceptRefusesAReadableKey: the signing key can impersonate
// every site to every client that trusts the CA, so an operator finds
// out from "xproxy check" rather than from a refused start.
func TestInterceptRefusesAReadableKey(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca-key.pem")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	section := "          ca_cert_file: " + cert + "\n          ca_key_file: " + key +
		"\n          hosts: [a.test]\n"
	if _, err := Parse([]byte(interceptConfig(section))); err != nil {
		t.Fatalf("an owner-only key was refused: %v", err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Parse([]byte(interceptConfig(section)))
	if err == nil || !strings.Contains(err.Error(), "readable by more than its owner") {
		t.Fatalf("a world-readable key loaded: %v", err)
	}
}

func hasAdvice(c *Config, substr string) bool {
	for _, a := range c.Advice() {
		if strings.Contains(a, substr) {
			return true
		}
	}
	return false
}

// httpAwareConfig is a forward listener with one rule that needs a visible
// request, and whatever intercept section the caller wants under it.
func httpAwareConfig(intercept string) string {
	return `
version: 1
server:
  listeners:
    - name: fwd
      address: ":3128"
      kind: forward
      forward:
        rules:
          - name: no-uploads
            action: deny
            methods: [POST]
` + intercept + `
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes: []
`
}

// TestInterceptHTTPAwareness: whether the requests inside a decrypted tunnel
// are read is the setting that decides whether a rule about a method is a
// policy or a decoration, so the three answers are pinned, and so is the
// advice for the one combination that cannot fire -- rules that need a request
// on a listener that decrypts and then does not read.
func TestInterceptHTTPAwareness(t *testing.T) {
	const section = "        intercept:\n" + interceptKeys + "          hosts: [a.test]\n"

	// The default says what a tunnel does when nobody chose.
	cfg, err := ParseWith([]byte(httpAwareConfig(section)), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.Listeners[0].Forward.Intercept.HTTP; got != "auto" {
		t.Errorf("intercept.http defaulted to %q, want auto", got)
	}
	if hasAdvice(cfg, "intercept.http is off") {
		t.Errorf("warned about a listener that does read the requests: %v", cfg.Advice())
	}

	// Off is allowed -- an estate may want the stream rules and nothing else
	// -- and is never quiet when the policy needed the other answer.
	cfg, err = ParseWith([]byte(httpAwareConfig(section+"          http: off\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "intercept.http is off") {
		t.Errorf("no advice about a rule that cannot fire: %v", cfg.Advice())
	}

	// On is the other end of it, and reads every tunnel.
	cfg, err = ParseWith([]byte(httpAwareConfig(section+"          http: on\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasAdvice(cfg, "intercept.http is off") {
		t.Errorf("warned about a listener set to read: %v", cfg.Advice())
	}

	// And nothing else is a setting.
	_, err = ParseWith([]byte(httpAwareConfig(section+"          http: sometimes\n")), false)
	if err == nil || !strings.Contains(err.Error(), "not auto, on or off") {
		t.Errorf("http: sometimes loaded, or the error did not say what is allowed: %v", err)
	}
}
