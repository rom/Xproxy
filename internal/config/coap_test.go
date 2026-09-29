package config

import (
	"strings"
	"testing"
)

// The two tables that turn a CoAP DTLS peer into a name, checked at load.
//
// Everything here is a load error rather than a runtime surprise for one
// reason: on this protocol the identity *is* the identity. A row with a typo
// in it is a policy about a device that will never connect, and a rule naming
// a name no table produces is a line that reads in a file as a control and is
// not one.
func coapConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: field
      address: "127.0.0.1:5684"
      kind: coap
      coap:
` + section + `
upstreams:
  - {name: devices, endpoints: [{address: "10.0.0.5:5683"}]}
`
}

func TestTheCoAPIdentityTablesAreCheckedAtLoad(t *testing.T) {
	for _, c := range []struct{ what, section, want string }{
		{
			"an empty identity",
			"        upstream: devices\n        psk:\n          identities:\n            - {identity: \"\", key: \"env:K\"}\n",
			"identity: required",
		},
		{
			"a psk section with no identities",
			"        upstream: devices\n        psk: {hint: plant}\n",
			"identities: required",
		},
		{
			"an identity with no key",
			"        upstream: devices\n        psk:\n          identities:\n            - {identity: sensor-1}\n",
			"key: required",
		},
		{
			"the same identity twice",
			"        upstream: devices\n        psk:\n          identities:\n            - {identity: sensor-1, key: \"env:A\"}\n            - {identity: sensor-1, key: \"env:B\"}\n",
			"appears twice",
		},
		{
			"a key file that is not an absolute path",
			"        upstream: devices\n        psk:\n          identities:\n            - {identity: sensor-1, key: \"file:keys/sensor-1\"}\n",
			"absolute path",
		},
		{
			"a fingerprint that is not one",
			"        upstream: devices\n        public_keys:\n          - {fingerprint: \"sha256:nonsense\", name: gw}\n",
			"fingerprint",
		},
		{
			"a pinned key with no name",
			"        upstream: devices\n        public_keys:\n          - {fingerprint: \"" + strings.Repeat("ab", 32) + "\"}\n",
			"name: required",
		},
		{
			// The check that matters most in a file somebody reads as a
			// policy: a rule about a device nothing can ever be.
			"a rule naming a security name no table produces",
			"        upstream: devices\n        psk:\n          identities:\n            - {identity: sensor-1, key: \"env:A\"}\n" +
				"        rules:\n          - {name: r, action: allow, security_names: [sensor-2]}\n",
			"can never match",
		},
		{
			"require_security_name with nothing to map a peer to",
			"        upstream: devices\n        require_security_name: true\n",
			"nothing for a peer to map to",
		},
		{
			"a pinned key with no tls section to ask for a certificate",
			"        upstream: devices\n        public_keys:\n          - {fingerprint: \"" + strings.Repeat("ab", 32) + "\", name: gw}\n",
			"no tls section",
		},
	} {
		_, err := Parse([]byte(coapConfig(c.section)))
		if err == nil {
			t.Errorf("%s was accepted", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.what, err, c.want)
		}
	}
}

// A pre-shared key table with no tls section is a PSK-only listener, not a
// mistake: the devices that speak this mode have no certificate machinery, and
// the estate that runs them usually has no authority of its own either.
func TestAPreSharedKeyListenerNeedsNoCertificate(t *testing.T) {
	cfg, err := Parse([]byte(coapConfig(
		"        upstream: devices\n        psk:\n          hint: plant-a\n          identities:\n" +
			"            - {identity: sensor-1, key: \"env:SENSOR_1_KEY\"}\n" +
			"        rules:\n          - {name: r, action: allow, security_names: [sensor-1]}\n")))
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Server.Listeners[0].CoAP
	if !m.RequiresSecurityName() {
		t.Error("a listener with a key table should require a security name by default: a session that authenticated some other way maps to nothing, and every rule naming a name is then silently not about it")
	}
	// And the NoSec warning is about having no identity at all, so a listener
	// with keys must not get it.
	for _, w := range cfg.Advice() {
		if strings.Contains(w, "CoAP NoSec") {
			t.Errorf("a pre-shared key listener was called NoSec: %s", w)
		}
	}
}

// Without either table nothing requires a name, because there would be nothing
// to map a peer through and every message would be refused.
func TestWithoutTablesNoNameIsRequired(t *testing.T) {
	cfg, err := Parse([]byte(coapConfig("        upstream: devices\n        default_action: allow\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listeners[0].CoAP.RequiresSecurityName() {
		t.Error("a listener with no tables requires a security name")
	}
	var nosec bool
	for _, w := range cfg.Advice() {
		if strings.Contains(w, "CoAP NoSec") {
			nosec = true
		}
	}
	if !nosec {
		t.Error("a listener with no tls section and no keys was not called NoSec")
	}
}

// require_any is a certificate checked against nothing, which is a credential
// only where something else decides whether the peer is anybody.
func TestRequireAnyIsOnlyForAPinnedKeyListener(t *testing.T) {
	withTLS := func(coap string) string {
		return `
version: 1
server:
  listeners:
    - name: field
      address: "127.0.0.1:5684"
      kind: coap
      tls:
        client_auth: require_any
        certificates:
          - {cert_file: /etc/xproxy/c.pem, key_file: /etc/xproxy/k.pem}
      coap:
` + coap + `
upstreams:
  - {name: devices, endpoints: [{address: "10.0.0.5:5683"}]}
`
	}
	// With a pinned key it is the right thing and the file loads (the
	// certificate paths do not exist, so the only error must be about those).
	_, err := Parse([]byte(withTLS("        upstream: devices\n        public_keys:\n          - {fingerprint: \"" +
		strings.Repeat("ab", 32) + "\", name: gw}\n")))
	if err != nil && strings.Contains(err.Error(), "client_auth") {
		t.Errorf("require_any was refused on a listener that pins keys: %v", err)
	}
	// Without one it is a certificate nobody verified.
	_, err = Parse([]byte(withTLS("        upstream: devices\n")))
	if err == nil || !strings.Contains(err.Error(), "require_any") {
		t.Errorf("require_any was accepted with no key table: %v", err)
	}
}
