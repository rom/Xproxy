package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The validator for the three authentication kinds.
//
// What is checked here is the half a reader of the reference cannot see: that
// a configuration which reads as though it did something is refused rather
// than loaded. The pattern grammar is the sharp case -- a command pattern
// with a wildcard in the middle looks like it covers something, and on a
// protocol that authorises each command separately a pattern whose author and
// whose reader disagree is worse than no pattern at all.

func radiusConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: auth
      address: "127.0.0.1:1812"
      kind: radius
      radius:
` + section + `
upstreams:
  - name: servers
    endpoints: [{address: "10.0.0.20:1812"}]
`
}

func tacacsConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: admin
      address: "127.0.0.1:49"
      kind: tacacs
      tacacs:
` + section + `
upstreams:
  - name: servers
    endpoints: [{address: "10.0.0.30:49"}]
`
}

func kkdcpConfig(section, tls string) string {
	return `
version: 1
server:
  listeners:
    - name: kdcproxy
      address: "127.0.0.1:443"
      kind: kkdcp
` + tls + `      kkdcp:
` + section + `
upstreams:
  - name: kdcs
    endpoints: [{address: "10.0.1.10:88"}]
`
}

// tlsSection is a certificate pair a kkdcp listener needs to load at all.
// The files are not read by ParseWith(_, false), which is what the examples
// test relies on too.
const tlsSection = `      tls:
        certificates:
          - cert_file: /etc/xproxy/tls/kdcproxy.pem
            key_file: /etc/xproxy/tls/kdcproxy.key
`

// check runs one case: a document, and either the text an error must contain
// or an empty string for a document that must load.
func check(t *testing.T, doc, wants string) {
	t.Helper()
	_, err := ParseWith([]byte(doc), false)
	if wants == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("no error, want one mentioning %q", wants)
	}
	if !strings.Contains(err.Error(), wants) {
		t.Fatalf("error %q does not mention %q", err, wants)
	}
}

func TestRADIUSRefusesWhatCouldNeverWork(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "no upstream",
			section: "        allow_clients: [\"10.0.0.0/8\"]\n",
			wants:   "upstream: required",
		},
		{
			name:    "a code RADIUS does not have",
			section: "        upstream: servers\n        codes: [access-maybe]\n",
			wants:   `"access-maybe" is not a RADIUS code`,
		},
		{
			name:    "an authentication method this relay cannot tell apart",
			section: "        upstream: servers\n        auth_types: [kerberos]\n",
			wants:   `"kerberos" is not an authentication method`,
		},
		{
			name:    "an EAP method nobody has",
			section: "        upstream: servers\n        eap_types: [eap-telepathy]\n",
			wants:   `is not an EAP method`,
		},
		{
			name:    "an attribute that is not one",
			section: "        upstream: servers\n        deny_attributes: [user-intent]\n",
			wants:   `is not an attribute`,
		},
		{
			name:    "a privilege level outside the ladder",
			section: "        upstream: servers\n        max_privilege_level: 16\n",
			wants:   "must be between 0 and 15",
		},
		{
			name:    "a packet bound past the standard's own",
			section: "        upstream: servers\n        max_message_bytes: 9000\n",
			wants:   "RFC 2865's own maximum",
		},
		{
			name:    "a pending table wider than the identifier space",
			section: "        upstream: servers\n        max_pending: 1024\n",
			wants:   "how many identifiers the protocol has",
		},
		{
			name:    "a deny response this protocol cannot give",
			section: "        upstream: servers\n        deny_response: challenge\n",
			wants:   "must be reject or drop",
		},
		{
			name: "an upstream secret with no secret to verify with",
			section: "        upstream: servers\n" +
				"        upstream_secret_file: /etc/xproxy/radius/up.secret\n",
			wants: "re-sign packets it could not verify",
		},
		{
			name: "two rules with one name",
			section: "        upstream: servers\n        rules:\n" +
				"          - {name: same, action: allow}\n" +
				"          - {name: same, action: deny}\n",
			wants: "is used twice",
		},
		{
			name: "a rule action that is not one",
			section: "        upstream: servers\n        rules:\n" +
				"          - {name: r, action: maybe}\n",
			wants: "must be allow, deny or observe",
		},
		{
			name: "a number instead of a name, which the registry makes legitimate",
			section: "        upstream: servers\n        deny_attributes: [\"200\"]\n" +
				"        codes: [\"1\", \"4\"]\n        allow_clients: [\"10.0.0.0/8\"]\n",
		},
		{
			name: "the methods and realms a real listener names",
			section: "        upstream: servers\n        allow_clients: [\"10.0.0.0/8\"]\n" +
				"        auth_types: [eap]\n        eap_types: [peap, tls, mschapv2]\n" +
				"        realms: [corp.example]\n        max_privilege_level: 1\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, radiusConfig(tc.section), tc.wants) })
	}
}

func TestTACACSRefusesAPatternItsReaderCouldNotTrust(t *testing.T) {
	const withKey = "        upstream: servers\n        secret_file: /etc/xproxy/tacacs/k\n"
	for _, tc := range []struct{ name, section, wants string }{
		{
			// "copy ... tftp:" reads as a pattern and is not one: the
			// wildcard is only ever the last word, so what this says is that
			// a command line is `copy`, anything, and then nothing.
			name:    "a wildcard in the middle",
			section: withKey + "        commands: [\"copy ... tftp:\"]\n",
			wants:   `"..." must be the last word`,
		},
		{
			name:    "a star, which is not the grammar",
			section: withKey + "        commands: [\"show *\"]\n",
			wants:   `may only wildcard with a trailing "..."`,
		},
		{
			name:    "a pattern of nothing",
			section: withKey + "        commands: [\"\"]\n",
			wants:   "empty",
		},
		{
			name:    "a trailing wildcard, which is the grammar",
			section: withKey + "        commands: [\"show ...\", \"write memory\"]\n",
		},
		{
			name:    "commands with no key to read them with",
			section: "        upstream: servers\n        commands: [\"show ...\"]\n",
			wants:   "the command line cannot be read",
		},
		{
			name:    "users with no key to read them with",
			section: "        upstream: servers\n        users: [alice]\n",
			wants:   "these lists would match nothing",
		},
		{
			name:    "an exchange TACACS+ does not have",
			section: withKey + "        exchanges: [telepathy]\n",
			wants:   "is not an exchange",
		},
		{
			name:    "an authentication type that is not one",
			section: withKey + "        authen_types: [fingerprint]\n",
			wants:   "is not an authentication type",
		},
		{
			name:    "a service that is not one",
			section: withKey + "        authen_services: [everything]\n",
			wants:   "is not a service",
		},
		{
			name:    "an argument count past the protocol's own",
			section: withKey + "        max_args: 300\n",
			wants:   "the protocol's own bound",
		},
		{
			name:    "a deny response this protocol cannot give",
			section: withKey + "        deny_response: reject\n",
			wants:   "must be fail or drop",
		},
		{
			name:    "an upstream TLS mode that is not one",
			section: withKey + "        upstream_tls_mode: maybe\n",
			wants:   "must be disable, prefer or require",
		},
		{
			name:    "require_tls with no certificate to terminate it with",
			section: withKey + "        require_tls: true\n",
			wants:   "no tls section",
		},
		{
			name:    "upstream TLS settings a disabled mode would never use",
			section: withKey + "        upstream_tls: {min_version: \"1.3\"}\n",
			wants:   "never uses it",
		},
		{
			name: "a rule naming commands on a listener with no key",
			section: "        upstream: servers\n        rules:\n" +
				"          - {name: r, action: allow, commands: [\"show ...\"]}\n",
			wants: "no secret_file on the listener",
		},
		{
			name: "the shape a real device-administration listener has",
			section: withKey + "        allow_clients: [\"10.40.0.0/16\"]\n" +
				"        commands: [\"show ...\", \"configure ...\"]\n" +
				"        deny_commands: [\"write erase\"]\n" +
				"        max_privilege_level: 1\n" +
				"        rules:\n" +
				"          - {name: look, action: allow, commands: [\"show ...\"]}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, tacacsConfig(tc.section), tc.wants) })
	}
}

func TestKKDCPRequiresTLSAndARealmList(t *testing.T) {
	for _, tc := range []struct {
		name, section, tls, wants string
	}{
		{
			name:    "no tls at all",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n",
			wants:   "requires a tls section",
		},
		{
			name:    "no realms",
			section: "        upstream: kdcs\n",
			tls:     tlsSection,
			wants:   "realms: required",
		},
		{
			name:    "an empty realm in the list",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE, \"\"]\n",
			tls:     tlsSection,
			wants:   "realms[1]: empty",
		},
		{
			name:    "no upstream",
			section: "        realms: [CORP.EXAMPLE]\n",
			tls:     tlsSection,
			wants:   "upstream: required",
		},
		{
			name: "a message type a proxy does not carry",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        message_types: [krb-safe]\n",
			tls:   tlsSection,
			wants: "is not a request type",
		},
		{
			name: "an encryption type that is not one",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        etypes: [rot13]\n",
			tls:   tlsSection,
			wants: "is not an encryption type",
		},
		{
			name: "a KDC option that is not one",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        deny_options: [be-nice]\n",
			tls:   tlsSection,
			wants: "is not a KDC option",
		},
		{
			name: "a message bound below what real traffic needs",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        max_message_bytes: 1024\n",
			tls:   tlsSection,
			wants: "below what real traffic needs",
		},
		{
			name: "password changes with nowhere to send them",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        allow_password_change: true\n",
			tls:   tlsSection,
			wants: "password_upstream: required",
		},
		{
			name: "a path that is not one",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        path: KdcProxy\n",
			tls:   tlsSection,
			wants: "must begin with /",
		},
		{
			name: "a deny response this listener cannot give",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        deny_response: silence\n",
			tls:   tlsSection,
			wants: "must be error or status",
		},
		{
			name: "the shape an internet-facing listener has",
			section: "        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n" +
				"        etypes: [aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96]\n" +
				"        deny_options: [renew, validate]\n" +
				"        max_distinct_services: 15\n        max_preauth_failures: 10\n" +
				"        rules:\n" +
				"          - {name: logins, action: allow, message_types: [as-req]}\n",
			tls: tlsSection,
		},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, kkdcpConfig(tc.section, tc.tls), tc.wants) })
	}
}

// A shared secret anybody but its owner can read is an error rather than a
// warning, because of what the secret is: on RADIUS it is the whole of the
// cryptography, and a group that can read it can forge an Access-Accept.
func TestASharedSecretReadableByMoreThanItsOwnerIsRefused(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.secret")
	if err := os.WriteFile(open, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shut := filepath.Join(dir, "shut.secret")
	if err := os.WriteFile(shut, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := radiusConfig("        upstream: servers\n        secret_file: " + open + "\n" +
		"        allow_clients: [\"10.0.0.0/8\"]\n")
	if _, err := Parse([]byte(doc)); err == nil ||
		!strings.Contains(err.Error(), "readable by more than its owner") {
		t.Fatalf("a world-readable secret loaded: %v", err)
	}
	doc = radiusConfig("        upstream: servers\n        secret_file: " + shut + "\n" +
		"        allow_clients: [\"10.0.0.0/8\"]\n")
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("an owner-only secret was refused: %v", err)
	}
}

// The warnings. A configuration that loads with one of these is a
// configuration that reads less traffic than its author believes, which is
// the failure a validator exists to name.
func TestTheAuthKindsWarnAboutWhatTheyWillNotDo(t *testing.T) {
	for _, tc := range []struct{ name, doc, wants string }{
		{
			name:  "a RADIUS listener with no secret",
			doc:   radiusConfig("        upstream: servers\n        allow_clients: [\"10.0.0.0/8\"]\n"),
			wants: "nothing can be verified",
		},
		{
			name: "the digest requirement turned off",
			doc: radiusConfig("        upstream: servers\n        allow_clients: [\"10.0.0.0/8\"]\n" +
				"        secret_file: /etc/xproxy/radius/k\n" +
				"        require_message_authenticator: false\n"),
			wants: "CVE-2024-3596",
		},
		{
			name: "the dynamic authorization codes turned on",
			doc: radiusConfig("        upstream: servers\n        allow_clients: [\"10.0.0.0/8\"]\n" +
				"        secret_file: /etc/xproxy/radius/k\n" +
				"        allow_dynamic_authorization: true\n"),
			wants: "ends or re-authorises a live user's session",
		},
		{
			name:  "a TACACS+ listener with no key",
			doc:   tacacsConfig("        upstream: servers\n        allow_clients: [\"10.0.0.0/8\"]\n"),
			wants: "reads headers only",
		},
		{
			name: "a FOLLOW reply allowed",
			doc: tacacsConfig("        upstream: servers\n        allow_clients: [\"10.0.0.0/8\"]\n" +
				"        secret_file: /etc/xproxy/tacacs/k\n        allow_follow: true\n"),
			wants: "RFC 8907 deprecates it",
		},
		{
			name: "the AS-REP roasting check turned off",
			doc: kkdcpConfig("        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n"+
				"        refuse_preauth_exempt: false\n", tlsSection),
			wants: "AS-REP roasting",
		},
		{
			name: "the Kerberoasting check turned off",
			doc: kkdcpConfig("        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n"+
				"        refuse_weak_etypes: false\n", tlsSection),
			wants: "Kerberoasting",
		},
		{
			name: "the second half of a delegation chain without the first",
			doc: kkdcpConfig("        upstream: kdcs\n        realms: [CORP.EXAMPLE]\n"+
				"        allow_s4u2proxy: true\n", tlsSection),
			wants: "and not the first",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(tc.doc), false)
			if err != nil {
				t.Fatalf("the document did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.wants) {
				t.Fatalf("warnings %v do not mention %q", cfg.Advice(), tc.wants)
			}
		})
	}
}
