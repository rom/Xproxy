package config

import (
	"strings"
	"testing"
)

// authzConfig is a configuration with an authorization section and one listener
// of a kind the policy covers. The kind matters: a configuration carrying the
// section is refused when a listener's kind does not consult the policy, so a
// fixture here has to name one that does.
func authzConfig(t *testing.T, section string) string {
	t.Helper()
	return `
version: 1
server:
  listeners:
    - name: bastion
      address: ":2222"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xproxy/ssh/host_ed25519]
        authorized_keys: /etc/xproxy/ssh/authorized_keys
        upstream_key_file: /etc/xproxy/ssh/upstream_ed25519
        upstream_known_hosts: /etc/xproxy/ssh/known_hosts
upstreams:
  - {name: hosts, endpoints: [{address: "10.0.0.5:22"}]}
` + section
}

// Every way a policy can be wrong at load. The last one is the important one: a
// section that does not cover a listener is a section an operator believes in
// and is wrong about.
func TestTheAuthorizationPolicyIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"authorization: {rules: []}", "at least one is required"},
		{"authorization: {default: maybe, rules: [{name: a, allow: true}]}", "must be deny or allow"},
		{"authorization: {rules: [{allow: true}]}", "name: required"},
		{"authorization: {rules: [{name: \"not a name!\", allow: true}]}", "not a valid name"},
		{"authorization: {rules: [{name: a, allow: true}, {name: a}]}", "duplicate"},
		{"authorization: {rules: [{name: a, actions: [dance]}]}", "is not an action"},
		{"authorization: {rules: [{name: a, networks: [\"nonsense\"]}]}", "not an address or a CIDR"},
		{"authorization: {rules: [{name: a, listeners: [nowhere]}]}", "no listener is called"},
		{"authorization: {rules: [{name: a, kinds: [telepathy]}]}", "not a listener kind"},
		{"authorization: {rules: [{name: a, targets: [\"\"]}]}", "empty"},
		// ** would widen a rule past the host or the directory it names.
		{"authorization: {rules: [{name: a, targets: [\"/srv/**\"]}]}", "is not a target pattern here"},
		{"authorization: {rules: [{name: a, schedule: {days: [caturday]}}]}", "not a day"},
	} {
		_, err := ParseWith([]byte(authzConfig(t, tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\nerror %v, want one about %q", tc.section, err, tc.want)
		}
	}
}

// A listener whose kind does not consult the policy is refused, and the message
// says which kinds do. This is what lets the section be delivered a few kinds at
// a time without ever being a lie.
//
// The second listener has to be a kind that is still outside the policy, so this
// fixture needs changing each time one is wired -- which is the test doing its
// job rather than a maintenance cost: it failed on the commit that wired mqtt,
// which is exactly the notice an author of the next kind should get.
func TestAListenerOutsideThePolicyIsRefused(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: bastion
      address: ":2222"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xproxy/ssh/host_ed25519]
        authorized_keys: /etc/xproxy/ssh/authorized_keys
        upstream_key_file: /etc/xproxy/ssh/upstream_ed25519
        upstream_known_hosts: /etc/xproxy/ssh/known_hosts
    - name: relay
      address: ":514"
      kind: syslog
      syslog: {upstream: collectors}
upstreams:
  - {name: hosts, endpoints: [{address: "10.0.0.5:22"}]}
  - {name: collectors, endpoints: [{address: "10.0.0.9:514"}]}
authorization:
  rules:
    - {name: everything, allow: true}
`
	_, err := ParseWith([]byte(yaml), false)
	if err == nil {
		t.Fatal("a listener outside the policy was accepted")
	}
	for _, want := range []string{`listener "relay"`, `kind "syslog"`, "does not consult"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v, want it to mention %q", err, want)
		}
	}
}

// What loads, and what it says out loud while loading.
func TestTheAuthorizationPolicyAdvises(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`authorization: {default: allow, rules: [{name: a, allow: true}]}`, "gaps are invisible"},
		{`authorization: {shadow: true, rules: [{name: a, allow: true}]}`, "enforces nothing"},
		{`authorization: {rules: [{name: open, allow: true}, {name: later, allow: true, users: [alice]}]}`,
			"Every rule after it is unreachable"},
	} {
		cfg, err := ParseWith([]byte(authzConfig(t, tc.section)), false)
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		if !hasAdvice(cfg, tc.want) {
			t.Errorf("%s: advice %v, want %q", tc.section, cfg.Advice(), tc.want)
		}
	}
	// And a policy in the shape this feature is for draws none of it.
	cfg, err := ParseWith([]byte(authzConfig(t, `authorization:
  rules:
    - {name: staff, allow: true, groups: ["cn=staff"], actions: [connect]}
    - {name: robots, allow: true, users: [robot], targets: ["10.0.0.5:*"]}`)), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"gaps are invisible", "enforces nothing", "unreachable"} {
		if hasAdvice(cfg, unwanted) {
			t.Errorf("advised about %q on a plain policy: %v", unwanted, cfg.Advice())
		}
	}
}
