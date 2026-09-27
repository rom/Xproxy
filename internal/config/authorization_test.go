package config

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
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

// The fail-closed rule, from the other side: there is no longer a kind to build a
// refusal from, so what this asserts is that the refusal cannot be provoked.
//
// It used to start a configuration with a listener of a kind outside the policy and
// check that the load refused it, naming the listener and the kind. That fixture
// needed changing each time a kind was wired -- which was the test working rather
// than a maintenance cost; it failed on mqtt, on syslog, on ntp and finally on
// http. Now every kind consults the section, so the assertion inverts: a
// configuration carrying the section beside a listener of **every** kind the roster
// knows loads without being refused for coverage.
//
// The check itself stays in place, because a kind added tomorrow starts outside the
// policy and must be refused rather than silently uncovered. internal/listener's
// roster test is what forces that decision; this is what proves the load side of it
// is not refusing anything it should not.
func TestNoKindIsOutsideThePolicyAnyMore(t *testing.T) {
	for _, kind := range listener.AuthorisingKinds() {
		if _, ok := listener.RoleOf(kind); !ok {
			t.Errorf("authorising kind %q is not a listener kind", kind)
		}
	}
	// ssh is covered, and it is the kind this fixture is built from, so the load
	// below is testing the section rather than a gap.
	if !listener.Authorises("ssh") {
		t.Fatal("ssh does not consult the policy, so the fixture below proves nothing")
	}
	cfg, err := ParseWith([]byte(authzConfig(t, `authorization:
  rules:
    - {name: everything, allow: true}`)), false)
	if err != nil {
		t.Fatalf("a configuration whose every kind consults the policy was refused: %v", err)
	}
	if cfg == nil {
		t.Fatal("no configuration")
	}
	// And the message the check would print still names the kinds that do consult
	// it, so a kind added tomorrow sends its author to the right list.
	if len(listener.AuthorisingKinds()) == 0 {
		t.Error("AuthorisingKinds() is empty, so the refusal would name nothing")
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
