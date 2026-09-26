package ssh_test

import (
	"strings"
	"testing"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/proxy"
)

// authzBastion is a bastion under an authorisation policy, with the policy
// written as the estate would write it: a section of its own, above the
// listeners, naming identities rather than keys.
func authzBastion(t *testing.T, policy string) (*proxy.Server, string, cssh.Signer, *targetSSH) {
	t.Helper()
	return bastionWith(t, "", "authorization:\n"+policy)
}

// A policy that does not cover the client refuses the session, and refuses it
// before the target is dialled: the point of asking above the protocol is that
// a machine never sees a session nobody authorised.
func TestAPolicyThatDoesNotCoverTheClientRefuses(t *testing.T) {
	s, addr, key, tg := authzBastion(t, `  rules:
    - {name: robots-only, allow: true, users: [robot]}
`)

	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session opened for a user no rule covers")
	}
	if n := len(tg.seen()); n != 0 {
		t.Errorf("the target saw %d sessions, want none", n)
	}
	if got := s.Counters().SSHRejected.Load(); got == 0 {
		t.Error("the refusal was not counted")
	}
}

// The same bastion with a rule that does cover the client: the policy is a
// decision, not a wall, and the session runs.
func TestAPolicyThatCoversTheClientAdmits(t *testing.T) {
	_, addr, key, tg := authzBastion(t, `  rules:
    - {name: staff, allow: true, users: [alice], actions: [connect]}
`)

	sess, err := sshSession(t, addr, key)
	if err != nil {
		t.Fatalf("a session the policy allows was refused: %v", err)
	}
	if _, err := sess.Output("id"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if n := len(tg.seen()); n == 0 {
		t.Error("the target saw nothing")
	}
}

// The default decides what no rule did, and the default is deny. A policy whose
// rules are all about somebody else is a policy that refuses everybody else.
func TestTheDefaultDecidesWhatNoRuleDid(t *testing.T) {
	_, addr, key, _ := authzBastion(t, `  default: allow
  rules:
    - {name: nobody, users: [mallory]}
`)

	if _, err := sshSession(t, addr, key); err != nil {
		t.Fatalf("default: allow refused a session no rule matched: %v", err)
	}
}

// An earlier deny wins over a later allow, because the first rule that matches
// decides -- which is how every other list in this project reads.
func TestTheFirstMatchingRuleDecides(t *testing.T) {
	s, addr, key, tg := authzBastion(t, `  rules:
    - {name: not-from-there, not_networks: ["192.0.2.0/24"]}
    - {name: staff, allow: true, users: [alice]}
`)

	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a later allow overrode an earlier deny")
	}
	if n := len(tg.seen()); n != 0 {
		t.Errorf("the target saw %d sessions, want none", n)
	}
	_ = s
}

// A rule may name the target, which on an ssh listener is the upstream pool:
// the machine is chosen by balancer after this point, so a rule that means "not
// this pool" is the rule an operator writes.
func TestARuleMayNameTheUpstreamPool(t *testing.T) {
	_, addr, key, tg := authzBastion(t, `  rules:
    - {name: no-hosts, targets: [hosts]}
    - {name: staff, allow: true, users: [alice]}
`)

	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session reached a pool a deny rule named")
	}
	if n := len(tg.seen()); n != 0 {
		t.Errorf("the target saw %d sessions, want none", n)
	}

	// And the same rule with not_targets does not apply to this pool, so the
	// allow below it decides: the two selectors are each other's opposite, and
	// a policy that read them the same way would be a policy nobody could
	// write a per-pool exception in.
	_, addr, key, tg = authzBastion(t, `  rules:
    - {name: not-hosts, not_targets: [hosts]}
    - {name: staff, allow: true, users: [alice]}
`)
	if _, err := sshSession(t, addr, key); err != nil {
		t.Fatalf("not_targets excluded the pool it names: %v", err)
	}
	if n := len(tg.seen()); n == 0 {
		t.Error("the target saw nothing")
	}
}

// A policy in shadow mode records what it would have refused and admits the
// session anyway, which is how an estate reads a policy against real traffic
// before it decides anything. The record is the deliverable, so it has to be
// there.
func TestAShadowedPolicyRecordsAndAdmits(t *testing.T) {
	// A named deny rule, so the record has a rule to name. (Where the default
	// decides instead, there is no rule and the field is empty -- which is
	// itself the useful distinction: "no rule covered this" reads differently
	// from "this rule refused it".)
	s, addr, key, tg := authzBastion(t, `  shadow: true
  rules:
    - {name: not-alice, users: [alice]}
`)

	if _, err := sshSession(t, addr, key); err != nil {
		t.Fatalf("a shadowed policy refused a session: %v", err)
	}
	if n := len(tg.seen()); n == 0 {
		t.Error("the target saw nothing, so the session was not really admitted")
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "ssh" && e.Reason == "authorization" {
			found = true
			if !strings.Contains(e.Sample, "alice") {
				t.Errorf("shadow entry sample %q, want the subject in it", e.Sample)
			}
			// The rule reaches its own field, so a report an operator reads
			// names the rule that decided rather than only the reason.
			if e.Rule != "not-alice" {
				t.Errorf("shadow entry rule %q, want not-alice", e.Rule)
			}
		}
	}
	if !found {
		t.Errorf("no shadow entry for the refusal: %+v", s.Shadow().Report())
	}
	if s.Counters().SSHRejected.Load() != 0 {
		t.Error("a shadowed refusal was counted as a refusal")
	}
}

// The other shadow switch: the policy enforces, and the listener is the thing in
// shadow mode. An estate turning the policy on one listener at a time needs this
// half to work, and it is a different code path from the policy's own switch.
func TestAShadowedListenerRecordsAPolicyRefusal(t *testing.T) {
	s, addr, key, tg := bastionWith(t, "", `policy: {mode: shadow}
authorization:
  rules:
    - {name: not-alice, users: [alice]}
`)

	if _, err := sshSession(t, addr, key); err != nil {
		t.Fatalf("a shadowed listener refused a session: %v", err)
	}
	if n := len(tg.seen()); n == 0 {
		t.Error("the target saw nothing, so the session was not really admitted")
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "ssh" && e.Reason == "authorization" && e.Rule == "not-alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry for the refusal: %+v", s.Shadow().Report())
	}
	if s.Counters().SSHRejected.Load() != 0 {
		t.Error("a shadowed refusal was counted as a refusal")
	}
}

// No section at all is not "deny everything": a bastion with no policy over it
// keeps the policy it had before there was one.
func TestNoPolicyAdmits(t *testing.T) {
	_, addr, key, _ := bastionWith(t, "", "")
	if _, err := sshSession(t, addr, key); err != nil {
		t.Fatalf("a bastion with no authorization section refused a session: %v", err)
	}
}
