package config

import (
	"strings"
	"testing"
)

func answerConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: resolver
      address: ":5353"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53"]
` + section
}

// An answer policy that denies nothing reads like rebinding protection
// and is not one. It is refused at load, because the operator who wrote
// the section meant to get something for it.
func TestAnAnswerPolicyThatDeniesNothingIsRefused(t *testing.T) {
	_, err := ParseWith([]byte(answerConfig("        answer_policy: {deny_private: false}\n")), false)
	if err == nil || !strings.Contains(err.Error(), "denies nothing") {
		t.Fatalf("error %v, want one about denying nothing", err)
	}
	// With ranges of its own it is a policy, even with deny_private off.
	if _, err := ParseWith([]byte(answerConfig("        answer_policy: {deny_private: false, deny: [10.0.0.0/8]}\n")), false); err != nil {
		t.Fatalf("a policy with its own ranges: %v", err)
	}
}

// The section defaults to denying the unroutable ranges and to nxdomain,
// so writing answer_policy at all is enough to get rebinding protection.
func TestAnswerPolicyDefaults(t *testing.T) {
	cfg, err := ParseWith([]byte(answerConfig("        answer_policy: {}\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	ap := cfg.Server.Listeners[0].DNS.AnswerPolicy
	if ap == nil {
		t.Fatal("no answer_policy section")
	}
	if ap.DenyPrivate == nil || !*ap.DenyPrivate {
		t.Fatalf("deny_private defaulted to %v, want true", ap.DenyPrivate)
	}
	if ap.Action != "nxdomain" {
		t.Fatalf("action defaulted to %q, want nxdomain", ap.Action)
	}
	// And the client subnet is stripped unless an operator says forward.
	if got := cfg.Server.Listeners[0].DNS.ECS; got != "strip" {
		t.Fatalf("ecs defaulted to %q, want strip", got)
	}
}

func TestAnswerPolicyRejectsNonsense(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"        answer_policy: {action: drop}\n", "must be nxdomain, refuse, servfail or strip"},
		{"        answer_policy: {deny: [\"not-a-cidr\"]}\n", "is not a CIDR"},
		{"        answer_policy: {allow: [\"10.0.0.1\"]}\n", "is not a CIDR"},
		{"        answer_policy: {allow_names: [\"not a name\"]}\n", "is not a name"},
		{"        ecs: maybe\n", "must be strip or forward"},
	} {
		_, err := ParseWith([]byte(answerConfig(tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", strings.TrimSpace(tc.section), err, tc.want)
		}
	}
}
