package admit

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/intel"
)

// recorder is a Gate that remembers what it was told.
type recorder struct {
	shadow                        bool
	recorded, denied, quarantined []string
	recordRule, denyRule          string
}

func (r *recorder) gate() Gate {
	return Gate{
		Shadowing: func() bool { return r.shadow },
		Record: func(reason, rule, detail string) {
			r.recorded = append(r.recorded, reason)
			r.recordRule = rule
		},
		Deny: func(reason, rule, detail string) {
			r.denied = append(r.denied, reason)
			r.denyRule = rule
		},
		Quarantine: func(reason, rule, detail string) {
			r.quarantined = append(r.quarantined, reason)
		},
	}
}

// lists builds an intel set from one cidr file with the action given.
func lists(t *testing.T, body, action string) *intel.Set {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nets.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := intel.New([]intel.Spec{{Name: "listed", File: p, Action: action}})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func policy(t *testing.T, users []string) *authorization.Policy {
	t.Helper()
	p, err := authorization.New(&config.Authorization{
		Rules: []config.AuthzRule{{Name: "allowed", Allow: true, Networks: users}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func subject(ip string) authorization.Subject {
	return authorization.Subject{
		Listener: "relay", Kind: "modbus", Client: netip.MustParseAddr(ip),
		Target: "plc", Action: authorization.ActionConnect,
	}
}

// The order the two questions are asked in is the thing this package exists to
// fix, so it is what the tests are about.
func TestTheListsAreAskedBeforeThePolicy(t *testing.T) {
	// A client that is both on a blocking list and outside the policy is
	// refused as the list's doing, because the import is the more specific
	// statement and an operator looking for a rule would not find one.
	r := &recorder{}
	got := Client(Deps{Lists: lists(t, "203.0.113.0/24\n", "block"),
		Policy: policy(t, []string{"10.0.0.0/8"})}, subject("203.0.113.7"), r.gate())
	if got != Reason {
		t.Errorf("reason %q, want %q", got, Reason)
	}
	if r.denyRule != "listed" {
		t.Errorf("the refusal did not name the list: %q", r.denyRule)
	}
}

// A client no list knows falls through to the policy, and the refusal is the
// policy's with the rule that decided.
func TestAClientNoListKnowsIsThePolicysQuestion(t *testing.T) {
	r := &recorder{}
	got := Client(Deps{Lists: lists(t, "203.0.113.0/24\n", "block"),
		Policy: policy(t, []string{"10.0.0.0/8"})}, subject("192.0.2.9"), r.gate())
	if got != authorization.Reason {
		t.Errorf("reason %q, want %q", got, authorization.Reason)
	}
	// Nothing matched, so the default decided and there is no rule to name.
	if r.denyRule != "" {
		t.Errorf("rule %q, want empty for a default decision", r.denyRule)
	}
}

// And a client the policy allows is carried, with neither question refusing.
func TestAClientBothAllowIsCarried(t *testing.T) {
	r := &recorder{}
	got := Client(Deps{Lists: lists(t, "203.0.113.0/24\n", "block"),
		Policy: policy(t, []string{"10.0.0.0/8"})}, subject("10.0.0.5"), r.gate())
	if got != "" {
		t.Errorf("reason %q, want none", got)
	}
	if len(r.denied) != 0 || len(r.recorded) != 0 {
		t.Errorf("something was refused: denied %v recorded %v", r.denied, r.recorded)
	}
}

// A list asking for a challenge is not a block on these kinds: there is no
// request to serve a challenge into, and turning it into a refusal would be a
// policy the operator did not write.
func TestAChallengeListDoesNotBecomeABlock(t *testing.T) {
	r := &recorder{}
	got := Client(Deps{Lists: lists(t, "203.0.113.0/24\n", "challenge"),
		Policy: policy(t, []string{"203.0.113.0/24"})}, subject("203.0.113.7"), r.gate())
	if got != "" {
		t.Errorf("a challenge list refused: %q", got)
	}
}

// Shadow mode records both refusals and enforces neither.
func TestShadowModeRecordsAndCarriesOn(t *testing.T) {
	// On a blocking list and outside the policy, so both have something to say.
	r := &recorder{shadow: true}
	if got := Client(Deps{Lists: lists(t, "203.0.113.0/24\n", "block"),
		Policy: policy(t, []string{"10.0.0.0/8"})},
		subject("203.0.113.7"), r.gate()); got != "" {
		t.Errorf("shadow mode refused: %q", got)
	}
	// Both questions recorded: the list's, then the policy's.
	if len(r.recorded) != 2 {
		t.Errorf("recorded %v, want the list's refusal and the policy's", r.recorded)
	}
	if len(r.denied) != 0 {
		t.Errorf("shadow mode enforced: %v", r.denied)
	}
}

// Neither configured asks nothing, which is what a deployment with no lists and
// no policy has always had.
func TestNeitherConfiguredRefusesNothing(t *testing.T) {
	r := &recorder{}
	if got := Client(Deps{}, subject("203.0.113.7"), r.gate()); got != "" {
		t.Errorf("reason %q, want none", got)
	}
}

func TestQuarantineDoesNotUseOrdinaryDenyPath(t *testing.T) {
	r := &recorder{}
	got := Client(Deps{
		Quarantined: func(netip.Addr) (string, bool) { return "deny-pack", true },
		Policy:      policy(t, []string{"203.0.113.0/24"}),
	}, subject("203.0.113.7"), r.gate())
	if got != QuarantineReason {
		t.Fatalf("reason %q, want %q", got, QuarantineReason)
	}
	if len(r.quarantined) != 1 || r.quarantined[0] != QuarantineReason {
		t.Errorf("quarantine callbacks %v, want [%s]", r.quarantined, QuarantineReason)
	}
	if len(r.denied) != 0 {
		t.Errorf("quarantine entered ordinary deny path: %v", r.denied)
	}
}
