package authorization

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// policy compiles a policy from rules, with the default the test wants.
func policy(t *testing.T, def string, rules ...config.AuthzRule) *Policy {
	t.Helper()
	p, err := New(&config.Authorization{Default: def, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The first rule that matches decides, and what nothing matches is decided by
// the default -- which is deny, because a policy whose gaps allow is a policy
// whose gaps are invisible.
func TestTheFirstRuleThatMatchesDecides(t *testing.T) {
	p := policy(t, "",
		config.AuthzRule{Name: "no-robots-at-night", Users: []string{"robot"},
			Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}},
		config.AuthzRule{Name: "robots", Allow: true, Users: []string{"robot"}},
		config.AuthzRule{Name: "dbas", Allow: true, Groups: []string{"CN=DBA"}, Kinds: []string{"postgres"}},
	)
	day := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	night := time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		sub  Subject
		want string // the rule that should decide, "" for the default
		ok   bool
	}{
		{"the robot in the day", Subject{User: "robot", At: day}, "robots", true},
		// The order is the policy: the night rule is first, so it wins.
		{"the robot at night", Subject{User: "robot", At: night}, "no-robots-at-night", false},
		// Groups are compared without case, because a directory returns a name
		// in whatever case it likes.
		{"a dba on postgres", Subject{Groups: []string{"cn=dba"}, Kind: "postgres", At: day}, "dbas", true},
		// Every selector a rule names has to hold: the same person on another
		// kind matches nothing.
		{"a dba on ssh", Subject{Groups: []string{"cn=dba"}, Kind: "ssh", At: day}, "", false},
		{"somebody nothing mentions", Subject{User: "nobody", At: day}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Decide(tc.sub)
			if got.Allow != tc.ok || got.Rule != tc.want {
				t.Errorf("decide = {%v %q}, want {%v %q}", got.Allow, got.Rule, tc.ok, tc.want)
			}
		})
	}
	// And the counters: what the rules decided, and how often the default did,
	// which is the number that says whether the rules describe the estate.
	if p.NoRule.Load() != 2 {
		t.Errorf("no_rule %d, want the two subjects nothing matched", p.NoRule.Load())
	}
	if p.Allowed.Load() != 2 || p.Denied.Load() != 3 {
		t.Errorf("allowed %d denied %d", p.Allowed.Load(), p.Denied.Load())
	}
	rules := p.Rules()
	if len(rules) != 3 || rules[0].Name != "no-robots-at-night" || rules[0].Hits != 1 {
		t.Errorf("rules: %+v", rules)
	}
}

// A rule that names nothing matches everything, which is how a catch-all is
// written -- and an allow default is the other way of saying it.
func TestACatchAllAndAnAllowDefault(t *testing.T) {
	all := policy(t, "", config.AuthzRule{Name: "everything", Allow: true})
	if d := all.Decide(Subject{User: "anybody", Kind: "ssh"}); !d.Allow || d.Rule != "everything" {
		t.Errorf("a catch-all: %+v", d)
	}
	open := policy(t, "allow", config.AuthzRule{Name: "not-the-robot", Users: []string{"robot"}})
	if d := open.Decide(Subject{User: "robot"}); d.Allow {
		t.Error("the deny rule did not fire")
	}
	if d := open.Decide(Subject{User: "alice"}); !d.Allow || d.Rule != "" {
		t.Errorf("the allow default: %+v", d)
	}
	if !open.DefaultAllows() {
		t.Error("DefaultAllows does not say so")
	}
	// A nil policy allows: no policy is not "deny everything", and a listener
	// with no section keeps the policy it had before there was one.
	var none *Policy
	if d := none.Decide(Subject{}); !d.Allow {
		t.Error("a nil policy refused")
	}
	if none.Rules() != nil || none.DefaultAllows() || none.Shadows() {
		t.Error("a nil policy answered something about itself")
	}
}

// The negative selectors: everybody but. They are separate keys because a name
// can begin with any character, so a "!" prefix would make some names
// unwritable.
func TestTheNegativeSelectors(t *testing.T) {
	p := policy(t, "",
		config.AuthzRule{Name: "staff-not-contractors", Allow: true,
			NotUsers: []string{"contractor"}, NotGroups: []string{"cn=external"},
			NotNetworks: []string{"203.0.113.0/24"}},
	)
	office := netip.MustParseAddr("10.1.2.3")
	outside := netip.MustParseAddr("203.0.113.9")
	for _, tc := range []struct {
		name string
		sub  Subject
		ok   bool
	}{
		{"a member of staff", Subject{User: "alice", Client: office}, true},
		{"the contractor", Subject{User: "contractor", Client: office}, false},
		{"somebody in the external group", Subject{User: "alice", Groups: []string{"CN=External"}, Client: office}, false},
		{"staff from the excluded network", Subject{User: "alice", Client: outside}, false},
		// A subject with no user at all is not "the contractor": an empty name
		// must not match a not_users entry, or an unauthenticated session would
		// be refused by a rule about one person.
		{"nobody in particular", Subject{Client: office}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Decide(tc.sub); got.Allow != tc.ok {
				t.Errorf("allow = %v, want %v (rule %q)", got.Allow, tc.ok, got.Rule)
			}
		})
	}
}

// A target pattern names a host or a path element, and a * in it does not cross
// a colon or a slash. A wildcard that crossed those would quietly widen a rule
// past what it looks like -- "10.0.0.5:*" would cover another host whose name
// contained the text, and "/srv/*" would cover the whole tree under it.
func TestATargetPatternDoesNotCrossASeparator(t *testing.T) {
	p := policy(t, "",
		config.AuthzRule{Name: "one-host", Allow: true, Targets: []string{"10.0.0.5:*"}},
		config.AuthzRule{Name: "one-directory", Allow: true, Targets: []string{"/srv/incoming/*"}},
		config.AuthzRule{Name: "any-db", Allow: true, Targets: []string{"db-*.internal:5432"}},
	)
	for _, tc := range []struct {
		target string
		ok     bool
	}{
		{"10.0.0.5:22", true},
		{"10.0.0.5:5432", true},
		// Another host: the pattern is about ports, not about anything whose
		// text happens to start the same way.
		{"10.0.0.50:22", false},
		{"10.0.0.5:22:extra", false},
		{"/srv/incoming/report.csv", true},
		// One level only.
		{"/srv/incoming/2026/report.csv", false},
		{"/srv/incoming", false},
		{"db-reports.internal:5432", true},
		{"db-reports.internal:22", false},
		// A * inside a name does cross dots -- that is what a glob does, and
		// the separators that matter for a target are the ones that divide a
		// host from a port and a directory from what is in it.
		{"db-a.b.internal:5432", true},
		{"", false},
	} {
		if got := p.Decide(Subject{Target: tc.target}); got.Allow != tc.ok {
			t.Errorf("%q: allow = %v, want %v", tc.target, got.Allow, tc.ok)
		}
	}
	// The one pattern that means everything, including a subject with no target
	// at all: a rule about a listener rather than about what was asked for.
	any := policy(t, "", config.AuthzRule{Name: "any", Allow: true, Targets: []string{"*"}})
	for _, target := range []string{"", "anything:1", "/a/b/c"} {
		if !any.Decide(Subject{Target: target}).Allow {
			t.Errorf("* did not match %q", target)
		}
	}
}

// An action is this policy's vocabulary rather than any one protocol's, and the
// list a configuration is validated against is the one the constants name.
func TestTheActionVocabularyIsOneList(t *testing.T) {
	for _, a := range []string{ActionConnect, ActionSession, ActionExec, ActionForward, ActionRead, ActionWrite, ActionAdmin} {
		if !config.AuthzActions[a] {
			t.Errorf("%q is a constant here and not in config.AuthzActions, so a rule naming it would not load", a)
		}
	}
	if len(config.AuthzActions) != 7 {
		t.Errorf("config.AuthzActions holds %d actions and this test knows 7", len(config.AuthzActions))
	}
	p := policy(t, "", config.AuthzRule{Name: "reads", Allow: true, Actions: []string{ActionRead}})
	if !p.Decide(Subject{Action: ActionRead}).Allow {
		t.Error("a read was not allowed by a read rule")
	}
	if p.Decide(Subject{Action: ActionWrite}).Allow {
		t.Error("a write was allowed by a read rule")
	}
	if _, err := New(&config.Authorization{Rules: []config.AuthzRule{{Name: "x", Actions: []string{"dance"}}}}); err == nil {
		t.Error("an action nobody defined compiled")
	}
}

// What a policy refuses to compile, which is what a caller building one in Go
// has to be told: the YAML path is validated before it gets here.
func TestAPolicyIsCheckedWhenItIsCompiled(t *testing.T) {
	for _, tc := range []struct {
		rules []config.AuthzRule
		want  string
	}{
		{[]config.AuthzRule{{}}, "name is required"},
		{[]config.AuthzRule{{Name: "a"}, {Name: "a"}}, "duplicate name"},
		{[]config.AuthzRule{{Name: "a", Networks: []string{"not-an-address"}}}, "networks"},
		{[]config.AuthzRule{{Name: "a", NotNetworks: []string{"10.0.0.0/64"}}}, "not_networks"},
		{[]config.AuthzRule{{Name: "a", Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}}, "not a day"},
	} {
		_, err := New(&config.Authorization{Rules: tc.rules})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: error %v, want one about %q", tc.rules, err, tc.want)
		}
	}
	// A nil section is a nil policy, so a caller can pass the configuration
	// straight through.
	p, err := New(nil)
	if err != nil || p != nil {
		t.Errorf("New(nil) = %v, %v", p, err)
	}
}

// Shadow mode says so rather than deciding, which is what lets a policy be read
// against real traffic before it refuses anything.
func TestShadowSaysSoWithoutChangingTheDecision(t *testing.T) {
	p, err := New(&config.Authorization{Shadow: true, Rules: []config.AuthzRule{{Name: "deny-all"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Shadows() {
		t.Fatal("Shadows() is false on a shadow policy")
	}
	// The decision is still made and still counted: what changes is what the
	// caller does with it.
	if d := p.Decide(Subject{User: "alice"}); d.Allow || d.Rule != "deny-all" {
		t.Errorf("shadow changed the decision: %+v", d)
	}
	if p.Denied.Load() != 1 {
		t.Error("a shadowed decision was not counted")
	}
}
