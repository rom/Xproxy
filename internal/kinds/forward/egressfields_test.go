package forward

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Each field of an egress rule narrows what it selects, and the "not"
// forms are the ones worth their own test: a rule that selects
// everything except one thing is how an estate writes a broad control
// with a hole in it, and a hole in the wrong place is a control that
// does not apply.

// oneRule compiles a policy of a single rule, with the groups and
// categories the rules below name.
func oneRule(t *testing.T, r config.ForwardRule) *egressPolicy {
	t.Helper()
	return policy(t, &config.ForwardListener{
		Auth: &config.ForwardAuth{UsersFile: "/dev/null",
			Groups: map[string][]string{"agents": {"build1"}, "staff": {"alice"}}},
		Categories: []config.ForwardCategory{
			{Name: "mirrors", Hosts: []string{"proxy.golang.org"}},
			{Name: "social", Hosts: []string{"example.social"}},
		},
		Rules: []config.ForwardRule{r},
	})
}

func TestEachFieldOfARuleNarrowsWhatItSelects(t *testing.T) {
	at := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	base := egressSubject{client: addr(t, "192.0.2.9"), user: "alice", host: "proxy.golang.org",
		ips: []netip.Addr{addr(t, "203.0.113.7")}, port: 443, phase: phaseRequest,
		method: "GET", path: "/dl/go.tgz", reqType: "application/json", at: at}

	for _, c := range []struct {
		name string
		rule config.ForwardRule
		// hits is the subject the rule must select, misses the one it
		// must not. Both start from base and are changed in place.
		hits, misses func(*egressSubject)
	}{
		{
			name:   "users",
			rule:   config.ForwardRule{Name: "r", Action: "deny", Users: []string{"alice"}},
			misses: func(s *egressSubject) { s.user = "bob" },
		},
		{
			name:   "not_users",
			rule:   config.ForwardRule{Name: "r", Action: "deny", NotUsers: []string{"bob"}},
			misses: func(s *egressSubject) { s.user = "bob" },
		},
		{
			name:   "not_groups",
			rule:   config.ForwardRule{Name: "r", Action: "deny", NotGroups: []string{"agents"}},
			misses: func(s *egressSubject) { s.user = "build1" },
		},
		{
			name:   "not_categories",
			rule:   config.ForwardRule{Name: "r", Action: "deny", NotCategories: []string{"social"}},
			misses: func(s *egressSubject) { s.host = "example.social" },
		},
		{
			name:   "not_hosts",
			rule:   config.ForwardRule{Name: "r", Action: "deny", NotHosts: []string{"example.test"}},
			misses: func(s *egressSubject) { s.host = "example.test" },
		},
		{
			name:   "ports",
			rule:   config.ForwardRule{Name: "r", Action: "deny", Ports: []int{443}},
			misses: func(s *egressSubject) { s.port = 8443 },
		},
		{
			name:   "paths",
			rule:   config.ForwardRule{Name: "r", Action: "deny", Paths: []string{"/dl/*"}},
			misses: func(s *egressSubject) { s.path = "/upload" },
		},
		{
			name:   "request_types",
			rule:   config.ForwardRule{Name: "r", Action: "deny", RequestTypes: []string{"application/json"}},
			misses: func(s *egressSubject) { s.reqType = "text/plain" },
		},
		{
			name: "response_bytes_over",
			rule: config.ForwardRule{Name: "r", Action: "deny", ResponseBytesOver: 1000},
			hits: func(s *egressSubject) {
				s.phase, s.respBytes = phaseResponse, 2000
			},
			misses: func(s *egressSubject) {
				s.phase, s.respBytes = phaseResponse, 10
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := oneRule(t, c.rule)
			hit := base
			if c.hits != nil {
				c.hits(&hit)
			}
			// What nobody wrote a rule for is refused anyway, so the
			// two cases are told apart by which rule decided rather
			// than by whether the answer was no.
			if d := p.Decide(hit); d.Rule != "r" || d.Reason != "rule_deny" {
				t.Errorf("the subject the rule names was decided by %q (%s)", d.Rule, d.Reason)
			}
			miss := base
			if c.misses != nil {
				c.misses(&miss)
			}
			if d := p.Decide(miss); d.Rule == "r" {
				t.Errorf("the rule selected a subject it does not name")
			}
		})
	}
}

// A rule with no action is a deny: an operator who wrote a rule and
// left the verb out wrote something they meant to be refused, and
// defaulting the other way would turn a mistake into a grant.
func TestARuleWithNoActionRefuses(t *testing.T) {
	p := oneRule(t, config.ForwardRule{Name: "r", Hosts: []string{"proxy.golang.org"}})
	d := p.Decide(egressSubject{client: addr(t, "192.0.2.9"), host: "proxy.golang.org",
		port: 443, phase: phaseSession, at: time.Now()})
	if d.Allowed || d.Rule != "r" {
		t.Errorf("a rule with no action decided %v by %q", d.Allowed, d.Rule)
	}
}

// A rule that cannot be compiled is refused at load, because a rule
// that is not compiled is a policy that is not applied.
func TestARuleThatCannotBeCompiledIsRefusedAtLoad(t *testing.T) {
	for _, c := range []struct {
		name string
		fc   config.ForwardListener
		want string
	}{
		{
			name: "a category with no destination in it",
			fc:   config.ForwardListener{Categories: []config.ForwardCategory{{Name: "c", Hosts: []string{""}}}},
			want: "category c",
		},
		{
			name: "a host with no destination in it",
			fc: config.ForwardListener{Rules: []config.ForwardRule{
				{Name: "r", Action: "deny", Hosts: []string{""}}}},
			want: "hosts",
		},
		{
			name: "a not_hosts with no destination in it",
			fc: config.ForwardListener{Rules: []config.ForwardRule{
				{Name: "r", Action: "deny", NotHosts: []string{""}}}},
			want: "not_hosts",
		},
		{
			name: "a schedule that is not one",
			fc: config.ForwardListener{Rules: []config.ForwardRule{
				{Name: "r", Action: "deny", Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}},
			want: "schedule",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			fc := c.fc
			_, err := compileEgress(&fc)
			if err == nil {
				t.Fatalf("the policy compiled with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, which does not name %q", err, c.want)
			}
		})
	}
}
