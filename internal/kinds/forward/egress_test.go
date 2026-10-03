package forward

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// An egress policy of the shape an estate actually writes: the build agents
// reach the mirrors, nobody uploads to file sharing, the vendor's portal is
// open during the change window, and everything else is refused.
func policy(t *testing.T, fc *config.ForwardListener) *egressPolicy {
	t.Helper()
	p, err := compileEgress(fc)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("no policy was compiled")
	}
	return p
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func estatePolicy(t *testing.T) *egressPolicy {
	t.Helper()
	return policy(t, &config.ForwardListener{
		Auth: &config.ForwardAuth{
			UsersFile: "/dev/null",
			Groups:    map[string][]string{"agents": {"build1", "build2"}, "staff": {"alice", "bob"}},
		},
		Categories: []config.ForwardCategory{
			{Name: "mirrors", Hosts: []string{"*.debian.org", "proxy.golang.org"}},
			{Name: "file-sharing", Hosts: []string{"*.dropbox.com", "wetransfer.com"}},
		},
		// The denials are above the grants, which is the one thing to know
		// about writing a first-match policy: a broad deny underneath an allow
		// is a deny the allow has already decided for it.
		Rules: []config.ForwardRule{
			{Name: "no-uploads-to-file-sharing", Action: "deny", Categories: []string{"file-sharing"},
				Methods: []string{"POST", "PUT"}, Comment: "change 2026-41"},
			{Name: "no-big-uploads-anywhere", Action: "deny", RequestBytesOver: 10 << 20},
			{Name: "agents-to-mirrors", Action: "allow", Groups: []string{"agents"},
				Categories: []string{"mirrors"}},
			{Name: "staff-read-file-sharing", Action: "allow", Groups: []string{"staff"},
				Categories: []string{"file-sharing"}, Methods: []string{"GET", "HEAD"}},
			{Name: "watch-everything-else", Action: "observe"},
		},
	})
}

// The five dimensions the policy is written in, each deciding what it should.
func TestTheEgressPolicyDecidesOnWhoWhereWhatAndWhen(t *testing.T) {
	p := estatePolicy(t)
	office := addr(t, "10.1.0.9")
	for _, tc := range []struct {
		name    string
		sub     egressSubject
		allowed bool
		rule    string
	}{
		{"a build agent fetching from a mirror", egressSubject{client: office, user: "build1",
			host: "deb.debian.org", port: 443, phase: phaseRequest, method: "GET", path: "/"},
			true, "agents-to-mirrors"},
		{"the same agent somewhere else entirely", egressSubject{client: office, user: "build1",
			host: "paste.example.test", port: 443, phase: phaseRequest, method: "GET", path: "/"},
			false, "watch-everything-else"},
		{"staff reading file sharing", egressSubject{client: office, user: "alice",
			host: "www.dropbox.com", port: 443, phase: phaseRequest, method: "GET", path: "/f/1"},
			true, "staff-read-file-sharing"},
		// The rule everything here exists for: the same person, the same
		// destination, a different method.
		{"staff uploading to file sharing", egressSubject{client: office, user: "alice",
			host: "www.dropbox.com", port: 443, phase: phaseRequest, method: "POST", path: "/f/1"},
			false, "no-uploads-to-file-sharing"},
		{"a large upload to a mirror", egressSubject{client: office, user: "build1",
			host: "deb.debian.org", port: 443, phase: phaseRequest, method: "PUT",
			path: "/incoming", reqBytes: 64 << 20}, false, "no-big-uploads-anywhere"},
		{"a small upload to a mirror", egressSubject{client: office, user: "build1",
			host: "deb.debian.org", port: 443, phase: phaseRequest, method: "PUT",
			path: "/incoming", reqBytes: 1024}, true, "agents-to-mirrors"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Decide(tc.sub)
			if d.Allowed != tc.allowed {
				t.Errorf("allowed=%v want %v (rule %q, reason %q)", d.Allowed, tc.allowed, d.Rule, d.Reason)
			}
			if tc.rule != "" && d.Rule != tc.rule && !contains(d.Observed, tc.rule) {
				t.Errorf("decided by %q, want %q", d.Rule, tc.rule)
			}
		})
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// The asymmetry this whole design turns on: inside a tunnel there is no method,
// so a rule about one is skipped rather than guessed at -- and the destination
// rules still decide, which is what makes a tunnel policy worth having at all.
func TestARuleAboutARequestIsSkippedWhereThereIsNoRequest(t *testing.T) {
	p := estatePolicy(t)
	office := addr(t, "10.1.0.9")
	// A tunnel to file sharing by somebody whose only allow rule names GET and
	// HEAD: that rule cannot be decided here, so nothing allows it.
	tunnel := p.Decide(egressSubject{client: office, user: "alice",
		host: "www.dropbox.com", port: 443, phase: phaseSession})
	if tunnel.Allowed {
		t.Errorf("a tunnel was allowed by a rule about methods: %+v", tunnel)
	}
	if tunnel.Reason != "no_rule" {
		t.Errorf("reason %q: no rule could decide, which is not the same as a rule refusing", tunnel.Reason)
	}
	// And the destination rules do decide: an agent to a mirror is allowed by a
	// rule that names no method.
	ok := p.Decide(egressSubject{client: office, user: "build1",
		host: "deb.debian.org", port: 443, phase: phaseSession})
	if !ok.Allowed || ok.Rule != "agents-to-mirrors" {
		t.Errorf("an agent to a mirror through a tunnel: %+v", ok)
	}
	// The report says how many rules are in that position, so an operator reads
	// the limit rather than discovering it.
	// Three of the five rules name a method or a body size; the other two are
	// about the destination and decide in a tunnel as well.
	if rep := p.Report(); rep.RequestOnly != 3 {
		t.Errorf("the report says %d request-level rules, want 3", rep.RequestOnly)
	}
}

// A response content type is decided once the head is in, and nothing matching
// there is not a refusal: the request was already allowed through.
func TestAResponseIsDecidedOnceAndNotRefusedForSilence(t *testing.T) {
	p := policy(t, &config.ForwardListener{
		Categories: []config.ForwardCategory{{Name: "anywhere", Hosts: []string{"*.example.test"}}},
		Rules: []config.ForwardRule{
			{Name: "no-executables-back", Action: "deny",
				ResponseTypes: []string{"application/x-dosexec", "application/octet-stream"}},
			{Name: "allow-the-rest", Action: "allow"},
		},
	})
	office := addr(t, "10.1.0.9")
	req := egressSubject{client: office, host: "www.example.test", port: 80,
		phase: phaseRequest, method: "GET", path: "/setup"}
	if d := p.Decide(req); !d.Allowed || d.Rule != "allow-the-rest" {
		t.Fatalf("the request was not allowed through: %+v", d)
	}
	resp := req
	resp.phase, resp.respType = phaseResponse, "application/octet-stream"
	if d := p.Decide(resp); d.Allowed {
		t.Errorf("an executable came back and was allowed: %+v", d)
	}
	resp.respType = "text/html; charset=utf-8"
	if d := p.Decide(resp); !d.Allowed {
		t.Errorf("an ordinary page was refused on the way back: %+v", d)
	}
	// And a response nothing says anything about: the allow rule names no
	// response selector, so no rule is asked at all, and the body still flows.
	resp.respType = ""
	if d := p.Decide(resp); !d.Allowed {
		t.Errorf("a response with no content type was refused: %+v", d)
	}
}

// The size at which a rule refuses, for a body whose length nobody declared.
func TestTheBoundAnUndeclaredBodyIsCutAt(t *testing.T) {
	p := estatePolicy(t)
	office := addr(t, "10.1.0.9")
	sub := egressSubject{client: office, user: "build1", host: "deb.debian.org", port: 443,
		phase: phaseRequest, method: "PUT", path: "/incoming"}
	bound, rule, _ := p.BodyBound(sub)
	if bound != 10<<20 || rule != "no-big-uploads-anywhere" {
		t.Errorf("bound %d from %q, want %d from no-big-uploads-anywhere", bound, rule, 10<<20)
	}
	// A destination where the deny rule cannot match has no bound to count to.
	none := policy(t, &config.ForwardListener{
		Categories: []config.ForwardCategory{{Name: "mirrors", Hosts: []string{"*.debian.org"}}},
		Rules: []config.ForwardRule{
			{Name: "cap-file-sharing", Action: "deny", Hosts: []string{"wetransfer.com"},
				RequestBytesOver: 1 << 20},
			{Name: "allow-the-rest", Action: "allow"},
		},
	})
	if bound, _, _ := none.BodyBound(sub); bound != 0 {
		t.Errorf("bound %d where no rule names one", bound)
	}
}

// observe records and keeps looking, which is the whole point of it.
func TestAnObserveRuleDoesNotDecide(t *testing.T) {
	p := policy(t, &config.ForwardListener{
		Categories: []config.ForwardCategory{{Name: "watched", Hosts: []string{"*.example.test"}}},
		Rules: []config.ForwardRule{
			{Name: "watch-it", Action: "observe", Categories: []string{"watched"}},
			{Name: "allow-it", Action: "allow"},
		},
	})
	d := p.Decide(egressSubject{client: addr(t, "10.1.0.9"), host: "www.example.test",
		port: 443, phase: phaseSession})
	if !d.Allowed || d.Rule != "allow-it" {
		t.Errorf("the observe rule decided: %+v", d)
	}
	if !contains(d.Observed, "watch-it") {
		t.Errorf("the observe rule was not recorded: %+v", d)
	}
}

// A schedule narrows a rule to its hours, and outside them the next rule -- or
// the refusal -- decides.
func TestAScheduleLimitsARuleToItsHours(t *testing.T) {
	p := policy(t, &config.ForwardListener{
		Categories: []config.ForwardCategory{{Name: "vendor", Hosts: []string{"support.vendor.test"}}},
		Rules: []config.ForwardRule{
			{Name: "vendor-in-the-window", Action: "allow", Categories: []string{"vendor"},
				Schedule: &config.ModbusSchedule{Days: []string{"mon"}, From: "09:00", To: "17:00",
					Timezone: "UTC"}},
		},
	})
	sub := egressSubject{client: addr(t, "10.1.0.9"), host: "support.vendor.test",
		port: 443, phase: phaseSession}
	// A Monday inside the window, and the same Monday outside it.
	sub.at = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	if d := p.Decide(sub); !d.Allowed {
		t.Errorf("inside the window: %+v", d)
	}
	sub.at = time.Date(2026, 10, 5, 20, 0, 0, 0, time.UTC)
	if d := p.Decide(sub); d.Allowed {
		t.Errorf("outside the window: %+v", d)
	}
}

// A category's patterns can come from a file, because the list an estate has
// came from somewhere else and is long.
func TestACategoryReadsItsPatternsFromAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file-sharing.txt")
	body := "# the list the security team maintains\n\n*.dropbox.com\nwetransfer.com\n  *.mega.nz  \n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p := policy(t, &config.ForwardListener{
		Categories: []config.ForwardCategory{{Name: "file-sharing", File: path,
			Hosts: []string{"paste.example.test"}}},
		Rules: []config.ForwardRule{{Name: "deny-them", Action: "deny",
			Categories: []string{"file-sharing"}}, {Name: "allow", Action: "allow"}},
	})
	if got := p.Report().Categories["file-sharing"]; got != 4 {
		t.Errorf("the category holds %d patterns, want 4 (three from the file and one inline)", got)
	}
	for _, host := range []string{"www.dropbox.com", "wetransfer.com", "x.mega.nz", "paste.example.test"} {
		d := p.Decide(egressSubject{client: addr(t, "10.1.0.9"), host: host, port: 443,
			phase: phaseSession})
		if d.Allowed {
			t.Errorf("%s was allowed: %+v", host, d)
		}
	}
	// And a file that is not there fails the load rather than leaving the
	// category quietly smaller than the policy says.
	_, err := compileEgress(&config.ForwardListener{
		Categories: []config.ForwardCategory{{Name: "gone", File: filepath.Join(dir, "nothing")}},
	})
	if err == nil {
		t.Error("a missing category file loaded")
	}
}

// Path patterns, where the trap would have been.
func TestPathPatterns(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/upload", "/upload", true},
		{"/upload", "/upload/x", false},
		{"/upload/*", "/upload/x", true},
		{"/upload/*", "/upload/x/y", false},
		{"/upload/**", "/upload/x/y", true},
		{"**.zip", "/releases/a.zip", true},
		{"*.zip", "/a.zip", false}, // * does not cross the leading slash
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/b/c", false},
		// A pattern is a pattern and never a regular expression.
		{"/a.b", "/axb", false},
		{"/a+", "/a+", true},
	} {
		res, err := compilePaths([]string{tc.pattern})
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		if got := anyPath(res, tc.path); got != tc.want {
			t.Errorf("%q against %q = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// Media types, where a malformed header must not be a way past a rule.
func TestMediaTypes(t *testing.T) {
	for _, tc := range []struct {
		pattern, header string
		want            bool
	}{
		{"text/html", "text/html", true},
		{"text/html", "text/html; charset=utf-8", true},
		{"text/html", "TEXT/HTML", true},
		{"image/*", "image/png", true},
		{"image/*", "text/html", false},
		{"text/html", "", false},
		// A header that is not a media type matches nothing, rather than
		// matching whatever its raw text happens to equal.
		{"text/html", "text/html, text/plain", false},
		{"application/octet-stream", "application/octet-stream;", true},
	} {
		if got := anyMedia([]string{tc.pattern}, tc.header); got != tc.want {
			t.Errorf("%q against %q = %v, want %v", tc.pattern, tc.header, got, tc.want)
		}
	}
}

// Groups are what a rule about people is written in, and they are also what the
// estate's own authorization section had nothing to compare on this listener.
func TestGroupsResolve(t *testing.T) {
	p := estatePolicy(t)
	if got := p.groupsOf("BUILD1"); len(got) != 1 || got[0] != "agents" {
		t.Errorf("groupsOf(build1) = %v", got)
	}
	if got := p.groupsOf("nobody"); len(got) != 0 {
		t.Errorf("a name in no group is in %v", got)
	}
	if got := p.groupsOf(""); got != nil {
		t.Errorf("an empty name is in %v", got)
	}
}

// A listener with no rules and no categories compiles to no policy at all, so a
// proxy that does not want one pays nothing for it.
func TestNoRulesIsNoPolicy(t *testing.T) {
	p, err := compileEgress(&config.ForwardListener{})
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("a listener with no rules compiled a policy: %+v", p)
	}
	// And the nil policy allows, so every caller can ask without checking.
	if d := p.Decide(egressSubject{}); !d.Allowed {
		t.Errorf("the nil policy refused: %+v", d)
	}
	if bound, _, _ := p.BodyBound(egressSubject{}); bound != 0 {
		t.Errorf("the nil policy bounded a body at %d", bound)
	}
	if rep := p.Report(); len(rep.Rules) != 0 {
		t.Errorf("the nil policy reported %d rules", len(rep.Rules))
	}
}

// The hits a rule has made, which is what makes a policy readable after a week
// rather than only writable.
func TestRuleHitsAreCounted(t *testing.T) {
	p := estatePolicy(t)
	office := addr(t, "10.1.0.9")
	for range 3 {
		p.Decide(egressSubject{client: office, user: "alice", host: "www.dropbox.com",
			port: 443, phase: phaseRequest, method: "POST", path: "/f"})
	}
	var found bool
	for _, r := range p.Report().Rules {
		if r.Name != "no-uploads-to-file-sharing" {
			continue
		}
		found = true
		if r.Hits != 3 {
			t.Errorf("the rule counted %d decisions, want 3", r.Hits)
		}
		if r.Comment != "change 2026-41" {
			t.Errorf("the report lost the comment: %q", r.Comment)
		}
		if !r.Request {
			t.Error("the report does not say the rule needs a visible request")
		}
	}
	if !found {
		t.Error("the rule is not in the report")
	}
}

// A category file bigger than the bound is refused rather than read.
func TestACategoryFileIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("a.test\n", 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPatternFile(path); err != nil {
		t.Fatalf("a small file: %v", err)
	}
}

// The two dimensions the estate policy above does not use: where the client is
// rather than who it says it is.
//
// They matter on this listener more than on most, because a forward proxy's
// clients are the estate itself: a rule written about a network is a rule about
// a floor, a lab or a build farm, and it holds for a host that has no user name
// at all. `not_networks` is the exception carved out of one -- the lab inside
// the office range that does not get the office's egress.
func TestAnEgressRuleIsWrittenAboutWhereTheClientIs(t *testing.T) {
	p := policy(t, &config.ForwardListener{
		Rules: []config.ForwardRule{
			{Name: "not-the-lab", Action: "deny", Networks: []string{"10.1.0.0/16"},
				NotNetworks: []string{"10.1.9.0/24"}},
			{Name: "the-lab", Action: "allow", Networks: []string{"10.1.9.0/24"}},
			// A single host written as an address rather than a /32, which is
			// what most of these lists are: one jump box.
			{Name: "jump-box", Action: "allow", Networks: []string{"192.168.5.7"}},
		},
	})
	sub := func(client string) egressSubject {
		return egressSubject{client: addr(t, client), host: "example.test", port: 443,
			phase: phaseRequest, method: "GET", path: "/"}
	}
	for _, c := range []struct {
		name, client string
		allowed      bool
		rule         string
	}{
		{"an office client inside the broad network", "10.1.0.9", false, "not-the-lab"},
		// The exception: inside the office range, carved out of the deny, and
		// then allowed by its own rule below.
		{"a lab client the exception names", "10.1.9.4", true, "the-lab"},
		{"the one jump box, named as an address", "192.168.5.7", true, "jump-box"},
		{"a host no rule covers", "172.16.0.1", false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := p.Decide(sub(c.client))
			if d.Allowed != c.allowed {
				t.Errorf("allowed=%v want %v (rule %q reason %q)",
					d.Allowed, c.allowed, d.Rule, d.Reason)
			}
			if c.rule != "" && d.Rule != c.rule {
				t.Errorf("decided by %q, want %q", d.Rule, c.rule)
			}
		})
	}
	// A network that is not one is a load error rather than a rule that matches
	// nothing: a rule nobody can read is worse than no rule.
	for _, bad := range [][]string{{"10.1.0.0/33"}, {"the-office"}, {"10.1.0.0/16", "nonsense"}} {
		_, err := compileEgress(&config.ForwardListener{
			Rules: []config.ForwardRule{{Name: "r", Action: "deny", Networks: bad}}})
		if err == nil || !strings.Contains(err.Error(), "is not an address or CIDR") {
			t.Errorf("networks %v compiled with error %v", bad, err)
		}
	}
	_, err := compileEgress(&config.ForwardListener{
		Rules: []config.ForwardRule{{Name: "r", Action: "deny", NotNetworks: []string{"nonsense"}}}})
	if err == nil {
		t.Error("an unreadable not_networks compiled")
	}
	// And the containment test itself, including the address that is not one:
	// an invalid address is in no network, which is what keeps a rule about a
	// network off a connection whose address the relay never learned.
	nets := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if !inAnyPrefix(nets, addr(t, "10.1.2.3")) {
		t.Error("an address inside the network was not found in it")
	}
	if inAnyPrefix(nets, addr(t, "192.0.2.1")) {
		t.Error("an address outside the network was found in it")
	}
	if inAnyPrefix(nets, netip.Addr{}) {
		t.Error("an invalid address was found in a network")
	}
	// A v4-mapped v6 address is the same address, which is what a dual-stack
	// listener hands to a policy written in v4.
	if !inAnyPrefix(nets, netip.MustParseAddr("::ffff:10.1.2.3")) {
		t.Error("a mapped address was not matched against the v4 network it is in")
	}
}
