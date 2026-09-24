package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const feedZone = `$TTL 300
$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
@ NS ns.rpz.local.
evil.example.rpz.local.        CNAME .
*.evil.example.rpz.local.      CNAME .
empty.example.rpz.local.       CNAME *.
good.evil.example.rpz.local.   CNAME rpz-passthru.
quiet.example.rpz.local.       CNAME rpz-drop.
slow.example.rpz.local.        CNAME rpz-tcp-only.
walled.example.rpz.local.      A     10.0.0.1
walled6.example.rpz.local.     AAAA  2001:db8::1
moved.example.rpz.local.       CNAME landing.estate.example.
`

func writeZone(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.rpz")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func zoneSet(t *testing.T, body string, spec ...RPZSpec) (*RPZ, string) {
	t.Helper()
	path := writeZone(t, body)
	s := RPZSpec{Name: "feed", File: path}
	if len(spec) > 0 {
		s = spec[0]
		s.File = path
		if s.Name == "" {
			s.Name = "feed"
		}
	}
	set, err := NewRPZ([]RPZSpec{s})
	if err != nil {
		t.Fatalf("zone: %v", err)
	}
	t.Cleanup(set.Stop)
	return set, path
}

// The file a feed ships, read as the policy it is: each record form
// becomes the action it stands for, and the zone's own name comes off
// the front of every rule.
func TestEachRecordFormIsTheActionItStandsFor(t *testing.T) {
	set, _ := zoneSet(t, feedZone)
	for _, tc := range []struct{ name, action, rule string }{
		{"evil.example", RPZNXDomain, "evil.example"},
		{"under.evil.example", RPZNXDomain, "*.evil.example"},
		{"deeper.under.evil.example", RPZNXDomain, "*.evil.example"},
		{"deeper.good.evil.example", RPZNXDomain, "*.evil.example"},
		{"empty.example", RPZNoData, "empty.example"},
		{"good.evil.example", RPZPassthru, "good.evil.example"},
		{"quiet.example", RPZDrop, "quiet.example"},
		{"slow.example", RPZTCPOnly, "slow.example"},
		{"walled.example", RPZLocalData, "walled.example"},
		{"moved.example", RPZLocalData, "moved.example"},
	} {
		hit, ok := set.Match(tc.name)
		if !ok {
			t.Errorf("%s: no rule matched", tc.name)
			continue
		}
		if hit.Action != tc.action {
			t.Errorf("%s: action %q, want %q", tc.name, hit.Action, tc.action)
		}
		if tc.rule != "" && hit.Rule != tc.rule {
			t.Errorf("%s: rule %q, want %q", tc.name, hit.Rule, tc.rule)
		}
		if hit.Zone != "feed" {
			t.Errorf("%s: zone %q", tc.name, hit.Zone)
		}
	}
	// A name no rule covers is not the zone's business.
	if hit, ok := set.Match("ordinary.example"); ok {
		t.Errorf("a name with no rule matched %+v", hit)
	}
	// The local data is the record the answer is built from.
	hit, _ := set.Match("walled.example")
	if len(hit.Records) != 1 || hit.Records[0].Type != TypeA || hit.Records[0].Addr.String() != "10.0.0.1" {
		t.Errorf("local data %+v", hit.Records)
	}
	hit, _ = set.Match("moved.example")
	if len(hit.Records) != 1 || hit.Records[0].Type != TypeCNAME || hit.Records[0].Text != "landing.estate.example" {
		t.Errorf("local CNAME %+v", hit.Records)
	}
	if got := set.Matches.Load(); got == 0 {
		t.Error("matches are not counted")
	}
	if got := set.Passthru.Load(); got == 0 {
		t.Error("exceptions are not counted")
	}
}

// An exception is more specific than the wildcard above it, whichever
// order the file lists them in: the point of a passthru rule is that it
// wins.
func TestAnExceptionBeatsTheWildcardAboveIt(t *testing.T) {
	set, _ := zoneSet(t, `$TTL 60
$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
*.bank.example.rpz.local.  CNAME .
www.bank.example.rpz.local. CNAME rpz-passthru.
`)
	if hit, ok := set.Match("www.bank.example"); !ok || hit.Action != RPZPassthru {
		t.Errorf("the exception did not win: %+v (%v)", hit, ok)
	}
	if hit, ok := set.Match("login.bank.example"); !ok || hit.Action != RPZNXDomain {
		t.Errorf("the wildcard did not apply: %+v (%v)", hit, ok)
	}
}

// Zones are tried in order, so a local zone in front of a subscription
// is how an estate overrules a feed.
func TestTheFirstZoneDecides(t *testing.T) {
	local := writeZone(t, `$ORIGIN local.
@ SOA ns.local. hostmaster.local. 1 3600 600 86400 60
partner.example.local.  CNAME rpz-passthru.
`)
	feed := writeZone(t, `$ORIGIN feed.
@ SOA ns.feed. hostmaster.feed. 1 3600 600 86400 60
partner.example.feed.   CNAME .
other.example.feed.     CNAME .
`)
	set, err := NewRPZ([]RPZSpec{{Name: "local", File: local}, {Name: "feed", File: feed}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Stop)
	if hit, ok := set.Match("partner.example"); !ok || hit.Zone != "local" || hit.Action != RPZPassthru {
		t.Errorf("the first zone did not decide: %+v (%v)", hit, ok)
	}
	if hit, ok := set.Match("other.example"); !ok || hit.Zone != "feed" {
		t.Errorf("the second zone did not apply: %+v (%v)", hit, ok)
	}
}

// An override replaces every rule's own action, which is how a new feed
// is tried out before it is trusted.
func TestAnOverrideReplacesTheZonesOwnAction(t *testing.T) {
	set, _ := zoneSet(t, feedZone, RPZSpec{Override: RPZPassthru})
	for _, name := range []string{"evil.example", "walled.example", "quiet.example"} {
		hit, ok := set.Match(name)
		if !ok || hit.Action != RPZPassthru {
			t.Errorf("%s: %+v (%v), want every rule overridden", name, hit, ok)
		}
	}
	if st := set.Status(); len(st) != 1 || st[0].Override != RPZPassthru {
		t.Errorf("the status does not report the override: %+v", st)
	}
}

// A trigger this resolver does not implement fails the load by name,
// because a zone whose rules half apply is a policy the operator
// believes is working.
func TestAnUnsupportedTriggerFailsTheLoad(t *testing.T) {
	body := `$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
8.0.0.0.10.rpz-ip.rpz.local.  CNAME .
evil.example.rpz.local.       CNAME .
`
	path := writeZone(t, body)
	if _, err := NewRPZ([]RPZSpec{{Name: "feed", File: path}}); err == nil || !strings.Contains(err.Error(), "rpz-ip") {
		t.Fatalf("error %v, want one naming the trigger", err)
	}
	// And with the escape hatch it loads, skipping them and saying how
	// many.
	set, err := NewRPZ([]RPZSpec{{Name: "feed", File: path, IgnoreUnsupported: true}})
	if err != nil {
		t.Fatalf("ignore_unsupported: %v", err)
	}
	t.Cleanup(set.Stop)
	st := set.Status()
	if len(st) != 1 || st[0].Ignored != 1 || st[0].Rules != 1 {
		t.Errorf("status %+v, want one rule held and one skipped", st)
	}
	if _, ok := set.Match("evil.example"); !ok {
		t.Error("the rules that are supported were not kept")
	}
}

// What a zone file can get wrong, each named rather than skipped.
func TestABrokenZoneIsRefused(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"", "no rules"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. CNAME\n", "CNAME with no data"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. A 10.0.0.999\n", "A "},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. A ::1\n", "needs an IPv4"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. MX 10 mail.\n", "not a record type"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. CH CNAME .\n", "class CH"},
		{"$WRONG 1\n", "not a directive"},
		{"$TTL notanumber\n@ SOA ns. h. 1 3600 600 86400 60\n", "$TTL"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nev*il.example.rpz.local. CNAME .\n", "wildcard is only the first label"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. CNAME (\n  .\n)\n", "one record per line"},
		{" CNAME .\n", "no owner"},
		{"@ SOA ns. h. 1 3600 600 86400 60\nevil.example.rpz.local. CNAME not a name!\n", "neither a policy name nor a domain name"},
	} {
		path := writeZone(t, tc.body)
		_, err := NewRPZ([]RPZSpec{{Name: "feed", File: path}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q\nerror %v, want one about %q", tc.body, err, tc.want)
		}
	}
	// A file that is not there is an error too: a zone that silently
	// matches nothing is worse than none.
	if _, err := NewRPZ([]RPZSpec{{Name: "feed", File: filepath.Join(t.TempDir(), "absent")}}); err == nil {
		t.Error("a missing zone file loaded")
	}
	if _, err := NewRPZ(nil); err == nil {
		t.Error("a set with no zones was built")
	}
	// Two zones cannot share a name: the status and the logs identify a
	// zone by it.
	path := writeZone(t, feedZone)
	if _, err := NewRPZ([]RPZSpec{{Name: "feed", File: path}, {Name: "feed", File: path}}); err == nil {
		t.Error("duplicate zone names loaded")
	}
	if _, err := NewRPZ([]RPZSpec{{File: path}}); err == nil {
		t.Error("a zone with no name loaded")
	}
}

// A comment is a comment, and a semicolon inside a quoted string is not.
func TestCommentsAreStrippedAndQuotedTextIsNot(t *testing.T) {
	set, _ := zoneSet(t, `$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
; a whole line of comment
evil.example.rpz.local. CNAME .   ; and a trailing one
noted.example.rpz.local. TXT "blocked; by the feed"
`)
	if _, ok := set.Match("evil.example"); !ok {
		t.Error("a rule with a trailing comment was not read")
	}
	hit, ok := set.Match("noted.example")
	if !ok || len(hit.Records) != 1 || hit.Records[0].Text != "blocked; by the feed" {
		t.Errorf("quoted text: %+v (%v)", hit, ok)
	}
}

// A zone file that is rewritten is re-read, and one that breaks keeps
// the rules already in force.
func TestAChangedZoneIsReReadAndABrokenOneKeepsTheOldRules(t *testing.T) {
	set, path := zoneSet(t, `$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
first.example.rpz.local. CNAME .
`)
	if _, ok := set.Match("first.example"); !ok {
		t.Fatal("the first rule was not read")
	}
	// An unchanged file is not read again.
	if err := set.Reload(); err != nil {
		t.Fatal(err)
	}
	if set.Reloads.Load() != 0 {
		t.Errorf("an unchanged file was re-read: %d", set.Reloads.Load())
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		// The stamp is size and modification time, so a rewrite of the
		// same size in the same second has to move the time.
		future := time.Now().Add(2 * time.Second)
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatal(err)
		}
	}
	write(`$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 2 3600 600 86400 60
second.example.rpz.local. CNAME .
`)
	if err := set.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Match("second.example"); !ok {
		t.Error("the rewritten file was not read")
	}
	if _, ok := set.Match("first.example"); ok {
		t.Error("the old rules are still in force after a re-read")
	}
	if set.Reloads.Load() != 1 {
		t.Errorf("reloads counted: %d", set.Reloads.Load())
	}
	// A file being replaced in place, caught halfway: the rules already
	// loaded stay, and the error says so.
	write("this is not a zone file\n")
	if err := set.Reload(); err == nil {
		t.Error("a broken file reloaded without an error")
	}
	if _, ok := set.Match("second.example"); !ok {
		t.Error("a broken re-read emptied the policy")
	}
	if set.Errors.Load() == 0 {
		t.Error("the failure is not counted")
	}
	// And a file that went away is reported rather than silently
	// emptying the zone.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := set.Errors.Load()
	if err := set.Reload(); err == nil {
		t.Error("a missing file reloaded without an error")
	}
	if _, ok := set.Match("second.example"); !ok {
		t.Error("a missing file emptied the policy")
	}
	if set.Errors.Load() == before {
		t.Error("a file that went away was not counted as a failure")
	}
}

// The refresh loop reads a changed file on its own, and says whether it
// is running.
func TestTheRefreshLoopReadsAChangedZone(t *testing.T) {
	set, path := zoneSet(t, `$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
first.example.rpz.local. CNAME .
`)
	if set.Refreshing() {
		t.Error("a set with no interval is refreshing")
	}
	// No interval means no loop, rather than a ticker of zero.
	set.Refresh(0, nil)
	if set.Refreshing() {
		t.Error("an interval of zero started a loop")
	}
	set.Refresh(10*time.Millisecond, nil)
	if !set.Refreshing() {
		t.Error("the loop did not start")
	}
	body := `$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 2 3600 600 86400 60
second.example.rpz.local. CNAME .
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := set.Match("second.example"); ok {
			set.Stop()
			if set.Refreshing() {
				t.Error("Stop did not end the loop")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	set.Stop()
	t.Error("the refresh loop did not read the changed file")
}

// The bounds, and what a nil set does: a resolver with no zones must not
// pay for one.
func TestTheBoundsAndTheNilSet(t *testing.T) {
	var none *RPZ
	if _, ok := none.Match("anything.example"); ok {
		t.Error("a nil set matched")
	}
	if none.Zones() != 0 || none.Refreshing() || none.Status() != nil {
		t.Error("a nil set reports something")
	}
	none.Stop()
	if err := none.Reload(); err != nil {
		t.Errorf("a nil set reload: %v", err)
	}
	long := strings.Repeat("a", MaxRPZLine+1)
	path := writeZone(t, "@ SOA ns. h. 1 3600 600 86400 60\n"+long+".rpz.local. CNAME .\n")
	if _, err := NewRPZ([]RPZSpec{{Name: "feed", File: path}}); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Errorf("an overlong line: %v", err)
	}
}

// A relative owner takes the $ORIGIN in force, which is not always the
// zone's own name: a master file may move the origin part way down, and
// then the rule is the relative name under that origin with the zone's
// name taken off the end.
func TestARelativeOwnerTakesTheOriginInForce(t *testing.T) {
	set, _ := zoneSet(t, `rpz.local. SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
$ORIGIN sub.rpz.local.
evil  CNAME .
`)
	if hit, ok := set.Match("evil.sub"); !ok || hit.Action != RPZNXDomain {
		t.Errorf("a relative owner under a moved origin: %+v (%v)", hit, ok)
	}
	if _, ok := set.Match("evil"); ok {
		t.Error("the origin was not applied: the rule matched the bare label")
	}
}

// An owner without the zone's own name is read as written: a feed that
// lists bare names, or one whose $ORIGIN is the zone.
func TestTheZoneNameComesOffAndAnOriginIsApplied(t *testing.T) {
	set, _ := zoneSet(t, `$ORIGIN rpz.local.
$TTL 300
@ SOA ns hostmaster 1 3600 600 86400 60
evil.example  CNAME .
`)
	if hit, ok := set.Match("evil.example"); !ok || hit.Action != RPZNXDomain {
		t.Errorf("a relative owner under an origin: %+v (%v)", hit, ok)
	}
	// The apex carries the SOA and the NS records, not a rule: a policy
	// record there would match every name.
	if hit, ok := set.Match("rpz.local"); ok {
		t.Errorf("the apex became a rule: %+v", hit)
	}
}
