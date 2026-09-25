package snmp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/snmp"
)

func policyFor(t *testing.T, l *config.SNMPListener) *Policy {
	t.Helper()
	p, err := compile(l, func() time.Time {
		// A Wednesday at 14:00 UTC, so a schedule in a test is about the
		// window and not about when the test happens to run.
		return time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func decide(t *testing.T, p *Policy, from string, raw []byte) Decision {
	t.Helper()
	return p.Decide(request{client: netip.MustParseAddr(from), msg: parse(raw)})
}

// The version is the first thing decided, because "v3 only" is the single
// most useful line an operator can write about this protocol.
func TestTheVersionListDecidesBeforeAnythingElse(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{Versions: []string{"v3"}, DefaultAction: "allow"})
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1))); d.Allow {
		t.Error("a v2c message passed a v3-only listener")
	} else if d.Reason != "snmp_version" || d.Detail != "v2c" {
		t.Errorf("reason %q detail %q", d.Reason, d.Detail)
	}
	if d := decide(t, p, "10.0.0.1", v3(0x05, "monitor", "", get(1, 1, 3, 6, 1, 2, 1))); !d.Allow {
		t.Errorf("a v3 message was refused: %+v", d)
	}
}

// The credential, read from the place each version puts it, and never
// crossing over: a rule about community strings must not decide about a v3
// message and a rule about users must not decide about a v2c one.
func TestTheCredentialIsReadPerVersionAndDoesNotCrossOver(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Communities: []string{"nms-only"}, Users: []string{"monitor"}, DefaultAction: "allow"})
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("an unlisted community was allowed")
	} else if d.Reason != "snmp_community" {
		t.Errorf("reason %q", d.Reason)
	} else if d.Detail != "" {
		// The community string is a credential. A security log that
		// printed every guessed one would be a list of passwords to try.
		t.Errorf("the refusal printed the community string: %q", d.Detail)
	}
	if d := decide(t, p, "10.0.0.1", v2c("nms-only", get(1, 1, 3, 6, 1))); !d.Allow {
		t.Errorf("the listed community was refused: %+v", d)
	}
	if d := decide(t, p, "10.0.0.1", v3(0x05, "intruder", "", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("an unlisted user was allowed")
	} else if d.Reason != "snmp_user" {
		t.Errorf("reason %q", d.Reason)
	}
	// A user name that happens to equal a listed community string is still
	// not a listed user, and the reverse.
	p = policyFor(t, &config.SNMPListener{Communities: []string{"monitor"}, DefaultAction: "allow"})
	if d := decide(t, p, "10.0.0.1", v3(0x05, "monitor", "", get(1, 1, 3, 6, 1))); !d.Allow {
		t.Errorf("a v3 message was decided by the community list: %+v", d)
	}
	rules := []config.SNMPRule{{Name: "by-community", Action: "allow", Communities: []string{"monitor"}}}
	p = policyFor(t, &config.SNMPListener{Rules: rules})
	if d := decide(t, p, "10.0.0.1", v3(0x05, "monitor", "", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("a rule about community strings matched a v3 message")
	}
	rules = []config.SNMPRule{{Name: "by-user", Action: "allow", Users: []string{"monitor"}}}
	p = policyFor(t, &config.SNMPListener{Rules: rules})
	if d := decide(t, p, "10.0.0.1", v2c("monitor", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("a rule about users matched a v2c message")
	}
}

// noAuthNoPriv is version 2c with more fields, so a listener that went to
// the trouble of requiring v3 can require more than the version number.
func TestTheSecurityLevelIsAFloorNotADecoration(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Versions: []string{"v3"}, MinSecurityLevel: "authNoPriv", DefaultAction: "allow"})
	if d := decide(t, p, "10.0.0.1", v3(0x04, "monitor", "", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("a noAuthNoPriv message passed an authNoPriv floor")
	} else if d.Reason != "snmp_security_level" || d.Detail != "noAuthNoPriv" {
		t.Errorf("reason %q detail %q", d.Reason, d.Detail)
	}
	if d := decide(t, p, "10.0.0.1", v3(0x05, "monitor", "", get(1, 1, 3, 6, 1))); !d.Allow {
		t.Errorf("an authNoPriv message was refused: %+v", d)
	}
	// authPriv is above the floor, and its payload cannot be read: the
	// decision says so rather than pretending it inspected one.
	d := decide(t, p, "10.0.0.1", v3(0x07, "monitor", "", get(1, 1, 3, 6, 1)))
	if !d.Allow || d.Reason != "snmp_encrypted" {
		t.Errorf("an encrypted authPriv message: %+v", d)
	}
	// And the privacy bit without the authentication bit is not a level the
	// standard defines, so it does not buy its way past the floor.
	if d := decide(t, p, "10.0.0.1", v3(0x02, "monitor", "", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("privacy without authentication passed an authNoPriv floor")
	}
}

// read_only is one line covering the whole of "nobody reconfigures anything
// through this relay", and a rule cannot open a hole in it.
func TestReadOnlyCannotBeOverriddenByARule(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		ReadOnly: true, DefaultAction: "allow",
		Rules: []config.SNMPRule{{Name: "let-them-write", Action: "allow", Access: []string{"write"}}}})
	d := decide(t, p, "10.0.0.1", v2c("private", set(9, "newname", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	if d.Allow {
		t.Error("a rule wrote through a read-only listener")
	}
	if d.Reason != "snmp_read_only" || d.Detail != "1.3.6.1.2.1.1.5.0" {
		t.Errorf("reason %q detail %q", d.Reason, d.Detail)
	}
	// Reads are untouched by it.
	if d := decide(t, p, "10.0.0.1", v2c("public", get(9, 1, 3, 6, 1, 2, 1, 1, 5, 0))); !d.Allow {
		t.Errorf("a read was refused by read_only: %+v", d)
	}
}

// A trap arriving at an agent front, or a request at a trap port, is a
// datagram sent to the wrong place at best.
func TestTheDirectionOfTheMessageHasToMatchTheListener(t *testing.T) {
	front := policyFor(t, &config.SNMPListener{DefaultAction: "allow"})
	if d := decide(t, front, "10.0.0.1", v2c("public", trap(1, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3))); d.Allow {
		t.Error("a trap was relayed through an agent front")
	} else if d.Reason != "snmp_direction" {
		t.Errorf("reason %q", d.Reason)
	}
	traps := policyFor(t, &config.SNMPListener{Traps: true, DefaultAction: "allow"})
	if d := decide(t, traps, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1))); d.Allow {
		t.Error("a GetRequest was relayed through a trap listener")
	}
	if d := decide(t, traps, "10.0.0.1", v2c("public", trap(1, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3))); !d.Allow {
		t.Errorf("a trap was refused by a trap listener: %+v", d)
	}
}

// The subtree test is per sub-identifier, which is the whole reason an OID
// is kept as numbers: the string "1.3.6.1.2.1" is a prefix of the string
// "1.3.6.1.2.11", and the object is not under the subtree.
func TestASubtreeIsComparedPerSubIdentifierNotPerCharacter(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "mib-2", Action: "allow", OIDs: []string{"1.3.6.1.2.1"}}}})
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0))); !d.Allow {
		t.Errorf("an object under the subtree was refused: %+v", d)
	}
	d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 11, 1)))
	if d.Allow {
		t.Error("1.3.6.1.2.11 was allowed by a rule naming 1.3.6.1.2.1")
	}
	if d.Detail != "1.3.6.1.2.11.1" {
		t.Errorf("the refusal did not name the object: %q", d.Detail)
	}
}

// An exception inside an allowed subtree: all of mib-2 except the ARP
// table. The rule stops covering the message, so the search carries on --
// it does not allow it.
func TestADenyListInsideAnAllowedSubtreeIsAnException(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{
			{Name: "mib-2", Action: "allow", OIDs: []string{"1.3.6.1.2.1"},
				DenyOIDs: []string{"1.3.6.1.2.1.4.22"}},
		}})
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1))); !d.Allow {
		t.Errorf("the interface table was refused: %+v", d)
	}
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1, 4, 22, 1, 2))); d.Allow {
		t.Error("the ARP table was allowed by the rule that excluded it")
	}
}

// One rule, a wide read and a narrow write: the write list replaces the
// read list rather than adding to it.
func TestAWriteListReplacesTheReadListForASetRequest(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "ops", Action: "allow",
			OIDs: []string{"1.3.6.1.2.1"}, WriteOIDs: []string{"1.3.6.1.2.1.1.5"}}}})
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1, 2, 2))); !d.Allow {
		t.Errorf("a wide read was refused: %+v", d)
	}
	if d := decide(t, p, "10.0.0.1", v2c("private", set(1, "x", 1, 3, 6, 1, 2, 1, 1, 5, 0))); !d.Allow {
		t.Errorf("the permitted write was refused: %+v", d)
	}
	if d := decide(t, p, "10.0.0.1", v2c("private", set(1, "x", 1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 1))); d.Allow {
		t.Error("a write outside write_oids was allowed by the read list")
	}
}

// A rule that carries a repetition bound does not match traffic past its
// own bound, so the next rule -- or the default -- decides. Matching and
// then allowing would make the bound a suggestion.
func TestARuleWithARepetitionBoundDoesNotCoverTrafficPastIt(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "walks", Action: "allow",
			PDUs: []string{"get_bulk"}, MaxRepetitions: 50}}})
	if d := decide(t, p, "10.0.0.1", v2c("public", bulk(1, 50, 1, 3, 6, 1, 2, 1))); !d.Allow || d.Rule != "walks" {
		t.Errorf("a walk at the bound: %+v", d)
	}
	if d := decide(t, p, "10.0.0.1", v2c("public", bulk(1, 51, 1, 3, 6, 1, 2, 1))); d.Allow {
		t.Error("a walk past the rule's bound was allowed by that rule")
	}
	// And the rule's number is what the relay lowers to for its traffic.
	req := request{msg: parse(v2c("public", bulk(1, 50, 1, 3, 6, 1, 2, 1)))}
	if got := p.MaxRepetitions(req, "walks"); got != 50 {
		t.Errorf("the rule's bound is %d", got)
	}
	if got := p.MaxRepetitions(req, ""); got != 100 {
		t.Errorf("the listener's default bound is %d", got)
	}
}

// observe logs and counts and then keeps looking, which is how a rule is
// tried on live traffic before it decides anything.
func TestAnObserveRuleDoesNotDecide(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{
			{Name: "watch-writes", Action: "observe", Access: []string{"write"}},
			{Name: "allow-all", Action: "allow"},
		}})
	d := decide(t, p, "10.0.0.1", v2c("private", set(1, "x", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	if !d.Allow || d.Rule != "allow-all" {
		t.Errorf("the observe rule decided: %+v", d)
	}
}

// A schedule limits a rule to a window, and a window whose end is before
// its start spans midnight, which is how a night shift is written.
func TestAScheduleLimitsARuleToItsWindow(t *testing.T) {
	day := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "office", Action: "allow",
			Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "09:00", To: "17:00"}}}})
	if d := decide(t, day, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1))); !d.Allow {
		t.Errorf("a Wednesday afternoon was outside a Wednesday window: %+v", d)
	}
	night := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "night", Action: "allow",
			Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}}}})
	if d := decide(t, night, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("14:00 fell inside a 22:00-to-06:00 window")
	}
	other := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "monday", Action: "allow",
			Schedule: &config.ModbusSchedule{Days: []string{"mon"}}}}})
	if d := decide(t, other, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("a Wednesday matched a Monday rule")
	}
}

// The bindings bound, the client list, and the default.
func TestTheBoundsAndTheDefaults(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{MaxVarBinds: 1, DefaultAction: "allow"})
	many := pduOf(wire.TagGetRequest, 1, 0, 0,
		varbind(oid(1, 3, 6, 1, 1), tlv(wire.TagNull)),
		varbind(oid(1, 3, 6, 1, 2), tlv(wire.TagNull)))
	if d := decide(t, p, "10.0.0.1", v2c("public", many)); d.Allow {
		t.Error("two bindings passed a bound of one")
	} else if d.Reason != "snmp_var_binds" {
		t.Errorf("reason %q", d.Reason)
	}

	p = policyFor(t, &config.SNMPListener{})
	d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1, 2, 1)))
	if d.Allow || d.Reason != "snmp_default_deny" || d.Detail != "1.3.6.1.2.1" {
		t.Errorf("the default: %+v", d)
	}

	p = policyFor(t, &config.SNMPListener{
		AllowClients: []string{"10.0.0.0/8"}, DenyClients: []string{"10.1.0.0/16"}})
	for from, want := range map[string]bool{"10.0.0.5": true, "10.1.2.3": false, "192.0.2.1": false} {
		if got := p.Client(netip.MustParseAddr(from)); got != want {
			t.Errorf("client %s: %v", from, got)
		}
	}
}

// A context name is what separates the agents behind one engine, so a rule
// can be written about one of them.
func TestARuleCanNameTheContext(t *testing.T) {
	p := policyFor(t, &config.SNMPListener{
		Rules: []config.SNMPRule{{Name: "bridge", Action: "allow", Contexts: []string{"bridge1"}}}})
	if d := decide(t, p, "10.0.0.1", v3(0x05, "monitor", "bridge1", get(1, 1, 3, 6, 1))); !d.Allow {
		t.Errorf("the named context was refused: %+v", d)
	}
	if d := decide(t, p, "10.0.0.1", v3(0x05, "monitor", "bridge2", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("another context matched a rule naming bridge1")
	}
	// A v2c message has no context at all, so a rule naming one cannot
	// cover it.
	if d := decide(t, p, "10.0.0.1", v2c("public", get(1, 1, 3, 6, 1))); d.Allow {
		t.Error("a v2c message matched a rule naming a context")
	}
}

// Everything that can be wrong about a rule is wrong at load, not at the
// first message that matches it.
func TestEveryBadRuleIsRefusedAtLoad(t *testing.T) {
	for what, l := range map[string]*config.SNMPListener{
		"a version that is not one":  {Versions: []string{"v4"}},
		"a level that is not one":    {MinSecurityLevel: "paranoid"},
		"a client that is not a net": {AllowClients: []string{"10.0.0.1"}},
		"a deny that is not a net":   {DenyClients: []string{"nonsense"}},
		"a rule version":             {Rules: []config.SNMPRule{{Name: "r", Versions: []string{"v9"}}}},
		"a rule level":               {Rules: []config.SNMPRule{{Name: "r", MinSecurityLevel: "x"}}},
		"a rule client":              {Rules: []config.SNMPRule{{Name: "r", Clients: []string{"x"}}}},
		"an operation":               {Rules: []config.SNMPRule{{Name: "r", PDUs: []string{"get_everything"}}}},
		"an access class":            {Rules: []config.SNMPRule{{Name: "r", Access: []string{"execute"}}}},
		"an oid":                     {Rules: []config.SNMPRule{{Name: "r", OIDs: []string{"1.3.6.x"}}}},
		"a deny oid":                 {Rules: []config.SNMPRule{{Name: "r", DenyOIDs: []string{"..."}}}},
		"a write oid":                {Rules: []config.SNMPRule{{Name: "r", WriteOIDs: []string{"1..2"}}}},
		"a schedule day": {Rules: []config.SNMPRule{{Name: "r",
			Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}}},
		"a schedule time": {Rules: []config.SNMPRule{{Name: "r",
			Schedule: &config.ModbusSchedule{From: "25:00"}}}},
		"a schedule zone": {Rules: []config.SNMPRule{{Name: "r",
			Schedule: &config.ModbusSchedule{Timezone: "Mars/Olympus"}}}},
	} {
		if _, err := compile(l, time.Now); err == nil {
			t.Errorf("%s compiled", what)
		}
	}
}

// accessOf names what an operation does, in the words a rule is written in,
// so a policy about writing does not have to list the operations that write.
func TestAnOperationIsNamedByWhatItDoes(t *testing.T) {
	for _, c := range []struct {
		t    wire.PDUType
		want string
	}{
		{wire.GetRequest, "read"},
		{wire.GetNextRequest, "read"},
		{wire.GetBulkRequest, "read"},
		{wire.SetRequest, "write"},
		{wire.TrapV1, "notify"},
		{wire.TrapV2, "notify"},
		{wire.InformRequest, "notify"},
		{wire.Response, ""},
	} {
		if got := accessOf(c.t); got != c.want {
			t.Errorf("%s does %q, wanted %q", c.t, got, c.want)
		}
	}
}
