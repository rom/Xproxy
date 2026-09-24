package modbus

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
)

func ptr[T any](v T) *T { return &v }

// req builds a parsed request the way the session does, so a policy test
// decides about the same thing the relay decides about.
func req(t *testing.T, client string, role string, unit byte, pdu []byte) request {
	t.Helper()
	p, err := wire.ParseRequest(pdu)
	if err != nil {
		t.Fatalf("pdu %x: %v", pdu, err)
	}
	return request{client: netip.MustParseAddr(client), role: role, unit: unit, pdu: p}
}

func policy(t *testing.T, l *config.ModbusListener, now time.Time) *Policy {
	t.Helper()
	p, err := compile(l, func() time.Time { return now })
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

var (
	readRegs   = []byte{3, 0x00, 0x64, 0x00, 0x0A} // read 10 registers at 100
	readWide   = []byte{3, 0x00, 0x64, 0x00, 0x7D} // read 125 registers at 100
	writeReg   = []byte{6, 0x01, 0x90, 0x00, 0x32} // write 50 to register 400
	writeBig   = []byte{6, 0x01, 0x90, 0x03, 0x84} // write 900 to register 400
	writeCoil  = []byte{5, 0x00, 0x05, 0xFF, 0x00} // set coil 5
	clearCoil  = []byte{5, 0x00, 0x05, 0x00, 0x00} // clear coil 5
	writeMulti = []byte{16, 0x01, 0x90, 0x00, 0x02, 4, 0, 10, 0, 20}
	diagnose   = []byte{8, 0x00, 0x01, 0xFF, 0x00} // restart communications
)

// read_only is the commonest requirement in a plant, and it is the one
// that must not be overridable: a read-only listener a single rule could
// write through is not a read-only listener.
func TestReadOnlyCannotBeOverriddenByARule(t *testing.T) {
	p := policy(t, &config.ModbusListener{
		ReadOnly: true,
		Rules: []config.ModbusRule{
			{Name: "everything", Action: "allow", Access: []string{"read", "write"}},
		},
	}, time.Now())
	if d := p.Decide(req(t, "10.0.0.5", "", 1, readRegs)); !d.Allow {
		t.Errorf("a read was refused: %+v", d)
	}
	for _, pdu := range [][]byte{writeReg, writeCoil, writeMulti} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, pdu))
		if d.Allow || d.Reason != "read_only" {
			t.Errorf("a write passed a read-only listener: %+v", d)
		}
	}
	// A diagnostic changes nothing of the process and can still restart
	// the link, so it is not a read either.
	if d := p.Decide(req(t, "10.0.0.5", "", 1, diagnose)); d.Allow {
		t.Errorf("a diagnostic passed a read-only listener: %+v", d)
	}
	// A function code this relay does not know is not a read, whatever
	// a rule says about access: a vendor code does whatever the vendor
	// decided, and a read-only listener that let one through would be
	// promising something it cannot check.
	for _, pdu := range [][]byte{
		{65, 0x00, 0x01},     // a user-defined code
		{43, 13, 0x01, 0x02}, // CANopen, which is a second protocol
		{100, 0x00},          // the other user-defined range
	} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, pdu))
		if d.Allow || d.Reason != "read_only_unknown_function" {
			t.Errorf("function code %d passed a read-only listener: %+v", pdu[0], d)
		}
	}
}

// The rules decide in order, and the first match wins.
func TestTheFirstMatchingRuleDecides(t *testing.T) {
	p := policy(t, &config.ModbusListener{
		Rules: []config.ModbusRule{
			{Name: "hmi-setpoints", Action: "allow", Clients: []string{"10.0.1.0/24"},
				Units: []string{"1-4"}, Functions: []string{"write_single_register"},
				WriteAddresses: []string{"400-499"}},
			{Name: "no-writing", Action: "deny", Access: []string{"write"}},
			{Name: "reads", Action: "allow", Access: []string{"read"}},
		},
	}, time.Now())
	if d := p.Decide(req(t, "10.0.1.7", "", 2, writeReg)); !d.Allow || d.Rule != "hmi-setpoints" {
		t.Errorf("the HMI's setpoint write: %+v", d)
	}
	// The same write from another network falls to the deny rule.
	if d := p.Decide(req(t, "10.0.9.7", "", 2, writeReg)); d.Allow || d.Rule != "no-writing" {
		t.Errorf("a write from elsewhere: %+v", d)
	}
	// The same write to a register outside the range falls through too:
	// a rule that covers half of what is asked for does not match.
	if d := p.Decide(req(t, "10.0.1.7", "", 2, []byte{6, 0x00, 0x10, 0x00, 0x01})); d.Allow {
		t.Errorf("a write outside write_addresses: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.9.7", "", 2, readRegs)); !d.Allow || d.Rule != "reads" {
		t.Errorf("a read: %+v", d)
	}
	// Nothing matched: the default decides, and the default is deny.
	p2 := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "only-unit-1", Action: "allow", Units: []string{"1"}},
	}}, time.Now())
	if d := p2.Decide(req(t, "10.0.0.1", "", 9, readRegs)); d.Allow || d.Reason != "no_rule" {
		t.Errorf("no rule matched: %+v", d)
	}
}

// An address rule has to cover the whole range a request asks for. A read
// of 0 to 200 against a rule for 0 to 99 is a read of addresses the rule
// does not name, and splitting it is not the relay's decision.
func TestAnAddressRuleCoversTheWholeRange(t *testing.T) {
	p := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "window", Action: "allow", Addresses: []string{"100-199"}},
	}}, time.Now())
	if d := p.Decide(req(t, "10.0.0.1", "", 1, readRegs)); !d.Allow {
		t.Errorf("a read inside the window: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.1", "", 1, readWide)); d.Allow {
		t.Errorf("a read running past the window: %+v", d)
	}
	// A request with no range of its own cannot match an address rule.
	if d := p.Decide(req(t, "10.0.0.1", "", 1, []byte{17})); d.Allow {
		t.Errorf("a report-server-id matched an address rule: %+v", d)
	}
}

// The value bounds are the deep inspection a plant actually needs, and a
// value outside them is a refusal by that rule rather than a fall-through
// to a rule that permits it.
func TestAValueOutsideTheBoundIsRefusedByTheRuleThatSetIt(t *testing.T) {
	p := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "setpoints", Action: "allow", Functions: []string{"write_single_register", "write_multiple_registers", "mask_write_register"},
			Values: []config.ModbusValueRule{{Registers: "400-499", Min: ptr(0), Max: ptr(100)}}},
		{Name: "anything-else", Action: "allow"},
	}}, time.Now())
	if d := p.Decide(req(t, "10.0.0.1", "", 1, writeReg)); !d.Allow {
		t.Errorf("a setpoint inside the bound: %+v", d)
	}
	d := p.Decide(req(t, "10.0.0.1", "", 1, writeBig))
	if d.Allow || d.Reason != "value_out_of_range" || d.Rule != "setpoints" {
		t.Errorf("a setpoint of 900 where 0 to 100 is allowed: %+v", d)
	}
	// Every value of a multi-register write is checked, not just the
	// first: the second word is where somebody puts the interesting one.
	over := []byte{16, 0x01, 0x90, 0x00, 0x02, 4, 0, 10, 0x03, 0x84}
	if d := p.Decide(req(t, "10.0.0.1", "", 1, over)); d.Allow {
		t.Errorf("a multi-register write with one value over the bound: %+v", d)
	}
	// A bound written about values cannot be applied to the masks of a
	// mask-write, so that request is refused rather than passed as if the
	// bound had been checked.
	mask := []byte{22, 0x01, 0x90, 0x00, 0xF2, 0x00, 0x25}
	if d := p.Decide(req(t, "10.0.0.1", "", 1, mask)); d.Allow || d.Reason != "value_masked_write" {
		t.Errorf("a mask write under a value bound: %+v", d)
	}
	// A signed bound reads the value as most setpoints are encoded.
	ps := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "signed", Action: "allow", Values: []config.ModbusValueRule{
			{Min: ptr(-50), Max: ptr(50), Signed: true}}},
	}}, time.Now())
	minusTen := []byte{6, 0x01, 0x90, 0xFF, 0xF6}
	if d := ps.Decide(req(t, "10.0.0.1", "", 1, minusTen)); !d.Allow {
		t.Errorf("a signed -10 inside -50 to 50: %+v", d)
	}
	minusThousand := []byte{6, 0x01, 0x90, 0xFC, 0x18}
	if d := ps.Decide(req(t, "10.0.0.1", "", 1, minusThousand)); d.Allow {
		t.Errorf("a signed -1000 outside the bound: %+v", d)
	}
}

// A coil bound says which way a coil may be driven, which is how "this
// client may stop the pump but not start it" is written.
func TestACoilBoundSaysWhichWayItMayBeDriven(t *testing.T) {
	p := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "stop-only", Action: "allow", Values: []config.ModbusValueRule{
			{Registers: "5", Coils: ptr(false)}}},
	}}, time.Now())
	if d := p.Decide(req(t, "10.0.0.1", "", 1, clearCoil)); !d.Allow {
		t.Errorf("clearing the coil: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.1", "", 1, writeCoil)); d.Allow || d.Reason != "coil_set_not_allowed" {
		t.Errorf("setting the coil: %+v", d)
	}
	// And the other direction is the same rule written the other way
	// round: a client that may start the pump and not stop it.
	q := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "start-only", Action: "allow", Values: []config.ModbusValueRule{
			{Registers: "5", Coils: ptr(true)}}},
	}}, time.Now())
	if d := q.Decide(req(t, "10.0.0.1", "", 1, writeCoil)); !d.Allow {
		t.Errorf("setting the coil: %+v", d)
	}
	if d := q.Decide(req(t, "10.0.0.1", "", 1, clearCoil)); d.Allow || d.Reason != "coil_clear_not_allowed" {
		t.Errorf("clearing the coil: %+v", d)
	}
	// A coil outside the range the bound names is not what the bound is
	// about, so a rule that otherwise matches still allows it.
	if d := q.Decide(req(t, "10.0.0.1", "", 1, []byte{5, 0x00, 0x09, 0x00, 0x00})); !d.Allow {
		t.Errorf("a coil outside the bound's range: %+v", d)
	}
}

// A rule naming a role never matches a session without one: that is what
// makes a Modbus/TCP Security role an authorisation rather than a hint.
func TestARuleNamingARoleNeedsOne(t *testing.T) {
	p := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "engineers", Action: "allow", Roles: []string{"engineer"}},
	}}, time.Now())
	if d := p.Decide(req(t, "10.0.0.1", "engineer", 1, writeReg)); !d.Allow {
		t.Errorf("the engineer: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.1", "operator", 1, writeReg)); d.Allow {
		t.Errorf("another role: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.1", "", 1, writeReg)); d.Allow {
		t.Errorf("no role at all: %+v", d)
	}
}

// Schedules: rules in force during the shift, and others in force when
// the scheduled ones are not.
func TestASchedulePutsARuleInForceForAWindow(t *testing.T) {
	cfg := &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "shift-writes", Action: "allow", Access: []string{"write"},
			Schedule: &config.ModbusSchedule{Days: []string{"mon", "tue", "wed", "thu", "fri"},
				From: "06:00", To: "18:00", Timezone: "UTC"}},
		{Name: "outside-the-shift", Action: "deny", Access: []string{"write"}},
		{Name: "reads-always", Action: "allow", Access: []string{"read"}},
	}}
	// A Wednesday at ten.
	inShift := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	p := policy(t, cfg, inShift)
	if d := p.Decide(req(t, "10.0.0.1", "", 1, writeReg)); !d.Allow || d.Rule != "shift-writes" {
		t.Errorf("a write during the shift: %+v", d)
	}
	// The same Wednesday at ten in the evening.
	p2 := policy(t, cfg, time.Date(2026, 9, 23, 22, 0, 0, 0, time.UTC))
	if d := p2.Decide(req(t, "10.0.0.1", "", 1, writeReg)); d.Allow || d.Rule != "outside-the-shift" {
		t.Errorf("a write out of hours: %+v", d)
	}
	// And a Sunday at ten, which is a day the window does not name.
	p3 := policy(t, cfg, time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC))
	if d := p3.Decide(req(t, "10.0.0.1", "", 1, writeReg)); d.Allow {
		t.Errorf("a write at the weekend: %+v", d)
	}
	// Reads are unscheduled, so they hold whatever the clock says.
	if d := p3.Decide(req(t, "10.0.0.1", "", 1, readRegs)); !d.Allow {
		t.Errorf("a read at the weekend: %+v", d)
	}
}

// A window whose end is before its start spans midnight, which is how a
// night shift is written, and the small hours belong to the day the shift
// started on.
func TestAWindowSpanningMidnightIsTheNightShift(t *testing.T) {
	cfg := &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "nights", Action: "allow",
			Schedule: &config.ModbusSchedule{Days: []string{"fri"}, From: "22:00", To: "06:00"}},
	}}
	for _, tc := range []struct {
		name string
		when time.Time
		want bool
	}{
		{"friday at eleven at night", time.Date(2026, 9, 25, 23, 0, 0, 0, time.UTC), true},
		{"saturday at two in the morning", time.Date(2026, 9, 26, 2, 0, 0, 0, time.UTC), true},
		{"saturday at seven in the morning", time.Date(2026, 9, 26, 7, 0, 0, 0, time.UTC), false},
		{"friday at noon", time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC), false},
		{"sunday at two in the morning", time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC), false},
	} {
		p := policy(t, cfg, tc.when)
		if got := p.Decide(req(t, "10.0.0.1", "", 1, readRegs)).Allow; got != tc.want {
			t.Errorf("%s: allowed %v, want %v", tc.name, got, tc.want)
		}
	}
	// A schedule in a named zone is in that zone, not the host's.
	tz := &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "stockholm-shift", Action: "allow",
			Schedule: &config.ModbusSchedule{From: "08:00", To: "17:00", Timezone: "Europe/Stockholm"}},
	}}
	// 07:30 UTC is 09:30 in Stockholm in September.
	p := policy(t, tz, time.Date(2026, 9, 23, 7, 30, 0, 0, time.UTC))
	if !p.Decide(req(t, "10.0.0.1", "", 1, readRegs)).Allow {
		t.Error("a window in a named zone was read in UTC")
	}
}

// An observe rule records the frame and decides nothing, which is how a
// rule is tried against live traffic before it is trusted.
func TestAnObserveRuleDecidesNothing(t *testing.T) {
	p := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "watch-writes", Action: "observe", Access: []string{"write"}},
		{Name: "allow-all", Action: "allow"},
	}}, time.Now())
	r := req(t, "10.0.0.1", "", 1, writeReg)
	d := p.Decide(r)
	if !d.Allow || d.Rule != "allow-all" {
		t.Errorf("the observe rule decided: %+v", d)
	}
	if got := p.Observed(r); len(got) != 1 || got[0] != "watch-writes" {
		t.Errorf("observed %v", got)
	}
	if got := p.Observed(req(t, "10.0.0.1", "", 1, readRegs)); len(got) != 0 {
		t.Errorf("a read was observed by a write rule: %v", got)
	}
}

// The unit allow list and the client lists decide before the rules.
func TestTheUnitAndClientListsDecideFirst(t *testing.T) {
	p := policy(t, &config.ModbusListener{
		Units:        []string{"1-8"},
		AllowClients: []string{"10.0.0.0/8"},
		DenyClients:  []string{"10.9.0.0/16"},
		Rules:        []config.ModbusRule{{Name: "all", Action: "allow"}},
	}, time.Now())
	if d := p.Decide(req(t, "10.0.0.1", "", 9, readRegs)); d.Allow || d.Reason != "unit_not_allowed" {
		t.Errorf("unit 9 against an allow list of 1 to 8: %+v", d)
	}
	if !p.ClientAllowed(netip.MustParseAddr("10.0.0.1")) {
		t.Error("a client inside the allow list was refused")
	}
	if p.ClientAllowed(netip.MustParseAddr("192.168.1.1")) {
		t.Error("a client outside the allow list was admitted")
	}
	// Deny is evaluated first, so a network inside the allow list and
	// inside the deny list is refused.
	if p.ClientAllowed(netip.MustParseAddr("10.9.0.1")) {
		t.Error("a denied network inside the allow list was admitted")
	}
}

// What a policy cannot say is refused when it is compiled, not when the
// first frame matches it.
func TestABrokenPolicyIsRefusedAtCompile(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.ModbusListener
		want string
	}{
		{"a range that starts after it ends", &config.ModbusListener{Units: []string{"9-2"}}, "starts after it ends"},
		{"a unit past 255", &config.ModbusListener{Units: []string{"300"}}, "outside 0 to 255"},
		{"a range that is not one", &config.ModbusListener{Units: []string{"one"}}, "units"},
		{"a function code nobody has", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Functions: []string{"read_the_mind_of_the_operator"}}}}, "function code"},
		{"an access class nobody has", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Access: []string{"sideways"}}}}, "read, write, diagnostic"},
		{"a value rule with no bounds", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Values: []config.ModbusValueRule{{Registers: "1"}}}}}, "min and max"},
		{"a signed bound outside a signed word", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Values: []config.ModbusValueRule{{Min: ptr(0), Max: ptr(40000), Signed: true}}}}}, "not a range inside"},
		{"a day nobody has", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}}, "is not a day"},
		{"a time that is not one", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Schedule: &config.ModbusSchedule{From: "25:00"}}}}, "time of day"},
		{"a zone nobody has", &config.ModbusListener{Rules: []config.ModbusRule{
			{Name: "r", Schedule: &config.ModbusSchedule{Timezone: "Mars/Olympus"}}}}, "timezone"},
		{"a client list that is not a CIDR", &config.ModbusListener{AllowClients: []string{"10.0.0.1"}}, "allow_clients"},
	} {
		_, err := compile(tc.cfg, time.Now)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one about %q", tc.name, err, tc.want)
		}
	}
}

// max_quantity is the bound a device's own limits do not give: a read of
// 125 registers is legal and still more than a rule means to allow.
func TestMaxQuantityBoundsOneRequest(t *testing.T) {
	p := policy(t, &config.ModbusListener{Rules: []config.ModbusRule{
		{Name: "small-reads", Action: "allow", MaxQuantity: 16},
	}}, time.Now())
	if d := p.Decide(req(t, "10.0.0.1", "", 1, readRegs)); !d.Allow {
		t.Errorf("a read of ten: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.1", "", 1, readWide)); d.Allow {
		t.Errorf("a read of 125 against a bound of 16: %+v", d)
	}
}

// The role policy: off, allow and require, and the allow list of roles.
func TestTheRoleModes(t *testing.T) {
	off := policy(t, &config.ModbusListener{}, time.Now())
	if off.RoleRequired() || off.RoleMode() != "off" {
		t.Errorf("default role mode %q", off.RoleMode())
	}
	req := policy(t, &config.ModbusListener{Security: &config.ModbusSecurity{
		Mode: "require", RoleSource: "cn", Roles: []string{"engineer"}}}, time.Now())
	if !req.RoleRequired() || req.RoleSource() != "cn" {
		t.Errorf("require mode: %v %q", req.RoleRequired(), req.RoleSource())
	}
	if !req.RoleAllowed("engineer") || req.RoleAllowed("intruder") {
		t.Error("the role allow list does not decide")
	}
	if !off.RoleAllowed("anything") {
		t.Error("an empty role list refused a role")
	}
}
