package modbus

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy is written in Modbus's own terms, because that is the only
// vocabulary a plant has: the unit identifier, the function code, the
// register range, the value. A rule about "a TCP connection to port 502"
// says nothing about whether a master may write a setpoint, and a rule
// about a setpoint is the one an engineer can confirm.
//
// Rules are ordered and the first match decides, with one exception that
// is deliberate: read_only on the listener is checked before any rule and
// cannot be overridden by one. A read-only listener that a single rule
// could write through is not a read-only listener, and the person who
// asked for read-only asked for the property rather than for a default.

// Decision is what the policy decided about one frame.
type Decision struct {
	// Allow says the frame may go on.
	Allow bool
	// Rule is the rule that decided, or "" for a default.
	Rule string
	// Reason is why, as a stable label: the counters and the security
	// log both use it.
	Reason string
	// Comment is the rule's own note, carried into the log.
	Comment string
	// Observed says a rule matched with action observe: the frame was
	// recorded and the search carried on, so this is not the decision.
	Observed bool
}

// valueRule is a compiled value bound: the deep inspection a plant needs.
type valueRule struct {
	registers numrange.Set
	min, max  int
	signed    bool
	coils     *bool

	// The checks that need to know what the value is now. Each is off
	// when its zero value says so, and each says what to do when this
	// relay has not seen a value for the address (onUnknown).
	maxDelta    int
	transitions []transition
	rate        *valueRate
	before      *precondition
	refuseUnk   bool
}

// transition is one permitted value change. A negative bound means "any".
type transition struct {
	from, to int
	anyFrom  bool
	anyTo    bool
}

// valueRate bounds how often an address may be written.
type valueRate struct {
	max       int
	period    time.Duration
	perClient bool
}

// precondition is select-before-operate: the register that has to have
// been written, the value it has to hold, and for how long that counts.
type precondition struct {
	registers numrange.Set
	equals    int
	within    time.Duration
	unit      *int
}

// rule is a compiled rule.
type rule struct {
	name    string
	action  string
	comment string

	clients   []netip.Prefix
	roles     map[string]bool
	units     numrange.Set
	functions map[byte]bool
	access    map[wire.Access]bool
	addresses numrange.Set
	writeAddr numrange.Set
	maxQty    int
	values    []valueRule
	schedule  *schedule.Window

	// diags, umas and effects are the sub-function selectors: which
	// diagnostic sub-functions of function code 8, which UMAS commands of
	// function code 90, and what the sub-function does whichever code
	// carried it.
	diags   numrange.Set
	umas    numrange.Set
	effects map[wire.SubEffect]bool
	// namesSub says this rule mentions the sub-function at all, by any of
	// the three. It is what lifts refuse_unsafe_sub_functions: a rule that
	// names it meant it.
	namesSub bool
}

// Policy is the compiled listener policy.
type Policy struct {
	readOnly      bool
	units         numrange.Set
	rules         []*rule
	defaultAllow  bool
	refuseUnsafe  bool
	allow, deny   []netip.Prefix
	roleMode      string
	roleSource    string
	allowedRoles  map[string]bool
	maxFrameBytes int
	now           func() time.Time
	// state is what this relay has seen at each address, for the value
	// rules that are about a change rather than about a value.
	state *valueState
}

// request is what the policy decides about: a parsed frame and who sent
// it.
type request struct {
	client netip.Addr
	role   string
	unit   byte
	pdu    *wire.PDU
}

// compile builds the policy from the configuration. Everything that can
// be wrong about a rule is wrong here, at load, rather than at the first
// frame that matches it.
func compile(l *config.ModbusListener, now func() time.Time) (*Policy, error) {
	p := &Policy{readOnly: l.ReadOnly, defaultAllow: l.DefaultAction == "allow",
		maxFrameBytes: l.MaxFrameBytes, now: now, state: newValueState(l.MaxValuePoints)}
	if p.now == nil {
		p.now = time.Now
	}
	p.refuseUnsafe = l.RefuseUnsafeSubFunctions == nil || *l.RefuseUnsafeSubFunctions
	var err error
	if p.units, err = numrange.Parse("units", l.Units, 255); err != nil {
		return nil, err
	}
	if p.allow, err = prefixes("allow_clients", l.AllowClients); err != nil {
		return nil, err
	}
	if p.deny, err = prefixes("deny_clients", l.DenyClients); err != nil {
		return nil, err
	}
	p.roleMode, p.roleSource = "off", "extension"
	if s := l.Security; s != nil {
		if s.Mode != "" {
			p.roleMode = s.Mode
		}
		if s.RoleSource != "" {
			p.roleSource = s.RoleSource
		}
		if len(s.Roles) > 0 {
			p.allowedRoles = map[string]bool{}
			for _, r := range s.Roles {
				p.allowedRoles[r] = true
			}
		}
	}
	for i := range l.Rules {
		r, err := compileRule(&l.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func prefixes(what string, in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func compileRule(c *config.ModbusRule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, comment: c.Comment, maxQty: c.MaxQuantity}
	if r.action == "" {
		r.action = "allow"
	}
	var err error
	if r.clients, err = prefixes("rules."+c.Name+".clients", c.Clients); err != nil {
		return nil, err
	}
	if len(c.Roles) > 0 {
		r.roles = map[string]bool{}
		for _, role := range c.Roles {
			r.roles[role] = true
		}
	}
	if r.units, err = numrange.Parse("rules."+c.Name+".units", c.Units, 255); err != nil {
		return nil, err
	}
	if r.addresses, err = numrange.Parse("rules."+c.Name+".addresses", c.Addresses, 0xFFFF); err != nil {
		return nil, err
	}
	if r.writeAddr, err = numrange.Parse("rules."+c.Name+".write_addresses", c.WriteAddresses, 0xFFFF); err != nil {
		return nil, err
	}
	if len(c.Functions) > 0 {
		r.functions = map[byte]bool{}
		for _, f := range c.Functions {
			fc, err := functionCode(f)
			if err != nil {
				return nil, fmt.Errorf("rules.%s.functions: %w", c.Name, err)
			}
			r.functions[fc] = true
		}
	}
	if len(c.Access) > 0 {
		r.access = map[wire.Access]bool{}
		for _, a := range c.Access {
			switch wire.Access(a) {
			case wire.AccessRead, wire.AccessWrite, wire.AccessDiagnostic,
				wire.AccessIdentify, wire.AccessVendor:
				r.access[wire.Access(a)] = true
			default:
				return nil, fmt.Errorf("rules.%s.access: %q is not read, write, diagnostic, identify or vendor", c.Name, a)
			}
		}
	}
	if err := compileSubFunctions(c, r); err != nil {
		return nil, err
	}
	for i := range c.Values {
		v, err := compileValue(c.Name, &c.Values[i])
		if err != nil {
			return nil, err
		}
		if err := compileValueState(c.Name, &c.Values[i], &v); err != nil {
			return nil, err
		}
		r.values = append(r.values, v)
	}
	if r.schedule, err = schedule.Compile(c.Schedule); err != nil {
		return nil, fmt.Errorf("rules.%s.%w", c.Name, err)
	}
	return r, nil
}

// functionCode reads a function code written as a name or a number.
func functionCode(s string) (byte, error) {
	if fc, ok := wire.FunctionCode(s); ok {
		return fc, nil
	}
	n, err := numrange.ParseNum(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 127 {
		return 0, fmt.Errorf("%q is not a function code name or a number from 1 to 127", s)
	}
	return byte(n), nil
}

// compileSubFunctions compiles the three sub-function selectors.
//
// They are one function because they answer one question -- does this rule
// mention the sub-function -- and because the answer decides whether the
// rule may allow one of the sub-functions a listener refuses by default.
func compileSubFunctions(c *config.ModbusRule, r *rule) error {
	var err error
	if r.diags, err = subSet(c.Name, "diagnostics", wire.FCDiagnostic, c.Diagnostics); err != nil {
		return err
	}
	if r.umas, err = subSet(c.Name, "umas_commands", wire.FCUMAS, c.UMASCommands); err != nil {
		return err
	}
	if len(c.Effects) > 0 {
		r.effects = map[wire.SubEffect]bool{}
		for _, s := range c.Effects {
			e, ok := wire.ParseSubEffect(s)
			if !ok {
				return fmt.Errorf("rules.%s.effects: %q is not read, write, control, program, clear, session or unknown",
					c.Name, s)
			}
			r.effects[e] = true
		}
	}
	r.namesSub = len(r.diags) > 0 || len(r.umas) > 0 || len(r.effects) > 0
	return nil
}

// subSet compiles a list of sub-functions written as names, numbers or
// ranges.
//
// The names are translated to numbers and the whole list then goes through
// numrange, which is where every other numeric list in a Modbus rule is
// read: that is what makes `11-18` mean here what it means in an address
// list, so an engineer writing "the counters" does not have to find out
// that this one field reads ranges differently.
func subSet(rule, field string, fc byte, in []string) (numrange.Set, error) {
	if len(in) == 0 {
		return nil, nil
	}
	where := "rules." + rule + "." + field
	max := wire.SubMax(fc)
	out := make(numrange.Set, 0, len(in))
	for _, s := range in {
		if sub, ok := wire.SubCode(fc, s); ok {
			out = append(out, numrange.Range{Lo: int(sub), Hi: int(sub)})
			continue
		}
		// Not a name and not a number, so it is a range or it is nothing.
		// The message says all three forms rather than leaving an engineer
		// who mistyped a name to read an error about numbers.
		set, err := numrange.Parse(where, []string{s}, max)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a %s sub-function name, a number from 0 to %d, or a range of them",
				where, s, wire.FunctionName(fc), max)
		}
		out = append(out, set...)
	}
	return out, nil
}

func compileValue(rule string, c *config.ModbusValueRule) (valueRule, error) {
	v := valueRule{signed: c.Signed, coils: c.Coils}
	if c.Registers != "" {
		rs, err := numrange.Parse("rules."+rule+".values.registers", []string{c.Registers}, 0xFFFF)
		if err != nil {
			return v, err
		}
		v.registers = rs
	}
	if c.Coils != nil {
		return v, nil
	}
	if c.Min == nil || c.Max == nil {
		return v, fmt.Errorf("rules.%s.values: min and max are both required (or coils)", rule)
	}
	lo, hi := -32768, 65535
	if c.Signed {
		hi = 32767
	} else {
		lo = 0
	}
	if *c.Min < lo || *c.Max > hi || *c.Min > *c.Max {
		return v, fmt.Errorf("rules.%s.values: min %d and max %d are not a range inside %d to %d",
			rule, *c.Min, *c.Max, lo, hi)
	}
	v.min, v.max = *c.Min, *c.Max
	return v, nil
}

// compileValueState compiles the checks that need the address's current
// value. They are separate from the range because they are separate in
// kind: a range is a statement about a value and these are statements
// about a change.
func compileValueState(rule string, c *config.ModbusValueRule, v *valueRule) error {
	where := "rules." + rule + ".values"
	v.maxDelta = c.MaxDelta
	if c.MaxDelta < 0 || c.MaxDelta > 0xFFFF {
		return fmt.Errorf("%s.max_delta: must be between 0 and 65535", where)
	}
	switch c.OnUnknown {
	case "", "allow":
	case "refuse":
		v.refuseUnk = true
	default:
		return fmt.Errorf("%s.on_unknown: must be allow or refuse", where)
	}
	for _, t := range c.Transitions {
		tr, err := parseTransition(where, t)
		if err != nil {
			return err
		}
		v.transitions = append(v.transitions, tr)
	}
	if r := c.Rate; r != nil {
		if r.Max < 1 {
			return fmt.Errorf("%s.rate.max: must be at least 1", where)
		}
		d := r.Period.D()
		if d < time.Second || d > 24*time.Hour {
			return fmt.Errorf("%s.rate.period: must be between 1s and 24h", where)
		}
		v.rate = &valueRate{max: r.Max, period: d, perClient: r.PerClient}
	}
	if b := c.RequireBefore; b != nil {
		if b.Registers == "" {
			return fmt.Errorf("%s.require_before.registers: required", where)
		}
		rs, err := numrange.Parse(where+".require_before.registers", []string{b.Registers}, 0xFFFF)
		if err != nil {
			return err
		}
		within := b.Within.D()
		if within == 0 {
			within = 30 * time.Second
		}
		if within < time.Second || within > time.Hour {
			return fmt.Errorf("%s.require_before.within: must be between 1s and 1h", where)
		}
		if b.Unit != nil && (*b.Unit < 0 || *b.Unit > 255) {
			return fmt.Errorf("%s.require_before.unit: must be between 0 and 255", where)
		}
		v.before = &precondition{registers: rs, equals: b.Equals, within: within, unit: b.Unit}
	}
	return nil
}

// parseTransition reads "0->1", with "*" for any value on either side.
func parseTransition(where, s string) (transition, error) {
	parts := strings.SplitN(s, "->", 2)
	if len(parts) != 2 {
		return transition{}, fmt.Errorf("%s.transitions: %q is not a transition (\"from->to\")", where, s)
	}
	var t transition
	for i, half := range parts {
		text := strings.TrimSpace(half)
		if text == "*" {
			if i == 0 {
				t.anyFrom = true
			} else {
				t.anyTo = true
			}
			continue
		}
		n, err := numrange.ParseNum(text)
		if err != nil || n < -32768 || n > 65535 {
			return transition{}, fmt.Errorf("%s.transitions: %q in %q is not a value or *", where, text, s)
		}
		if i == 0 {
			t.from = n
		} else {
			t.to = n
		}
	}
	if t.anyFrom && t.anyTo {
		return transition{}, fmt.Errorf("%s.transitions: %q permits every change, which is the same as no list", where, s)
	}
	return t, nil
}

// allows says whether a change from one value to another is in the list.
func (t transition) allows(from, to int) bool {
	return (t.anyFrom || t.from == from) && (t.anyTo || t.to == to)
}

// checkChange applies the three bounds that are about a change rather
// than a value, and the rate. It returns the refusal reason, or empty.
//
// Each of the three needs the address's current value, and what that
// means here is the last value this relay saw -- a write it forwarded or a
// read it relayed. A value changed by another master, a local panel or
// the process itself was never on this path. So a rule that needs one and
// has none is decided by on_unknown, and the counter says how often that
// happened: a policy running on less than it asks for should be visible
// rather than silently permissive.
func (v valueRule) checkChange(state *valueState, req request, addr, val int, now time.Time) string {
	if v.rate != nil {
		n := state.WritesIn(req.unit, addr, v.rate.period, req.client, v.rate.perClient, now)
		if n >= v.rate.max {
			return "value_rate"
		}
	}
	if v.before != nil {
		unit := req.unit
		if v.before.unit != nil {
			unit = byte(*v.before.unit) //nolint:gosec // validated 0..255
		}
		if !state.Selected(unit, v.before.registers, v.before.equals, v.before.within, now) {
			return "value_no_select"
		}
	}
	if v.maxDelta == 0 && len(v.transitions) == 0 {
		return ""
	}
	last, _, known := state.Last(req.unit, addr)
	if !known {
		if state != nil {
			state.mu.Lock()
			state.Unknown++
			state.mu.Unlock()
		}
		if v.refuseUnk {
			return "value_unknown"
		}
		return ""
	}
	if v.maxDelta > 0 {
		d := val - last
		if d < 0 {
			d = -d
		}
		if d > v.maxDelta {
			return "value_delta"
		}
	}
	if len(v.transitions) > 0 {
		for _, t := range v.transitions {
			if t.allows(last, val) {
				return ""
			}
		}
		return "value_transition"
	}
	return ""
}

// ClientAllowed applies the address lists. It is separate from the frame
// policy because it decides before a frame exists: a master that may not
// connect is refused at accept, without a PLC hearing from it at all.
func (p *Policy) ClientAllowed(ip netip.Addr) bool {
	if len(p.deny) > 0 && netutil.Contains(p.deny, ip) {
		return false
	}
	if len(p.allow) == 0 {
		return true
	}
	return netutil.Contains(p.allow, ip)
}

// RoleRequired says whether a session must present a usable role.
func (p *Policy) RoleRequired() bool { return p.roleMode == "require" }

// RoleMode is off, allow or require.
func (p *Policy) RoleMode() string { return p.roleMode }

// RoleSource is where the role is read from.
func (p *Policy) RoleSource() string { return p.roleSource }

// RoleAllowed applies the role allow list.
func (p *Policy) RoleAllowed(role string) bool {
	if len(p.allowedRoles) == 0 {
		return true
	}
	return p.allowedRoles[role]
}

// Decide applies the policy to one request.
//
// The order is the order the refusals are worth making in: the frame's
// own validity first (a frame nobody can read is not a frame to decide
// about), then read-only, then the unit allow list, then the rules.
func (p *Policy) Decide(req request) Decision {
	if p.readOnly && req.pdu.Writes() {
		return Decision{Reason: "read_only", Rule: "read_only"}
	}
	if p.readOnly && !req.pdu.SafeUnderReadOnly() {
		// A function code this relay does not know is not a read, and a
		// read-only listener that let one through would be promising
		// something it cannot check.
		return Decision{Reason: "read_only_unknown_function", Rule: "read_only"}
	}
	if len(p.units) > 0 && !p.units.Has(int(req.unit)) {
		return Decision{Reason: "unit_not_allowed"}
	}
	now := p.now()
	for _, r := range p.rules {
		if !r.matches(req, now) {
			continue
		}
		switch r.action {
		case "deny":
			return Decision{Rule: r.name, Reason: "rule_deny", Comment: r.comment}
		case "observe":
			// Recorded, and the search carries on: this is how a rule
			// is tried against live traffic without deciding anything.
			continue
		default:
			if !r.namesSub && p.unsafeSub(req) {
				return Decision{Rule: r.name, Reason: "unsafe_sub_function", Comment: r.comment}
			}
			if reason := r.checkValues(req, p.state, now); reason != "" {
				return Decision{Rule: r.name, Reason: reason, Comment: r.comment}
			}
			return Decision{Allow: true, Rule: r.name, Comment: r.comment}
		}
	}
	if p.defaultAllow {
		// A default is the least deliberate thing in a configuration, so
		// it is the last place a frame that stops a PLC should get
		// through: default_action: allow permits the traffic nobody wrote
		// a rule about, and forcing a device into listen-only mode is not
		// that traffic.
		if p.unsafeSub(req) {
			return Decision{Reason: "unsafe_sub_function"}
		}
		return Decision{Allow: true, Reason: "default_allow"}
	}
	return Decision{Reason: "no_rule"}
}

// unsafeSub says this request carries a sub-function the listener refuses
// unless a rule named it: one that stops a device, changes what it runs,
// clears the record of either, or is one this relay cannot read.
//
// The guard is a separate thing from a rule because of what it is for. A
// rule says what the traffic may be; this says that a rule permitting a
// function code has not, by saying nothing, permitted the worst thing that
// code can do. A listener that wants the whole code back says
// refuse_unsafe_sub_functions: false, and a rule that wants one of them
// names it -- both of which are visible in the configuration, which is the
// point.
func (p *Policy) unsafeSub(req request) bool {
	if !p.refuseUnsafe || req.pdu == nil {
		return false
	}
	e, ok := req.pdu.SubEffect()
	return ok && e.Unsafe()
}

// observeWrite records the values a write carries, so the next write's
// delta, transition and rate are measured against them.
func (p *Policy) observeWrite(req request, now time.Time) {
	if p == nil || p.state == nil || req.pdu == nil || !req.pdu.Writes() {
		return
	}
	pdu := req.pdu
	base := int(pdu.Address)
	if pdu.Function == wire.FCReadWriteMultiple {
		base = int(pdu.WriteAddress)
	}
	if pdu.Function == wire.FCMaskWriteRegister {
		// A masked write is not a value at an address, so recording one
		// would be inventing what the register now holds. The address is
		// forgotten instead: a delta measured against a value this relay
		// only thinks it knows would be worse than one that says it does
		// not know.
		p.state.Forget(req.unit, base)
		return
	}
	p.state.Observe(req.unit, base, pdu.Registers, true, req.client, now)
	p.state.ObserveCoils(req.unit, base, pdu.Coils, true, req.client, now)
}

// observeRead records what a device answered a read with. It is where the
// value of a register this relay never wrote comes from.
func (p *Policy) observeRead(req request, resp *wire.PDU, now time.Time) {
	if p == nil || p.state == nil || req.pdu == nil || resp == nil || req.pdu.Writes() {
		return
	}
	base := int(req.pdu.Address)
	p.state.Observe(req.unit, base, resp.Registers, false, req.client, now)
	p.state.ObserveCoils(req.unit, base, resp.Coils, false, req.client, now)
}

// ValueState is the value table's own numbers, for the status view.
func (p *Policy) ValueState() (points int, unknown, dropped uint64) {
	if p == nil || p.state == nil {
		return 0, 0, 0
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	return len(p.state.points), p.state.Unknown, p.state.Dropped
}

// Observed reports the names of the observe rules a request matches, for
// the log and the counters. It is separate from Decide because an
// observe rule does not decide, and a caller that wanted both would
// otherwise have to run the list twice.
func (p *Policy) Observed(req request) []string {
	var out []string
	now := p.now()
	for _, r := range p.rules {
		if r.action == "observe" && r.matches(req, now) {
			out = append(out, r.name)
		}
	}
	return out
}

// matches says whether every selector the rule sets holds.
func (r *rule) matches(req request, now time.Time) bool {
	if !r.schedule.InForce(now) {
		return false
	}
	if len(r.clients) > 0 && !netutil.Contains(r.clients, req.client) {
		return false
	}
	if len(r.roles) > 0 {
		// A rule naming a role never matches a session without one:
		// that is what makes a role an authorisation rather than a hint.
		if req.role == "" || !r.roles[req.role] {
			return false
		}
	}
	if len(r.units) > 0 && !r.units.Has(int(req.unit)) {
		return false
	}
	if len(r.functions) > 0 && !r.functions[req.pdu.Function] {
		return false
	}
	if len(r.access) > 0 && !r.access[req.pdu.Access] {
		return false
	}
	for _, sel := range []struct {
		fc  byte
		set numrange.Set
	}{{wire.FCDiagnostic, r.diags}, {wire.FCUMAS, r.umas}} {
		if len(sel.set) == 0 {
			continue
		}
		// A rule naming a sub-function of one function code never matches
		// another code's frame, whether or not the rule also named the
		// code: the sub-function numbers are not one namespace.
		if req.pdu.Function != sel.fc || !req.pdu.HasSubFunction ||
			!sel.set.Has(int(req.pdu.SubFunction)) {
			return false
		}
	}
	if len(r.effects) > 0 {
		// A rule about an effect never matches a frame that has no
		// sub-function: "nothing that stops a PLC" is a statement about
		// the frames that could, and a register read is not one of them.
		e, ok := req.pdu.SubEffect()
		if !ok || !r.effects[e] {
			return false
		}
	}
	if r.maxQty > 0 && req.pdu.HasRange && int(req.pdu.Quantity) > r.maxQty {
		return false
	}
	if len(r.addresses) > 0 {
		if !req.pdu.HasRange {
			return false
		}
		last, ok := req.pdu.Last()
		if !ok || !r.addresses.Covers(int(req.pdu.Address), int(last)) {
			return false
		}
	}
	if len(r.writeAddr) > 0 {
		lo, hi, ok := writeSpan(req.pdu)
		if !ok {
			return false
		}
		if hi >= 0 && !r.writeAddr.Covers(lo, hi) {
			return false
		}
	}
	return true
}

// writeSpan is the range a request writes to, and whether it writes at
// all. hi is -1 for a request that writes nothing, so a rule with
// write_addresses still matches a pure read.
func writeSpan(p *wire.PDU) (int, int, bool) {
	switch {
	case p.Function == wire.FCReadWriteMultiple:
		last, ok := p.WriteLast()
		if !ok {
			return 0, 0, false
		}
		return int(p.WriteAddress), int(last), true
	case p.Access == wire.AccessWrite && p.HasRange:
		last, ok := p.Last()
		if !ok {
			return 0, 0, false
		}
		return int(p.Address), int(last), true
	case p.Access == wire.AccessWrite:
		// A write with no range of its own -- a file record -- cannot be
		// checked against an address range, and a rule that named one
		// must not match it silently.
		return 0, 0, false
	}
	return 0, -1, true
}

// checkValues applies the value bounds of a rule that otherwise matched.
// A value outside them is a refusal by that rule rather than a failure to
// match, because a setpoint of 900 where 0 to 100 is allowed is exactly
// what the rule was written to stop, and falling through to the next
// rule would be looking for one that permits it.
func (r *rule) checkValues(req request, state *valueState, now time.Time) string {
	if len(r.values) == 0 {
		return ""
	}
	p := req.pdu
	base := int(p.Address)
	if p.Function == wire.FCReadWriteMultiple {
		base = int(p.WriteAddress)
	}
	if p.Function == wire.FCMaskWriteRegister {
		// The AND and OR masks are not a value at an address; a bound
		// written about values cannot be applied to them, and applying
		// it anyway would be inventing a meaning.
		for _, v := range r.values {
			if len(v.registers) == 0 || v.registers.Has(base) {
				return "value_masked_write"
			}
		}
		return ""
	}
	for i, raw := range p.Registers {
		addr := base + i
		for _, v := range r.values {
			if len(v.registers) > 0 && !v.registers.Has(addr) {
				continue
			}
			if v.coils != nil {
				continue
			}
			val := int(raw)
			if v.signed {
				val = int(int16(raw)) //nolint:gosec // the point is the reinterpretation
			}
			if val < v.min || val > v.max {
				return "value_out_of_range"
			}
			if reason := v.checkChange(state, req, addr, val, now); reason != "" {
				return reason
			}
		}
	}
	for i, on := range p.Coils {
		addr := base + i
		for _, v := range r.values {
			if v.coils == nil {
				continue
			}
			if len(v.registers) > 0 && !v.registers.Has(addr) {
				continue
			}
			// The bound says which way this rule may drive the coil:
			// "may stop the pump but not start it" is coils: false, and
			// the other direction is the same rule written the other
			// way round. A bound that only held in one direction would
			// be half a bound.
			if on && !*v.coils {
				return "coil_set_not_allowed"
			}
			if !on && *v.coils {
				return "coil_clear_not_allowed"
			}
			// A coil is a value of 0 or 1, so the same rate,
			// transition and select-before-operate machinery covers
			// it: "the pump may be started once a minute, and only
			// after the permissive is set" is a coil rule.
			val := 0
			if on {
				val = 1
			}
			if reason := v.checkChange(state, req, addr, val, now); reason != "" {
				return reason
			}
		}
	}
	return ""
}

// Rules is the number of compiled rules, for the status view.
func (p *Policy) Rules() int { return len(p.rules) }
