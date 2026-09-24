package modbus

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/netutil"
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

// rng is an inclusive numeric range, which is how every list in this
// policy is written: unit identifiers, addresses, values.
type rng struct{ lo, hi int }

func (r rng) has(v int) bool { return v >= r.lo && v <= r.hi }

// ranges is a set of them.
type ranges []rng

func (rs ranges) has(v int) bool {
	for _, r := range rs {
		if r.has(v) {
			return true
		}
	}
	return false
}

// covers says whether the whole span from lo to hi is inside one range.
// A request is not allowed by a rule that covers half of what it asks
// for: a read of 0 to 200 against a rule for 0 to 99 is a read of
// addresses the rule does not name, and splitting it is not this relay's
// decision to make.
func (rs ranges) covers(lo, hi int) bool {
	for _, r := range rs {
		if lo >= r.lo && hi <= r.hi {
			return true
		}
	}
	return false
}

// parseRanges reads "5", "1-16" and "0x10-0x1F" the way an engineer
// writes them.
func parseRanges(what string, in []string, max int) (ranges, error) {
	out := make(ranges, 0, len(in))
	for _, s := range in {
		text := strings.TrimSpace(s)
		if text == "" {
			return nil, fmt.Errorf("%s: an empty range", what)
		}
		lo, hi := text, text
		if i := strings.IndexByte(text, '-'); i > 0 {
			lo, hi = strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:])
		}
		l, err := parseNum(lo)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		h, err := parseNum(hi)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		if l > h {
			return nil, fmt.Errorf("%s: %q starts after it ends", what, s)
		}
		if l < 0 || h > max {
			return nil, fmt.Errorf("%s: %q is outside 0 to %d", what, s, max)
		}
		out = append(out, rng{l, h})
	}
	return out, nil
}

func parseNum(s string) (int, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 32)
		return int(v), err
	}
	return strconv.Atoi(s)
}

// valueRule is a compiled value bound: the deep inspection a plant needs.
type valueRule struct {
	registers ranges
	min, max  int
	signed    bool
	coils     *bool
}

// rule is a compiled rule.
type rule struct {
	name    string
	action  string
	comment string

	clients   []netip.Prefix
	roles     map[string]bool
	units     ranges
	functions map[byte]bool
	access    map[wire.Access]bool
	addresses ranges
	writeAddr ranges
	maxQty    int
	values    []valueRule
	schedule  *schedule
}

// schedule is when a rule is in force.
type schedule struct {
	days map[time.Weekday]bool
	// from and to are minutes past midnight in loc. to before from
	// spans midnight.
	from, to int
	loc      *time.Location
}

func (s *schedule) active(now time.Time) bool {
	if s == nil {
		return true
	}
	t := now.In(s.loc)
	if len(s.days) > 0 && !s.days[t.Weekday()] {
		// A window spanning midnight belongs to the day it started on,
		// so the small hours of Saturday are still Friday's night
		// shift.
		if s.to >= s.from {
			return false
		}
		yesterday := t.AddDate(0, 0, -1).Weekday()
		if !s.days[yesterday] {
			return false
		}
		return t.Hour()*60+t.Minute() < s.to
	}
	mins := t.Hour()*60 + t.Minute()
	if s.from == s.to {
		return true
	}
	if s.to > s.from {
		return mins >= s.from && mins < s.to
	}
	return mins >= s.from || mins < s.to
}

// Policy is the compiled listener policy.
type Policy struct {
	readOnly      bool
	units         ranges
	rules         []*rule
	defaultAllow  bool
	allow, deny   []netip.Prefix
	roleMode      string
	roleSource    string
	allowedRoles  map[string]bool
	maxFrameBytes int
	now           func() time.Time
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
		maxFrameBytes: l.MaxFrameBytes, now: now}
	if p.now == nil {
		p.now = time.Now
	}
	var err error
	if p.units, err = parseRanges("units", l.Units, 255); err != nil {
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
	if r.units, err = parseRanges("rules."+c.Name+".units", c.Units, 255); err != nil {
		return nil, err
	}
	if r.addresses, err = parseRanges("rules."+c.Name+".addresses", c.Addresses, 0xFFFF); err != nil {
		return nil, err
	}
	if r.writeAddr, err = parseRanges("rules."+c.Name+".write_addresses", c.WriteAddresses, 0xFFFF); err != nil {
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
	for i := range c.Values {
		v, err := compileValue(c.Name, &c.Values[i])
		if err != nil {
			return nil, err
		}
		r.values = append(r.values, v)
	}
	if c.Schedule != nil {
		if r.schedule, err = compileSchedule(c.Name, c.Schedule); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// functionCode reads a function code written as a name or a number.
func functionCode(s string) (byte, error) {
	if fc, ok := wire.FunctionCode(s); ok {
		return fc, nil
	}
	n, err := parseNum(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 127 {
		return 0, fmt.Errorf("%q is not a function code name or a number from 1 to 127", s)
	}
	return byte(n), nil
}

func compileValue(rule string, c *config.ModbusValueRule) (valueRule, error) {
	v := valueRule{signed: c.Signed, coils: c.Coils}
	if c.Registers != "" {
		rs, err := parseRanges("rules."+rule+".values.registers", []string{c.Registers}, 0xFFFF)
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

func compileSchedule(rule string, c *config.ModbusSchedule) (*schedule, error) {
	s := &schedule{loc: time.UTC}
	if c.Timezone != "" {
		loc, err := time.LoadLocation(c.Timezone)
		if err != nil {
			return nil, fmt.Errorf("rules.%s.schedule.timezone: %w", rule, err)
		}
		s.loc = loc
	}
	if len(c.Days) > 0 {
		s.days = map[time.Weekday]bool{}
		for _, d := range c.Days {
			wd, ok := weekday(d)
			if !ok {
				return nil, fmt.Errorf("rules.%s.schedule.days: %q is not a day", rule, d)
			}
			s.days[wd] = true
		}
	}
	from, err := clock(c.From)
	if err != nil {
		return nil, fmt.Errorf("rules.%s.schedule.from: %w", rule, err)
	}
	to, err := clock(c.To)
	if err != nil {
		return nil, fmt.Errorf("rules.%s.schedule.to: %w", rule, err)
	}
	s.from, s.to = from, to
	return s, nil
}

func weekday(s string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "mon", "monday":
		return time.Monday, true
	case "tue", "tuesday":
		return time.Tuesday, true
	case "wed", "wednesday":
		return time.Wednesday, true
	case "thu", "thursday":
		return time.Thursday, true
	case "fri", "friday":
		return time.Friday, true
	case "sat", "saturday":
		return time.Saturday, true
	case "sun", "sunday":
		return time.Sunday, true
	}
	return 0, false
}

// clock reads "HH:MM". An empty time is midnight, which with an equal
// from and to means the whole day.
func clock(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	hh, err := strconv.Atoi(h)
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	mm, err := strconv.Atoi(m)
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	if hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("%q is not a time of day", s)
	}
	return hh*60 + mm, nil
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
	if len(p.units) > 0 && !p.units.has(int(req.unit)) {
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
			if reason := r.checkValues(req); reason != "" {
				return Decision{Rule: r.name, Reason: reason, Comment: r.comment}
			}
			return Decision{Allow: true, Rule: r.name, Comment: r.comment}
		}
	}
	if p.defaultAllow {
		return Decision{Allow: true, Reason: "default_allow"}
	}
	return Decision{Reason: "no_rule"}
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
	if !r.schedule.active(now) {
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
	if len(r.units) > 0 && !r.units.has(int(req.unit)) {
		return false
	}
	if len(r.functions) > 0 && !r.functions[req.pdu.Function] {
		return false
	}
	if len(r.access) > 0 && !r.access[req.pdu.Access] {
		return false
	}
	if r.maxQty > 0 && req.pdu.HasRange && int(req.pdu.Quantity) > r.maxQty {
		return false
	}
	if len(r.addresses) > 0 {
		if !req.pdu.HasRange {
			return false
		}
		last, ok := req.pdu.Last()
		if !ok || !r.addresses.covers(int(req.pdu.Address), int(last)) {
			return false
		}
	}
	if len(r.writeAddr) > 0 {
		lo, hi, ok := writeSpan(req.pdu)
		if !ok {
			return false
		}
		if hi >= 0 && !r.writeAddr.covers(lo, hi) {
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
func (r *rule) checkValues(req request) string {
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
			if len(v.registers) == 0 || v.registers.has(base) {
				return "value_masked_write"
			}
		}
		return ""
	}
	for i, raw := range p.Registers {
		addr := base + i
		for _, v := range r.values {
			if len(v.registers) > 0 && !v.registers.has(addr) {
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
		}
	}
	for i, on := range p.Coils {
		addr := base + i
		for _, v := range r.values {
			if v.coils == nil {
				continue
			}
			if len(v.registers) > 0 && !v.registers.has(addr) {
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
		}
	}
	return ""
}

// Rules is the number of compiled rules, for the status view.
func (p *Policy) Rules() int { return len(p.rules) }
