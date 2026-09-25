package iec104

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/netutil"
)

// The policy is written in the protocol's own terms, because those terms
// are what a grid operator's documentation and a substation's point list
// are written in: the common address (which station), the type
// identification (what this is), the cause of transmission (why it was
// sent), the originator address (which control centre) and the information
// object address (which point).
//
// Rules are ordered and the first match decides, with one exception that
// is deliberate: monitor_only on the listener is checked before any rule
// and cannot be overridden by one. A monitor-only relay that a single rule
// could command through is not a monitor-only relay, and the person who
// asked for it asked for the property rather than for a default.

// Decision is what the policy decided about one frame.
type Decision struct {
	// Allow says the frame may go on.
	Allow bool
	// Rule is the rule that decided, or "" for a default.
	Rule string
	// Reason is why, as a stable label shared by the counters and the
	// security log.
	Reason string
	// Observed says a rule matched with action observe: the frame was
	// recorded and the search carried on, so this is not the decision.
	Observed bool
}

// rng is an inclusive numeric range, which is how every list in this
// policy is written.
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

// parseRanges reads "5", "1-16" and "0x10-0x1F" the way an engineer writes
// them.
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

func prefixes(what string, in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// schedule is a compiled time window.
type schedule struct {
	days     [7]bool
	anyDay   bool
	from, to int // minutes since midnight; equal means the whole day
	loc      *time.Location
}

func compileSchedule(c *config.ModbusSchedule) (*schedule, error) {
	if c == nil {
		return nil, nil
	}
	s := &schedule{loc: time.UTC, anyDay: len(c.Days) == 0}
	for _, d := range c.Days {
		i, ok := dayIndex(d)
		if !ok {
			return nil, fmt.Errorf("schedule.days: %q is not a day", d)
		}
		s.days[i] = true
	}
	var err error
	if s.from, err = clockMinutes(c.From); err != nil {
		return nil, err
	}
	if s.to, err = clockMinutes(c.To); err != nil {
		return nil, err
	}
	if c.Timezone != "" {
		if s.loc, err = time.LoadLocation(c.Timezone); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func dayIndex(d string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "sun":
		return 0, true
	case "mon":
		return 1, true
	case "tue":
		return 2, true
	case "wed":
		return 3, true
	case "thu":
		return 4, true
	case "fri":
		return 5, true
	case "sat":
		return 6, true
	}
	return 0, false
}

func clockMinutes(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, fmt.Errorf("schedule: %q is not HH:MM", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("schedule: %q is not a time of day", s)
	}
	return h*60 + m, nil
}

// inForce says whether a schedule includes a moment. A window whose end is
// before its start spans midnight, which is how a night shift is written.
func (s *schedule) inForce(now time.Time) bool {
	if s == nil {
		return true
	}
	t := now.In(s.loc)
	if !s.anyDay && !s.days[int(t.Weekday())] {
		return false
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

// rule is one compiled rule.
type rule struct {
	name    string
	action  string
	clients []netip.Prefix
	commons ranges
	origins ranges
	types   map[wire.Type]bool
	classes map[string]bool
	causes  map[wire.Cause]bool
	addrs   ranges
	maxObj  int
	// sel is "", "select" or "execute": which half of a two-step command
	// this rule is about.
	sel   string
	sched *schedule
}

// Policy is the compiled listener policy.
type Policy struct {
	monitorOnly  bool
	commons      ranges
	rules        []*rule
	defaultAllow bool
	allow, deny  []netip.Prefix
	controls     map[wire.Control]bool
	now          func() time.Time
}

// request is what the policy decides about: a parsed frame and who sent it.
type request struct {
	client netip.Addr
	frame  *wire.Frame
}

// compile builds the policy. Everything that can be wrong about a rule is
// wrong here, at load, rather than at the first frame that matches it.
func compile(l *config.IEC104Listener, now func() time.Time) (*Policy, error) {
	p := &Policy{monitorOnly: l.MonitorOnly, defaultAllow: l.DefaultAction == "allow", now: now}
	if p.now == nil {
		p.now = time.Now
	}
	var err error
	if p.commons, err = parseRanges("common_addresses", l.CommonAddresses, 65535); err != nil {
		return nil, err
	}
	if p.allow, err = prefixes("allow_clients", l.AllowClients); err != nil {
		return nil, err
	}
	if p.deny, err = prefixes("deny_clients", l.DenyClients); err != nil {
		return nil, err
	}
	if len(l.AllowControls) > 0 {
		p.controls = map[wire.Control]bool{}
		for _, name := range l.AllowControls {
			c, ok := wire.ControlOf(strings.TrimSpace(name))
			if !ok {
				return nil, fmt.Errorf("allow_controls: %q is not a control function", name)
			}
			p.controls[c] = true
			// A confirmation is the answer to its own activation, and a
			// policy that named the activation and not the confirmation
			// would refuse the station's reply. Naming one names the pair.
			p.controls[confirmationOf(c)] = true
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

// confirmationOf pairs an activation with its confirmation, and a
// confirmation with itself.
func confirmationOf(c wire.Control) wire.Control {
	switch c {
	case wire.StartDTAct:
		return wire.StartDTCon
	case wire.StopDTAct:
		return wire.StopDTCon
	case wire.TestFRAct:
		return wire.TestFRCon
	}
	return c
}

func compileRule(c *config.IEC104Rule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, maxObj: c.MaxObjects, sel: c.Select}
	if r.action == "" {
		r.action = "allow"
	}
	var err error
	where := "rules." + c.Name
	if r.clients, err = prefixes(where+".clients", c.Clients); err != nil {
		return nil, err
	}
	if r.commons, err = parseRanges(where+".common_addresses", c.CommonAddresses, 65535); err != nil {
		return nil, err
	}
	if r.origins, err = parseRanges(where+".originators", c.Originators, 255); err != nil {
		return nil, err
	}
	if r.addrs, err = parseRanges(where+".addresses", c.Addresses, 1<<24-1); err != nil {
		return nil, err
	}
	if len(c.Types) > 0 {
		r.types = map[wire.Type]bool{}
		for _, name := range c.Types {
			t, ok := typeName(name)
			if !ok {
				return nil, fmt.Errorf("%s.types: %q is not a type identification", where, name)
			}
			r.types[t] = true
		}
	}
	if len(c.Class) > 0 {
		r.classes = map[string]bool{}
		for _, cl := range c.Class {
			switch cl {
			case "monitoring", "command", "system", "parameter", "file":
				r.classes[cl] = true
			default:
				return nil, fmt.Errorf("%s.class: %q is not a class", where, cl)
			}
		}
	}
	if len(c.Causes) > 0 {
		r.causes = map[wire.Cause]bool{}
		for _, name := range c.Causes {
			cs, ok := causeName(name)
			if !ok {
				return nil, fmt.Errorf("%s.causes: %q is not a cause of transmission", where, name)
			}
			r.causes[cs] = true
		}
	}
	if r.sched, err = compileSchedule(c.Schedule); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	return r, nil
}

// typeName reads a type identification by the standard's name or by
// number.
func typeName(s string) (wire.Type, bool) {
	if t, ok := wire.TypeOf(strings.TrimSpace(s)); ok {
		return t, true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 1 && n <= 255 {
		return wire.Type(n), true
	}
	return 0, false
}

// causeName reads a cause of transmission by name or by number.
func causeName(s string) (wire.Cause, bool) {
	if c, ok := wire.CauseOf(strings.TrimSpace(s)); ok {
		return c, true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 1 && n <= 63 {
		return wire.Cause(n), true
	}
	return 0, false
}

// classOf names what a type does, in the words a rule is written in.
func classOf(t wire.Type) string {
	switch {
	case t.Monitoring():
		return "monitoring"
	case t.Command():
		return "command"
	case t.System():
		return "system"
	case t >= 110 && t <= 113:
		return "parameter"
	case t >= 120 && t <= 127:
		return "file"
	}
	return ""
}

// Client decides whether a controlling station may connect at all. It is
// separate from Decide because it happens before a frame exists, and
// because it is not policy in the shadow sense: an address that may not
// reach a substation is refused whether or not the rest is enforced.
func (p *Policy) Client(a netip.Addr) bool {
	if netutil.Contains(p.deny, a) {
		return false
	}
	if len(p.allow) > 0 {
		return netutil.Contains(p.allow, a)
	}
	return true
}

// Control decides about a U-format frame: the start, stop and test
// functions that carry no data.
//
// STOPDT_act is the interesting one. It stops data transfer, so a client
// that may send it can blind a control room without refusing a single
// command -- and a relay whose policy only looked at ASDUs would never see
// it.
func (p *Policy) Control(c wire.Control) Decision {
	if p.controls == nil {
		return Decision{Allow: true}
	}
	if p.controls[c] {
		return Decision{Allow: true}
	}
	return Decision{Reason: "iec104_control"}
}

// Decide applies the policy to one I-format frame.
func (p *Policy) Decide(req request) Decision {
	a := req.frame.ASDU
	if a == nil {
		// Not an I frame, or one whose ASDU could not be read. The reader
		// refuses the second case before this, so this is the first.
		return Decision{Allow: true}
	}
	// monitor_only first, and not overridable: a relay that carries
	// telemetry up and nothing down.
	if p.monitorOnly && !a.Type.Monitoring() && a.Cause.Commanding() {
		return Decision{Reason: "iec104_monitor_only"}
	}
	if len(p.commons) > 0 && !p.commons.has(int(a.Common)) {
		return Decision{Reason: "iec104_common_address"}
	}
	now := p.now()
	for _, r := range p.rules {
		if !r.matches(req, now) {
			continue
		}
		switch r.action {
		case "deny":
			return Decision{Rule: r.name, Reason: "iec104_rule"}
		case "observe":
			// Recorded, and the search carries on: this is how a rule is
			// tried on live traffic before it decides anything.
			continue
		default:
			return Decision{Allow: true, Rule: r.name}
		}
	}
	if p.defaultAllow {
		return Decision{Allow: true}
	}
	return Decision{Reason: "iec104_default_deny"}
}

// matches says whether a rule covers this frame.
func (r *rule) matches(req request, now time.Time) bool {
	a := req.frame.ASDU
	if !r.sched.inForce(now) {
		return false
	}
	if len(r.clients) > 0 && !netutil.Contains(r.clients, req.client) {
		return false
	}
	if len(r.commons) > 0 && !r.commons.has(int(a.Common)) {
		return false
	}
	if len(r.origins) > 0 && !r.origins.has(int(a.Originator)) {
		return false
	}
	if r.types != nil && !r.types[a.Type] {
		return false
	}
	if r.classes != nil && !r.classes[classOf(a.Type)] {
		return false
	}
	if r.causes != nil && !r.causes[a.Cause] {
		return false
	}
	switch r.sel {
	case "select":
		if !a.Select {
			return false
		}
	case "execute":
		// The second half of a two-step command, which is a command
		// activation without the select bit. A monitoring ASDU has no
		// select bit at all and is not an execute.
		if a.Select || !a.Type.Command() {
			return false
		}
	}
	if r.maxObj > 0 && a.Objects > r.maxObj {
		return false
	}
	if len(r.addrs) > 0 {
		if len(a.Addresses) == 0 {
			// A rule about addresses cannot match a frame that names
			// none, and forwarding on the strength of a rule whose
			// condition was not checked would be worse than looking at
			// the next rule.
			return false
		}
		for _, at := range a.Addresses {
			if !r.addrs.has(int(at)) {
				return false
			}
		}
	}
	return true
}
