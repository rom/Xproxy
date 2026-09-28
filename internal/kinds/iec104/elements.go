package iec104

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// What the information element says, and what this listener does about it.
//
// Three policies live here, and they pull in opposite directions on purpose.
//
// **The quality descriptor and the reported value are alerting policies.** A
// relay that refused telemetry would blind a control room, which is its own kind
// of incident and a worse one than a substituted value reaching a trend. So the
// default for both is a security event and a counter, with the reading going
// through, and `deny` exists for the estate that has decided otherwise about a
// particular bit or a particular point. Those refusals are soft: monitor and
// shadow mode carry them and record that they would not have.
//
// **The timestamp on a command is a refusing policy.** A time-tagged command
// replayed an hour later carries the hour-old timestamp with it, and nothing in
// IEC 60870-5-104 makes a station compare it against its clock. A command
// forwarded so that its age could be written down is a moved actuator, so these
// refusals are hard -- monitor mode does not shadow them, for the same reason it
// does not shadow a refused command.

// qualityPolicy is what to do about the quality bits.
type qualityPolicy struct {
	alert wire.Quality
	deny  wire.Quality
}

// timestampPolicy is the replay check on a time-tagged command.
type timestampPolicy struct {
	require     bool
	maxAge      time.Duration
	maxFuture   time.Duration
	denyInvalid bool
}

// on says whether anything here is worth evaluating, so an unconfigured
// listener does not walk the elements of every frame to conclude nothing.
func (p *timestampPolicy) on() bool {
	return p != nil && (p.require || p.maxAge > 0 || p.maxFuture > 0 || p.denyInvalid)
}

func (p *qualityPolicy) on() bool { return p != nil && (p.alert != 0 || p.deny != 0) }

// measureRule bounds what a station may report on a point.
type measureRule struct {
	name     string
	points   ranges
	commons  ranges
	types    map[wire.Type]bool
	min, max float64
	deny     bool
}

// covers says whether this bound is about this element.
func (r *measureRule) covers(a *wire.ASDU, addr uint32) bool {
	if len(r.commons) > 0 && !r.commons.has(int(a.Common)) {
		return false
	}
	if r.types != nil && !r.types[a.Type] {
		return false
	}
	return r.points.has(int(addr))
}

// compileQuality builds the quality policy.
//
// The default is an alert on substituted and nothing else. It is the bit that
// means a person typed the value in rather than an instrument measuring it, no
// HMI shows it, and a control centre acting on one is acting on somebody's
// opinion of the plant. The others are left to be asked for: `invalid` and
// `not_topical` are ordinary on a substation with a device out for maintenance,
// and a listener that alerted on them by default would teach an operator to
// ignore the alert.
func compileQuality(c *config.IEC104Quality) (*qualityPolicy, error) {
	p := &qualityPolicy{alert: wire.QualitySubstituted}
	if c == nil {
		return p, nil
	}
	if c.AlertOn != nil {
		bits, err := qualityBits("quality.alert_on", c.AlertOn)
		if err != nil {
			return nil, err
		}
		p.alert = bits
	}
	bits, err := qualityBits("quality.deny", c.Deny)
	if err != nil {
		return nil, err
	}
	p.deny = bits
	// A bit that refuses is a bit worth an alert, whatever alert_on says: the
	// refusal is the event, and an estate that named a bit in deny and left it
	// out of alert_on did not mean for the refusal to be silent.
	p.alert |= p.deny
	return p, nil
}

func qualityBits(where string, names []string) (wire.Quality, error) {
	var out wire.Quality
	for _, n := range names {
		bit, ok := wire.QualityBitOf(strings.TrimSpace(n))
		if !ok {
			return 0, fmt.Errorf("%s: %q is not a quality bit (%s)", where, n,
				strings.Join(wire.QualityNames, ", "))
		}
		out |= bit
	}
	return out, nil
}

// compileTimestamps builds the command replay check.
func compileTimestamps(c *config.IEC104Timestamps) (*timestampPolicy, error) {
	if c == nil {
		return &timestampPolicy{}, nil
	}
	p := &timestampPolicy{require: c.RequireOnCommands, denyInvalid: c.DenyInvalid,
		maxAge: c.MaxCommandAge.D(), maxFuture: c.MaxCommandFuture.D()}
	if p.maxAge < 0 || p.maxFuture < 0 {
		return nil, fmt.Errorf("timestamps: max_command_age and max_command_future must not be negative")
	}
	return p, nil
}

// compileMeasurements builds the reported-value bounds.
func compileMeasurements(in []config.IEC104Measurement) ([]*measureRule, error) {
	out := make([]*measureRule, 0, len(in))
	seen := map[string]bool{}
	for i := range in {
		c := &in[i]
		where := "measurements." + c.Name
		if c.Name == "" {
			return nil, fmt.Errorf("measurements[%d].name: required", i)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("measurements: duplicate name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Points) == 0 {
			return nil, fmt.Errorf("%s.points: required", where)
		}
		r := &measureRule{name: c.Name}
		var err error
		if r.points, err = parseRanges(where+".points", c.Points, 1<<24-1); err != nil {
			return nil, err
		}
		if r.commons, err = parseRanges(where+".common_addresses", c.CommonAddresses, 65535); err != nil {
			return nil, err
		}
		for _, name := range c.Types {
			t, ok := typeName(name)
			if !ok {
				return nil, fmt.Errorf("%s.types: %q is not a type identification", where, name)
			}
			if !wire.Decodes(t) || t.Command() || t.System() {
				return nil, fmt.Errorf("%s.types: %s carries no measured value this relay reads",
					where, strings.TrimSpace(name))
			}
			if r.types == nil {
				r.types = map[wire.Type]bool{}
			}
			r.types[t] = true
		}
		if c.Min == nil || c.Max == nil {
			return nil, fmt.Errorf("%s: min and max are both required", where)
		}
		if math.IsNaN(*c.Min) || math.IsNaN(*c.Max) {
			return nil, fmt.Errorf("%s: min and max must be numbers", where)
		}
		if *c.Min > *c.Max {
			return nil, fmt.Errorf("%s: min %v is above max %v", where, *c.Min, *c.Max)
		}
		r.min, r.max = *c.Min, *c.Max
		switch c.Action {
		case "", "alert":
		case "deny":
			r.deny = true
		default:
			return nil, fmt.Errorf("%s.action: must be alert or deny", where)
		}
		out = append(out, r)
	}
	return out, nil
}

// elementFinding is one thing wrong with one information object.
type elementFinding struct {
	reason string
	detail string
	deny   bool
	// hard marks a refusal monitor and shadow mode do not carry. Only the
	// timestamp checks on a command set it: those are about a command, and a
	// command forwarded so that its age could be written down is a moved
	// actuator.
	hard bool
}

// checkElements reads the information objects of one ASDU and reports what is
// wrong with them.
//
// It walks every object rather than only the first, because an ASDU carrying
// forty measurements carries forty chances for one of them to be the substituted
// one -- and a check that read only the first would be a check a station could
// evade by ordering its report.
func (t *server) checkElements(a *wire.ASDU, raw []byte, fromClient bool, now time.Time) []elementFinding {
	if a == nil {
		return nil
	}
	command := a.Type.Command()
	// A command's timestamp is checked only on the way down and only on an
	// activation. A station's confirmation carries the same type and the same
	// timestamp, and refusing that would leave a control centre waiting for the
	// answer to a command this relay already let through.
	checkTime := t.stamps.on() && command && fromClient && a.Cause.Commanding()
	checkValue := !command && (t.quality.on() || len(t.measures) > 0)
	if !checkTime && !checkValue {
		return nil
	}
	els := a.Elements(raw)
	if len(els) == 0 {
		if checkTime && t.stamps.require && wire.Decodes(a.Type) {
			// A time-tagged command whose elements would not decode has no
			// timestamp to offer, which is what require is about.
			if timeTagged(a.Type) {
				return []elementFinding{{reason: "command_timestamp_missing",
					detail: a.Type.String(), deny: true, hard: true}}
			}
		}
		return nil
	}
	var out []elementFinding
	for i := range els {
		e := &els[i]
		if checkTime {
			out = append(out, t.checkTime(a, e, now)...)
		}
		if checkValue {
			out = append(out, t.checkQuality(a, e)...)
			out = append(out, t.checkMeasure(a, e)...)
		}
		// One finding per frame is enough to act on, and forty of them from one
		// report is forty log lines about one station. The first is kept and the
		// rest of the objects are still walked only while nothing has been
		// found.
		if len(out) > 0 {
			break
		}
	}
	return out
}

// checkTime is the replay check on one command element.
func (t *server) checkTime(a *wire.ASDU, e *wire.Element, now time.Time) []elementFinding {
	p := t.stamps
	if !timeTagged(a.Type) {
		// A command type with no time tag has nothing to check. It is not
		// excused from the policy -- there is no timestamp for the policy to be
		// about -- and an estate that wants every command timestamped says so by
		// not allowing the untagged types.
		return nil
	}
	if !e.HasTime || !e.HasDate {
		if p.require {
			return []elementFinding{{reason: "command_timestamp_missing",
				detail: fmt.Sprintf("%s at %d", a.Type, e.Address), deny: true, hard: true}}
		}
		return nil
	}
	if e.TimeInvalid {
		if p.denyInvalid {
			return []elementFinding{{reason: "command_timestamp_invalid",
				detail: fmt.Sprintf("%s at %d", a.Type, e.Address), deny: true, hard: true}}
		}
		// The station has said its clock is not to be trusted, so its timestamp
		// is not compared against ours: an age computed from a timestamp its own
		// sender disclaims is arithmetic on nothing.
		return nil
	}
	if p.maxAge > 0 {
		if age := now.Sub(e.Time); age > p.maxAge {
			return []elementFinding{{reason: "command_timestamp_old",
				detail: fmt.Sprintf("%s at %d, %s old", a.Type, e.Address, age.Round(time.Millisecond)),
				deny:   true, hard: true}}
		}
	}
	if p.maxFuture > 0 {
		if ahead := e.Time.Sub(now); ahead > p.maxFuture {
			return []elementFinding{{reason: "command_timestamp_future",
				detail: fmt.Sprintf("%s at %d, %s ahead", a.Type, e.Address, ahead.Round(time.Millisecond)),
				deny:   true, hard: true}}
		}
	}
	return nil
}

// checkQuality is the quality policy on one monitored element.
func (t *server) checkQuality(a *wire.ASDU, e *wire.Element) []elementFinding {
	p := t.quality
	if !p.on() || !e.HasQuality {
		// No quality descriptor is not a good one. M_ME_ND_1 carries none, and
		// a policy that read absent as good would be asserting something the
		// wire never said.
		return nil
	}
	hit := e.Quality & (p.alert | p.deny)
	if hit == 0 {
		return nil
	}
	return []elementFinding{{
		reason: "quality",
		detail: fmt.Sprintf("%s at %d: %s", a.Type, e.Address, hit),
		deny:   e.Quality&p.deny != 0,
	}}
}

// checkMeasure is the reported-value bound on one monitored element.
func (t *server) checkMeasure(a *wire.ASDU, e *wire.Element) []elementFinding {
	if len(t.measures) == 0 || !e.HasValue {
		return nil
	}
	for _, r := range t.measures {
		if !r.covers(a, e.Address) {
			continue
		}
		if e.Value >= r.min && e.Value <= r.max {
			return nil
		}
		return []elementFinding{{
			reason: "measurement_range",
			detail: fmt.Sprintf("%s at %d: %g outside %g..%g (%s)",
				a.Type, e.Address, e.Value, r.min, r.max, r.name),
			deny: r.deny,
		}}
	}
	return nil
}

// timeTagged answers the one question the policy asks outside the decoder:
// whether a command that carried no readable timestamp was a type that should
// have had one. The seven command types below carry a CP56Time2a; the rest carry
// nothing, and require_on_commands has nothing to require of them.
func timeTagged(t wire.Type) bool {
	switch t {
	case wire.CScTA1, wire.CDcTA1, wire.CRcTA1, wire.CSeTA1, wire.CSeTB1, wire.CSeTC1, wire.CBoTA1:
		return true
	}
	return false
}

// decideElements applies the element policies to one frame.
//
// It runs after the rules and before the setpoint bound, which is the order the
// three questions come in: the policy says whether this client may say this to
// this station at all, this says whether what it said is sane, and the setpoint
// bound says how far it may move the point.
func (se *session) decideElements(frame *wire.Frame, fromClient bool) (string, bool) {
	t := se.t
	a := frame.ASDU
	if a == nil {
		return "", true
	}
	findings := t.checkElements(a, frame.Raw[wire.APCILen:], fromClient, time.Now())
	for _, f := range findings {
		reason := "iec104_" + f.reason
		if !f.deny {
			// An alert, and the frame goes on. This is the whole posture for
			// telemetry: an operator is told, and the control room still sees
			// the reading.
			t.alert(se.ip, reason, f.detail)
			continue
		}
		t.deny(se.ip, reason, f.detail)
		if t.enforcing() || f.hard {
			return reason, false
		}
		t.shadowed(reason, "", a)
	}
	return "", true
}
