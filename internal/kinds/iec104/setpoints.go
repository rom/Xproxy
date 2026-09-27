package iec104

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// The value bound is what makes an IEC 104 policy a policy about the
// process rather than about the frame.
//
// A rule says a control centre may send C_SE_NB_1 to point 4711. That is a
// statement about who may act and on what. It says nothing about what may
// happen, and on this protocol what may happen is bounded only by the
// encoding: a scaled setpoint can carry anything from -32768 to 32767, and
// a short float most of the real line. A turbine governor, a tap changer or
// a reactive power setpoint driven to the end of its encoding is a fault
// that a policy about types cannot express and an RTU will not refuse.
//
// So a bound has two halves, and they are different in kind:
//
//	min / max   a statement about a value, which needs nothing
//	max_delta   a statement about a *change*, which needs to know the value now
//
// What "the value now" means here is the honest limit of the second half:
// it is the last value *this relay saw* for that point, from a setpoint it
// forwarded or a station's confirmation of one. A value changed by another
// control centre, by a local panel or by the process itself was never on
// this path, so the relay does not know it -- which is why a rule that
// needs one says what to do when there is none (on_unknown), and why the
// range bound, which needs nothing, is the one that always holds.
//
// The value is read as a float64 whatever the encoding was, because a bound
// is a statement about the process and an operator should not have to write
// it three times. What the number *means* still differs: a normalised
// setpoint is a fraction of a full scale configured in the device, which
// this relay cannot see. The load warns about a normalised bound written in
// engineering units, and the reference says it again.

// MaxSetpointPoints bounds the points whose last value is remembered. A
// substation has hundreds of setpoints, not sixty-five thousand, so a
// table this size is reached by a scan rather than by an estate.
const MaxSetpointPoints = 65536

// setpointRule is one compiled value bound.
type setpointRule struct {
	name     string
	points   ranges
	commons  ranges
	types    map[wire.Type]bool
	min, max float64
	maxDelta float64
	// refuseUnknown is on_unknown: refuse holds a command whose point has
	// no previous value, where allow carries it with the range still in
	// force.
	refuseUnknown bool
}

// compileSetpoints builds the bounds. Everything that can be wrong about
// one is wrong here, at load: a bound that would not do what its author
// meant is worse than no bound, because an operator who has written one
// stops watching the point.
func compileSetpoints(in []config.IEC104Setpoint) ([]*setpointRule, error) {
	out := make([]*setpointRule, 0, len(in))
	seen := map[string]bool{}
	for i := range in {
		c := &in[i]
		where := "setpoints." + c.Name
		if c.Name == "" {
			return nil, fmt.Errorf("setpoints[%d].name: required", i)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("setpoints: duplicate name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Points) == 0 {
			return nil, fmt.Errorf("%s.points: required", where)
		}
		r := &setpointRule{name: c.Name, maxDelta: c.MaxDelta}
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
			if kind, _ := wire.SetpointEncoding(t); kind == wire.NotASetpoint {
				return nil, fmt.Errorf("%s.types: %s carries no setpoint value", where, strings.TrimSpace(name))
			}
			if r.types == nil {
				r.types = map[wire.Type]bool{}
			}
			r.types[t] = true
		}
		if c.Min == nil || c.Max == nil {
			return nil, fmt.Errorf("%s: min and max are both required", where)
		}
		if *c.Min > *c.Max {
			return nil, fmt.Errorf("%s: min %v is above max %v", where, *c.Min, *c.Max)
		}
		if math.IsNaN(*c.Min) || math.IsNaN(*c.Max) {
			// A bound nothing can satisfy, which would refuse every
			// command to the point and look like a broken relay.
			return nil, fmt.Errorf("%s: min and max must be numbers", where)
		}
		r.min, r.max = *c.Min, *c.Max
		if c.MaxDelta < 0 {
			return nil, fmt.Errorf("%s.max_delta: must not be negative", where)
		}
		switch c.OnUnknown {
		case "", "allow":
		case "refuse":
			r.refuseUnknown = true
		default:
			return nil, fmt.Errorf("%s.on_unknown: must be allow or refuse", where)
		}
		out = append(out, r)
	}
	return out, nil
}

// covers says whether this bound is about this command.
func (r *setpointRule) covers(a *wire.ASDU, addr uint32) bool {
	if len(r.commons) > 0 && !r.commons.has(int(a.Common)) {
		return false
	}
	if r.types != nil && !r.types[a.Type] {
		return false
	}
	return r.points.has(int(addr))
}

// setpointPoint is what makes two setpoints the same setpoint: the
// station, the point, and the encoding.
//
// The encoding is in the key because the values are not comparable across
// it. A normalised setpoint is a fraction from -1 to nearly +1 and a scaled
// one an integer in the point's own unit, so a delta computed between them
// would be arithmetic on two different quantities. A point commanded in two
// encodings -- which a real point list does not do -- gets two memories and
// one on_unknown decision, which is the answer that says what the relay
// actually knows.
type setpointPoint struct {
	common uint16
	addr   uint32
	kind   wire.SetpointKind
}

// setpointState is the last value this relay saw at each point. It is per
// listener rather than per connection: the process does not reset when a
// control centre reconnects, and a delta bound that did would be a bound
// any client could clear by dropping its association.
type setpointState struct {
	mu   sync.Mutex
	last map[setpointPoint]float64
	max  int
	// unknowns counts the delta checks that needed a value this relay did
	// not have, and dropped the points the bound above refused to
	// remember. Both are visible because a policy running on less than it
	// asks for should be visible rather than silently permissive.
	unknowns, dropped uint64
}

func newSetpointState(max int) *setpointState {
	if max <= 0 || max > MaxSetpointPoints {
		max = MaxSetpointPoints
	}
	return &setpointState{last: map[setpointPoint]float64{}, max: max}
}

// pointOf identifies the point a setpoint command names, and says whether
// it named one at all.
func pointOf(a *wire.ASDU) (setpointPoint, bool) {
	if a == nil || len(a.Addresses) == 0 {
		return setpointPoint{}, false
	}
	kind, _ := wire.SetpointEncoding(a.Type)
	if kind == wire.NotASetpoint {
		return setpointPoint{}, false
	}
	return setpointPoint{common: a.Common, addr: a.Addresses[0], kind: kind}, true
}

// Observe records the value a setpoint carried.
func (s *setpointState) Observe(a *wire.ASDU, val float64) {
	if s == nil || math.IsNaN(val) {
		return
	}
	p, ok := pointOf(a)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.last[p]; !known && len(s.last) >= s.max {
		s.dropped++
		return
	}
	s.last[p] = val
}

// Last is the value last seen at a point, and whether one was.
func (s *setpointState) Last(a *wire.ASDU) (float64, bool) {
	if s == nil {
		return 0, false
	}
	p, ok := pointOf(a)
	if !ok {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, known := s.last[p]
	return v, known
}

// Forget drops what is known about a point, for the case where the relay's
// idea of the value has been contradicted: a station answering a setpoint
// with a negative confirmation did not apply it, so what this relay
// recorded on forwarding the command is not what the point holds.
func (s *setpointState) Forget(a *wire.ASDU) {
	if s == nil {
		return
	}
	if p, ok := pointOf(a); ok {
		s.mu.Lock()
		delete(s.last, p)
		s.mu.Unlock()
	}
}

// Unknown counts one delta check that had no previous value.
func (s *setpointState) Unknown() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.unknowns++
	s.mu.Unlock()
}

// Status is how many points are remembered, how many checks ran without a
// previous value, and how many points the bound refused to remember.
func (s *setpointState) Status() (int, uint64, uint64) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.last), s.unknowns, s.dropped
}

// Setpoint decides about the value a setpoint command carries.
//
// The order is range then delta, because the range needs nothing and the
// delta needs a previous value: a command outside the range is refused
// whether or not the relay knows where the point was.
func (p *Policy) Setpoint(a *wire.ASDU) Decision {
	if len(p.setpoints) == 0 || a == nil {
		return Decision{Allow: true}
	}
	val, isSetpoint := a.Setpoint()
	if !isSetpoint || len(a.Addresses) == 0 {
		return Decision{Allow: true}
	}
	addr := a.Addresses[0]
	var r *setpointRule
	for _, c := range p.setpoints {
		if c.covers(a, addr) {
			r = c
			break
		}
	}
	if r == nil {
		// No bound is about this point. Which points may be commanded at
		// all is what the rules and default_action decide; this is only
		// about the value, and inventing a bound for a point nobody
		// bounded would refuse traffic nobody asked to refuse.
		return Decision{Allow: true}
	}
	// A short float can carry NaN and the infinities, and a comparison with
	// NaN is false in both directions -- so a value bound that only asked
	// "is it below min or above max" would pass every NaN straight through
	// to the equipment. A value that cannot be shown to be inside the
	// bound is outside it.
	if math.IsNaN(val) || math.IsInf(val, 0) || val < r.min || val > r.max {
		return Decision{Rule: r.name, Reason: "iec104_setpoint_range"}
	}
	if r.maxDelta <= 0 {
		return Decision{Allow: true, Rule: r.name}
	}
	last, known := p.state.Last(a)
	if !known {
		p.state.Unknown()
		if r.refuseUnknown {
			return Decision{Rule: r.name, Reason: "iec104_setpoint_unknown"}
		}
		return Decision{Allow: true, Rule: r.name}
	}
	if math.Abs(val-last) > r.maxDelta {
		return Decision{Rule: r.name, Reason: "iec104_setpoint_delta"}
	}
	return Decision{Allow: true, Rule: r.name}
}

// setpointEffect is what a forwarded setpoint does to what this relay knows
// about the point it names.
type setpointEffect int

const (
	// learnNothing is every frame that says nothing new: a selection, a
	// deactivation, a station's report of something else.
	learnNothing setpointEffect = iota
	// learnValue records the value as the point's current one.
	learnValue
	// learnForget drops what was recorded, because it has been
	// contradicted.
	learnForget
)

// setpointLearned decides which of the three a frame is.
//
// Three things are deliberate. Only an *execute* teaches the relay
// anything: a selection the station never acted on did not move the
// process, and learning from selections would let a client walk a setpoint
// anywhere in selections nobody executed -- each one measured from the last,
// none of them ever performed. A station's positive confirmation teaches it
// too, because that is the equipment saying what it accepted. And a
// *negative* confirmation makes it forget: the command did not take effect,
// so the value recorded when the command was forwarded is not what the point
// holds, and a delta measured from it would be measured from a value the
// equipment refused.
func setpointLearned(a *wire.ASDU, fromClient bool) setpointEffect {
	if a == nil {
		return learnNothing
	}
	if _, isSetpoint := a.Setpoint(); !isSetpoint {
		return learnNothing
	}
	if fromClient {
		if a.Cause == wire.CauseActivation && !a.Select {
			return learnValue
		}
		return learnNothing
	}
	switch {
	case a.Cause != wire.CauseActCon && a.Cause != wire.CauseActTerm:
		return learnNothing
	case a.Negative:
		return learnForget
	case a.Cause == wire.CauseActCon:
		return learnValue
	}
	return learnNothing
}

// setpointDetail describes a refused value for the security event and the
// shadow ledger's sample: what was asked, at which point, against which
// bound. "A setpoint was refused" is not an audit trail; "C_SE_NB_1 act
// ca=1 ioa=4711 value=900 (0 to 40)" is.
func setpointDetail(a *wire.ASDU, r string, val float64) string {
	out := detailOf(a)
	if out != "" {
		out += " "
	}
	out += "value=" + strconv.FormatFloat(val, 'g', -1, 64)
	if r != "" {
		out += " bound=" + r
	}
	return out
}
