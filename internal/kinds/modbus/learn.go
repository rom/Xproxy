package modbus

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/numrange"
)

// Learning mode exists because nobody knows what a plant's Modbus
// traffic actually is.
//
// The drawings say what it was meant to be. The traffic says what the
// integrator left behind: a historian polling a range nobody documented,
// an HMI writing a register the drawings call read-only, a laptop that
// has been plugged in since the commissioning. A policy written from the
// drawings refuses half of it on the first shift, which is how a security
// control gets turned off and stays off.
//
// So this records what crosses the listener -- per client, role, unit and
// function code -- with the address numrange.Set and the value numrange.Set actually
// used, and writes it out as a rule set to start from. Run it for a week,
// read the file, paste the rules, turn enforcement on.

// maxObservedRanges bounds the distinct address numrange.Set held for one
// subject. Past it the numrange.Set are merged into their span, which is
// honest about being a bound rather than dropping what it cannot hold.
const maxObservedRanges = 32

// subjectKey identifies one observation: who, as what, to which device,
// doing what.
type subjectKey struct {
	client   string
	role     string
	unit     byte
	function byte
	// sub is the sub-function, for the function codes that have one, and
	// hasSub says the code does. It is part of what a subject *is* rather
	// than something recorded inside the observation, because the two
	// halves of function code 8 -- a counter poll and Force Listen Only
	// Mode -- are not one activity to be reported as a range. A report
	// that merged them would propose a rule allowing `diagnostic`, which
	// is a rule allowing an outage.
	sub    uint16
	hasSub bool
}

// subjectOf is what a request is, as a subject: who, as what, to which
// device, doing what -- to the depth the function code has.
func subjectOf(req request) subjectKey {
	k := subjectKey{client: req.client.String(), role: req.role,
		unit: req.unit, function: req.pdu.Function}
	if req.pdu.HasSubFunction {
		k.sub, k.hasSub = req.pdu.SubFunction, true
	}
	return k
}

// observation is what was seen of one subject.
type observation struct {
	first, last time.Time
	frames      uint64
	denied      uint64
	// addresses are the numrange.Set read or written, merged as they grow.
	addresses []numrange.Range
	// writeAddresses are the numrange.Set written, kept apart because that is
	// the rule an engineer reads most carefully.
	writeAddresses []numrange.Range
	// minValue and maxValue are the span of the register values written,
	// and haveValues says any write carried one.
	minValue, maxValue int
	haveValues         bool
	// coilSet and coilClear say which way coils were driven.
	coilSet, coilClear bool
	// exceptions counts the exception responses the device sent for this
	// subject, which is how a learning run finds the requests a device
	// already refuses.
	exceptions uint64
}

// Learner records traffic and writes the report.
//
// The table, the interval, the atomic counters and the atomic file write are
// internal/learn's, which every kind since IEC 104 uses. What is here is the two
// things that are Modbus's own: what a subject *is*, and the per-address value
// baseline -- which is kept beside the subjects rather than inside them because a
// value's envelope is a property of the point and not of whoever wrote it.
type Learner struct {
	run *learn.Run[subjectKey, observation]
	// base is the per-address value baseline, which is what a value policy is
	// written from.
	base *baselines
}

// NewLearner prepares a learner. The file is written on the interval and at
// shutdown.
func NewLearner(listener, path string, interval time.Duration, max int) *Learner {
	l := &Learner{base: newBaselines()}
	l.run = learn.New(learn.Options[subjectKey, observation]{
		Kind:     "modbus",
		Listener: listener,
		Path:     path,
		Interval: interval,
		Max:      max,
		Less:     lessSubject,
		Clone:    observation.clone,
		Render: func(listener string, subjects []learn.Subject[subjectKey, observation],
			st learn.Stats) string {
			return l.report(listener, subjects, st)
		},
	})
	return l
}

// lessSubject orders the rows: who, as what, to which device, doing what.
func lessSubject(a, b subjectKey) bool {
	if a.client != b.client {
		return a.client < b.client
	}
	if a.role != b.role {
		return a.role < b.role
	}
	if a.unit != b.unit {
		return a.unit < b.unit
	}
	if a.function != b.function {
		return a.function < b.function
	}
	return a.sub < b.sub
}

// Dropped, Observed, Writes and Failures are the run's own counters, exposed
// because the listener's status view and the tests read them.
func (l *Learner) Dropped() uint64 { return counter(l, func() uint64 { return l.run.Dropped.Load() }) }
func (l *Learner) Observed() uint64 {
	return counter(l, func() uint64 { return l.run.Observed.Load() })
}
func (l *Learner) Writes() uint64 { return counter(l, func() uint64 { return l.run.Writes.Load() }) }
func (l *Learner) Failures() uint64 {
	return counter(l, func() uint64 { return l.run.Failures.Load() })
}

func counter(l *Learner, load func() uint64) uint64 {
	if l == nil || l.run == nil {
		return 0
	}
	return load()
}

// Subjects is how many subjects the table holds.
func (l *Learner) Subjects() int {
	if l == nil {
		return 0
	}
	return l.run.Subjects()
}

// Report renders what was learned as YAML: a description of the traffic, and under
// it a rule set that permits exactly what was seen.
//
// The rules are deliberately one per client, role and unit rather than one per
// frame: a rule per observation would be a rule set nobody reads. The addresses are
// the ranges actually used, widened to nothing, and the value bounds are the values
// actually written -- which an engineer then widens on purpose, having seen what the
// traffic is.
func (l *Learner) Report() string {
	if l == nil {
		return ""
	}
	return l.run.Report()
}

// Write replaces the file atomically.
func (l *Learner) Write() error {
	if l == nil {
		return nil
	}
	return l.run.Write()
}

// Start runs the periodic write.
func (l *Learner) Start(onError func(error)) {
	if l == nil {
		return
	}
	l.run.Start(onError)
}

// Stop ends the loop and writes the report one last time.
func (l *Learner) Stop() error {
	if l == nil {
		return nil
	}
	return l.run.Stop()
}

// Observe records one request and what was decided about it.
func (l *Learner) Observe(req request, allowed bool, now time.Time) {
	if l == nil {
		return
	}
	key := subjectOf(req)
	p := req.pdu
	// The per-address baseline, outside the subject table because it is keyed on
	// the point rather than on who wrote it.
	l.base.observe(req.unit, p, now)
	l.run.Observe(key, func(o *observation, first bool) {
		if first {
			o.first = now
			o.minValue, o.maxValue = 1<<30, -(1 << 30)
		}
		o.last = now
		o.frames++
		if !allowed {
			o.denied++
		}
		if p.HasRange {
			if last, ok := p.Last(); ok {
				o.addresses = addRange(o.addresses, int(p.Address), int(last))
			}
		}
		if lo, hi, ok := writeSpan(p); ok && hi >= 0 {
			o.writeAddresses = addRange(o.writeAddresses, lo, hi)
		}
		// carriesValues decides what counts as a value: a coil write's Registers
		// holds 0xFF00, a masked write's holds two masks and a diagnostic's holds
		// a sub-function argument. Recording any of them here reported a
		// values_written span the plant never wrote -- 65280..65280 for a coil
		// somebody switched on.
		if carriesValues(p.Function) {
			for _, v := range p.Registers {
				val := int(v)
				o.haveValues = true
				if val < o.minValue {
					o.minValue = val
				}
				if val > o.maxValue {
					o.maxValue = val
				}
			}
		}
		for _, on := range p.Coils {
			if on {
				o.coilSet = true
			} else {
				o.coilClear = true
			}
		}
	})
}

// ObserveException records that the device refused a request, which is
// the other half of what a learning run is for: the requests a master
// makes and the device already rejects are the ones to write out of the
// policy rather than into it.
func (l *Learner) ObserveException(req request, now time.Time) {
	if l == nil {
		return
	}
	key := subjectOf(req)
	// ObserveExisting rather than Observe: an exception belongs to a request this
	// run already recorded, and creating a subject from the answer alone would
	// invent one the run never saw asked for.
	l.run.ObserveExisting(key, func(o *observation) {
		o.exceptions++
		o.last = now
	})
}

// addRange merges a range into a set, keeping it bounded. Overlapping and
// adjacent numrange.Set become one, and past the bound the whole set collapses
// to its span -- which is wider than the truth and says so, rather than
// forgetting the parts that did not fit.
func addRange(rs []numrange.Range, lo, hi int) []numrange.Range {
	for i := range rs {
		if lo <= rs[i].Hi+1 && hi+1 >= rs[i].Lo {
			if lo < rs[i].Lo {
				rs[i].Lo = lo
			}
			if hi > rs[i].Hi {
				rs[i].Hi = hi
			}
			return mergeRanges(rs)
		}
	}
	rs = append(rs, numrange.Range{Lo: lo, Hi: hi})
	if len(rs) > maxObservedRanges {
		span := rs[0]
		for _, r := range rs[1:] {
			if r.Lo < span.Lo {
				span.Lo = r.Lo
			}
			if r.Hi > span.Hi {
				span.Hi = r.Hi
			}
		}
		return []numrange.Range{span}
	}
	return mergeRanges(rs)
}

func mergeRanges(rs []numrange.Range) []numrange.Range {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Lo < rs[j].Lo })
	out := rs[:0]
	for _, r := range rs {
		if n := len(out); n > 0 && r.Lo <= out[n-1].Hi+1 {
			if r.Hi > out[n-1].Hi {
				out[n-1].Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// clone is a copy that shares nothing with the original.
//
// A plain value copy would not be. The range sets are slices, and addRange
// merges in place -- rs[i].Lo = lo, and mergeRanges writes through rs[:0] -- so
// a copy that shared their backing arrays would be read by the renderer, outside
// the lock, while the next request rewrote it. A data race, and a report that
// could name a range half way through being merged.
func (o observation) clone() observation {
	c := o
	c.addresses = append([]numrange.Range(nil), o.addresses...)
	c.writeAddresses = append([]numrange.Range(nil), o.writeAddresses...)
	return c
}

// report is the Render callback: the subjects arrive already snapshotted, cloned
// and ordered, and the baselines are read here because they are keyed on the point
// rather than on the subject.
func (l *Learner) report(listener string, subjects []learn.Subject[subjectKey, observation],
	st learn.Stats) string {
	keys := make([]subjectKey, 0, len(subjects))
	snapshot := make([]observation, 0, len(subjects))
	for _, s := range subjects {
		keys = append(keys, s.Key)
		snapshot = append(snapshot, s.Obs)
	}
	baseKeys, basePts, baseDropped := l.base.snapshot()

	var b strings.Builder
	// "frames" rather than "events": a Modbus subject counts frames, and a shared
	// header that called one an event would be slightly wrong in order to be shared.
	b.WriteString(learn.HeaderWith("Modbus", listener, "frames", st, time.Now()))
	b.WriteString("# Every range below is what was actually used, widened to nothing. Read it,\n")
	b.WriteString("# decide what the traffic ought to be, and paste the rules under modbus.rules.\n")
	b.WriteString("# A subject whose exceptions are not zero is a request the device itself\n")
	b.WriteString("# refuses: write those out of the policy rather than into it.\n\n")
	b.WriteString("observed:\n")
	for i, k := range keys {
		o := snapshot[i]
		fmt.Fprintf(&b, "  - client: %s\n", k.client)
		if k.role != "" {
			fmt.Fprintf(&b, "    role: %s\n", k.role)
		}
		fmt.Fprintf(&b, "    unit: %d\n", k.unit)
		fmt.Fprintf(&b, "    function: %s\n", wire.FunctionName(k.function))
		access, _ := wire.AccessOf(k.function)
		fmt.Fprintf(&b, "    access: %s\n", access)
		if k.hasSub {
			fmt.Fprintf(&b, "    sub_function: %s\n", wire.SubName(k.function, k.sub))
			if e, ok := wire.SubEffectOf(k.function, k.sub); ok {
				fmt.Fprintf(&b, "    effect: %s\n", e)
			}
		}
		fmt.Fprintf(&b, "    frames: %d\n", o.frames)
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		if o.exceptions > 0 {
			fmt.Fprintf(&b, "    device_exceptions: %d\n", o.exceptions)
		}
		if len(o.addresses) > 0 {
			fmt.Fprintf(&b, "    addresses: [%s]\n", rangeList(o.addresses))
		}
		if len(o.writeAddresses) > 0 {
			fmt.Fprintf(&b, "    write_addresses: [%s]\n", rangeList(o.writeAddresses))
		}
		if o.haveValues {
			fmt.Fprintf(&b, "    values_written: {min: %d, max: %d}  # across every address this subject wrote; the per-address envelopes are below\n",
				o.minValue, o.maxValue)
		}
		if o.coilSet || o.coilClear {
			fmt.Fprintf(&b, "    coils_written: {set: %t, cleared: %t}\n", o.coilSet, o.coilClear)
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}
	if len(keys) == 0 {
		b.WriteString("  []\n")
	}
	b.WriteString("\n# A rule set permitting exactly what was observed.\n")
	b.WriteString("rules:\n")
	for i, k := range keys {
		o := snapshot[i]
		if o.frames == 0 {
			continue
		}
		// The function and sub-function names are already identifiers, so
		// only the client address is sanitised: a name run through
		// sanitise as well would have read_holding_registers in it as
		// read-holding-registers, which is not what the rule's functions
		// list says two lines below.
		name := wire.FunctionName(k.function)
		if k.hasSub {
			name += "_" + wire.SubName(k.function, k.sub)
		}
		fmt.Fprintf(&b, "  - name: learned-%s-u%d-%s\n", sanitise(k.client), k.unit, name)
		b.WriteString("    action: allow\n")
		fmt.Fprintf(&b, "    clients: [%s/32]\n", k.client)
		if k.role != "" {
			fmt.Fprintf(&b, "    roles: [%s]\n", k.role)
		}
		fmt.Fprintf(&b, "    units: [%d]\n", k.unit)
		fmt.Fprintf(&b, "    functions: [%s]\n", wire.FunctionName(k.function))
		// The sub-function goes into the rule as well as into the
		// observation, and not only because it is more exact. A listener
		// refuses the sub-functions that stop a device to a rule that did
		// not name them, so a learned rule that named the function code
		// alone would be a rule that does not permit the traffic it was
		// generated from -- and the difference would show up on the shift
		// after enforcement went on rather than here.
		switch {
		case k.hasSub && k.function == wire.FCDiagnostic:
			fmt.Fprintf(&b, "    diagnostics: [%s]\n", wire.SubName(k.function, k.sub))
		case k.hasSub && k.function == wire.FCUMAS:
			fmt.Fprintf(&b, "    umas_commands: [%s]\n", wire.SubName(k.function, k.sub))
		case k.hasSub:
			fmt.Fprintf(&b, "    effects: [%s]\n", subEffectName(k))
		}
		if len(o.addresses) > 0 {
			fmt.Fprintf(&b, "    addresses: [%s]\n", rangeList(o.addresses))
		}
		if len(o.writeAddresses) > 0 {
			fmt.Fprintf(&b, "    write_addresses: [%s]\n", rangeList(o.writeAddresses))
		}
		if o.exceptions > 0 {
			fmt.Fprintf(&b, "    comment: \"the device refused %d of these\"\n", o.exceptions)
		}
	}
	if len(keys) == 0 {
		b.WriteString("  []\n")
	}
	renderBaselines(&b, baseKeys, basePts, baseDropped)
	return b.String()
}

// subEffectName is the effect of a subject's sub-function, for the one
// function code that has sub-functions and no selector of its own: the
// encapsulated interface, whose MEI type is named by what it does because
// a rule about "the CANopen tunnel" is a rule about a tunnel.
func subEffectName(k subjectKey) string {
	e, ok := wire.SubEffectOf(k.function, k.sub)
	if !ok {
		return string(wire.SubUnknown)
	}
	return string(e)
}

// rangeList renders numrange.Set the way the policy reads them.
func rangeList(rs []numrange.Range) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Lo == r.Hi {
			parts = append(parts, fmt.Sprintf("%d", r.Lo))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
	}
	return strings.Join(parts, ", ")
}

// sanitise makes an address usable in a rule name.
func sanitise(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}
