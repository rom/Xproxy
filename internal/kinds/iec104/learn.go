package iec104

import (
	"fmt"
	"sort"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/learn"
	"github.com/rom/xproxy/internal/numrange"
)

// Learning mode for IEC 60870-5-104.
//
// The substation drawings say which points exist and which of them a control
// centre is supposed to command. The traffic says what is actually there: a
// gateway reporting points the drawings do not list, an interrogation of a
// common address nobody documented, a station sending spontaneous data far more
// often than the design says it should. A policy written from the drawings
// refuses half of it on the first shift, which is how a security control gets
// turned off and stays off -- so a listener in learning mode writes down what it
// sees and proposes a policy from that instead.
//
// What is recorded is the shape of the traffic, never the values: a setpoint's
// span is kept because it is the bound an engineer has to set, and the process
// values travelling upwards are not, because a learning report is a file that
// gets pasted into a ticket.

// maxLearnedRanges bounds the information object address ranges remembered for
// one subject, so that a station reporting ten thousand points does not produce
// a report nobody can read.
const maxLearnedRanges = 32

// maxLearnedCauses bounds the causes of transmission remembered for one
// subject. There are sixty-odd defined and a subject legitimately uses a
// handful; a subject that has used this many is a subject whose report says so
// rather than one that grows without end.
const maxLearnedCauses = 16

// learnKey identifies one subject: who, in which direction, to which station,
// doing what.
//
// The cause of transmission is deliberately not part of it. A control centre
// interrogating a station uses several causes for the same type, and a subject
// per cause would be a report nobody reads -- so the causes seen are recorded
// against the subject instead, which is also the form the policy's `causes`
// takes.
type learnKey struct {
	client string
	// up says the frame travelled from the station to the control centre.
	// Direction is part of the identity because the same type identification
	// means different things in each: an activation going down is a command,
	// and the confirmation coming back is the station answering.
	up     bool
	common uint16
	typ    wire.Type
}

// learnObs is what was seen of one subject.
type learnObs struct {
	first, last time.Time
	frames      uint64
	// denied counts the frames the policy refused (or would have refused, on a
	// listener that is learning with the policy in shadow): a subject with
	// denials is a subject the current policy and the traffic disagree about,
	// which is the first thing to read in the report.
	denied uint64
	// negative counts the negative confirmations seen travelling this way,
	// which on an upward subject is the station answering "no".
	negative uint64
	// refused counts the negative confirmations the station sent *for this
	// subject*, which is only ever set on a command travelling down: it is how
	// a learning run finds the commands the equipment itself refuses, and those
	// belong out of the policy rather than in it.
	refused uint64
	// addresses are the information object addresses named, merged as they
	// grow.
	addresses []numrange.Range
	// causes are the causes of transmission seen, and causesDropped says the
	// bound was reached.
	causes        map[wire.Cause]bool
	causesDropped bool
	// selects counts the frames that carried a select bit, which says this
	// subject uses select-before-operate and the policy ought to require it.
	selects uint64
	// test counts the frames with the test bit set. A test frame in ordinary
	// traffic is worth an engineer's attention.
	test uint64
	// minValue and maxValue are the span of the setpoint values commanded, and
	// haveValues says any frame carried one.
	minValue, maxValue float64
	haveValues         bool
}

// learner is one listener's learning run.
type learner = learn.Run[learnKey, learnObs]

// newLearner prepares the run, or nil where the section is absent or off.
func newLearner(c *learnConfig) *learner {
	if c == nil || !c.enabled {
		return nil
	}
	return learn.New(learn.Options[learnKey, learnObs]{
		Kind:     "iec104",
		Listener: c.listener,
		Path:     c.file,
		Interval: c.interval,
		Max:      c.maxSubjects,
		Render:   renderLearned,
		Less:     learnLess,
		Clone:    cloneObs,
	})
}

// learnConfig is the part of the configuration the learner needs, so that the
// constructor does not take the whole listener.
type learnConfig struct {
	enabled     bool
	listener    string
	file        string
	interval    time.Duration
	maxSubjects int
}

// learnLess orders the subjects so two runs over the same traffic produce the
// same file and a diff between them means something.
func learnLess(a, b learnKey) bool {
	if a.client != b.client {
		return a.client < b.client
	}
	if a.up != b.up {
		// Downwards first: what the control centre asks for is what an
		// engineer reads first.
		return !a.up
	}
	if a.common != b.common {
		return a.common < b.common
	}
	return a.typ < b.typ
}

// cloneObs deep-copies an observation, because the report is rendered outside
// the table's lock and a shallow copy would leave the renderer reading a slice
// and a map that a later frame is still writing to.
func cloneObs(o learnObs) learnObs {
	out := o
	if o.addresses != nil {
		out.addresses = make([]numrange.Range, len(o.addresses))
		copy(out.addresses, o.addresses)
	}
	if o.causes != nil {
		out.causes = make(map[wire.Cause]bool, len(o.causes))
		for c := range o.causes {
			out.causes[c] = true
		}
	}
	return out
}

// observeLearn records one I-frame ASDU and what was decided about it.
func (se *session) observeLearn(a *wire.ASDU, fromClient, allowed bool, now time.Time) {
	t := se.t
	if t.learner == nil || a == nil {
		return
	}
	key := learnKey{client: se.ip.String(), up: !fromClient, common: a.Common, typ: a.Type}
	setpoint, hasSetpoint := a.Setpoint()
	// A negative confirmation is the equipment saying it will not do the thing
	// it was asked to do, and it arrives travelling the other way from the ask.
	// Counted only against the answer it arrived as, it would tell an engineer
	// that confirmations come back -- which they do. What is worth knowing is
	// that *this command* is refused, so it is counted against the command's own
	// subject as well, where the proposal can act on it.
	if !fromClient && a.Negative {
		t.learner.ObserveExisting(learnKey{client: key.client, up: false,
			common: a.Common, typ: a.Type}, func(o *learnObs) { o.refused++ })
	}
	t.learner.Observe(key, func(o *learnObs, first bool) {
		if first {
			o.first = now
			o.causes = map[wire.Cause]bool{}
		}
		o.last = now
		o.frames++
		if !allowed {
			o.denied++
		}
		if a.Negative {
			o.negative++
		}
		if a.Test {
			o.test++
		}
		if a.Select {
			o.selects++
		}
		if len(o.causes) < maxLearnedCauses {
			o.causes[a.Cause] = true
		} else if !o.causes[a.Cause] {
			o.causesDropped = true
		}
		for _, addr := range a.Addresses {
			o.addresses = addLearnedRange(o.addresses, int(addr))
		}
		if hasSetpoint {
			if !o.haveValues || setpoint < o.minValue {
				o.minValue = setpoint
			}
			if !o.haveValues || setpoint > o.maxValue {
				o.maxValue = setpoint
			}
			o.haveValues = true
		}
	})
}

// addLearnedRange folds one address into the ranges, merging where it extends
// one and dropping it where the bound is reached. Past the bound the ranges
// already recorded still say what the traffic is; what is lost is precision,
// which the report says plainly by showing the count against the ranges.
func addLearnedRange(rs []numrange.Range, v int) []numrange.Range {
	for i := range rs {
		switch {
		case v >= rs[i].Lo && v <= rs[i].Hi:
			return rs
		case v == rs[i].Lo-1:
			rs[i].Lo = v
			return mergeLearnedRanges(rs)
		case v == rs[i].Hi+1:
			rs[i].Hi = v
			return mergeLearnedRanges(rs)
		}
	}
	if len(rs) >= maxLearnedRanges {
		return rs
	}
	return mergeLearnedRanges(append(rs, numrange.Range{Lo: v, Hi: v}))
}

// mergeLearnedRanges sorts and coalesces, so that a subject that saw 1, 3 and
// then 2 ends with one range rather than three.
func mergeLearnedRanges(rs []numrange.Range) []numrange.Range {
	if len(rs) < 2 {
		return rs
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Lo < rs[j].Lo })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.Lo <= last.Hi+1 {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// renderLearned writes the report: what was seen, and under it a rule set that
// permits exactly that.
//
// The rules are one per client, direction and class rather than one per subject,
// because a rule per subject would be a rule set nobody reads. The addresses and
// the causes are the ones actually used, widened to nothing -- an engineer then
// widens them on purpose, having seen what the traffic is.
func renderLearned(listener string, subjects []learn.Subject[learnKey, learnObs], st learn.Stats) string {
	var b strings.Builder
	b.WriteString(learn.Header("IEC 60870-5-104", listener, st, time.Now()))
	b.WriteString("#\n")
	b.WriteString("# Every range and cause below is what was actually used, widened to nothing.\n")
	b.WriteString("# Read it, decide what the traffic ought to be, and paste the rules under\n")
	b.WriteString("# iec104.rules. Two things to read first: a subject with denied_by_policy is\n")
	b.WriteString("# one the current policy and the traffic disagree about, and a subject with\n")
	b.WriteString("# negative_confirmations is a command the equipment itself refuses -- write\n")
	b.WriteString("# those out of the policy rather than into it.\n")
	b.WriteString("# The process values travelling upwards are deliberately not here: a\n")
	b.WriteString("# learning report is a file that gets pasted into a ticket.\n\n")

	b.WriteString("observed:\n")
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		fmt.Fprintf(&b, "  - client: %s\n", learn.Sanitise(k.client))
		fmt.Fprintf(&b, "    direction: %s\n", directionName(k.up))
		fmt.Fprintf(&b, "    common_address: %d\n", k.common)
		fmt.Fprintf(&b, "    type: %s\n", k.typ)
		if class := classOf(k.typ); class != "" {
			fmt.Fprintf(&b, "    class: %s\n", class)
		}
		fmt.Fprintf(&b, "    frames: %d\n", o.frames)
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		if o.negative > 0 {
			fmt.Fprintf(&b, "    negative_confirmations: %d\n", o.negative)
		}
		if o.refused > 0 {
			fmt.Fprintf(&b, "    refused_by_equipment: %d  # the station answered no\n", o.refused)
		}
		if o.test > 0 {
			fmt.Fprintf(&b, "    test_frames: %d\n", o.test)
		}
		if o.selects > 0 {
			fmt.Fprintf(&b, "    selected: %d  # uses select-before-operate\n", o.selects)
		}
		if causes := causeList(o.causes); causes != "" {
			fmt.Fprintf(&b, "    causes: [%s]\n", causes)
			if o.causesDropped {
				fmt.Fprintf(&b, "    causes_incomplete: true  # more than %d seen\n", maxLearnedCauses)
			}
		}
		if len(o.addresses) > 0 {
			fmt.Fprintf(&b, "    addresses: [%s]\n", rangeText(o.addresses))
		}
		if o.haveValues {
			fmt.Fprintf(&b, "    setpoint_values: {min: %s, max: %s}\n",
				valueText(o.minValue), valueText(o.maxValue))
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}
	if len(subjects) == 0 {
		b.WriteString("  []\n")
	}

	b.WriteString("\n# A rule set that permits what was seen, and nothing else.\n")
	b.WriteString("rules:\n")
	proposeRules(&b, subjects)
	return b.String()
}

// proposal is one proposed rule: the subjects of one client, direction and
// class folded together.
type proposal struct {
	client string
	up     bool
	class  string
	types  map[wire.Type]bool
	causes map[wire.Cause]bool
	addrs  []numrange.Range
}

// proposeRules folds the subjects into one rule per client, direction and class.
func proposeRules(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	type groupKey struct {
		client string
		up     bool
		class  string
	}
	var order []groupKey
	groups := map[groupKey]*proposal{}
	for _, s := range subjects {
		// A command the equipment refuses every single time is not something to
		// write a rule for: permitting it would permit a thing that cannot
		// happen, and an engineer reading the rule would think it could.
		if s.Obs.frames > 0 && s.Obs.refused >= s.Obs.frames {
			continue
		}
		gk := groupKey{client: s.Key.client, up: s.Key.up, class: classOf(s.Key.typ)}
		p, ok := groups[gk]
		if !ok {
			p = &proposal{client: s.Key.client, up: s.Key.up, class: gk.class,
				types: map[wire.Type]bool{}, causes: map[wire.Cause]bool{}}
			groups[gk] = p
			order = append(order, gk)
		}
		p.types[s.Key.typ] = true
		for c := range s.Obs.causes {
			p.causes[c] = true
		}
		for _, r := range s.Obs.addresses {
			p.addrs = addLearnedRange(p.addrs, r.Lo)
			if r.Hi != r.Lo {
				p.addrs = addLearnedRange(p.addrs, r.Hi)
			}
		}
	}
	if len(order) == 0 {
		b.WriteString("  []\n")
		return
	}
	for i, gk := range order {
		p := groups[gk]
		name := fmt.Sprintf("learned-%d-%s", i+1, p.class)
		if p.class == "" {
			name = fmt.Sprintf("learned-%d", i+1)
		}
		fmt.Fprintf(b, "  - name: %s\n", name)
		b.WriteString("    action: allow\n")
		fmt.Fprintf(b, "    clients: [%s/32]  # %s\n", learn.Sanitise(p.client), directionName(p.up))
		if p.class != "" {
			fmt.Fprintf(b, "    class: [%s]\n", p.class)
		}
		fmt.Fprintf(b, "    types: [%s]\n", typeList(p.types))
		if causes := causeList(p.causes); causes != "" {
			fmt.Fprintf(b, "    causes: [%s]\n", causes)
		}
		if len(p.addrs) > 0 {
			fmt.Fprintf(b, "    addresses: [%s]\n", rangeText(p.addrs))
		}
	}
}

// directionName says which way a frame travelled, in the words an engineer
// uses: down to the substation, or up to the control centre.
func directionName(up bool) string {
	if up {
		return "station_to_centre"
	}
	return "centre_to_station"
}

// typeList is the type identifications, by the standard's name, in order.
func typeList(types map[wire.Type]bool) string {
	out := make([]string, 0, len(types))
	for t := range types {
		out = append(out, t.String())
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// causeList is the causes of transmission, in order.
func causeList(causes map[wire.Cause]bool) string {
	if len(causes) == 0 {
		return ""
	}
	nums := make([]int, 0, len(causes))
	for c := range causes {
		nums = append(nums, int(c))
	}
	sort.Ints(nums)
	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, wire.Cause(n).String())
	}
	return strings.Join(out, ", ")
}

// rangeText is the ranges as the configuration spells them.
func rangeText(rs []numrange.Range) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Lo == r.Hi {
			out = append(out, fmt.Sprintf("%d", r.Lo))
			continue
		}
		out = append(out, fmt.Sprintf("%q", fmt.Sprintf("%d-%d", r.Lo, r.Hi)))
	}
	return strings.Join(out, ", ")
}

// valueText writes a setpoint bound without exponent notation, because the
// number is pasted into a configuration an engineer reads.
func valueText(v float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", v), "0"), ".")
}
