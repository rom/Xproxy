package s7

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	"github.com/rom/xproxy/internal/numrange"
	wire "github.com/rom/xproxy/internal/s7"
)

// Learning mode for S7comm.
//
// The drawings say which blocks a controller has. They do not say which of them
// the integrator's HMI actually reads every second, which data block the
// historian polls, or that the commissioning laptop has been reading DB1 since
// 2014. A policy written from the drawings refuses half of it on the first
// shift, which is how a security control gets turned off and stays off -- so a
// listener in learning mode writes down what it sees and proposes a policy from
// that.
//
// What is recorded is the shape of the traffic and not the process data: which
// function, which area, which block, which bytes, how many items at a time.
// The values a block holds are the plant's, and a learning report is a file that
// gets pasted into a ticket.

// maxLearnedS7Ranges bounds the byte ranges remembered per subject, so that a
// client walking a whole block does not produce a report nobody can read.
const maxLearnedS7Ranges = 32

// learnKey identifies one subject: who, doing what, to which area and block.
//
// The data block number is part of the identity rather than a recorded detail
// because that is the grain an S7 rule is written at: `dbs: ["1", "10-19"]` is
// the line an engineer argues about.
type learnKey struct {
	client string
	// op is the operation in the vocabulary `operations` is written in, because
	// a proposal in any other vocabulary is a proposal the configuration
	// refuses to load. It is empty for a request whose operation this package
	// cannot name, which is recorded -- a run has to say it happened -- but
	// never proposed: there is no rule that could be written for it.
	op   wire.Op
	area uint8
	db   uint16
}

// learnObs is what was seen of one subject.
type learnObs struct {
	first, last time.Time
	requests    uint64
	// denied counts the requests the policy refused, or would have refused on a
	// listener learning without enforcement: a subject with denials is one the
	// policy and the traffic disagree about.
	denied uint64
	// faults counts the access faults the controller itself answered with,
	// which is how a learning run finds the requests the equipment already
	// refuses -- a password-protected CPU answers exactly this. Those belong
	// out of the policy rather than in it.
	faults uint64
	// bytes are the byte ranges the items covered, merged as they grow, and
	// writeBytes the ranges written -- kept apart because that is the rule an
	// engineer reads most carefully.
	bytes, writeBytes []numrange.Range
	// transports are the transport sizes seen, by name.
	transports map[string]bool
	// maxItems is the most items one request carried, which is what
	// `max_items` is written from.
	maxItems int
	// functions are the raw function codes seen, by name. An operation covers
	// several of them -- an upload is three -- and for a request this package
	// cannot name an operation for, this is the only thing that says what
	// arrived.
	functions map[string]bool
}

type learner = learn.Run[learnKey, learnObs]

// learnConfig is the part of the configuration the learner needs.
type learnConfig struct {
	enabled     bool
	listener    string
	file        string
	interval    time.Duration
	maxSubjects int
}

func newLearner(c *learnConfig) *learner {
	if c == nil || !c.enabled {
		return nil
	}
	return learn.New(learn.Options[learnKey, learnObs]{
		Kind:     "s7",
		Listener: c.listener,
		Path:     c.file,
		Interval: c.interval,
		Max:      c.maxSubjects,
		Render:   renderLearnedS7,
		Less:     learnLessS7,
		Clone:    cloneS7Obs,
	})
}

func learnLessS7(a, b learnKey) bool {
	if a.client != b.client {
		return a.client < b.client
	}
	if a.op != b.op {
		return a.op < b.op
	}
	if a.area != b.area {
		return a.area < b.area
	}
	return a.db < b.db
}

// cloneS7Obs deep-copies an observation, because the report is rendered outside
// the table's lock and the ranges are merged in place.
func cloneS7Obs(o learnObs) learnObs {
	out := o
	out.bytes = append([]numrange.Range(nil), o.bytes...)
	out.writeBytes = append([]numrange.Range(nil), o.writeBytes...)
	out.transports = cloneNameSet(o.transports)
	out.functions = cloneNameSet(o.functions)
	return out
}

func cloneNameSet(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// observeLearn records one classic S7 request and what was decided about it.
//
// S7comm-plus is deliberately not recorded. Its policy is about opcodes and
// function codes rather than areas and blocks, and a report that mixed the two
// vocabularies would propose rules in neither.
func (t *server) observeLearn(se *session, pdu *wire.PDU, allowed bool, now time.Time) {
	if t.learner == nil || pdu == nil {
		return
	}
	client := se.ip.String()
	// An operation this package cannot name is still recorded, under the empty
	// operation, because a learning run that hid it would hide the traffic the
	// policy refuses hardest.
	op, _ := pdu.Op()
	fn := wire.FunctionNameOf(pdu.Function)
	write := op == wire.OpWrite
	items, _ := pdu.Items()
	// One subject per area and block the request touched, because a request may
	// carry items for several and a policy is written per block.
	keys := make([]learnKey, 0, len(items))
	for _, it := range items {
		if !it.Address {
			// An addressing syntax this package does not decode -- a symbolic
			// address, for instance. There is no area and no block to record,
			// and recording it under the zero values would put `area: 0` in a
			// report an engineer reads as fact.
			continue
		}
		key := learnKey{client: client, op: op, area: it.Area, db: it.DB}
		keys = append(keys, key)
		t.learner.Observe(key, func(o *learnObs, first bool) {
			startObs(o, first, now)
			o.requests++
			if !allowed {
				o.denied++
			}
			if n := len(items); n > o.maxItems {
				o.maxItems = n
			}
			o.functions[fn] = true
			o.transports[wire.TransportName(it.Transport)] = true
			o.bytes = addS7Range(o.bytes, it.Byte(), it.Last())
			if write {
				o.writeBytes = addS7Range(o.writeBytes, it.Byte(), it.Last())
			}
		})
	}
	if len(keys) == 0 {
		// A request with nothing this package can address: a setup, a block
		// function, a clock read, or one addressed symbolically. It is still a
		// subject, because the policy has an operation for it and a report that
		// dropped it would be a report with a hole where an operation was.
		key := learnKey{client: client, op: op}
		keys = append(keys, key)
		t.learner.Observe(key, func(o *learnObs, first bool) {
			startObs(o, first, now)
			o.requests++
			if !allowed {
				o.denied++
			}
			o.functions[fn] = true
		})
	}
	se.mu.Lock()
	se.learnSubjects = keys
	se.mu.Unlock()
}

// observeFault records that the controller answered an access fault, against the
// subjects the request it answers belonged to.
//
// The response is no use for this on its own: it carries the function and the
// return codes and not the area or the block, so the request is where the
// subject was known. Only a subject the run has already seen is touched --
// ObserveExisting rather than Observe -- because an answer may not invent a
// request nobody made.
func (t *server) observeFault(se *session, pdu *wire.PDU) {
	if t.learner == nil || pdu == nil {
		return
	}
	op, _ := pdu.Op()
	se.mu.Lock()
	keys := append([]learnKey(nil), se.learnSubjects...)
	se.mu.Unlock()
	hit := false
	for _, k := range keys {
		if k.op != op {
			// The answer is to a different operation than the last request this
			// session recorded, so these are not the subjects it belongs to.
			// An answer that overtook a request, or one about something nobody
			// asked for, must not add a fault to the read the HMI is doing.
			continue
		}
		if t.learner.ObserveExisting(k, func(o *learnObs) { o.faults++ }) {
			hit = true
		}
	}
	if hit {
		return
	}
	// Nothing the session last asked for matches, so the fault belongs to the
	// operation itself if this run has seen it at all. ObserveExisting and not
	// Observe: an answer may not invent a request nobody made, or a controller
	// could write subjects into the report -- and rules out of it -- by
	// answering about operations that never happened.
	t.learner.ObserveExisting(learnKey{client: se.ip.String(), op: op},
		func(o *learnObs) { o.faults++ })
}

func startObs(o *learnObs, first bool, now time.Time) {
	if first {
		o.first = now
		o.transports = map[string]bool{}
		o.functions = map[string]bool{}
	}
	o.last = now
}

// addS7Range folds one span into the ranges, merging where it touches one.
func addS7Range(rs []numrange.Range, lo, hi int) []numrange.Range {
	if hi < lo {
		hi = lo
	}
	for i := range rs {
		if lo <= rs[i].Hi+1 && hi+1 >= rs[i].Lo {
			if lo < rs[i].Lo {
				rs[i].Lo = lo
			}
			if hi > rs[i].Hi {
				rs[i].Hi = hi
			}
			return mergeS7Ranges(rs)
		}
	}
	if len(rs) >= maxLearnedS7Ranges {
		return rs
	}
	return mergeS7Ranges(append(rs, numrange.Range{Lo: lo, Hi: hi}))
}

func mergeS7Ranges(rs []numrange.Range) []numrange.Range {
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

// renderLearnedS7 writes the report: what was seen, and a rule set that permits
// exactly that.
func renderLearnedS7(listener string, subjects []learn.Subject[learnKey, learnObs], st learn.Stats) string {
	var b strings.Builder
	b.WriteString(learn.Header("S7comm", listener, st, time.Now()))
	b.WriteString("#\n")
	b.WriteString("# Every range below is the bytes actually touched, widened to nothing. Read\n")
	b.WriteString("# it, decide what the traffic ought to be, and paste the rules under s7.rules.\n")
	b.WriteString("# Two things to read first: a subject with denied_by_policy is one the current\n")
	b.WriteString("# policy and the traffic disagree about, and a subject with access_faults is a\n")
	b.WriteString("# request the controller itself refuses -- a password-protected CPU answers\n")
	b.WriteString("# exactly that -- so write those out of the policy rather than into it.\n")
	b.WriteString("# The values the blocks hold are not here: they are the plant's, and a\n")
	b.WriteString("# learning report is a file that gets pasted into a ticket.\n")
	b.WriteString("# S7comm-plus traffic is not here either; its policy is about opcodes rather\n")
	b.WriteString("# than areas and blocks, and one report cannot propose both.\n\n")

	b.WriteString("observed:\n")
	if len(subjects) == 0 {
		b.WriteString("  []\n")
	}
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		fmt.Fprintf(&b, "  - client: %s\n", learn.Sanitise(k.client))
		if k.op == "" {
			b.WriteString("    operation: unknown  # no rule can be written for this\n")
		} else {
			fmt.Fprintf(&b, "    operation: %s\n", k.op)
		}
		if k.area != 0 {
			fmt.Fprintf(&b, "    area: %s\n", wire.AreaName(k.area))
		}
		if k.db != 0 {
			fmt.Fprintf(&b, "    db: %d\n", k.db)
		}
		fmt.Fprintf(&b, "    requests: %d\n", o.requests)
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		if o.faults > 0 {
			fmt.Fprintf(&b, "    access_faults: %d  # the controller answered no\n", o.faults)
		}
		if len(o.bytes) > 0 {
			fmt.Fprintf(&b, "    bytes: [%s]\n", s7RangeText(o.bytes))
		}
		if len(o.writeBytes) > 0 {
			fmt.Fprintf(&b, "    written: [%s]\n", s7RangeText(o.writeBytes))
		}
		if fs := transportList(o.functions); fs != "" {
			fmt.Fprintf(&b, "    functions: [%s]\n", fs)
		}
		if ts := transportList(o.transports); ts != "" {
			fmt.Fprintf(&b, "    transports: [%s]\n", ts)
		}
		if o.maxItems > 0 {
			fmt.Fprintf(&b, "    max_items_seen: %d\n", o.maxItems)
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}

	b.WriteString("\n# A rule set that permits what was seen, and nothing else.\n")
	b.WriteString("rules:\n")
	proposeS7Rules(&b, subjects)
	return b.String()
}

// proposeS7Rules folds the subjects into one rule per client and operation,
// because a rule per block would be a rule set nobody reads.
func proposeS7Rules(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	type groupKey struct {
		client string
		op     wire.Op
	}
	type group struct {
		areas  map[string]bool
		dbs    map[uint16]bool
		bytes  []numrange.Range
		writes []numrange.Range
		items  int
	}
	var order []groupKey
	groups := map[groupKey]*group{}
	for _, s := range subjects {
		// A request the controller refuses every time is not something to write
		// a rule for: permitting it would permit a thing that cannot happen.
		if s.Obs.requests > 0 && s.Obs.faults >= s.Obs.requests {
			continue
		}
		// An operation with no name has no rule: `operations` is a closed
		// vocabulary, and a proposal naming something outside it would not
		// load.
		if s.Key.op == "" {
			continue
		}
		gk := groupKey{client: s.Key.client, op: s.Key.op}
		g, ok := groups[gk]
		if !ok {
			g = &group{areas: map[string]bool{}, dbs: map[uint16]bool{}}
			groups[gk] = g
			order = append(order, gk)
		}
		if s.Key.area != 0 {
			g.areas[wire.AreaName(s.Key.area)] = true
		}
		if s.Key.db != 0 {
			g.dbs[s.Key.db] = true
		}
		for _, r := range s.Obs.bytes {
			g.bytes = addS7Range(g.bytes, r.Lo, r.Hi)
		}
		for _, r := range s.Obs.writeBytes {
			g.writes = addS7Range(g.writes, r.Lo, r.Hi)
		}
		if s.Obs.maxItems > g.items {
			g.items = s.Obs.maxItems
		}
	}
	if len(order) == 0 {
		b.WriteString("  []\n")
		return
	}
	for i, gk := range order {
		g := groups[gk]
		fmt.Fprintf(b, "  - name: learned-%d-%s\n", i+1, gk.op)
		b.WriteString("    action: allow\n")
		fmt.Fprintf(b, "    clients: [%s/32]\n", learn.Sanitise(gk.client))
		fmt.Fprintf(b, "    operations: [%s]\n", gk.op)
		if names := sortedKeys(g.areas); len(names) > 0 {
			fmt.Fprintf(b, "    areas: [%s]\n", strings.Join(names, ", "))
		}
		if len(g.dbs) > 0 {
			fmt.Fprintf(b, "    dbs: [%s]\n", dbList(g.dbs))
		}
		if len(g.bytes) > 0 {
			fmt.Fprintf(b, "    addresses: [%s]\n", s7RangeText(g.bytes))
		}
		if len(g.writes) > 0 {
			fmt.Fprintf(b, "    write_addresses: [%s]\n", s7RangeText(g.writes))
		}
		if g.items > 0 {
			fmt.Fprintf(b, "    max_items: %d\n", g.items)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func transportList(m map[string]bool) string {
	return strings.Join(sortedKeys(m), ", ")
}

func dbList(m map[uint16]bool) string {
	nums := make([]int, 0, len(m))
	for n := range m {
		nums = append(nums, int(n))
	}
	sort.Ints(nums)
	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, fmt.Sprintf("%q", fmt.Sprintf("%d", n)))
	}
	return strings.Join(out, ", ")
}

func s7RangeText(rs []numrange.Range) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Lo == r.Hi {
			out = append(out, fmt.Sprintf("%q", fmt.Sprintf("%d", r.Lo)))
			continue
		}
		out = append(out, fmt.Sprintf("%q", fmt.Sprintf("%d-%d", r.Lo, r.Hi)))
	}
	return strings.Join(out, ", ")
}
