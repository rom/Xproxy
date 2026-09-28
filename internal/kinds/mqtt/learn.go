package mqtt

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/mqtt"
)

// Learning mode for MQTT.
//
// A broker in a plant carries topics nobody wrote down. The integrator's naming
// convention is in a document from 2019, the gateway that was replaced still
// publishes under the old prefix, and the historian subscribes to something
// wider than anyone remembers agreeing to. A `publish_allow` list written from
// the convention refuses the traffic that does not follow it, which on a message
// bus means telemetry silently stops arriving -- the client keeps connecting and
// keeps publishing, and nothing on the screen changes until somebody notices a
// flat line.
//
// So a listener in learning mode writes down the topics it saw and proposes
// filters from them. The proposing is the whole difficulty, and it is worth
// being explicit about how it is done, because the easy answer is wrong.
//
// **A `#` is never proposed.** `plant/#` covers every level below `plant`,
// including the ones that do not exist yet and the one an attacker adds
// tomorrow, so a report that reached for it would have produced an allow list
// that allows the thing it was supposed to bound. What is proposed instead is a
// filter of exactly the depth that was observed, with `+` -- which matches one
// level and no more -- at the positions where the traffic actually varied:
//
//	plant/line3/press1/temperature   seen
//	plant/line3/press1/pressure      seen
//	plant/line3/press2/temperature   seen
//	                                 proposed: plant/line3/+/+
//
// The depth is part of the subject's identity for the same reason: a filter with
// `+` matches one level, so topics of different depths cannot share one filter
// without a `#`, and a report that folded them together would have had no choice
// but to widen.
//
// A filter the *client* wrote is a different thing and is recorded verbatim.
// A subscription is a filter already, so there is nothing to generalise; if the
// client subscribed to `plant/#` then `plant/#` is what it needs, and the report
// says so and flags it rather than quietly proposing something narrower that
// would break it.

const (
	// maxLearnedLevels bounds the distinct values remembered per topic
	// position. Past it the position is proposed as `+`, which is what it would
	// have been anyway -- the bound changes how much the report can show, not
	// what it proposes.
	maxLearnedLevels = 16
	// maxLearnedDepth bounds the depth a subject may have. A topic deeper than
	// this is recorded under the bound with its tail folded, because a report
	// with a column per level of a fifty-level topic is not a report.
	maxLearnedDepth = 12
	// maxLearnedFilters bounds the client-written filters remembered.
	maxLearnedFilters = 16
	// maxLearnedIDs bounds the client identifiers remembered per subject, which
	// is what `client_id_pattern` gets written from.
	maxLearnedIDs = 8
)

// learnDir is which way a topic was used.
type learnDir string

const (
	dirPublish   learnDir = "publish"
	dirSubscribe learnDir = "subscribe"
)

// learnKey identifies one subject: who, which direction, and how deep.
//
// The identity is the CONNECT username when there is one and the client's
// address otherwise. Not the client identifier: a great many MQTT clients
// generate a fresh one per connection, so a subject per identifier would be a
// report with one subject per reboot. The identifiers seen are recorded inside
// the subject instead, which is what `client_id_pattern` is written from.
//
// depth is the number of topic levels, or filterDepth for a filter the client
// wrote itself.
type learnKey struct {
	identity string
	dir      learnDir
	depth    int
}

// filterDepth marks the subject holding filters the client wrote, which are
// recorded verbatim rather than generalised.
const filterDepth = -1

// learnObs is what was seen of one subject.
type learnObs struct {
	first, last time.Time
	messages    uint64
	// denied counts what the policy refused, or would have refused on a
	// listener learning without enforcement.
	denied uint64
	// levels[i] is the distinct values seen at topic position i, and
	// levelsFull[i] whether that position outran its bound.
	levels     []map[string]bool
	levelsFull []bool
	// deeper counts the topics whose depth was past the bound, whose tail was
	// folded into the last position.
	deeper uint64
	// filters are the filters the client wrote, verbatim.
	filters     map[string]bool
	filtersFull bool
	// ids are the client identifiers seen, for `client_id_pattern`.
	ids     map[string]bool
	idsFull bool
	// maxPayload is the largest payload seen, which is what
	// `max_payload_bytes` is written from; maxQoS and minQoS the qualities of
	// service, which is what `max_qos` and `min_qos` are written from.
	maxPayload int
	maxQoS     int
	minQoS     int
	haveQoS    bool
	// retained counts the publications that asked to be retained, because
	// `allow_retain` is the one topic property a report must not guess at.
	retained uint64
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
		Kind:     "MQTT",
		Listener: c.listener,
		Path:     c.file,
		Interval: c.interval,
		Max:      c.maxSubjects,
		Render:   renderLearnedMQTT,
		Less:     learnLessMQTT,
		Clone:    cloneMQTTObs,
	})
}

func learnLessMQTT(a, b learnKey) bool {
	if a.identity != b.identity {
		return a.identity < b.identity
	}
	if a.dir != b.dir {
		return a.dir < b.dir
	}
	return a.depth < b.depth
}

func cloneMQTTObs(o learnObs) learnObs {
	out := o
	out.levels = make([]map[string]bool, len(o.levels))
	for i, m := range o.levels {
		out.levels[i] = cloneStrSet(m)
	}
	out.levelsFull = append([]bool(nil), o.levelsFull...)
	out.filters = cloneStrSet(o.filters)
	out.ids = cloneStrSet(o.ids)
	return out
}

func cloneStrSet(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// learnIdentity is what a subject is keyed on: the username the client asserted,
// or its address when it asserted none.
func (se *session) learnIdentity() string {
	if se.username != "" {
		return "user:" + learn.Sanitise(se.username)
	}
	return "addr:" + se.ip.String()
}

// topicLevels splits a topic into its levels, folding a topic deeper than the
// bound into the last position.
//
// Folding rather than dropping: a topic fifty levels deep is still traffic, and
// a report that left it out would be a report that says the traffic is narrower
// than it is. What is lost is the ability to propose a filter of that depth,
// which is said in the report.
func topicLevels(topic string) (levels []string, folded bool) {
	parts := strings.Split(topic, "/")
	if len(parts) <= maxLearnedDepth {
		return parts, false
	}
	out := append([]string(nil), parts[:maxLearnedDepth-1]...)
	return append(out, strings.Join(parts[maxLearnedDepth-1:], "/")), true
}

// observePublish records one publication and what the policy said about it.
func (se *session) observePublish(pub *wire.Publish, payload int, allowed bool, now time.Time) {
	t := se.t
	if t.learner == nil {
		return
	}
	levels, folded := topicLevels(pub.Topic)
	key := learnKey{identity: se.learnIdentity(), dir: dirPublish, depth: len(levels)}
	t.learner.Observe(key, func(o *learnObs, first bool) {
		se.startObs(o, first, now)
		o.messages++
		if !allowed {
			o.denied++
		}
		if folded {
			o.deeper++
		}
		addLevels(o, levels)
		if payload > o.maxPayload {
			o.maxPayload = payload
		}
		se.noteQoS(o, int(pub.QoS))
		if pub.Retain {
			o.retained++
		}
	})
}

// observeSubscribe records the filters of one subscription.
//
// refused is the filter the policy stopped at, empty when it allowed the packet.
// The packet is refused as a whole -- a partial grant would leave this proxy's
// idea of the session and the broker's out of step -- so only the filter that
// was actually reached is counted as denied.
func (se *session) observeSubscribe(filters []wire.Subscription, refused string, now time.Time) {
	t := se.t
	if t.learner == nil {
		return
	}
	id := se.learnIdentity()
	for _, f := range filters {
		allowed := refused == "" || f.Filter != refused
		q := int(f.Options & 0x03)
		if strings.ContainsAny(f.Filter, "+#") {
			// A filter the client wrote. There is nothing to generalise: this
			// is already the thing an allow list holds.
			t.learner.Observe(learnKey{identity: id, dir: dirSubscribe, depth: filterDepth},
				func(o *learnObs, first bool) {
					se.startObs(o, first, now)
					o.messages++
					if !allowed {
						o.denied++
					}
					addBoundedStr(o.filters, learn.Sanitise(f.Filter), maxLearnedFilters, &o.filtersFull)
					se.noteQoS(o, q)
				})
			continue
		}
		levels, folded := topicLevels(f.Filter)
		t.learner.Observe(learnKey{identity: id, dir: dirSubscribe, depth: len(levels)},
			func(o *learnObs, first bool) {
				se.startObs(o, first, now)
				o.messages++
				if !allowed {
					o.denied++
				}
				if folded {
					o.deeper++
				}
				addLevels(o, levels)
				se.noteQoS(o, q)
			})
	}
}

func (se *session) startObs(o *learnObs, first bool, now time.Time) {
	if first {
		o.first = now
		o.filters = map[string]bool{}
		o.ids = map[string]bool{}
	}
	o.last = now
	if se.clientID != "" {
		addBoundedStr(o.ids, learn.Sanitise(se.clientID), maxLearnedIDs, &o.idsFull)
	}
}

func (se *session) noteQoS(o *learnObs, q int) {
	if !o.haveQoS {
		o.minQoS, o.maxQoS, o.haveQoS = q, q, true
		return
	}
	if q > o.maxQoS {
		o.maxQoS = q
	}
	if q < o.minQoS {
		o.minQoS = q
	}
}

// addLevels folds one topic's levels into the subject's per-position sets.
func addLevels(o *learnObs, levels []string) {
	for len(o.levels) < len(levels) {
		o.levels = append(o.levels, map[string]bool{})
		o.levelsFull = append(o.levelsFull, false)
	}
	for i, l := range levels {
		addBoundedStr(o.levels[i], learn.Sanitise(l), maxLearnedLevels, &o.levelsFull[i])
	}
}

func addBoundedStr(m map[string]bool, v string, max int, full *bool) {
	if m == nil || m[v] {
		return
	}
	if len(m) >= max {
		*full = true
		return
	}
	m[v] = true
}

// proposeFilter generalises a subject's observed levels into one filter.
//
// A position with exactly one observed value stays literal. Anything else
// becomes `+`, which matches one level and no more. `#` is never produced, at
// any depth, for any subject: a filter that matched an unbounded tail is not
// something a report should derive from traffic it has seen the end of.
func proposeFilter(o *learnObs) (string, bool) {
	if len(o.levels) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(o.levels))
	for _, vals := range o.levels {
		if len(vals) == 1 {
			for v := range vals {
				parts = append(parts, v)
			}
			continue
		}
		parts = append(parts, "+")
	}
	return strings.Join(parts, "/"), true
}

// renderLearnedMQTT writes the report: what was seen, and the lists that permit
// exactly that.
func renderLearnedMQTT(listener string, subjects []learn.Subject[learnKey, learnObs], st learn.Stats) string {
	var b strings.Builder
	b.WriteString(learn.Header("MQTT", listener, st, time.Now()))
	b.WriteString("#\n")
	b.WriteString("# A subject is one client, one direction and one topic depth. The depth is\n")
	b.WriteString("# part of it because a `+` matches exactly one level, so topics of different\n")
	b.WriteString("# depths cannot share a filter -- and folding them together would leave no\n")
	b.WriteString("# way to write one but `#`.\n")
	b.WriteString("#\n")
	b.WriteString("# No `#` is proposed below, at any depth. `plant/#` covers every level under\n")
	b.WriteString("# `plant`, including the ones that do not exist yet, so an allow list built\n")
	b.WriteString("# from one allows the thing it was meant to bound. What is proposed is a\n")
	b.WriteString("# filter of the depth that was seen, with `+` where the traffic varied. The\n")
	b.WriteString("# levels observed at each position are listed, so a `+` can be narrowed by\n")
	b.WriteString("# hand where an estate knows the position is closed.\n")
	b.WriteString("#\n")
	b.WriteString("# A filter the *client* wrote is recorded verbatim, under depth: filter,\n")
	b.WriteString("# because a subscription is already a filter and there is nothing to\n")
	b.WriteString("# generalise. One containing `#` is flagged: it is the widest thing an allow\n")
	b.WriteString("# list can hold, and narrowing it is a conversation with whoever runs that\n")
	b.WriteString("# client rather than an edit to this file.\n")
	b.WriteString("#\n")
	b.WriteString("# The identity is the CONNECT username, or the address when there was none.\n")
	b.WriteString("# Not the client identifier: many clients generate a fresh one per\n")
	b.WriteString("# connection, so a subject each would be a subject per reboot. The\n")
	b.WriteString("# identifiers seen are listed instead, which is what client_id_pattern gets\n")
	b.WriteString("# written from.\n")
	b.WriteString("#\n")
	b.WriteString("# No payload is here. An MQTT payload is a process value or a command, and a\n")
	b.WriteString("# learning report is a file that gets pasted into a ticket. Payload *sizes*\n")
	b.WriteString("# are, because max_payload_bytes is written from them.\n\n")

	b.WriteString("observed:\n")
	if len(subjects) == 0 {
		b.WriteString("  []\n")
	}
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		fmt.Fprintf(&b, "  - identity: %s\n", k.identity)
		fmt.Fprintf(&b, "    direction: %s\n", k.dir)
		if k.depth == filterDepth {
			b.WriteString("    depth: filter  # the client wrote these itself\n")
		} else {
			fmt.Fprintf(&b, "    depth: %d\n", k.depth)
		}
		fmt.Fprintf(&b, "    messages: %d\n", o.messages)
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		if fs := sortedStrs(o.filters); len(fs) > 0 {
			fmt.Fprintf(&b, "    filters: [%s]\n", quoteStrs(fs))
			for _, f := range fs {
				if strings.Contains(f, "#") {
					fmt.Fprintf(&b, "    # %q is a multi-level wildcard: everything under it, now and later.\n", f)
				}
			}
			if o.filtersFull {
				fmt.Fprintf(&b, "    filters_truncated: true  # more than %d distinct filters\n", maxLearnedFilters)
			}
		}
		for i, vals := range o.levels {
			vs := sortedStrs(vals)
			line := fmt.Sprintf("    level_%d: [%s]", i, quoteStrs(vs))
			if o.levelsFull[i] {
				line += fmt.Sprintf("  # and more than %d others", maxLearnedLevels)
			}
			b.WriteString(line + "\n")
		}
		if o.deeper > 0 {
			fmt.Fprintf(&b, "    deeper_than_%d: %d  # the tail was folded into the last level\n",
				maxLearnedDepth, o.deeper)
		}
		if ids := sortedStrs(o.ids); len(ids) > 0 {
			fmt.Fprintf(&b, "    client_ids: [%s]\n", quoteStrs(ids))
			if o.idsFull {
				fmt.Fprintf(&b, "    client_ids_truncated: true  # more than %d distinct identifiers\n", maxLearnedIDs)
			}
		}
		if o.haveQoS {
			fmt.Fprintf(&b, "    qos_seen: %d..%d\n", o.minQoS, o.maxQoS)
		}
		if o.maxPayload > 0 {
			fmt.Fprintf(&b, "    max_payload_seen: %d\n", o.maxPayload)
		}
		if o.retained > 0 {
			fmt.Fprintf(&b, "    retained: %d\n", o.retained)
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}

	b.WriteString("\n# The lists that permit what was seen, and nothing else.\n")
	proposeMQTTLists(&b, subjects)
	return b.String()
}

// proposeMQTTLists writes publish_allow, subscribe_allow and the topic rules the
// payload, QoS and retain observations support.
func proposeMQTTLists(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	pub := map[string]bool{}
	sub := map[string]bool{}
	// maxPayload and the QoS span are per proposed filter, because that is the
	// grain `topics[]` is written at.
	type bounds struct {
		payload  int
		minQ     int
		maxQ     int
		haveQ    bool
		retained bool
	}
	pubBounds := map[string]*bounds{}
	for _, s := range subjects {
		var want map[string]bool
		switch s.Key.dir {
		case dirPublish:
			want = pub
		default:
			want = sub
		}
		if s.Key.depth == filterDepth {
			for f := range s.Obs.filters {
				want[f] = true
			}
			continue
		}
		f, ok := proposeFilter(&s.Obs)
		if !ok {
			continue
		}
		want[f] = true
		if s.Key.dir != dirPublish {
			continue
		}
		bd := pubBounds[f]
		if bd == nil {
			bd = &bounds{}
			pubBounds[f] = bd
		}
		if s.Obs.maxPayload > bd.payload {
			bd.payload = s.Obs.maxPayload
		}
		if s.Obs.haveQoS {
			if !bd.haveQ {
				bd.minQ, bd.maxQ, bd.haveQ = s.Obs.minQoS, s.Obs.maxQoS, true
			}
			if s.Obs.maxQoS > bd.maxQ {
				bd.maxQ = s.Obs.maxQoS
			}
			if s.Obs.minQoS < bd.minQ {
				bd.minQ = s.Obs.minQoS
			}
		}
		if s.Obs.retained > 0 {
			bd.retained = true
		}
	}
	writeList(b, "publish_allow", pub)
	writeList(b, "subscribe_allow", sub)

	if len(pubBounds) == 0 {
		return
	}
	b.WriteString("\n# What those topics carried. max_payload_bytes is the largest payload seen and\n")
	b.WriteString("# not a round number above it, so read it before pasting: a firmware topic\n")
	b.WriteString("# whose largest image so far is 3 MiB will refuse a 4 MiB one.\n")
	b.WriteString("topics:\n")
	names := make([]string, 0, len(pubBounds))
	for f := range pubBounds {
		names = append(names, f)
	}
	sort.Strings(names)
	for i, f := range names {
		bd := pubBounds[f]
		fmt.Fprintf(b, "  - name: learned-%d\n", i+1)
		fmt.Fprintf(b, "    filters: [%q]\n", f)
		if bd.payload > 0 {
			fmt.Fprintf(b, "    max_payload_bytes: %d\n", bd.payload)
		}
		if bd.haveQ {
			fmt.Fprintf(b, "    max_qos: %d\n", bd.maxQ)
			if bd.minQ > 0 {
				fmt.Fprintf(b, "    min_qos: %d\n", bd.minQ)
			}
		}
		if bd.retained {
			b.WriteString("    allow_retain: true\n")
		} else {
			b.WriteString("    # Nothing on these topics asked to be retained, so allow_retain is left\n")
			b.WriteString("    # out rather than set to false: the listener's own default decides,\n")
			b.WriteString("    # and a run that saw no retained message has not learned that none is\n")
			b.WriteString("    # wanted.\n")
		}
	}
}

func writeList(b *strings.Builder, name string, set map[string]bool) {
	ss := sortedStrs(set)
	if len(ss) == 0 {
		fmt.Fprintf(b, "%s: []\n", name)
		return
	}
	fmt.Fprintf(b, "%s:\n", name)
	for _, s := range ss {
		fmt.Fprintf(b, "  - %q\n", s)
	}
}

func sortedStrs(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func quoteStrs(ss []string) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return strings.Join(out, ", ")
}
