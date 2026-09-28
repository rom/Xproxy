package ntp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/ntp"
)

// Learning mode exists because nobody knows what asks a plant's time
// server for the time.
//
// The inventory says what is on the network. The traffic says what is
// actually polling, in which version, in which mode, how often, and
// whether any of it is authenticated -- and the answer is always a few
// devices nobody could name. Run this for a week and the file is the
// allow list, the version profile and the mode profile, written out ready
// to paste.
//
// A learning run decides nothing unless it is told to, and validation
// warns while it is not: a listener left in learning mode is a listener
// with no policy, and that should be a choice somebody made in writing.

// maxPolls bounds the poll intervals remembered per subject.
const maxPolls = 8

type subjectKey struct {
	client  string
	version uint8
	mode    string
}

type observation struct {
	first, last   time.Time
	packets       uint64
	denied        uint64
	nts           bool
	authenticated bool
	keyIDs        map[uint32]bool
	// polls are the intervals seen between this subject's packets,
	// rounded to a second: what a device's poll actually is rather than
	// what its manual says.
	polls    []int
	lastSeen time.Time
	// No stratum. One was recorded here and rendered nowhere, which looked like
	// a gap next to the `allow_strata` policy key -- and filling that gap would
	// have been wrong. allow_strata is the list of strata an *answer* may carry,
	// and this learner sees the client's requests: a request's stratum field is
	// the client's own, usually 0, which is the kiss-o'-death value a server
	// sends. Proposing it as a stratum this relay accepts from a server would be
	// a proposal derived from the wrong half of the conversation.
}

// Learner records what crosses the listener.
//
// The table, the interval, the counters and the atomic file write are
// internal/learn's, which every kind since IEC 104 uses. What is here is the one
// thing that is NTP's own: what a subject is, and what is worth remembering about it.
type Learner struct {
	run *learn.Run[subjectKey, observation]
}

// NewLearner prepares a learner.
func NewLearner(listener, path string, interval time.Duration, max int) *Learner {
	return &Learner{run: learn.New(learn.Options[subjectKey, observation]{
		Kind:     "ntp",
		Listener: listener,
		Path:     path,
		Interval: interval,
		Max:      max,
		Less:     lessSubject,
		Clone:    observation.clone,
		Render:   renderLearned,
	})}
}

// lessSubject orders the rows: who, in which version, in which mode.
func lessSubject(a, b subjectKey) bool {
	if a.client != b.client {
		return a.client < b.client
	}
	if a.version != b.version {
		return a.version < b.version
	}
	return a.mode < b.mode
}

// Dropped, Observed, Writes and Failures are the run's own counters, exposed
// because the status view and the tests read them.
func (l *Learner) Dropped() uint64 { return ntpCount(l, func() uint64 { return l.run.Dropped.Load() }) }
func (l *Learner) Observed() uint64 {
	return ntpCount(l, func() uint64 { return l.run.Observed.Load() })
}
func (l *Learner) Writes() uint64 { return ntpCount(l, func() uint64 { return l.run.Writes.Load() }) }
func (l *Learner) Failures() uint64 {
	return ntpCount(l, func() uint64 { return l.run.Failures.Load() })
}

func ntpCount(l *Learner, load func() uint64) uint64 {
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

// Report renders what was learned: a description of the traffic, and under it the
// three lists a policy is made of.
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
func (l *Learner) Observe(r request, d Decision, now time.Time) {
	if l == nil {
		return
	}
	key := subjectKey{client: r.client.Addr().String(),
		version: r.pkt.Version, mode: r.pkt.Mode.String()}
	l.run.Observe(key, func(o *observation, first bool) {
		if first {
			o.first = now
			o.keyIDs = map[uint32]bool{}
		}
		if !o.lastSeen.IsZero() {
			if gap := int(now.Sub(o.lastSeen).Round(time.Second).Seconds()); gap > 0 &&
				len(o.polls) < maxPolls {
				o.polls = append(o.polls, gap)
			}
		}
		o.lastSeen, o.last = now, now
		o.packets++
		if !d.Allow {
			o.denied++
		}
		if n := r.pkt.NTS(); n.Present {
			o.nts = true
		}
		if r.pkt.HasMAC {
			o.authenticated = true
			o.keyIDs[r.pkt.KeyID] = true
		}
	})
}

// clone is a copy that shares nothing with the original.
//
// A plain value copy would share the two maps and the poll slice, and the report
// is rendered outside the lock: the next packet writing a key identifier or
// appending a poll interval would be writing what the renderer is reading. A map
// written during a range over it is not a race the runtime tolerates -- it is a
// fatal "concurrent map iteration and map write" that takes the process down,
// which for a relay in front of a plant's clocks is an outage caused by writing a
// report.
func (o observation) clone() observation {
	c := o
	c.keyIDs = make(map[uint32]bool, len(o.keyIDs))
	for k, v := range o.keyIDs {
		c.keyIDs[k] = v
	}
	c.polls = append([]int(nil), o.polls...)
	return c
}

// renderLearned is the Render callback: the subjects arrive already snapshotted,
// cloned and ordered.
func renderLearned(listener string, subjects []learn.Subject[subjectKey, observation],
	st learn.Stats) string {
	keys := make([]subjectKey, 0, len(subjects))
	snap := make([]observation, 0, len(subjects))
	for _, s := range subjects {
		keys = append(keys, s.Key)
		snap = append(snap, s.Obs)
	}

	var b strings.Builder
	// "packets" rather than "events": an NTP subject counts packets, and a shared
	// header that called one an event would be slightly wrong in order to be shared.
	b.WriteString(learn.HeaderWith("NTP", listener, "packets", st, time.Now()))
	b.WriteString("# A subject is a client, a protocol version and a mode. Read it, decide what\n")
	b.WriteString("# the estate ought to be asking, and paste the lists at the end under\n")
	b.WriteString("# the listener's ntp section.\n\n")
	b.WriteString("observed:\n")
	clients := map[string]bool{}
	versions := map[uint8]bool{}
	modes := map[string]bool{}
	for i, k := range keys {
		o := snap[i]
		clients[k.client] = true
		versions[k.version] = true
		modes[k.mode] = true
		fmt.Fprintf(&b, "  - client: %s\n", k.client)
		fmt.Fprintf(&b, "    version: %d\n", k.version)
		fmt.Fprintf(&b, "    mode: %s\n", k.mode)
		fmt.Fprintf(&b, "    packets: %d\n", o.packets)
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		fmt.Fprintf(&b, "    nts_fields: %t\n", o.nts)
		fmt.Fprintf(&b, "    authenticated: %t\n", o.authenticated)
		if len(o.keyIDs) > 0 {
			fmt.Fprintf(&b, "    key_ids: [%s]\n", joinUint32(o.keyIDs))
		}
		if len(o.polls) > 0 {
			fmt.Fprintf(&b, "    poll_seconds: [%s]\n", joinInts(o.polls))
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}
	if len(keys) == 0 {
		b.WriteString("  []\n")
	}
	b.WriteString("\n# A policy permitting exactly what was observed.\n")
	b.WriteString("allow_clients: [")
	b.WriteString(strings.Join(hostPrefixes(clients), ", "))
	b.WriteString("]\n")
	fmt.Fprintf(&b, "versions: [%s]\n", joinUint8(versions))
	fmt.Fprintf(&b, "modes: [%s]\n", joinStrings(modes))
	return b.String()
}

func hostPrefixes(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for a := range in {
		if strings.Contains(a, ":") {
			out = append(out, a+"/128")
			continue
		}
		out = append(out, a+"/32")
	}
	sort.Strings(out)
	return out
}

func joinUint8(in map[uint8]bool) string {
	vals := make([]int, 0, len(in))
	for v := range in {
		vals = append(vals, int(v))
	}
	sort.Ints(vals)
	return joinInts(vals)
}

func joinUint32(in map[uint32]bool) string {
	vals := make([]int, 0, len(in))
	for v := range in {
		vals = append(vals, int(v))
	}
	sort.Ints(vals)
	return joinInts(vals)
}

func joinInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", ")
}

func joinStrings(in map[string]bool) string {
	out := make([]string, 0, len(in))
	for s := range in {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// unused keeps the wire import honest when the report grows.
var _ = wire.MinVersion
