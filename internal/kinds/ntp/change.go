package ntp

import (
	"context"
	"fmt"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/ntp"
)

// The watcher answers a different question from every bound in the
// quality section.
//
// Those ask whether one answer is good enough: is the stratum low enough,
// the dispersion small enough, the offset inside the bound. This asks
// whether the server is still the same server, answering the same way.
//
// The difference matters because the interesting attack passes every
// static bound. A source that was a GPS clock at stratum 1 and now
// answers as something else at stratum 4 is within max_stratum 8. An
// offset that steps by fourteen seconds between two polls is within
// max_offset 30s. A dispersion that grows from a millisecond to a second
// is within max_root_dispersion 2s. A server that stops carrying NTS is
// carrying valid NTP. Each of those is the shape of a time source being
// replaced, re-pointed, or stood in front of -- and in an estate where
// logs, certificates, authentication windows and event ordering rest on
// the time, a second either way is the point of the exercise.
//
// So the watcher keeps one baseline per server and compares. It reports
// by default and refuses only when the estate says so: refusing stops the
// corrections rather than merely reporting them, which is a decision with
// its own outage in it.

// Change is what the watcher noticed.
type Change struct {
	// Reason is the counter label and the event name's tail.
	Reason string
	Detail string
}

// baseline is what one server looked like when it was last believed.
type baseline struct {
	seen bool
	// refid is the identity the server reports: the reference clock's
	// name at stratum 0 and 1, the dotted quad above.
	refid   string
	stratum uint8
	// offset and dispersion are the last measurements accepted.
	offset     time.Duration
	dispersion time.Duration
	nts        bool
	leap       wire.Leap
	// at is when this baseline was taken, on the monotonic clock.
	at time.Duration
}

// watcher holds the baselines. It is keyed by the server's address rather
// than by the backend pointer, so a pool that re-resolves and hands out a
// new backend for the same address keeps its history.
type watcher struct {
	s *server

	mu   sync.Mutex
	base map[string]*baseline
}

func newWatcher(s *server) *watcher {
	return &watcher{s: s, base: map[string]*baseline{}}
}

// watchConfig is the compiled section, with the defaults in one place.
type watchConfig struct {
	on         bool
	step       time.Duration
	jump       int
	growth     int
	refuse     bool
	maxSources int
}

func (w *watcher) cfg() watchConfig {
	c := watchConfig{on: true, step: time.Second, jump: 2, growth: 8, maxSources: 1024}
	if d := w.s.n.ChangeDetection; d != nil {
		if d.Enabled != nil {
			c.on = *d.Enabled
		}
		if d.MaxStep.D() > 0 {
			c.step = d.MaxStep.D()
		}
		if d.MaxStratumJump > 0 {
			c.jump = d.MaxStratumJump
		}
		if d.DispersionGrowth > 0 {
			c.growth = d.DispersionGrowth
		}
		c.refuse = d.Action == "refuse"
	}
	return c
}

// Enabled says whether the watching is on, for the status view and so a
// caller can skip the work.
func (w *watcher) Enabled() bool { return w != nil && w.cfg().on }

// Refusing says whether a detection refuses the answer as well as
// reporting it.
func (w *watcher) Refusing() bool { return w != nil && w.cfg().refuse }

// Check folds one measurement of one server into its baseline and reports
// every change it names. The measurement may come from a probe the
// listener made itself or from an exchange it forwarded; both say the
// same things about the server.
//
// It returns the changes rather than deciding, because what a change
// means to the traffic is the listener's policy and what it means to the
// operator is the same either way.
func (w *watcher) Check(server string, pkt *wire.Packet, offset time.Duration) []Change {
	if w == nil {
		return nil
	}
	c := w.cfg()
	if !c.on {
		return nil
	}
	// A kiss-o'-death or an unsynchronised answer carries no measurement
	// of the server's time, so folding it into the baseline would make
	// the next real answer look like a change.
	if pkt.KissOfDeath() || pkt.Unsynchronised() {
		return nil
	}
	now := time.Duration(w.s.nanos())
	next := baseline{seen: true, refid: pkt.RefIDText(), stratum: pkt.Stratum,
		offset: offset, dispersion: pkt.RootDispersion.Duration(),
		nts: pkt.NTS().Present, leap: pkt.Leap, at: now}

	w.mu.Lock()
	old := w.base[server]
	if old == nil {
		if len(w.base) >= c.maxSources {
			// The table is bounded like every other table here. A
			// listener has a handful of servers; a table this size means
			// something else is wrong, and growing without limit would
			// make this the memory leak rather than the detector.
			w.mu.Unlock()
			return nil
		}
		w.base[server] = &next
		w.mu.Unlock()
		return nil
	}
	was := *old
	// The baseline moves to what was measured whether or not a change is
	// reported: a source that really did change is the new normal, and a
	// watcher that kept the old baseline would report the same change on
	// every poll for ever.
	*old = next
	w.mu.Unlock()

	var out []Change
	add := func(reason, format string, args ...any) {
		out = append(out, Change{Reason: reason, Detail: fmt.Sprintf(format, args...)})
	}
	if was.refid != next.refid {
		add("source_changed", "the time source changed from %q to %q", was.refid, next.refid)
	}
	if d := jump(was.stratum, next.stratum); c.jump > 0 && d > c.jump {
		add("stratum_jumped", "the stratum moved from %d to %d", was.stratum, next.stratum)
	}
	if c.step > 0 && offset != 0 && was.offset != 0 && abs(next.offset-was.offset) > c.step {
		add("offset_stepped", "the offset moved by %v, from %v to %v",
			abs(next.offset-was.offset), was.offset, next.offset)
	}
	if c.growth > 0 && was.dispersion > 0 &&
		next.dispersion > was.dispersion*time.Duration(c.growth) {
		add("dispersion_grew", "the root dispersion grew from %v to %v", was.dispersion, next.dispersion)
	}
	if was.nts && !next.nts {
		add("nts_lost", "the server was carrying NTS and now is not")
	}
	if !was.leap.Announcing() && next.leap.Announcing() {
		add("leap_announced", "the server began announcing a leap second (%s)", next.leap)
	}
	return out
}

// Report writes the security event and counts each change. It is separate
// from Check so the decision and the record are one place each, and so a
// test can read the changes without reading a log.
func (w *watcher) Report(server string, changes []Change) {
	if w == nil || len(changes) == 0 {
		return
	}
	c := w.s.host.Counters()
	for _, ch := range changes {
		switch ch.Reason {
		case "source_changed":
			c.NTPSourceChanged.Add(1)
		case "stratum_jumped":
			c.NTPStratumJumped.Add(1)
		case "offset_stepped":
			c.NTPOffsetStepped.Add(1)
		case "dispersion_grew":
			c.NTPDispersionGrew.Add(1)
		case "nts_lost":
			c.NTPNTSLost.Add(1)
		case "leap_announced":
			c.NTPLeapAnnounced.Add(1)
		}
		w.s.host.Logs().SecurityEvent(context.Background(), "alert", "ntp_"+ch.Reason,
			"listener", w.s.cfg.Name, "proto", "ntp", "server", server, "detail", ch.Detail)
	}
}

// jump is the distance between two strata, as a stratum that fell and one
// that rose are the same distance.
func jump(a, b uint8) int {
	if a > b {
		return int(a - b)
	}
	return int(b - a)
}
