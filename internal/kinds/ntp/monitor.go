package ntp

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/ntp"
)

// The monitor is the half of this listener that a client could not do for
// itself.
//
// A client asks one server and believes it. A relay asks every server the
// estate has, measures each the same way, and can therefore answer the
// question that matters: do they agree? A server that is reachable,
// synchronised, authenticated and wrong is the case every other check
// passes, and comparison is the only thing that catches it.
//
// Four states, kept apart because the operator's next action differs:
//
//	unreachable -- no answer at all
//	unsynchronised -- it answers and says not to use its time
//	suspect -- it answers, claims to be fine, and disagrees with its peers
//	healthy -- it answers, claims to be fine, and agrees
//
// The transitions have hysteresis. One slow answer on a busy network is
// not a fault, and a relay that moved every client in a plant on one
// sample would be an outage generator with a health check attached.

// State is a server's state as the monitor sees it.
type State string

const (
	StateUnknown        State = "unknown"
	StateHealthy        State = "healthy"
	StateUnsynchronised State = "unsynchronised"
	StateSuspect        State = "suspect"
	StateUnreachable    State = "unreachable"
)

// Health is one server's measured state.
type Health struct {
	State State
	// Offset and Delay are the smoothed measurements.
	Offset, Delay time.Duration
	// RootDispersion is the server's own statement of its error.
	RootDispersion time.Duration
	Stratum        uint8
	// Since is when this state began, on the monotonic clock.
	Since time.Duration
	// Reason says why a state that is not healthy is not.
	Reason string
	// Probes and Failures count what the measurement is made of.
	Probes, Failures uint64
}

// Monitor probes the servers and decides about their time.
type Monitor struct {
	s *server
	// good and bad count consecutive results, which is where the
	// hysteresis lives.
	good, bad []int
	// smoothed offsets and delays, exponentially weighted.
	offset, delay []time.Duration
	// firstBad is when a backend first went bad, for the holdover bound.
	firstBad []time.Duration
	probes   atomic.Uint64
	alerts   atomic.Uint64
}

// NewMonitor prepares the monitor. The backends are opened lazily, so it
// sizes itself on first use.
func NewMonitor(s *server) *Monitor { return &Monitor{s: s} }

func (m *Monitor) interval() time.Duration {
	if q := m.s.n.Quality; q != nil && q.ProbeInterval.D() > 0 {
		return q.ProbeInterval.D()
	}
	return 64 * time.Second
}

func (m *Monitor) healthyAfter() int {
	if q := m.s.n.Quality; q != nil && q.HealthyAfter > 0 {
		return q.HealthyAfter
	}
	return 3
}

func (m *Monitor) unhealthyAfter() int {
	if q := m.s.n.Quality; q != nil && q.UnhealthyAfter > 0 {
		return q.UnhealthyAfter
	}
	return 3
}

func (m *Monitor) maxDisagreement() time.Duration {
	if q := m.s.n.Quality; q != nil && q.MaxDisagreement.D() > 0 {
		return q.MaxDisagreement.D()
	}
	return 100 * time.Millisecond
}

// run probes on the interval until the listener stops.
func (m *Monitor) run() {
	if q := m.s.n.Quality; q != nil && q.CompareSources != nil && !*q.CompareSources {
		return
	}
	t := time.NewTicker(m.interval())
	defer t.Stop()
	for {
		select {
		case <-m.s.done:
			return
		case <-t.C:
		}
		m.round()
	}
}

// round probes every server once and then compares them.
func (m *Monitor) round() {
	m.s.mu.Lock()
	if len(m.s.backends) == 0 {
		// Nothing has asked for a server yet; open them so the monitor
		// has something to measure before the first client arrives.
		_ = m.s.openBackends()
	}
	backends := append([]*backend(nil), m.s.backends...)
	m.s.mu.Unlock()
	m.resize(len(backends))
	type sample struct {
		b      *backend
		offset time.Duration
		ok     bool
	}
	samples := make([]sample, 0, len(backends))
	for i, b := range backends {
		pkt, offset, rtt, err := m.s.probe(b)
		m.probes.Add(1)
		m.s.host.Counters().NTPProbes.Add(1)
		if err != nil {
			m.fail(i, b, StateUnreachable, err.Error())
			continue
		}
		switch {
		case pkt.Unsynchronised():
			m.fail(i, b, StateUnsynchronised, "the server says its clock is not synchronised")
			continue
		case pkt.Stratum >= 16:
			m.fail(i, b, StateUnsynchronised, fmt.Sprintf("stratum %d", pkt.Stratum))
			continue
		case pkt.KissOfDeath():
			m.fail(i, b, StateUnreachable, "kiss-o'-death: "+pkt.KissCode())
			continue
		}
		m.offset[i] = smooth(m.offset[i], offset)
		m.delay[i] = smooth(m.delay[i], rtt)
		samples = append(samples, sample{b: b, offset: m.offset[i], ok: true})
		m.pass(i, b, pkt)
	}
	// The comparison. With three or more sources the median is the
	// estate's opinion and a source far from it is the suspect one; with
	// two that disagree neither can be called wrong, so both are marked
	// and the log says exactly that.
	if len(samples) < 2 {
		return
	}
	offsets := make([]time.Duration, 0, len(samples))
	for _, s := range samples {
		offsets = append(offsets, s.offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	median := offsets[len(offsets)/2]
	limit := m.maxDisagreement()
	if len(samples) == 2 {
		if abs(samples[0].offset-samples[1].offset) > limit {
			for i, b := range backends {
				for _, s := range samples {
					if s.b == b {
						m.fail(i, b, StateSuspect,
							"two sources disagree and neither can be called wrong")
					}
				}
			}
			m.alert("two sources disagree", samples[0].b.addr.String(), samples[0].offset,
				samples[1].b.addr.String(), samples[1].offset)
		}
		return
	}
	for i, b := range backends {
		for _, s := range samples {
			if s.b != b {
				continue
			}
			if d := abs(s.offset - median); d > limit {
				m.fail(i, b, StateSuspect,
					fmt.Sprintf("%v from the median of %d sources", d, len(samples)))
				m.alert("a source disagrees with its peers", b.addr.String(), s.offset, "median", median)
			}
		}
	}
}

// resize grows the per-backend state.
func (m *Monitor) resize(n int) {
	for len(m.good) < n {
		m.good = append(m.good, 0)
		m.bad = append(m.bad, 0)
		m.offset = append(m.offset, 0)
		m.delay = append(m.delay, 0)
		m.firstBad = append(m.firstBad, 0)
	}
}

// pass records a good probe and promotes the server once enough of them
// agree in a row.
func (m *Monitor) pass(i int, b *backend, pkt *wire.Packet) {
	m.good[i]++
	m.bad[i] = 0
	h := &Health{State: StateHealthy, Offset: m.offset[i], Delay: m.delay[i],
		RootDispersion: pkt.RootDispersion.Duration(), Stratum: pkt.Stratum,
		Since: time.Duration(m.s.nanos()), Probes: m.probes.Load()}
	old := b.health.Load()
	if old != nil && old.State == StateHealthy {
		h.Since = old.Since
		b.health.Store(h)
		return
	}
	if m.good[i] < m.healthyAfter() {
		// Not promoted yet: the state stays what it was, and the reason
		// says what it is waiting for.
		if old != nil {
			pending := *old
			pending.Reason = fmt.Sprintf("%d of %d good probes", m.good[i], m.healthyAfter())
			b.health.Store(&pending)
		}
		return
	}
	m.firstBad[i] = 0
	b.health.Store(h)
	m.s.host.Counters().NTPSourceHealthy.Add(1)
	m.s.host.Logs().Error.Info("ntp source is healthy again",
		"listener", m.s.cfg.Name, "server", b.addr.String(),
		"offset_ms", float64(h.Offset.Microseconds())/1000)
}

// fail records a bad probe and demotes the server once enough of them
// agree in a row. The holdover bound is applied here: a server that has
// been bad for longer than the estate is willing to keep distributing its
// time stops being usable at all.
func (m *Monitor) fail(i int, b *backend, state State, reason string) {
	m.bad[i]++
	m.good[i] = 0
	m.s.host.Counters().NTPProbeFailed.Add(1)
	now := time.Duration(m.s.nanos())
	if m.firstBad[i] == 0 {
		m.firstBad[i] = now
	}
	if m.bad[i] < m.unhealthyAfter() {
		return
	}
	old := b.health.Load()
	h := &Health{State: state, Offset: m.offset[i], Delay: m.delay[i],
		Since: now, Reason: reason, Failures: uint64(m.bad[i]), Probes: m.probes.Load()} //nolint:gosec // non-negative
	if old != nil && old.State == state {
		h.Since = old.Since
	}
	b.health.Store(h)
	if old == nil || old.State != state {
		m.s.host.Counters().NTPSourceUnhealthy.Add(1)
		m.s.host.Logs().SecurityEvent(context.Background(), "alert", "ntp_source_"+string(state),
			"listener", m.s.cfg.Name, "proto", "ntp", "server", b.addr.String(),
			"detail", reason, "offset_ms", float64(m.offset[i].Microseconds())/1000)
	}
	// The holdover bound.
	if hold := m.holdover(); hold > 0 && now-m.firstBad[i] > hold {
		m.s.host.Counters().NTPHoldoverExpired.Add(1)
		m.s.host.Logs().Error.Warn("ntp source has been unusable past the holdover bound",
			"listener", m.s.cfg.Name, "server", b.addr.String(),
			"for", (now - m.firstBad[i]).String(), "bound", hold.String())
	}
}

func (m *Monitor) holdover() time.Duration {
	if h := m.s.n.Holdover; h != nil {
		return h.MaxDuration.D()
	}
	return 0
}

// alert writes the disagreement event. It is a security event rather than
// an error line because a clock that disagrees with its peers is either a
// fault or somebody's work, and the two are told apart by what else is in
// the log around it.
func (m *Monitor) alert(what string, a string, ao time.Duration, b string, bo time.Duration) {
	m.alerts.Add(1)
	m.s.host.Counters().NTPDisagreements.Add(1)
	m.s.host.Logs().SecurityEvent(context.Background(), "alert", "ntp_clock_disagreement",
		"listener", m.s.cfg.Name, "proto", "ntp", "detail", what,
		"source", a, "source_offset_ms", float64(ao.Microseconds())/1000,
		"against", b, "against_offset_ms", float64(bo.Microseconds())/1000)
}

// Observe folds one forwarded exchange into the measurements, so a
// listener with clients gets a measurement per poll rather than only per
// probe interval.
//
// It deliberately does not decide anything: a forwarded exchange's delay
// includes the client's own network, and a relay that demoted a server
// because one client is far away would be measuring the wrong thing. The
// probes decide; this only sharpens the numbers between them.
func (m *Monitor) Observe(b *backend, r response) {
	if r.delay == 0 && r.offset == 0 {
		return
	}
	h := b.health.Load()
	if h == nil {
		return
	}
	next := *h
	next.Offset = smooth(h.Offset, r.offset)
	next.Delay = smooth(h.Delay, r.delay)
	next.RootDispersion = r.pkt.RootDispersion.Duration()
	next.Stratum = r.pkt.Stratum
	b.health.CompareAndSwap(h, &next)
}

// States is what every server looks like now, for the status view and the
// tests.
func (m *Monitor) States() map[string]Health {
	m.s.mu.Lock()
	backends := append([]*backend(nil), m.s.backends...)
	m.s.mu.Unlock()
	out := make(map[string]Health, len(backends))
	for _, b := range backends {
		if h := b.health.Load(); h != nil {
			out[b.addr.String()] = *h
		}
	}
	return out
}

// smooth is the exponentially weighted average the measurements are kept
// as: one sample moves it an eighth of the way, which is enough to follow
// a real change and not enough to follow a single slow answer.
func smooth(old, sample time.Duration) time.Duration {
	if old == 0 {
		return sample
	}
	return old + (sample-old)/8
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
