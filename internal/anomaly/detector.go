package anomaly

import (
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Detector is the models plus what an operator asked to be done about a
// finding, which is the whole of what a listener kind needs.
//
// The models themselves report and never refuse -- that is the point of
// Set -- so the action lives out here, beside the three call-backs a kind
// fills in. Every OT kind does the same four things with a finding (log
// it, count it, record it in the shadow ledger, or refuse the request it
// came on), and doing them in eight places is how eight kinds end up
// behaving differently on the same signal.
type Detector struct {
	set  *Set
	deny bool
}

// FromConfig compiles a listener's `anomaly` block. It returns nil when
// the block is absent or turned off, so a kind can hold the result
// unconditionally and every method below tolerates a nil receiver.
//
// start is when this listener began serving, which the talkers model needs:
// every peer is new in the first minute of a process.
func FromConfig(c *config.Anomaly, start time.Time) (*Detector, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	p := Policy{MaxActors: c.MaxClients}
	if c.Settle != nil {
		p.Settle = time.Duration(*c.Settle)
		if p.Settle == 0 {
			// `settle: 0s` is the configuration's way of asking for a
			// report from a peer's first frame, which the models spell
			// NoSettle: zero there means "nothing was asked for".
			p.Settle = NoSettle
		}
	}
	// Novelty is on when the block is, because "this peer has never done
	// this" is the model that needs no configuration at all.
	n := c.Novelty
	p.Novelty = Novelty{Symbols: true, WritePoints: true, Burst: config.DefaultAnomalyBurst}
	if n != nil {
		p.Novelty.Symbols = n.Symbols == nil || *n.Symbols
		p.Novelty.WritePoints = n.WritePoints == nil || *n.WritePoints
		if n.Burst != nil {
			p.Novelty.Burst = *n.Burst
		}
		p.Novelty.Period = time.Duration(n.BurstPeriod)
	}
	if c.Cycle != nil {
		p.Cycle = Cycle{Enabled: c.Cycle.Enabled == nil || *c.Cycle.Enabled,
			MinSamples: c.Cycle.MinSamples, Tolerance: c.Cycle.Tolerance,
			ReportEvery: time.Duration(c.Cycle.ReportEvery)}
	}
	if c.Sequence != nil {
		p.Sequence = Sequence{Enabled: c.Sequence.Enabled == nil || *c.Sequence.Enabled,
			MinSamples: c.Sequence.MinSamples}
	}
	if c.Talkers != nil {
		p.Talkers = Talkers{Enabled: c.Talkers.Enabled == nil || *c.Talkers.Enabled,
			ReadyAfter: time.Duration(c.Talkers.ReadyAfter)}
	}
	if c.Telemetry != nil {
		p.Telemetry = Telemetry{Enabled: c.Telemetry.Enabled == nil || *c.Telemetry.Enabled,
			FrozenSamples: c.Telemetry.FrozenSamples, ReplayWindow: c.Telemetry.ReplayWindow}
	}
	for _, q := range c.Correlations {
		p.Correlations = append(p.Correlations, Correlation{Name: q.Name, A: q.A, B: q.B,
			Ratio: q.Ratio, Difference: q.Difference, Tolerance: q.Tolerance,
			MaxAge: time.Duration(q.MaxAge)})
	}
	d := &Detector{}
	switch c.Action {
	case "", "alert":
	case "deny":
		d.deny = true
	default:
		return nil, fmt.Errorf("anomaly action %q: alert or deny", c.Action)
	}
	set, err := New(p, start)
	if err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}
	if set == nil {
		// Every model off. Validation refuses it, so reaching here means a
		// caller built the block in code; saying so is better than a
		// listener that silently has no detector.
		return nil, fmt.Errorf("anomaly: enabled with nothing to detect")
	}
	d.set = set
	return d, nil
}

// On reports whether there is a detector at all.
func (d *Detector) On() bool { return d != nil && d.set != nil }

// Deny reports whether the operator asked for the first occurrence to be
// refused.
func (d *Detector) Deny() bool { return d != nil && d.deny }

// Observe runs the models over one event.
func (d *Detector) Observe(e Event) []Finding {
	if !d.On() {
		return nil
	}
	return d.set.Observe(e)
}

// Values runs the two models that are about values over a reading this
// relay saw in a reply. It never refuses: a reply is not a request, and
// there is nothing to refuse by the time one has arrived.
func (d *Detector) Values(e Event, h Handler) {
	if !d.On() {
		return
	}
	for _, f := range d.set.Value(e) {
		if h.Alert != nil {
			h.Alert(f)
		}
	}
}

// Status is what the models hold now, for a status view.
func (d *Detector) Status() Status {
	if !d.On() {
		return Status{}
	}
	return d.set.Status()
}

// SetClock is for the tests, which cannot wait ten minutes for a settling
// window.
func (d *Detector) SetClock(f func() time.Time) {
	if d.On() {
		d.set.SetClock(f)
	}
}

// Handler is what a kind does about a finding. Every field is called with
// the finding's own reason and detail, which are the strings the security
// log, the refusal counters and internal/attack's mapping all use.
type Handler struct {
	// Alert records the finding. It is called for every finding, whatever
	// the action: an operator who set `action: deny` still wants the
	// record, and one who did not still wants the signal.
	Alert func(f Finding)
	// Would records what enforcing would have cost, for a listener in
	// shadow mode or a learning run. It is called instead of refusing.
	Would func(f Finding)
	// Refused is the refusal's own bookkeeping: the kind's denied counter,
	// its audit line. The caller does the refusing, because only it knows
	// what refusing means in its protocol.
	Refused func(f Finding)
}

// Decide runs the models over one event and says what to do with the
// request it came from: the reason to refuse it, or "" to carry it.
//
// Only the first finding refuses, and only when this listener is
// enforcing: in shadow mode or a learning run nothing is refused, which is
// the whole of what those modes mean. Every finding is alerted on
// regardless, and the event is recorded either way -- the point of the
// settling window is not to ignore traffic but to learn from it quietly.
//
// `deny` refuses the *first* occurrence and the retry goes through. That
// is deliberate and documented: refusing every occurrence until somebody
// intervened would mean a plant that could not be driven after any novelty
// at all, and there is no mechanism here for the intervening.
func (d *Detector) Decide(e Event, enforcing bool, h Handler) string {
	refuse, decided := "", false
	for _, f := range d.Observe(e) {
		if h.Alert != nil {
			h.Alert(f)
		}
		if !d.deny || decided {
			continue
		}
		// One decision per request, on the first finding, in both modes.
		// Shadow mode recording every finding as a would-be refusal would
		// overstate what enforcing costs: enforcing would have stopped at
		// this one, and the report exists to answer exactly that.
		decided = true
		if !enforcing {
			if h.Would != nil {
				h.Would(f)
			}
			continue
		}
		refuse = f.Reason
		if h.Refused != nil {
			h.Refused(f)
		}
	}
	return refuse
}
