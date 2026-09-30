// Package anomaly is behavioural detection for the control protocols: what
// a peer has been doing, and what it has just done that does not fit.
//
// The policies in the kinds answer "is this permitted", from rules somebody
// wrote down. This answers a different question -- "is this what has been
// happening here" -- and answers it without anybody having written
// anything. On these protocols that is worth more than it would be almost
// anywhere else, because control traffic is repetitive in a way other
// traffic is not: a master's scan cycle is the same few operations over the
// same few addresses, every cycle, for years. "This has never happened
// before" is a signal here where on a web front end it would be noise.
//
// # The models
//
// Six, each answering a different shape of question, and each built so that
// what it does *not* claim is clear:
//
//	novelty      an operation, or a write to a point, this peer has never done
//	cycle        the poll cycle's period and jitter, and a cycle that changed
//	sequence     the order operations come in, as transitions between them
//	talkers      a peer nobody has seen, and a peer on a device it has never touched
//	telemetry    a value that stopped moving, and a value sequence that repeats
//	correlation  two points that are supposed to track each other and stopped
//
// # It alerts
//
// None of them refuses anything by itself. A detector built on "I have not
// seen this before" refuses the first legitimate thing anybody does after a
// quiet year: the maintenance write, the commissioning of a new point, the
// operator who finally uses a function they have always been allowed to
// use. What comes out of here is a finding; what the kind does with it --
// log it, count it, refuse it where the operator asked for that -- is the
// kind's own policy. Nothing here reaches the ban ladder.
//
// # It settles first
//
// When a relay starts, everything is new. For the settle period after a
// peer is first seen its traffic is recorded and nothing about novelty is
// reported about it. That is the same honesty the learning report's warning
// is about: what this relay has seen is not the same as what is normal, and
// the first minutes of a session are not even what it has seen.
//
// The bounds are not suppressed while settling: a burst bound and a
// correlation tolerance are numbers an operator set rather than something
// learned, and a burst during the settling window is still a burst.
//
// # Bounds, and blinding
//
// Every table here is bounded, and a table that fills stops *detecting*
// rather than silently widening what counts as normal -- a detector that
// quietly redefined "seen" would be one that stopped working while
// continuing to look as though it worked. Where that happens the peer is
// counted as blinded, and the counter is in the status view.
package anomaly

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/textsafe"
)

// Model names which detector produced a finding.
type Model string

// The models.
const (
	ModelNovelty     Model = "novelty"
	ModelCycle       Model = "cycle"
	ModelSequence    Model = "sequence"
	ModelTalkers     Model = "talkers"
	ModelTelemetry   Model = "telemetry"
	ModelCorrelation Model = "correlation"
)

// The reasons a finding carries. They are the strings that reach the
// security log, the refusal counters and internal/attack's mapping, so they
// are stable and they are the same on every kind: an operations centre
// filtering on `anomaly_cycle_changed` should not have to know which
// protocol produced it.
const (
	ReasonNewSymbol         = "anomaly_new_symbol"
	ReasonNewWritePoint     = "anomaly_new_write_point"
	ReasonWriteBurst        = "anomaly_write_burst"
	ReasonNewTalker         = "anomaly_new_talker"
	ReasonNewPair           = "anomaly_new_pair"
	ReasonCycleChanged      = "anomaly_cycle_changed"
	ReasonSequenceUnseen    = "anomaly_sequence_unseen"
	ReasonTelemetryFrozen   = "anomaly_telemetry_frozen"
	ReasonTelemetryReplayed = "anomaly_telemetry_replayed"
	ReasonCorrelationBroken = "anomaly_correlation_broken"
)

// Reasons are every reason this package can report, for a test or a view
// that has to enumerate them.
func Reasons() []string {
	return []string{ReasonNewSymbol, ReasonNewWritePoint, ReasonWriteBurst,
		ReasonNewTalker, ReasonNewPair, ReasonCycleChanged, ReasonSequenceUnseen,
		ReasonTelemetryFrozen, ReasonTelemetryReplayed, ReasonCorrelationBroken}
}

// Event is one request, in terms every control protocol has.
//
// The kind translates its own vocabulary into this: a Modbus function code
// name, an IEC 104 type identification, an OPC UA service, an MMS service
// and functional constraint are all Symbols; a register, an information
// object address, a data block byte range and a node identifier are all
// Points. The translation is the kind's business, because what a symbol
// *means* is, and this package deliberately cannot tell one protocol from
// another.
type Event struct {
	// Actor is the peer that asked.
	Actor netip.Addr
	// Device is what it asked *of*, where the protocol addresses more than
	// one thing behind the relay: a unit identifier, a common address, a
	// rack and slot. Empty where there is only the upstream.
	Device string
	// Symbol is the operation, from the protocol's own vocabulary.
	Symbol string
	// Point is the addressed thing, where the request names one.
	Point string
	// Write says the request changes something. It is the kind's reading
	// of its own protocol, not a guess from the symbol's name.
	Write bool
	// Value and HasValue are the value the request carried or the reply
	// reported, for the telemetry and correlation models. A relay only
	// ever has the values that crossed it, which is the honest limit of
	// both.
	Value    float64
	HasValue bool
	// At is when. Zero means now.
	At time.Time
}

// Finding is one thing an event tripped.
type Finding struct {
	Model  Model
	Reason string
	Detail string
}

// Novelty is the "never seen this before" model.
type Novelty struct {
	// Symbols reports an operation this peer has not used.
	Symbols bool
	// WritePoints reports a write to a point this peer has not written.
	WritePoints bool
	// Burst is how many writes across every point in Period are too many;
	// 0 turns the burst off. It is not a per-point rate -- that is the
	// kinds' own value policy -- but a count across the whole address
	// space, which is the shape of walking it rather than of a control
	// action.
	Burst  int
	Period time.Duration
	// MaxSymbols and MaxPoints bound one peer's record.
	MaxSymbols, MaxPoints int
}

// Cycle is the poll-cycle model: how regular this peer's requests are, and
// when that changes.
//
// A control network's rhythm is its most stable property and one of the few
// things an attacker cannot help disturbing: a poller that has asked every
// two seconds for a year and now asks every two hundred milliseconds is a
// different program, whatever it is asking for.
type Cycle struct {
	Enabled bool
	// MinSamples is how many intervals are learned before anything is
	// reported. Below about twenty the mean is not a rhythm.
	MinSamples int
	// Tolerance is how many times the learned jitter an interval may
	// differ from the learned period before it is reported. Default 6,
	// which is wide on purpose: this model is about a cycle that
	// *changed*, not about one late packet.
	Tolerance float64
	// ReportEvery rate-limits the finding per peer, because a cycle that
	// changed produces a finding on every request until the model has
	// learned the new rhythm. Default 5m.
	ReportEvery time.Duration
}

// Sequence is the order model: a first-order Markov chain over the symbols
// a peer uses, and a transition it has never made.
//
// The order is information the individual requests do not carry. A tool
// that reads a block, writes it and reads it back does that in that order,
// every time; an operator's panel never writes twice in a row. "This
// operation has never followed that one" catches a legitimate-looking
// request in an illegitimate place.
type Sequence struct {
	Enabled bool
	// MinSamples is how many transitions are learned from a peer before
	// anything is reported about its order. Without it the model reports
	// the traffic it is learning from, which on a short settling window
	// is every transition once.
	MinSamples int
	// MaxSymbols bounds the alphabet and MaxTransitions the table. Past
	// either the peer's sequence detection is turned off rather than the
	// table being widened.
	MaxSymbols, MaxTransitions int
}

// Talkers is the "who is this" model: a peer nobody has seen on this
// listener, and a peer on a device it has never spoken to.
type Talkers struct {
	Enabled bool
	// ReadyAfter is how long the listener itself has to have been running
	// before a new peer is worth reporting. Every peer is new in the first
	// minute of a process, and reporting that is how an operator learns to
	// ignore the alerts. Default 15m.
	ReadyAfter time.Duration
	// MaxPairs bounds the devices remembered per peer.
	MaxPairs int
}

// Telemetry is the value model: a point that stopped moving, and a value
// sequence that repeats.
//
// Both are what a plant looks like when somebody is showing the control
// room a recording. A frozen point is the crude version -- one value, for
// ever -- and a repeating sequence is the careful version, which is what
// makes a screen look alive while the process does something else.
type Telemetry struct {
	Enabled bool
	// FrozenSamples is how many identical readings in a row, from a point
	// that had been moving, are reported. Default 20.
	FrozenSamples int
	// ReplayWindow is the length of the repeating run that is reported: a
	// sequence of this many readings that is immediately repeated.
	// Default 8. Below about four this fires on any oscillation.
	ReplayWindow int
	// MaxPoints bounds the points whose history is kept.
	MaxPoints int
}

// Correlation is one pair of points that are supposed to track each other,
// and the tolerance they may drift by.
//
// This is the only model here that needs an operator: nothing in a protocol
// says that a pump's speed and a flow meter belong together, and a relay
// that guessed would produce an alert a plant could not act on. What it
// buys for that configuration is the detection an attacker finds hardest to
// avoid -- a written value that is physically impossible next to a value
// the process itself produced.
type Correlation struct {
	// Name is what the pair is called in a finding.
	Name string
	// A and B are the points, as the kind spells a Point.
	A, B string
	// Ratio, when set, is the expected A/B; Difference, when set, is the
	// largest |A-B| that is normal. At least one is required.
	Ratio      float64
	Difference float64
	// Tolerance is the slack on the ratio, as a fraction of B. Default
	// 0.1.
	Tolerance float64
	// MaxAge is how old the other point's reading may be and still be
	// compared. Default 1m: two readings a quarter of an hour apart say
	// nothing about each other.
	MaxAge time.Duration
}

// Policy is the compiled configuration of every model.
type Policy struct {
	// Settle is how long a peer's traffic is learned before novelty about
	// it is reported. Default 10m.
	Settle time.Duration
	// MaxActors bounds the peers remembered.
	MaxActors int

	Novelty      Novelty
	Cycle        Cycle
	Sequence     Sequence
	Talkers      Talkers
	Telemetry    Telemetry
	Correlations []Correlation
}

// The defaults and the ceilings.
const (
	DefaultSettle      = 10 * time.Minute
	DefaultActors      = 1024
	MaxActorsCeil      = 65536
	DefaultBurstPeriod = 10 * time.Second
	DefaultSymbols     = 32
	DefaultPoints      = 64
	MaxPointsCeil      = 4096
	DefaultMinSamples  = 20
	DefaultSeqSamples  = 200
	DefaultTolerance   = 6
	DefaultReportEvery = 5 * time.Minute
	DefaultReadyAfter  = 15 * time.Minute
	DefaultPairs       = 32
	DefaultFrozen      = 20
	DefaultReplay      = 8
	DefaultMaxAge      = time.Minute
	DefaultSlack       = 0.1
	// maxTelemetry is the readings kept per point: twice the largest
	// replay window plus room for the frozen run.
	maxTelemetryHistory = 64
)

// Check fills in the defaults and refuses a policy that cannot work.
//
// A configuration that turned the detector on and every model off is the
// one worth refusing rather than defaulting: it is a mistake somebody
// spends an afternoon on, because nothing is wrong and nothing is reported.
func (p *Policy) Check() error {
	if p.Settle < 0 {
		return fmt.Errorf("settle %s: not negative", p.Settle)
	}
	if p.Settle == 0 {
		p.Settle = DefaultSettle
	}
	if p.MaxActors <= 0 {
		p.MaxActors = DefaultActors
	}
	if p.MaxActors > MaxActorsCeil {
		p.MaxActors = MaxActorsCeil
	}
	if p.Novelty.Burst < 0 {
		return fmt.Errorf("burst %d: not negative", p.Novelty.Burst)
	}
	if p.Novelty.Period <= 0 {
		p.Novelty.Period = DefaultBurstPeriod
	}
	if p.Novelty.MaxSymbols <= 0 {
		p.Novelty.MaxSymbols = DefaultSymbols
	}
	if p.Novelty.MaxPoints <= 0 {
		p.Novelty.MaxPoints = DefaultPoints
	}
	if p.Novelty.MaxPoints > MaxPointsCeil {
		p.Novelty.MaxPoints = MaxPointsCeil
	}
	if p.Cycle.MinSamples <= 0 {
		p.Cycle.MinSamples = DefaultMinSamples
	}
	if p.Cycle.Tolerance <= 0 {
		p.Cycle.Tolerance = DefaultTolerance
	}
	if p.Cycle.ReportEvery <= 0 {
		p.Cycle.ReportEvery = DefaultReportEvery
	}
	if p.Sequence.MinSamples <= 0 {
		p.Sequence.MinSamples = DefaultSeqSamples
	}
	if p.Sequence.MaxSymbols <= 0 {
		p.Sequence.MaxSymbols = DefaultSymbols
	}
	if p.Sequence.MaxTransitions <= 0 {
		p.Sequence.MaxTransitions = p.Sequence.MaxSymbols * 4
	}
	if p.Talkers.ReadyAfter <= 0 {
		p.Talkers.ReadyAfter = DefaultReadyAfter
	}
	if p.Talkers.MaxPairs <= 0 {
		p.Talkers.MaxPairs = DefaultPairs
	}
	if p.Telemetry.FrozenSamples <= 0 {
		p.Telemetry.FrozenSamples = DefaultFrozen
	}
	if p.Telemetry.FrozenSamples > maxTelemetryHistory {
		p.Telemetry.FrozenSamples = maxTelemetryHistory
	}
	if p.Telemetry.ReplayWindow <= 0 {
		p.Telemetry.ReplayWindow = DefaultReplay
	}
	if p.Telemetry.ReplayWindow < 4 {
		return fmt.Errorf("replay_window %d: below four this reports every oscillation",
			p.Telemetry.ReplayWindow)
	}
	if p.Telemetry.ReplayWindow*2 > maxTelemetryHistory {
		return fmt.Errorf("replay_window %d: at most %d, because twice it has to fit in the history kept per point",
			p.Telemetry.ReplayWindow, maxTelemetryHistory/2)
	}
	if p.Telemetry.MaxPoints <= 0 {
		p.Telemetry.MaxPoints = DefaultPoints
	}
	if p.Telemetry.MaxPoints > MaxPointsCeil {
		p.Telemetry.MaxPoints = MaxPointsCeil
	}
	seen := map[string]bool{}
	for i := range p.Correlations {
		c := &p.Correlations[i]
		if c.Name == "" {
			return fmt.Errorf("correlation %d: name required", i)
		}
		if seen[c.Name] {
			return fmt.Errorf("correlation %q: named twice", c.Name)
		}
		seen[c.Name] = true
		if c.A == "" || c.B == "" {
			return fmt.Errorf("correlation %q: two points required", c.Name)
		}
		if c.A == c.B {
			return fmt.Errorf("correlation %q: a point cannot be correlated with itself", c.Name)
		}
		if c.Ratio == 0 && c.Difference == 0 {
			return fmt.Errorf("correlation %q: ratio or difference required, otherwise nothing is being checked", c.Name)
		}
		if c.Ratio < 0 || c.Difference < 0 {
			return fmt.Errorf("correlation %q: ratio and difference are not negative", c.Name)
		}
		if c.Tolerance < 0 {
			return fmt.Errorf("correlation %q: tolerance is not negative", c.Name)
		}
		if c.Tolerance == 0 {
			c.Tolerance = DefaultSlack
		}
		if c.MaxAge <= 0 {
			c.MaxAge = DefaultMaxAge
		}
	}
	if !p.anything() {
		return fmt.Errorf("enabled with nothing to detect: every model is off")
	}
	return nil
}

// anything reports whether any model would report something.
func (p *Policy) anything() bool {
	return p.Novelty.Symbols || p.Novelty.WritePoints || p.Novelty.Burst > 0 ||
		p.Cycle.Enabled || p.Sequence.Enabled || p.Talkers.Enabled ||
		p.Telemetry.Enabled || len(p.Correlations) > 0
}

// Set is one listener's detector. A nil *Set reports nothing, so a kind
// that was configured without one calls it without checking.
type Set struct {
	p     Policy
	start time.Time
	now   func() time.Time

	mu     sync.Mutex
	actors map[netip.Addr]*actor
	order  []netip.Addr
	// points is the value history, per point rather than per actor: a
	// frozen reading is a property of the point, and which peer read it
	// does not change that.
	points map[string]*history
	// correlations index the configured pairs by point, so a value
	// arriving is matched without walking the list.
	byPoint map[string][]int

	dropped, blinded, findings uint64
}

// New compiles a detector. A nil policy, or one with nothing enabled,
// gives a nil *Set.
func New(p Policy, start time.Time) (*Set, error) {
	if !p.anything() {
		return nil, nil
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	s := &Set{p: p, start: start, now: time.Now,
		actors: map[netip.Addr]*actor{}, points: map[string]*history{},
		byPoint: map[string][]int{}}
	if s.start.IsZero() {
		s.start = time.Now()
	}
	for i, c := range p.Correlations {
		s.byPoint[c.A] = append(s.byPoint[c.A], i)
		s.byPoint[c.B] = append(s.byPoint[c.B], i)
	}
	return s, nil
}

// SetClock replaces the clock. For tests.
func (s *Set) SetClock(f func() time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.now = f
	s.mu.Unlock()
}

// actor is one peer's record.
type actor struct {
	since time.Time
	// symbols and writePoints are what this peer has done, and the two
	// full flags say the bound turned that detection off.
	symbols     map[string]bool
	writePoints map[string]bool
	symbolsFull bool
	pointsFull  bool
	// writes is the sliding window of write times, oldest first.
	writes []time.Time
	// last is when the last event arrived, and period and jitter the
	// learned rhythm; samples counts the intervals learned.
	last            time.Time
	period, jitter  float64
	samples         int
	lastCycleReport time.Time
	// prev is the previous symbol, and next the transitions seen from
	// each symbol. seqFull says the bound turned sequence detection off,
	// and seqSeen counts the transitions learned.
	prev    string
	next    map[string]map[string]bool
	edges   int
	seqSeen int
	seqFull bool
	// devices are the devices this peer has spoken to, and devicesFull
	// that the bound stopped that.
	devices     map[string]bool
	devicesFull bool
}

// history is one point's recent readings.
type history struct {
	values []float64
	at     time.Time
	// moved says the point has been seen to change, so a run of
	// identical readings from it means something.
	moved bool
	// reported says a frozen or replayed finding has been reported for
	// the current run, so one stuck point is one finding.
	frozenReported, replayReported bool
}

// Observe records an event and reports what it tripped.
//
// Recording happens whether or not anything is reported, and during the
// settling window: the point of settling is not to ignore the traffic but
// to learn from it quietly.
func (s *Set) Observe(e Event) []Finding {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := e.At
	if now.IsZero() {
		now = s.now()
	}

	a, isNew := s.actorFor(e.Actor, now)
	if a == nil {
		// The bound turned this peer away: nothing is recorded about it
		// and nothing is claimed about it either.
		return nil
	}
	settled := now.Sub(a.since) >= s.p.Settle

	var out []Finding
	if isNew && s.p.Talkers.Enabled && now.Sub(s.start) >= s.p.Talkers.ReadyAfter {
		// Every peer is new in the first minutes of a process, which is
		// why this waits for the listener itself to have settled.
		out = append(out, Finding{Model: ModelTalkers, Reason: ReasonNewTalker,
			Detail: "first seen on this listener"})
	}
	out = append(out, s.talkerPair(a, e, settled)...)
	out = append(out, s.novelty(a, e, now, settled)...)
	out = append(out, s.cycle(a, now, settled)...)
	out = append(out, s.sequence(a, e, settled)...)
	h := s.value(e, now)
	out = append(out, s.telemetry(e, h)...)
	out = append(out, s.correlation(e, now)...)

	s.findings += uint64(len(out))
	for i := range out {
		out[i].Detail = textsafe.Clip256(out[i].Detail)
	}
	return out
}

// actorFor finds or makes a peer's record, or reports nil when the bound
// turned it away.
func (s *Set) actorFor(addr netip.Addr, now time.Time) (*actor, bool) {
	if a := s.actors[addr]; a != nil {
		return a, false
	}
	if len(s.actors) >= s.p.MaxActors {
		// The oldest goes rather than the newest being refused: a table
		// full of peers from an hour ago would stop the detector seeing
		// what is happening now, which is the failure worth avoiding.
		s.evictOldest()
	}
	a := &actor{since: now, symbols: map[string]bool{}, writePoints: map[string]bool{},
		next: map[string]map[string]bool{}, devices: map[string]bool{}}
	s.actors[addr] = a
	s.order = append(s.order, addr)
	return a, true
}

func (s *Set) evictOldest() {
	for len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		if _, ok := s.actors[oldest]; ok {
			delete(s.actors, oldest)
			s.dropped++
			return
		}
	}
	// The order list is exhausted but the map is not: take any.
	for k := range s.actors {
		delete(s.actors, k)
		s.dropped++
		return
	}
}

// talkerPair reports a device this peer has not spoken to.
func (s *Set) talkerPair(a *actor, e Event, settled bool) []Finding {
	if !s.p.Talkers.Enabled || e.Device == "" {
		return nil
	}
	if a.devices[e.Device] {
		return nil
	}
	if len(a.devices) >= s.p.Talkers.MaxPairs {
		if !a.devicesFull {
			a.devicesFull = true
			s.blinded++
		}
		return nil
	}
	a.devices[e.Device] = true
	if !settled || len(a.devices) == 1 {
		// The first device a peer talks to is not a new pair; it is the
		// pair.
		return nil
	}
	return []Finding{{Model: ModelTalkers, Reason: ReasonNewPair,
		Detail: "first request to " + e.Device}}
}

// novelty is the three "never seen this" checks.
func (s *Set) novelty(a *actor, e Event, now time.Time, settled bool) []Finding {
	var out []Finding
	if e.Symbol != "" {
		if !a.symbols[e.Symbol] {
			if len(a.symbols) >= s.p.Novelty.MaxSymbols {
				if !a.symbolsFull {
					a.symbolsFull = true
					s.blinded++
				}
			} else {
				a.symbols[e.Symbol] = true
				if settled && s.p.Novelty.Symbols {
					out = append(out, Finding{Model: ModelNovelty, Reason: ReasonNewSymbol,
						Detail: e.Symbol + " has not been used by this peer"})
				}
			}
		}
	}
	if !e.Write {
		return out
	}
	if e.Point != "" && !a.writePoints[e.Point] {
		if len(a.writePoints) >= s.p.Novelty.MaxPoints {
			if !a.pointsFull {
				a.pointsFull = true
				s.blinded++
			}
		} else {
			a.writePoints[e.Point] = true
			if settled && s.p.Novelty.WritePoints {
				out = append(out, Finding{Model: ModelNovelty, Reason: ReasonNewWritePoint,
					Detail: "first write to " + e.Point})
			}
		}
	}
	if n := s.p.Novelty.Burst; n > 0 {
		cutoff := now.Add(-s.p.Novelty.Period)
		i := 0
		for i < len(a.writes) && a.writes[i].Before(cutoff) {
			i++
		}
		a.writes = append(a.writes[:0], a.writes[i:]...)
		a.writes = append(a.writes, now)
		if len(a.writes) > n {
			// Not suppressed while settling: this is a number an operator
			// set rather than something learned.
			out = append(out, Finding{Model: ModelNovelty, Reason: ReasonWriteBurst,
				Detail: fmt.Sprintf("%d writes in %s, over the bound of %d",
					len(a.writes), s.p.Novelty.Period, n)})
			// The window is emptied so one burst is one finding rather
			// than one per request for as long as it lasts.
			a.writes = a.writes[:0]
		}
	}
	return out
}

// cycle learns the rhythm and reports one that changed.
func (s *Set) cycle(a *actor, now time.Time, settled bool) []Finding {
	if !s.p.Cycle.Enabled {
		a.last = now
		return nil
	}
	last := a.last
	a.last = now
	if last.IsZero() {
		return nil
	}
	gap := now.Sub(last).Seconds()
	if gap <= 0 {
		return nil
	}
	if a.samples < s.p.Cycle.MinSamples {
		// Learning. The mean and the mean absolute deviation are taken
		// over the first samples rather than smoothed, because a rhythm
		// learned from an exponential average of its own outliers is not
		// one.
		a.samples++
		if a.samples == 1 {
			a.period = gap
			return nil
		}
		n := float64(a.samples)
		prev := a.period
		a.period += (gap - a.period) / n
		a.jitter += (math.Abs(gap-prev) - a.jitter) / n
		return nil
	}
	// A floor under the jitter, because a perfectly regular poller learns
	// a jitter of zero and would then report every microsecond of delay.
	slack := math.Max(a.jitter, a.period*0.05)
	if math.Abs(gap-a.period) <= s.p.Cycle.Tolerance*slack {
		// Inside the rhythm: keep learning slowly, so a plant that
		// legitimately changes its scan rate is relearned rather than
		// alerted on for ever.
		a.period += (gap - a.period) * 0.02
		a.jitter += (math.Abs(gap-a.period) - a.jitter) * 0.02
		return nil
	}
	if !settled {
		return nil
	}
	if !a.lastCycleReport.IsZero() && now.Sub(a.lastCycleReport) < s.p.Cycle.ReportEvery {
		// A cycle that changed produces a finding on every request until
		// the new rhythm is learned; one per period is the useful number.
		return nil
	}
	a.lastCycleReport = now
	return []Finding{{Model: ModelCycle, Reason: ReasonCycleChanged,
		Detail: fmt.Sprintf("interval %.3fs against a learned %.3fs (jitter %.3fs)",
			gap, a.period, a.jitter)}}
}

// sequence learns the transitions and reports one never made.
func (s *Set) sequence(a *actor, e Event, settled bool) []Finding {
	if !s.p.Sequence.Enabled || e.Symbol == "" {
		return nil
	}
	from := a.prev
	a.prev = e.Symbol
	if from == "" {
		return nil
	}
	a.seqSeen++
	to := a.next[from]
	if to != nil && to[e.Symbol] {
		return nil
	}
	if a.seqFull {
		return nil
	}
	if a.edges >= s.p.Sequence.MaxTransitions || len(a.next) >= s.p.Sequence.MaxSymbols {
		a.seqFull = true
		s.blinded++
		return nil
	}
	if to == nil {
		to = map[string]bool{}
		a.next[from] = to
	}
	to[e.Symbol] = true
	a.edges++
	if !settled || a.seqSeen <= s.p.Sequence.MinSamples {
		// Still learning what this peer's order is. Reporting here would
		// be reporting the traffic the model is learning from.
		return nil
	}
	return []Finding{{Model: ModelSequence, Reason: ReasonSequenceUnseen,
		Detail: e.Symbol + " has never followed " + from + " from this peer"}}
}

// value records a point's reading, for the two models that need one.
//
// It is here rather than inside the telemetry model because the
// correlation model reads the same history: a listener that configured
// correlations and no telemetry model still has to have the values to
// compare, and a version of this that recorded them in the telemetry model
// silently compared nothing.
func (s *Set) value(e Event, now time.Time) *history {
	if !e.HasValue || e.Point == "" {
		return nil
	}
	if !s.p.Telemetry.Enabled && len(s.p.Correlations) == 0 {
		return nil
	}
	h := s.points[e.Point]
	if h == nil {
		if len(s.points) >= s.p.Telemetry.MaxPoints {
			return nil
		}
		h = &history{}
		s.points[e.Point] = h
	}
	if n := len(h.values); n > 0 && h.values[n-1] != e.Value {
		h.moved = true
		h.frozenReported = false
	}
	h.values = append(h.values, e.Value)
	if len(h.values) > maxTelemetryHistory {
		h.values = append(h.values[:0], h.values[1:]...)
	}
	h.at = now
	return h
}

// telemetry reports a point that stopped moving, and one whose readings
// repeat.
func (s *Set) telemetry(e Event, h *history) []Finding {
	if !s.p.Telemetry.Enabled || h == nil {
		return nil
	}
	var out []Finding
	if h.moved && !h.frozenReported && frozen(h.values, s.p.Telemetry.FrozenSamples) {
		h.frozenReported = true
		out = append(out, Finding{Model: ModelTelemetry, Reason: ReasonTelemetryFrozen,
			Detail: fmt.Sprintf("%s has read %g for %d samples after moving",
				e.Point, e.Value, s.p.Telemetry.FrozenSamples)})
	}
	if repeated(h.values, s.p.Telemetry.ReplayWindow) {
		if !h.replayReported {
			h.replayReported = true
			out = append(out, Finding{Model: ModelTelemetry, Reason: ReasonTelemetryReplayed,
				Detail: fmt.Sprintf("%s repeated its last %d readings exactly",
					e.Point, s.p.Telemetry.ReplayWindow)})
		}
	} else {
		h.replayReported = false
	}
	return out
}

// frozen reports whether the last n readings are identical.
func frozen(v []float64, n int) bool {
	if len(v) < n {
		return false
	}
	last := v[len(v)-1]
	for _, x := range v[len(v)-n:] {
		if x != last {
			return false
		}
	}
	return true
}

// repeated reports whether the last n readings are the n before them, with
// at least two distinct values among them -- a constant run is frozen
// rather than replayed, and reporting it as both would be one fact twice.
func repeated(v []float64, n int) bool {
	if len(v) < 2*n {
		return false
	}
	tail := v[len(v)-n:]
	prev := v[len(v)-2*n : len(v)-n]
	distinct := false
	for i := range tail {
		if tail[i] != prev[i] {
			return false
		}
		if tail[i] != tail[0] {
			distinct = true
		}
	}
	return distinct
}

// correlation reports two points that stopped tracking each other.
func (s *Set) correlation(e Event, now time.Time) []Finding {
	if len(s.p.Correlations) == 0 || !e.HasValue || e.Point == "" {
		return nil
	}
	idx := s.byPoint[e.Point]
	if len(idx) == 0 {
		return nil
	}
	var out []Finding
	for _, i := range idx {
		c := s.p.Correlations[i]
		other := c.B
		if e.Point == c.B {
			other = c.A
		}
		h := s.points[other]
		if h == nil || len(h.values) == 0 || now.Sub(h.at) > c.MaxAge {
			// Nothing to compare with, or nothing recent enough. A relay
			// only has the values that crossed it, and comparing a
			// reading with a quarter-hour-old one would be inventing a
			// fact about the process.
			continue
		}
		a, b := e.Value, h.values[len(h.values)-1]
		if e.Point == c.B {
			a, b = b, a
		}
		if c.Difference > 0 && math.Abs(a-b) > c.Difference {
			out = append(out, Finding{Model: ModelCorrelation, Reason: ReasonCorrelationBroken,
				Detail: fmt.Sprintf("%s: %s=%g and %s=%g differ by more than %g",
					c.Name, c.A, a, c.B, b, c.Difference)})
			continue
		}
		if c.Ratio > 0 {
			want := c.Ratio * b
			if slack := math.Abs(want) * c.Tolerance; math.Abs(a-want) > slack {
				out = append(out, Finding{Model: ModelCorrelation, Reason: ReasonCorrelationBroken,
					Detail: fmt.Sprintf("%s: %s=%g against %g expected from %s=%g (ratio %g, tolerance %g)",
						c.Name, c.A, a, want, c.B, b, c.Ratio, c.Tolerance)})
			}
		}
	}
	return out
}

// Status is the detector's own numbers.
type Status struct {
	Actors   int      `json:"actors"`
	Points   int      `json:"points"`
	Findings uint64   `json:"findings"`
	Dropped  uint64   `json:"dropped"`
	Blinded  uint64   `json:"blinded"`
	Models   []string `json:"models"`
}

// Status reports what the detector holds. Dropped and Blinded are the pair
// worth an alert: a detector that turned itself off is the failure mode
// this package is most careful about.
func (s *Set) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Actors: len(s.actors), Points: len(s.points),
		Findings: s.findings, Dropped: s.dropped, Blinded: s.blinded}
	if s.p.Novelty.Symbols || s.p.Novelty.WritePoints || s.p.Novelty.Burst > 0 {
		st.Models = append(st.Models, string(ModelNovelty))
	}
	if s.p.Cycle.Enabled {
		st.Models = append(st.Models, string(ModelCycle))
	}
	if s.p.Sequence.Enabled {
		st.Models = append(st.Models, string(ModelSequence))
	}
	if s.p.Talkers.Enabled {
		st.Models = append(st.Models, string(ModelTalkers))
	}
	if s.p.Telemetry.Enabled {
		st.Models = append(st.Models, string(ModelTelemetry))
	}
	if len(s.p.Correlations) > 0 {
		st.Models = append(st.Models, string(ModelCorrelation))
	}
	sort.Strings(st.Models)
	return st
}
