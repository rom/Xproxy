package modbus

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/numrange"
)

// Behavioural detection: what a master has been doing, and when it stops.
//
// The policy in policy.go answers "is this permitted", from rules somebody wrote
// down. This answers a different question -- "is this what this master has been
// doing" -- and answers it without anybody having written anything. On this
// protocol that is worth more than it would be almost anywhere else, because
// control traffic is repetitive in a way other traffic is not: a master's scan
// cycle is the same few function codes over the same few address ranges, every
// cycle, for years. "This client has never done this before" is a signal here
// where on a web front end it would be noise.
//
// Three things are watched:
//
//	a new function code   a master that has only ever read starting to write
//	a new write address   a write to a register this master has never written
//	a burst of writes     forty registers moved in ten seconds
//
// The burst is not the per-address rate bound in values.go, and the difference
// matters. That one says "this setpoint may move once a minute" and would not
// notice a master that wrote forty *different* registers once each. This one
// counts a client's writes across every address, which is the shape of somebody
// walking the address space rather than of a control action.
//
// # It alerts
//
// It does not refuse, unless somebody asks it to. A detector built on "I have not
// seen this before" refuses the first legitimate thing anybody does after a quiet
// year: the maintenance write, the commissioning of a new point, the operator who
// finally uses a function the master has always been allowed to use. So the
// default is a security event and a counter, `action: deny` exists because some
// plants want it, and the documentation says what it costs. The events do not
// reach the ban ladder either: banning a plant's master over a function code it
// had not used yet takes the process away from the control room, which is a worse
// outcome than the one being guarded against.
//
// # It settles first
//
// When the relay starts, everything is new. For `settle` after a client is first
// seen its traffic is recorded and nothing about novelty is reported. That is the
// same honesty the learning report's warning is about: what this relay has seen is
// not the same as what is normal, and the first minutes of a session are not even
// what it has seen. The burst bound is not suppressed, because it is an absolute
// number an operator set rather than something learned -- a burst during the
// settling window is still a burst.

const (
	// defaultAnomalySettle is how long a client's traffic is recorded before
	// novelty is reported about it. Ten minutes because a master's startup is
	// several scan cycles and a recipe download, and none of that is what it
	// will be doing for the rest of the year.
	defaultAnomalySettle = 10 * time.Minute
	// defaultAnomalyPeriod is the window the burst is counted over. The bound
	// itself is config.DefaultModbusWriteBurst, which validation also needs. A
	// master nudging setpoints does nothing like twenty writes in ten seconds; a
	// plant that downloads recipes does, which is why the bound is a number in
	// the configuration and the default action is to say so rather than refuse.
	defaultAnomalyPeriod = 10 * time.Second
	// defaultAnomalyClients bounds the clients remembered.
	defaultAnomalyClients = 1024
	// maxAnomalyFunctions and maxAnomalyRanges bound one client's record. There
	// are twenty function codes in the specification, so the first is never
	// reached by a master; a client that reaches either has its novelty
	// detection turned off and the report says so, because a detector that
	// silently widened what counts as "seen" would be one that stopped
	// detecting without saying so.
	maxAnomalyFunctions = 32
	maxAnomalyRanges    = 64
)

// anomalyPolicy is the compiled configuration.
type anomalyPolicy struct {
	settle                       time.Duration
	newFunction, newWriteAddress bool
	burst                        int
	period                       time.Duration
	deny                         bool
	maxClients                   int
}

func compileAnomaly(c *config.ModbusAnomaly) (*anomalyPolicy, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	p := &anomalyPolicy{
		settle:          defaultAnomalySettle,
		newFunction:     c.NewFunction == nil || *c.NewFunction,
		newWriteAddress: c.NewWriteAddress == nil || *c.NewWriteAddress,
		burst:           config.DefaultModbusWriteBurst,
		period:          defaultAnomalyPeriod,
		maxClients:      defaultAnomalyClients,
	}
	if c.Settle != nil {
		p.settle = time.Duration(*c.Settle)
	}
	if c.WriteBurst != nil {
		p.burst = *c.WriteBurst
	}
	if c.BurstPeriod != 0 {
		p.period = time.Duration(c.BurstPeriod)
	}
	if c.MaxClients > 0 {
		p.maxClients = c.MaxClients
	}
	switch c.Action {
	case "", "alert":
	case "deny":
		p.deny = true
	default:
		return nil, fmt.Errorf("anomaly action %q: alert or deny", c.Action)
	}
	if p.settle < 0 {
		return nil, fmt.Errorf("anomaly settle %s: not negative", p.settle)
	}
	if p.burst < 0 {
		return nil, fmt.Errorf("anomaly write_burst %d: not negative", p.burst)
	}
	if p.period <= 0 {
		return nil, fmt.Errorf("anomaly burst_period %s: positive", p.period)
	}
	// A configuration that enabled the detector and turned off everything it
	// detects is a mistake somebody will spend an afternoon on.
	if !p.newFunction && !p.newWriteAddress && p.burst == 0 {
		return nil, fmt.Errorf("anomaly: enabled with nothing to detect")
	}
	return p, nil
}

func (p *anomalyPolicy) on() bool { return p != nil }

// anomalyClient is one master's record.
type anomalyClient struct {
	since time.Time
	funcs map[byte]bool
	// writeAddrs are the ranges this client has written, and full says the
	// bound was reached. Once it is, novelty about addresses is no longer
	// reported for this client: the alternative is collapsing the set into one
	// span, which widens what counts as seen and would stop the detector
	// detecting while it went on looking like it worked.
	writeAddrs []numrange.Range
	full       bool
	funcsFull  bool
	// writes is the sliding window of write times, oldest first.
	writes []time.Time
}

// anomalies is the per-listener table.
type anomalies struct {
	mu      sync.Mutex
	p       *anomalyPolicy
	clients map[netip.Addr]*anomalyClient
	order   []netip.Addr
	// Dropped counts the clients the bound turned away, and Blinded the
	// clients whose own bound turned their novelty detection off. Both are in
	// the status view, because a detector that quietly stopped detecting is
	// the failure mode worth counting.
	Dropped, Blinded uint64
}

func newAnomalies(p *anomalyPolicy) *anomalies {
	if !p.on() {
		return nil
	}
	return &anomalies{p: p, clients: map[netip.Addr]*anomalyClient{}}
}

// anomalyFinding is one thing a request tripped.
type anomalyFinding struct {
	reason, detail string
}

// check records the request and reports what was new about it.
//
// Recording happens whether or not anything is reported, and before the settling
// window is over: the point of settling is not to ignore the traffic but to learn
// from it quietly.
//
// It also happens when the finding is about to refuse the request. So `action:
// deny` refuses the *first* occurrence and the retry goes through, which is a
// deliberate limit: refusing every occurrence until somebody intervened would
// mean a plant that could not be driven after any novelty at all, and there is no
// mechanism here for the intervening. What deny buys is a hard stop on the first
// attempt and an operator's attention. It is not a block; the policy is what
// blocks.
func (a *anomalies) check(req request, now time.Time) []anomalyFinding {
	if a == nil || req.pdu == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.clients[req.client]
	if c == nil {
		if len(a.clients) >= a.p.maxClients {
			a.Dropped++
			return nil
		}
		c = &anomalyClient{since: now, funcs: map[byte]bool{}}
		a.clients[req.client] = c
		a.order = append(a.order, req.client)
	}
	settled := now.Sub(c.since) >= a.p.settle

	var out []anomalyFinding
	fn := req.pdu.Function
	if !c.funcs[fn] {
		if len(c.funcs) >= maxAnomalyFunctions {
			if !c.funcsFull {
				c.funcsFull, a.Blinded = true, a.Blinded+1
			}
		} else {
			c.funcs[fn] = true
			if settled && a.p.newFunction {
				out = append(out, anomalyFinding{
					reason: "anomaly_new_function",
					detail: fmt.Sprintf("unit %d %s", req.unit, wire.FunctionName(fn)),
				})
			}
		}
	}

	lo, hi, ok := writeSpan(req.pdu)
	if !ok || hi < 0 {
		// Not a write. Nothing below applies, and the read has already been
		// counted against the function set above.
		return out
	}
	if f := a.burstLocked(c, now); f != nil {
		out = append(out, *f)
	}
	if c.full {
		return out
	}
	if !covers(c.writeAddrs, lo, hi) {
		known := c.writeAddrs
		c.writeAddrs = addAnomalyRange(c.writeAddrs, lo, hi)
		if len(c.writeAddrs) > maxAnomalyRanges {
			c.writeAddrs, c.full = known, true
			a.Blinded++
			return out
		}
		if settled && a.p.newWriteAddress {
			out = append(out, anomalyFinding{
				reason: "anomaly_new_write_address",
				detail: fmt.Sprintf("unit %d %s %s", req.unit, wire.FunctionName(req.pdu.Function), rangeText(lo, hi)),
			})
		}
	}
	return out
}

// burstLocked counts this write against the window and reports a burst.
func (a *anomalies) burstLocked(c *anomalyClient, now time.Time) *anomalyFinding {
	if a.p.burst == 0 {
		return nil
	}
	cut := now.Add(-a.p.period)
	drop := 0
	for drop < len(c.writes) && c.writes[drop].Before(cut) {
		drop++
	}
	c.writes = append(c.writes[drop:], now)
	// Strictly greater: a bound of twenty means twenty are allowed.
	if len(c.writes) <= a.p.burst {
		return nil
	}
	return &anomalyFinding{
		reason: "anomaly_write_burst",
		detail: fmt.Sprintf("%d writes in %s, bound %d", len(c.writes), a.p.period, a.p.burst),
	}
}

// covers says whether every address from lo to hi is already known.
func covers(rs []numrange.Range, lo, hi int) bool {
	for _, r := range rs {
		if lo >= r.Lo && hi <= r.Hi {
			return true
		}
	}
	return false
}

// addAnomalyRange adds a span and coalesces, and unlike learn.go's addRange it
// does not collapse to one span at the bound. The caller checks the length and
// decides, because widening the known set is the one thing this table must not do
// on its own.
func addAnomalyRange(rs []numrange.Range, lo, hi int) []numrange.Range {
	out := make([]numrange.Range, len(rs), len(rs)+1)
	copy(out, rs)
	return mergeRanges(append(out, numrange.Range{Lo: lo, Hi: hi}))
}

// Clients is how many masters are remembered, for the status view.
func (a *anomalies) Clients() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.clients)
}

// decideAnomaly runs the detector over one request and says whether to carry it.
//
// Every finding is alerted on, whatever the action, because an operator who set
// `action: deny` still wants the record and an operator who did not still wants
// the signal. Only the first finding refuses, and only when this listener is
// enforcing: in shadow mode or a learning run nothing is refused, which is the
// whole of what those modes mean.
func (t *server) decideAnomaly(se *session, frame *wire.Frame, pdu *wire.PDU, req request, enforcing bool) (string, bool) {
	if t.anomalies == nil {
		return "", true
	}
	refuse := ""
	for _, f := range t.anomalies.check(req, time.Now()) {
		t.alert(se.ip, f.reason, f.detail)
		if !t.anomalies.p.deny || refuse != "" {
			continue
		}
		if !enforcing {
			// The detector would have refused. Saying so is what shadow mode is
			// for, and it goes in the same place the policy's would-be refusals
			// do so that one report answers "what would enforcing cost".
			t.host.Counters().ModbusWouldDeny.Add(1)
			t.host.Counters().WouldRefuse("modbus", f.reason)
			t.host.Shadow().Record("modbus", t.cfg.Name, f.reason, "anomaly",
				fmt.Sprintf("unit %d %s %s", frame.Unit, wire.FunctionName(pdu.Function), f.detail))
			continue
		}
		refuse = f.reason
	}
	if refuse == "" {
		return "", true
	}
	se.denied.Add(1)
	t.host.Counters().ModbusDenied.Add(1)
	t.audit(se, frame, pdu, Decision{Reason: refuse, Rule: "anomaly"}, "deny")
	return refuse, false
}
