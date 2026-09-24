package modbus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/modbus"
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
// function code -- with the address ranges and the value ranges actually
// used, and writes it out as a rule set to start from. Run it for a week,
// read the file, paste the rules, turn enforcement on.

// maxObservedRanges bounds the distinct address ranges held for one
// subject. Past it the ranges are merged into their span, which is
// honest about being a bound rather than dropping what it cannot hold.
const maxObservedRanges = 32

// subjectKey identifies one observation: who, as what, to which device,
// doing what.
type subjectKey struct {
	client   string
	role     string
	unit     byte
	function byte
}

// observation is what was seen of one subject.
type observation struct {
	first, last time.Time
	frames      uint64
	denied      uint64
	// addresses are the ranges read or written, merged as they grow.
	addresses []rng
	// writeAddresses are the ranges written, kept apart because that is
	// the rule an engineer reads most carefully.
	writeAddresses []rng
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
type Learner struct {
	path     string
	interval time.Duration
	max      int
	listener string

	mu   sync.Mutex
	seen map[subjectKey]*observation
	// order is insertion order, so the bound drops the oldest subject
	// rather than a random one.
	order []subjectKey

	// Dropped counts the subjects the bound could not hold, and
	// Observed the frames recorded. A learning run that quietly stopped
	// learning is worse than one that says so.
	Dropped, Observed atomic.Uint64
	Writes, Failures  atomic.Uint64

	stop chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// NewLearner prepares a learner. The file is written on the interval and
// at shutdown.
func NewLearner(listener, path string, interval time.Duration, max int) *Learner {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if max <= 0 {
		max = 8192
	}
	return &Learner{path: path, interval: interval, max: max, listener: listener,
		seen: map[subjectKey]*observation{}, stop: make(chan struct{})}
}

// Start runs the periodic write. onError hears about a report that could
// not be written, because a learning run whose file is not there is a
// week nobody gets back.
func (l *Learner) Start(onError func(error)) {
	if l == nil {
		return
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		t := time.NewTicker(l.interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				if err := l.Write(); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

// Stop ends the loop and writes the report one last time.
func (l *Learner) Stop() error {
	if l == nil {
		return nil
	}
	var err error
	l.once.Do(func() {
		close(l.stop)
		l.wg.Wait()
		err = l.Write()
	})
	return err
}

// Observe records one request and what was decided about it.
func (l *Learner) Observe(req request, allowed bool, now time.Time) {
	if l == nil {
		return
	}
	key := subjectKey{client: req.client.String(), role: req.role,
		unit: req.unit, function: req.pdu.Function}
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.seen[key]
	if o == nil {
		if len(l.seen) >= l.max {
			// The bound is reached. The oldest subject goes, and the
			// drop is counted: a report that silently held the first
			// eight thousand clients and none after them would be a
			// report nobody could trust.
			oldest := l.order[0]
			l.order = l.order[1:]
			delete(l.seen, oldest)
			l.Dropped.Add(1)
		}
		o = &observation{first: now, minValue: 1 << 30, maxValue: -(1 << 30)}
		l.seen[key] = o
		l.order = append(l.order, key)
	}
	o.last = now
	o.frames++
	if !allowed {
		o.denied++
	}
	l.Observed.Add(1)
	p := req.pdu
	if p.HasRange {
		if last, ok := p.Last(); ok {
			o.addresses = addRange(o.addresses, int(p.Address), int(last))
		}
	}
	if lo, hi, ok := writeSpan(p); ok && hi >= 0 {
		o.writeAddresses = addRange(o.writeAddresses, lo, hi)
	}
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
	for _, on := range p.Coils {
		if on {
			o.coilSet = true
		} else {
			o.coilClear = true
		}
	}
}

// ObserveException records that the device refused a request, which is
// the other half of what a learning run is for: the requests a master
// makes and the device already rejects are the ones to write out of the
// policy rather than into it.
func (l *Learner) ObserveException(req request, now time.Time) {
	if l == nil {
		return
	}
	key := subjectKey{client: req.client.String(), role: req.role,
		unit: req.unit, function: req.pdu.Function}
	l.mu.Lock()
	defer l.mu.Unlock()
	if o := l.seen[key]; o != nil {
		o.exceptions++
		o.last = now
	}
}

// addRange merges a range into a set, keeping it bounded. Overlapping and
// adjacent ranges become one, and past the bound the whole set collapses
// to its span -- which is wider than the truth and says so, rather than
// forgetting the parts that did not fit.
func addRange(rs []rng, lo, hi int) []rng {
	for i := range rs {
		if lo <= rs[i].hi+1 && hi+1 >= rs[i].lo {
			if lo < rs[i].lo {
				rs[i].lo = lo
			}
			if hi > rs[i].hi {
				rs[i].hi = hi
			}
			return mergeRanges(rs)
		}
	}
	rs = append(rs, rng{lo, hi})
	if len(rs) > maxObservedRanges {
		span := rs[0]
		for _, r := range rs[1:] {
			if r.lo < span.lo {
				span.lo = r.lo
			}
			if r.hi > span.hi {
				span.hi = r.hi
			}
		}
		return []rng{span}
	}
	return mergeRanges(rs)
}

func mergeRanges(rs []rng) []rng {
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	out := rs[:0]
	for _, r := range rs {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			if r.hi > out[n-1].hi {
				out[n-1].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// Write renders the report and replaces the file atomically.
func (l *Learner) Write() error {
	if l == nil || l.path == "" {
		return nil
	}
	body := l.Report()
	dir := filepath.Dir(l.path)
	tmp, err := os.CreateTemp(dir, ".modbus-learn-*")
	if err != nil {
		l.Failures.Add(1)
		return fmt.Errorf("modbus learn: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		l.Failures.Add(1)
		return fmt.Errorf("modbus learn: %w", err)
	}
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		l.Failures.Add(1)
		return fmt.Errorf("modbus learn: %w", err)
	}
	if err := tmp.Close(); err != nil {
		l.Failures.Add(1)
		return fmt.Errorf("modbus learn: %w", err)
	}
	if err := os.Rename(name, l.path); err != nil {
		l.Failures.Add(1)
		return fmt.Errorf("modbus learn: %w", err)
	}
	l.Writes.Add(1)
	return nil
}

// Report renders what was learned as YAML: a description of the traffic,
// and under it a rule set that permits exactly what was seen.
//
// The rules are deliberately one per client, role and unit rather than
// one per frame: a rule per observation would be a rule set nobody reads.
// The addresses are the ranges actually used, widened to nothing, and the
// value bounds are the values actually written -- which an engineer then
// widens on purpose, having seen what the traffic is.
func (l *Learner) Report() string {
	l.mu.Lock()
	keys := make([]subjectKey, 0, len(l.seen))
	for k := range l.seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.client != b.client {
			return a.client < b.client
		}
		if a.role != b.role {
			return a.role < b.role
		}
		if a.unit != b.unit {
			return a.unit < b.unit
		}
		return a.function < b.function
	})
	snapshot := make([]observation, 0, len(keys))
	for _, k := range keys {
		snapshot = append(snapshot, *l.seen[k])
	}
	dropped, observed := l.Dropped.Load(), l.Observed.Load()
	l.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "# Modbus traffic observed by listener %q.\n", l.listener)
	fmt.Fprintf(&b, "# Written %s. %d frames, %d subjects", time.Now().UTC().Format(time.RFC3339), observed, len(keys))
	if dropped > 0 {
		fmt.Fprintf(&b, ", %d subjects dropped at the bound (raise learn.max_subjects)", dropped)
	}
	b.WriteString(".\n#\n")
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
			fmt.Fprintf(&b, "    values_written: {min: %d, max: %d}\n", o.minValue, o.maxValue)
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
		fmt.Fprintf(&b, "  - name: learned-%s-u%d-%s\n", sanitise(k.client), k.unit, wire.FunctionName(k.function))
		b.WriteString("    action: allow\n")
		fmt.Fprintf(&b, "    clients: [%s/32]\n", k.client)
		if k.role != "" {
			fmt.Fprintf(&b, "    roles: [%s]\n", k.role)
		}
		fmt.Fprintf(&b, "    units: [%d]\n", k.unit)
		fmt.Fprintf(&b, "    functions: [%s]\n", wire.FunctionName(k.function))
		if len(o.addresses) > 0 {
			fmt.Fprintf(&b, "    addresses: [%s]\n", rangeList(o.addresses))
		}
		if len(o.writeAddresses) > 0 {
			fmt.Fprintf(&b, "    write_addresses: [%s]\n", rangeList(o.writeAddresses))
		}
		if o.haveValues {
			fmt.Fprintf(&b, "    values: [{min: %d, max: %d}]\n", o.minValue, o.maxValue)
		}
		if o.exceptions > 0 {
			fmt.Fprintf(&b, "    comment: \"the device refused %d of these\"\n", o.exceptions)
		}
	}
	if len(keys) == 0 {
		b.WriteString("  []\n")
	}
	return b.String()
}

// rangeList renders ranges the way the policy reads them.
func rangeList(rs []rng) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.lo == r.hi {
			parts = append(parts, fmt.Sprintf("%d", r.lo))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
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

// Subjects is how many subjects are held, for the status view.
func (l *Learner) Subjects() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}
