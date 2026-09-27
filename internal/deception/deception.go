// Package deception is the half of a decoy that is not protocol: who is
// lied to, what a fabricated device's process data looks like, and what
// the operator is told about it.
//
// The HTTP gateway has had this for a while -- honeypot routes, decoy
// bodies, deceptive answers on real routes -- and everything else either
// forwarded or refused. That asymmetry is worth naming, because a refusal
// is information:
//
//	PROBE: unit 1 read -> 2 registers [4660 0]
//	PROBE: unit 2 read -> exception 0x0a
//	PROBE: unit 3 read -> exception 0x0a
//
// That is a Modbus relay doing exactly what the specification says a
// gateway should: 0x0A is "gateway path unavailable", and it is the honest
// answer for a unit identifier nothing is behind. Sweep 1 to 247 and the
// answers draw the map: which unit identifiers exist, and by the same
// argument which function codes the policy permits. The relay refuses the
// scan and completes the survey.
//
// A decoy answers instead. The crawl finishes, the map is wrong, and the
// request that would have worked looks exactly like the one that did not.
//
// # The rule that makes this safe to use in a plant
//
// On a web gateway the worst case of a deceptive answer is a client
// receiving nonsense. On a plant floor the worst case is an operator
// reading a fabricated tank level off an HMI and acting on it. So the
// kinds using this package hold to one rule, and it is checked by tests
// rather than by intention: **a frame the policy allowed is never
// deceived.** Deception replaces a refusal, never an answer. The worst
// case is then bounded -- a master whose request was going to be refused
// gets a plausible answer instead of an exception -- and the remaining
// risk is a misconfigured policy refusing something legitimate, which is
// why the section also insists on being told which clients it may lie to
// before it will lie to anybody.
//
// # Fabricated values have to be answerable
//
// A decoy that answers a register with a random number every time is a
// decoy for about four seconds: a scanner that reads the same address
// twice sees noise, and no process does that. One that answers zero is
// worse, because zero is what an unconfigured device says.
//
// So the values here are derived rather than invented: stable for an
// address, moving slowly with time, and bounded by a band the profile
// declares -- an analogue measurement inside its range, a discrete bit
// that mostly stays where it is, a counter that only ever increases. They
// are derived from a seed and the clock rather than stored, so a sweep of
// every address in the space costs nothing to remember, and two reads a
// second apart agree while two reads a minute apart have moved. The seed
// defaults to the listener's name, so a decoy is the same device after a
// restart: a fake PLC whose serial number changes when the proxy is
// upgraded is a fake PLC somebody has noticed.
package deception

import (
	"encoding/binary"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Shape is how one band of addresses behaves. Getting this wrong is what
// gives a decoy away, so there are only three and each says what a real
// device of that sort does.
type Shape string

const (
	// ShapeAnalogue is a measurement: it sits inside a range and drifts.
	ShapeAnalogue Shape = "analogue"
	// ShapeDiscrete is a bit or a small state: it mostly stays where it
	// is and occasionally changes.
	ShapeDiscrete Shape = "discrete"
	// ShapeCounter only increases. A totaliser that goes backwards is
	// the tell that ends the pretence, so this one is monotone by
	// construction rather than by luck.
	ShapeCounter Shape = "counter"
)

// A Band is a run of addresses that behave the same way.
type Band struct {
	// Lo and Hi are the addresses this band covers, inclusive.
	Lo, Hi int
	Shape  Shape
	// Min and Max bound an analogue band's value, and Rate is how much a
	// counter adds per period.
	Min, Max, Rate int
}

// Values is a fabricated device's process data.
//
// Nothing is stored: a value is a function of the seed, the address and
// which period of the clock it is, which is what lets a decoy answer a
// sweep of the whole address space without remembering that it happened.
type Values struct {
	seed   uint64
	period time.Duration
	bands  []Band
	now    func() time.Time
}

// DefaultPeriod is how long one sample lasts. Half a minute is slow
// enough that a scanner reading an address twice sees the same value and
// fast enough that a curious engineer watching a trend sees it move.
const DefaultPeriod = 30 * time.Second

// NewValues builds the value source. An empty band list answers
// everything as an analogue in the range a 16-bit engineering value
// usually sits in, which is better than zero and worse than a profile.
func NewValues(seed uint64, period time.Duration, bands []Band) *Values {
	if period <= 0 {
		period = DefaultPeriod
	}
	if len(bands) == 0 {
		bands = []Band{{Lo: 0, Hi: 65535, Shape: ShapeAnalogue, Min: 0, Max: 27648}}
	}
	return &Values{seed: seed, period: period, bands: bands, now: time.Now}
}

// SetClockForTest replaces the clock.
func (v *Values) SetClockForTest(f func() time.Time) { v.now = f }

// bandFor is the first band covering an address, or the last band as the
// fallback: an address outside every band still has to answer something,
// and answering it as the device's commonest kind of register is closer
// to a real device than refusing one address in the middle of a range.
func (v *Values) bandFor(addr int) Band {
	for _, b := range v.bands {
		if addr >= b.Lo && addr <= b.Hi {
			return b
		}
	}
	return v.bands[len(v.bands)-1]
}

// mix is the derivation: a hash of everything that decides a value.
//
// The finaliser at the end is not decoration. Every use of this takes the
// result modulo a small range, which is the low bits, and FNV's low bits
// are its weakest: with the hash alone a band a thousand wide answered
// only between 1443 and 1889 across a hundred addresses. Every register on
// the device reading inside the middle half of its range is exactly the
// statistical tell that ends a pretence -- so the bits are avalanched
// before anybody takes a remainder of them.
func (v *Values) mix(parts ...uint64) uint64 {
	h := fnv.New64a()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v.seed)
	_, _ = h.Write(b[:])
	for _, p := range parts {
		binary.BigEndian.PutUint64(b[:], p)
		_, _ = h.Write(b[:])
	}
	return avalanche(h.Sum64())
}

// avalanche is the 64-bit finaliser of MurmurHash3: three shift-xor-
// multiply rounds that spread every input bit across the whole word.
func avalanche(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

// tick is which period of the clock it is.
func (v *Values) tick() uint64 {
	n := v.now().UTC().UnixNano() / int64(v.period)
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// nonneg is an address or a count at the width the hash wants.
//
// The inputs are addresses and unit identifiers, which are never negative.
// The check is here so that is a fact about the code rather than a habit of
// its callers: a negative address would otherwise convert to a number near
// 2^64 and answer from somewhere unrelated in the address space.
func nonneg(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n) //nolint:gosec // non-negative, checked above
}

// reduce fits a hash into 0..n-1.
//
// Every conversion to an unsigned width in this file goes through here, so
// that "n is positive" is a check rather than an argument: a band read out
// of a configuration is the sort of number that is negative exactly once,
// on the day somebody writes max below min.
func reduce(h uint64, n int) int {
	if n <= 0 {
		return 0
	}
	return int(h % uint64(n)) //nolint:gosec // n is positive, checked above
}

// Register is the 16-bit value at an address of a unit.
func (v *Values) Register(unit byte, addr int) uint16 {
	b := v.bandFor(addr)
	base := v.mix(uint64(unit), nonneg(addr))
	switch b.Shape {
	case ShapeCounter:
		// Monotone: the start is arbitrary, and every period adds the
		// rate. It wraps, because a 16-bit totaliser does.
		rate := b.Rate
		if rate <= 0 {
			rate = 1
		}
		return uint16((base + v.tick()*nonneg(rate)) & 0xFFFF) //nolint:gosec // a 16-bit register wraps
	case ShapeDiscrete:
		if v.Bit(unit, addr) {
			return 1
		}
		return 0
	default:
		lo, hi := b.Min, b.Max
		if hi <= lo {
			lo, hi = 0, 27648
		}
		span := hi - lo + 1
		// The address decides where in the band this point sits, and the
		// clock moves it inside a small window around that. A measurement
		// that swings across its whole range every half minute is not a
		// measurement anybody would believe.
		centre := lo + reduce(base, span)
		window := max(span/50, 1)
		off := reduce(v.mix(uint64(unit), nonneg(addr), v.tick()), 2*window+1) - window
		val := min(max(centre+off, lo), hi)
		return uint16(val) //nolint:gosec // bounded by the band above
	}
}

// Bit is the coil or discrete input at an address.
//
// A bit that changes every period is a bit nothing drives. The state
// holds for a run of periods whose length is derived from the address, so
// most bits are still where they were a minute ago and a few have moved.
func (v *Values) Bit(unit byte, addr int) bool {
	hold := 1 + reduce(v.mix(uint64(unit), nonneg(addr), 0x484f4c44), 20)
	era := v.tick() / nonneg(hold)
	return v.mix(uint64(unit), nonneg(addr), era, 0x424954)&1 == 1
}

// A Policy is who this listener may lie to, and the record of who it has.
type Policy struct {
	clients []netip.Prefix
	// anyone says there is no client list. It is only allowed where
	// nothing real is behind the listener at all, which the kinds check
	// at load rather than here: this package cannot know what a listener
	// is in front of.
	anyone bool
	max    int

	served  atomic.Uint64
	tripped atomic.Uint64

	mu   sync.Mutex
	seen map[netip.Addr]*Client
}

// A Client is one address this listener has answered with a fabrication.
// It is what the status view shows, and it is the point of the whole
// exercise: a decoy nobody reads is an ornament.
type Client struct {
	Addr        netip.Addr `json:"client_ip"`
	First, Last time.Time  `json:"-"`
	FirstSeen   string     `json:"first_seen"`
	LastSeen    string     `json:"last_seen"`
	Frames      uint64     `json:"frames"`
	// Tripped counts the frames that touched something no legitimate
	// client has a reason to touch.
	Tripped uint64 `json:"tripped"`
}

// DefaultMaxClients bounds the record. The addresses come off the
// network, so the table is bounded like every other one here; a scan from
// a whole subnet is exactly the case that would otherwise grow it.
const DefaultMaxClients = 1024

// NewPolicy compiles the client list. An empty list means everybody,
// which the caller has to have decided is safe.
func NewPolicy(clients []netip.Prefix, maxClients int) *Policy {
	if maxClients <= 0 {
		maxClients = DefaultMaxClients
	}
	return &Policy{clients: clients, anyone: len(clients) == 0, max: maxClients,
		seen: make(map[netip.Addr]*Client)}
}

// Admits reports whether this client gets the fabrication.
func (p *Policy) Admits(ip netip.Addr) bool {
	if p == nil {
		return false
	}
	if p.anyone {
		return true
	}
	for _, n := range p.clients {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Anyone reports whether the policy has no client list, which a status
// view and a load-time warning both want to say out loud.
func (p *Policy) Anyone() bool { return p != nil && p.anyone }

// Record notes one fabricated answer, and whether it touched a tripwire.
func (p *Policy) Record(ip netip.Addr, tripped bool, now time.Time) {
	if p == nil {
		return
	}
	p.served.Add(1)
	if tripped {
		p.tripped.Add(1)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.seen[ip]
	if c == nil {
		if len(p.seen) >= p.max {
			p.evictOldestLocked()
		}
		c = &Client{Addr: ip, First: now}
		p.seen[ip] = c
	}
	c.Last = now
	c.Frames++
	if tripped {
		c.Tripped++
	}
}

// evictOldestLocked drops the least recently seen client. Dropping the
// oldest rather than refusing to record keeps the table about whoever is
// probing now, which is the question being asked.
func (p *Policy) evictOldestLocked() {
	var oldest netip.Addr
	var at time.Time
	for addr, c := range p.seen {
		if at.IsZero() || c.Last.Before(at) {
			oldest, at = addr, c.Last
		}
	}
	delete(p.seen, oldest)
}

// Served and Tripped are the counters behind the status line.
func (p *Policy) Served() uint64  { return p.served.Load() }
func (p *Policy) Tripped() uint64 { return p.tripped.Load() }

// Clients lists who has been answered, most recent first.
func (p *Policy) Clients(limit int) []Client {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	out := make([]Client, 0, len(p.seen))
	for _, c := range p.seen {
		e := *c
		e.FirstSeen = e.First.UTC().Format(time.RFC3339)
		e.LastSeen = e.Last.UTC().Format(time.RFC3339)
		out = append(out, e)
	}
	p.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// SeedFor derives a stable seed from a name, so a listener that names no
// seed is still the same fabricated device after a restart.
func SeedFor(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}
