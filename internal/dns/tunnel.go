package dns

import (
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/netutil"
)

// DNS tunnelling is the oldest way out of a network that filters
// everything else, and it still works, because a resolver is usually
// the one thing every host may talk to. The payload goes up in the
// query name — a few dozen base32 characters per label, one label per
// chunk — and comes back down in the answer, most often TXT, sometimes
// NULL or CNAME. The tunnel's own domain is delegated to the
// attacker's name server, so every query reaches them whatever this
// proxy's upstream is: blocking the upstream does nothing, and a block
// list only works if somebody already knew the name.
//
// What gives it away is not any one query. It is the shape of a
// client's traffic under one registered domain: names carrying more
// information per character than words do, hundreds of distinct
// subdomains where an ordinary service has a handful, answers that are
// mostly TXT, and a high rate of NXDOMAIN from the probing and the
// encoding that produces names nothing resolves.
//
// So no single signal decides here. Each one alone has honest traffic
// behind it — a content delivery network's hostnames really are random,
// a reputation service really does encode a hash into a name and answer
// TXT, and a laptop waking up really does produce a burst of
// NXDOMAIN. What does not happen by accident is several of them at once
// under one domain from one client, which is what min_signals says out
// loud rather than hiding in a weighting nobody can read.

// TunnelPolicy is the compiled tunnelling detector configuration.
type TunnelPolicy struct {
	// Window is the period the signals are measured over.
	Window time.Duration
	// MinQueries is how many queries a client must make under one
	// domain before any judgement is made about it. Below it there is
	// not enough to be wrong about.
	MinQueries int
	// MinSignals is how many of the signals must fire together.
	MinSignals int
	// Entropy is the bits per character above which an encoded name is
	// counted, and EntropyShare the share of queries that must reach it.
	Entropy      float64
	EntropyShare float64
	// MinLabelLength is the shortest label the entropy test looks at.
	// A short string cannot carry much information and its entropy is
	// mostly noise, so judging one is judging nothing.
	MinLabelLength int
	// Distinct is the number of different subdomains under one domain
	// that counts as the cardinality of a tunnel rather than a service.
	Distinct int
	// TXTShare and NXShare are the shares of a domain's queries that
	// must be TXT (or the other record types a tunnel returns data in)
	// and that must answer NXDOMAIN.
	TXTShare float64
	NXShare  float64
	// PayloadBytes is the encoded bytes below the domain in a window:
	// the exfiltration itself, rather than a proxy for it.
	PayloadBytes int64
	// Action is log or block.
	Action string
	// Cooldown is how long a detected domain stays blocked for the
	// client it was detected for.
	Cooldown time.Duration
	// MaxTracked bounds the table. The key is a client and a domain and
	// both are chosen by whoever sends the queries, so the bound is not
	// a tuning knob but the thing that stops the detector being the
	// attack.
	MaxTracked int
	// Allow names domains never judged. Reputation services, telemetry
	// and anything else that legitimately looks like this goes here.
	Allow *BlockList
}

// tunnelWindow is what one client has done under one domain.
type tunnelWindow struct {
	started  time.Time
	seen     time.Time
	queries  int
	encoded  int
	txt      int
	nx       int
	payload  int64
	subs     map[string]bool
	overflow bool
	// flagged is when a detection fired; the domain is refused for this
	// client until flagged+cooldown.
	flagged time.Time
	reasons []string
}

// Detector holds the per client, per domain windows.
type Detector struct {
	p TunnelPolicy
	// subsCap bounds the distinct set of one window. It is derived from
	// the cardinality threshold but never zero, because the set is also
	// what tells a repeated name from a new one -- which the payload
	// total depends on whether or not the cardinality signal is on.
	subsCap int
	mu      sync.Mutex
	w       map[string]*tunnelWindow
	// Detections counts windows that crossed the bar, Blocked the
	// queries refused because of one, and Evicted the windows dropped
	// to stay inside MaxTracked.
	Detections, Blocked, Evicted uint64
}

// NewDetector compiles a policy into a detector.
func NewDetector(p TunnelPolicy) *Detector {
	if p.MaxTracked <= 0 {
		p.MaxTracked = 65536
	}
	if p.Window <= 0 {
		p.Window = 5 * time.Minute
	}
	subsCap := p.Distinct * 4
	if subsCap < 256 {
		subsCap = 256
	}
	return &Detector{p: p, subsCap: subsCap, w: map[string]*tunnelWindow{}}
}

// Detection is what a window crossed and why.
type Detection struct {
	Domain  string
	Reasons []string
	// Queries and Payload are what the window held when it fired, so
	// the record says how much left rather than only that something did.
	Queries int
	Payload int64
}

// Blocks reports whether a query is refused because this client is
// inside the cooldown of a detection under the same domain. It is the
// only thing on the query path, and it takes one map lookup.
func (d *Detector) Blocks(client netip.Addr, name string, now time.Time) (string, bool) {
	if d == nil || d.p.Action != "block" {
		return "", false
	}
	domain := netutil.Registrable(name)
	if domain == "" {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	w := d.w[key(client, domain)]
	if w == nil || w.flagged.IsZero() || now.Sub(w.flagged) >= d.p.Cooldown {
		return "", false
	}
	d.Blocked++
	return domain, true
}

// Observe records an answered query and reports a detection the moment
// one is complete. It runs after the answer because the response code
// is one of the signals, and because a detector that decided before the
// answer would be deciding on less than it has.
func (d *Detector) Observe(client netip.Addr, q Question, rcode int, now time.Time) (Detection, bool) {
	if d == nil || q.Name == "" {
		return Detection{}, false
	}
	domain := netutil.Registrable(q.Name)
	if domain == "" || domain == q.Name {
		// A query for the registered name itself carries nothing below
		// it, so there is no payload to measure and no cardinality to
		// count. It is still traffic, but it is not this.
		return Detection{}, false
	}
	if d.p.Allow != nil && d.p.Allow.Match(q.Name) {
		return Detection{}, false
	}
	sub := strings.TrimSuffix(q.Name, "."+domain)

	d.mu.Lock()
	defer d.mu.Unlock()
	k := key(client, domain)
	w := d.w[k]
	if w == nil {
		if len(d.w) >= d.p.MaxTracked {
			d.evictLocked(now)
		}
		if len(d.w) >= d.p.MaxTracked {
			// Still full: every window is live. Rather than evict a
			// window that might be a detection in progress, this query
			// goes unmeasured and is counted as such. A detector that
			// grew without bound would be the denial of service it is
			// meant to catch.
			d.Evicted++
			return Detection{}, false
		}
		w = &tunnelWindow{started: now, subs: map[string]bool{}}
		d.w[k] = w
	}
	if now.Sub(w.started) >= d.p.Window {
		flagged, reasons := w.flagged, w.reasons
		*w = tunnelWindow{started: now, subs: map[string]bool{}, flagged: flagged, reasons: reasons}
	}
	w.seen = now
	w.queries++
	if isTunnelType(q.Type) {
		w.txt++
	}
	if rcode == RcodeNXDomain {
		w.nx++
	}
	if encodedLooking(sub, d.p.Entropy, d.p.MinLabelLength) {
		w.encoded++
	}
	// The distinct set is what a tunnel inflates, so it is also what an
	// attacker would use to inflate this table. It is bounded per
	// window, and hitting the bound is itself the signal.
	novel := true
	if len(w.subs) < d.subsCap {
		novel = !w.subs[sub]
		w.subs[sub] = true
	} else {
		w.overflow = true
	}
	// Only a name not seen before in this window adds to the payload.
	// Asking for the same name twice carries no second copy of
	// anything -- it is a cache miss, not an export -- and counting it
	// would turn any client that polls a long name into an exfiltration
	// of megabytes. That distinction is what keeps this signal
	// independent of the entropy one rather than a second reading of it.
	if novel {
		w.payload += int64(len(sub))
	}

	if w.queries < d.p.MinQueries {
		return Detection{}, false
	}
	reasons := w.signals(d.p, d.subsCap)
	if len(reasons) < d.p.MinSignals {
		return Detection{}, false
	}
	if !w.flagged.IsZero() && now.Sub(w.flagged) < d.p.Cooldown {
		return Detection{}, false // already reported, still inside the cooldown
	}
	w.flagged = now
	w.reasons = reasons
	d.Detections++
	return Detection{Domain: domain, Reasons: reasons, Queries: w.queries, Payload: w.payload}, true
}

// signals names every threshold this window crossed. They are returned
// rather than summed so that the record says what was seen, which is
// what makes a detection arguable with afterwards.
func (w *tunnelWindow) signals(p TunnelPolicy, subsCap int) []string {
	var out []string
	n := float64(w.queries)
	if p.EntropyShare > 0 && float64(w.encoded)/n >= p.EntropyShare {
		out = append(out, "entropy")
	}
	distinct := len(w.subs)
	if w.overflow {
		distinct = subsCap
	}
	if p.Distinct > 0 && distinct >= p.Distinct {
		out = append(out, "distinct_subdomains")
	}
	if p.TXTShare > 0 && float64(w.txt)/n >= p.TXTShare {
		out = append(out, "txt_heavy")
	}
	if p.NXShare > 0 && float64(w.nx)/n >= p.NXShare {
		out = append(out, "nxdomain_rate")
	}
	if p.PayloadBytes > 0 && w.payload >= p.PayloadBytes {
		out = append(out, "payload_volume")
	}
	return out
}

// evictLocked drops windows that have gone quiet, oldest first. It is
// called with the lock held.
func (d *Detector) evictLocked(now time.Time) {
	// Two passes rather than a sort: everything past its window is
	// stale whatever else is in the table, and that is almost always
	// enough. Only if it is not does the oldest live window go.
	var oldestKey string
	var oldest time.Time
	for k, w := range d.w {
		if now.Sub(w.seen) >= d.p.Window && (w.flagged.IsZero() || now.Sub(w.flagged) >= d.p.Cooldown) {
			delete(d.w, k)
			d.Evicted++
			continue
		}
		if oldestKey == "" || w.seen.Before(oldest) {
			oldestKey, oldest = k, w.seen
		}
	}
	if len(d.w) >= d.p.MaxTracked && oldestKey != "" {
		delete(d.w, oldestKey)
		d.Evicted++
	}
}

// Snapshot is the management view of the detector.
func (d *Detector) Snapshot() TunnelStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return TunnelStatus{Action: d.p.Action, Detections: d.Detections,
		Blocked: d.Blocked, Tracked: len(d.w), Evicted: d.Evicted}
}

// Tracked is how many windows are held, for the status view.
func (d *Detector) Tracked() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.w)
}

func key(client netip.Addr, domain string) string {
	return client.String() + "|" + domain
}

// isTunnelType names the record types a tunnel carries data back in.
// TXT is the usual one because it holds the most; NULL exists for
// exactly this and nothing else uses it; CNAME and MX return names,
// which is a slower channel that still works where TXT is filtered.
func isTunnelType(t uint16) bool {
	switch t {
	case TypeTXT, TypeNULL, TypeCNAME, TypeMX, TypeSRV:
		return true
	}
	return false
}

// encodedLooking reports whether the labels below the domain carry more
// information per character than names people type do. Base32 and
// base64 payloads run near 5 and 6 bits; words, even unfamiliar ones,
// sit well below that because letters in a language repeat.
//
// Every label is measured on its own and the longest decides, because a
// tunnel puts its payload in one long label under an ordinary looking
// prefix as often as not, and averaging over the whole name would let
// the prefix hide it.
func encodedLooking(sub string, bound float64, minLen int) bool {
	if bound <= 0 {
		return false
	}
	for _, label := range strings.Split(sub, ".") {
		if len(label) < minLen {
			continue
		}
		if Entropy(label) >= bound {
			return true
		}
	}
	return false
}

// Entropy is the Shannon entropy of a string in bits per character.
// It is exported because it is the one number here an operator has to
// be able to check a name against by hand before choosing a threshold.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
