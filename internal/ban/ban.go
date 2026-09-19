// Package ban keeps the list of client addresses that are refused outright,
// either because an operator banned them or because a trigger turned
// repeated security denies into a temporary ban with escalating duration.
//
// Design (docs/AMR.md, AMR-019):
//
//   - The hot path (Banned) is a read-locked map lookup plus a scan of the
//     few manual CIDR entries. Expired entries are ignored on read and
//     swept by a background purge.
//   - All tables are bounded. When the ban table is full, the oldest
//     expiring entry is evicted. Trigger windows are bounded per trigger.
//   - Bans optionally persist in a bbolt file so a restart does not release
//     an attacker.
package ban

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rom/xproxy/internal/bound"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// Entry is one ban.
type Entry struct {
	// Target is an address or a CIDR in string form (the map key).
	Target    string    `json:"target"`
	Until     time.Time `json:"until"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"` // "manual" or "trigger:<name>"
	Count     int       `json:"count"`  // how many times this target has been banned
	CreatedAt time.Time `json:"created_at"`

	addr   netip.Addr
	prefix netip.Prefix
	isNet  bool
	fp     string // JA4 fingerprint of a "ja4:<fp>" target
	isFP   bool
}

// FingerprintPrefix marks a ban target that is a TLS client fingerprint
// (JA4) rather than an address: "ja4:t13d1516h2_8daaf6152771_b0da82dd1658".
const FingerprintPrefix = "ja4:"

// List is the ban list.
type List struct {
	mu       sync.RWMutex
	addrs    map[netip.Addr]*Entry
	prefixes []*Entry
	fps      map[string]*Entry
	hasFP    atomic.Bool        // any fingerprint ban present (hot path hint)
	history  map[string]history // repeat counts per target for escalation
	triggers []*trigger
	exempt   []netip.Prefix
	max      int
	drop     bool

	db        *bbolt.DB
	stateFile string
	log       *slog.Logger
	now       func() time.Time
	stop      chan struct{}
	wg        sync.WaitGroup
	closeMu   sync.Once

	// Total counts bans ever applied by this process.
	total uint64

	onChange func(e Entry, removed bool)
}

// PeerSource is the prefix of the source field for bans received from a
// cluster peer. Such bans are not re-announced.
const PeerSource = "peer:"

type history struct {
	count int
	last  time.Time
}

type trigger struct {
	cfg     config.BanTrigger
	reasons map[string]bool
	mu      sync.Mutex
	windows map[string]*window // keyed by address, network or fingerprint
	full    bound.Notice
}

type window struct {
	start   time.Time
	count   int
	sources map[netip.Addr]struct{} // distinct addresses, aggregates only
}

const (
	maxWindowsPerTrigger = 65536
	maxSourcesPerWindow  = 1024
	maxFingerprintBans   = 4096
)

var bucket = []byte("bans")

// ErrNotFound is returned by Unban for unknown targets.
var ErrNotFound = errors.New("ban not found")

// New creates a list from configuration and loads persisted bans.
func New(cfg *config.Bans, log *slog.Logger) (*List, error) {
	l := &List{
		addrs:   make(map[netip.Addr]*Entry),
		fps:     make(map[string]*Entry),
		history: make(map[string]history),
		log:     log.With("component", "bans"),
		now:     time.Now,
		stop:    make(chan struct{}),
	}
	l.configure(cfg)
	l.stateFile = cfg.StateFile
	if cfg.StateFile != "" {
		db, err := bbolt.Open(cfg.StateFile, 0o600, &bbolt.Options{Timeout: 2 * time.Second, NoFreelistSync: true})
		if err != nil {
			return nil, fmt.Errorf("open ban state %s: %w", cfg.StateFile, err)
		}
		l.db = db
		if err := l.load(); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	l.wg.Add(1)
	go l.purgeLoop()
	return l, nil
}

// OnChange registers a callback invoked after every locally originated ban
// or unban (manual or trigger, never peer). It is used by the cluster
// layer to announce changes.
func (l *List) OnChange(fn func(e Entry, removed bool)) {
	l.mu.Lock()
	l.onChange = fn
	l.mu.Unlock()
}

func (l *List) notify(e *Entry, removed bool) {
	l.mu.RLock()
	fn := l.onChange
	l.mu.RUnlock()
	if fn != nil && !strings.HasPrefix(e.Source, PeerSource) {
		fn(*e, removed)
	}
}

// Apply inserts or removes a ban received from a peer. Expired entries are
// ignored; exemptions still hold. The entry's source is rewritten to
// PeerSource + peer.
func (l *List) Apply(e Entry, removed bool, peer string) error {
	parsed, err := parseTarget(e.Target)
	if err != nil {
		return err
	}
	now := l.now()
	if removed {
		l.mu.Lock()
		l.removeLocked(parsed)
		l.mu.Unlock()
		l.persist(parsed, true)
		return nil
	}
	if !e.Until.After(now) {
		return nil
	}
	e.addr, e.prefix, e.isNet, e.fp, e.isFP = parsed.addr, parsed.prefix, parsed.isNet, parsed.fp, parsed.isFP
	e.Source = PeerSource + peer
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	l.mu.Lock()
	if l.exemptTarget(&e) {
		l.mu.Unlock()
		return nil
	}
	l.insertLocked(&e, now)
	l.mu.Unlock()
	l.persist(&e, false)
	return nil
}

// StateFile returns the configured persistence path ("" for memory only).
func (l *List) StateFile() string { return l.stateFile }

// Reconfigure applies new triggers, exemptions and limits without losing
// the current bans.
func (l *List) Reconfigure(cfg *config.Bans) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.configure(cfg)
}

func (l *List) configure(cfg *config.Bans) {
	l.max = cfg.MaxEntries
	l.drop = cfg.Action == "drop"
	l.exempt = netutil.ParsePrefixes(cfg.ExemptCIDRs)
	trig := make([]*trigger, 0, len(cfg.Triggers))
	for _, tc := range cfg.Triggers {
		t := &trigger{cfg: tc, windows: make(map[string]*window)}
		if len(tc.Reasons) > 0 {
			t.reasons = make(map[string]bool, len(tc.Reasons))
			for _, r := range tc.Reasons {
				t.reasons[r] = true
			}
		}
		trig = append(trig, t)
	}
	l.triggers = trig
}

// DropsConnections reports whether banned peers should be closed at accept.
func (l *List) DropsConnections() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.drop
}

// Banned reports whether addr is currently banned.
func (l *List) Banned(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	now := l.now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	if e, ok := l.addrs[addr]; ok && e.Until.After(now) {
		return true
	}
	for _, e := range l.prefixes {
		if e.Until.After(now) && e.prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// BannedFingerprint reports whether the JA4 fingerprint is banned. It is
// cheap when no fingerprint ban exists.
func (l *List) BannedFingerprint(ja4 string) bool {
	if ja4 == "" || !l.hasFP.Load() {
		return false
	}
	now := l.now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.fps[ja4]
	return ok && e.Until.After(now)
}

// BannedClient reports whether the address or, unless the address is
// exempt, the fingerprint of a client is banned.
func (l *List) BannedClient(addr netip.Addr, ja4 string) bool {
	if l.Banned(addr) {
		return true
	}
	if ja4 == "" || !l.hasFP.Load() {
		return false
	}
	l.mu.RLock()
	exempt := addr.IsValid() && netutil.Contains(l.exempt, addr.Unmap())
	l.mu.RUnlock()
	return !exempt && l.BannedFingerprint(ja4)
}

// Observe records a deny for addr with the given reason and applies any
// trigger whose threshold is reached. It returns the ban applied, if any.
func (l *List) Observe(addr netip.Addr, reason string) *Entry {
	return l.ObserveClient(addr, "", reason)
}

// ObserveClient is Observe with the client's JA4 fingerprint, which
// triggers with aggregate ja4 count and ban.
func (l *List) ObserveClient(addr netip.Addr, ja4, reason string) *Entry {
	if !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	now := l.now()
	l.mu.RLock()
	triggers := l.triggers
	exempt := netutil.Contains(l.exempt, addr)
	l.mu.RUnlock()
	if exempt {
		return nil
	}
	for _, t := range triggers {
		if t.reasons != nil && !t.reasons[reason] {
			continue
		}
		key, target := t.key(addr, ja4)
		if key == "" || !t.hit(key, addr, now) {
			continue
		}
		return l.applyTrigger(t, target, reason, now)
	}
	return nil
}

// key returns the window key of a client under the trigger's aggregate
// and the entry the trigger would ban; "" when the client lacks the
// aggregate (a plaintext connection for ja4).
func (t *trigger) key(addr netip.Addr, ja4 string) (string, *Entry) {
	switch t.cfg.Aggregate {
	case "net":
		bits := t.cfg.NetV4
		if addr.Is6() {
			bits = t.cfg.NetV6
		}
		p, err := addr.Prefix(bits)
		if err != nil {
			return "", nil
		}
		p = p.Masked()
		return p.String(), &Entry{Target: p.String(), prefix: p, isNet: true}
	case "ja4":
		if ja4 == "" {
			return "", nil
		}
		return ja4, &Entry{Target: FingerprintPrefix + ja4, fp: ja4, isFP: true}
	}
	return addr.String(), &Entry{Target: addr.String(), addr: addr}
}

func (t *trigger) hit(key string, addr netip.Addr, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	w, ok := t.windows[key]
	if !ok {
		if len(t.windows) >= maxWindowsPerTrigger {
			for k, ww := range t.windows {
				if now.Sub(ww.start) > t.cfg.Window.D() {
					delete(t.windows, k)
				}
			}
			if len(t.windows) >= maxWindowsPerTrigger {
				t.full.Hit(nil, "ban trigger window table full; new clients are not tracked until windows expire", "table", "ban_windows", "trigger", t.cfg.Name, "max", maxWindowsPerTrigger)
				return false
			}
		}
		w = &window{start: now}
		t.windows[key] = w
	}
	if now.Sub(w.start) > t.cfg.Window.D() {
		w.start, w.count, w.sources = now, 0, nil
	}
	w.count++
	aggregate := t.cfg.Aggregate != "" && t.cfg.Aggregate != "address"
	if aggregate {
		if w.sources == nil {
			w.sources = make(map[netip.Addr]struct{}, 4)
		}
		if len(w.sources) < maxSourcesPerWindow {
			w.sources[addr] = struct{}{}
		}
	}
	if w.count >= t.cfg.Threshold && (!aggregate || len(w.sources) >= t.cfg.MinSources) {
		delete(t.windows, key)
		return true
	}
	return false
}

// exemptTarget reports whether a target must not be banned: an exempt
// address, or a network overlapping an exempt range; caller holds the
// lock. Fingerprints are never exempt as targets (exempt addresses are
// spared at lookup instead).
func (l *List) exemptTarget(e *Entry) bool {
	switch {
	case e.isNet:
		for _, x := range l.exempt {
			if x.Overlaps(e.prefix) {
				return true
			}
		}
	case !e.isFP:
		return netutil.Contains(l.exempt, e.addr)
	}
	return false
}

func (l *List) applyTrigger(t *trigger, target *Entry, reason string, now time.Time) *Entry {
	l.mu.Lock()
	if l.exemptTarget(target) {
		l.mu.Unlock()
		return nil
	}
	h := l.history[target.Target]
	if now.Sub(h.last) > t.cfg.MaxDuration.D()*2 {
		h = history{}
	}
	h.count++
	h.last = now
	if len(l.history) >= l.max {
		for k, hh := range l.history {
			if now.Sub(hh.last) > t.cfg.MaxDuration.D()*2 {
				delete(l.history, k)
			}
		}
	}
	if len(l.history) < l.max {
		l.history[target.Target] = h
	}
	dur := t.cfg.Duration.D()
	for i := 1; i < h.count && dur < t.cfg.MaxDuration.D(); i++ {
		dur = time.Duration(float64(dur) * t.cfg.Escalation)
	}
	if dur > t.cfg.MaxDuration.D() {
		dur = t.cfg.MaxDuration.D()
	}
	e := &Entry{Target: target.Target, Until: now.Add(dur), Reason: reason, Source: "trigger:" + t.cfg.Name, Count: h.count, CreatedAt: now,
		addr: target.addr, prefix: target.prefix, isNet: target.isNet, fp: target.fp, isFP: target.isFP}
	l.insertLocked(e, now)
	l.mu.Unlock()
	l.persist(e, false)
	l.log.Warn("client banned", "target", e.Target, "reason", reason, "trigger", t.cfg.Name, "aggregate", t.cfg.Aggregate, "duration", dur.String(), "count", h.count)
	l.notify(e, false)
	return e
}

// Ban adds a manual ban for an address or CIDR.
func (l *List) Ban(target string, d time.Duration, reason string) (*Entry, error) {
	e, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	if d <= 0 || d > 366*24*time.Hour {
		return nil, errors.New("duration must be positive and at most one year")
	}
	now := l.now()
	e.Until = now.Add(d)
	e.Reason = reason
	e.Source = "manual"
	e.CreatedAt = now
	e.Count = 1
	l.mu.Lock()
	if l.exemptTarget(e) {
		l.mu.Unlock()
		return nil, errors.New("target is exempt from bans")
	}
	l.insertLocked(e, now)
	l.mu.Unlock()
	l.persist(e, false)
	l.log.Warn("client banned", "target", e.Target, "reason", reason, "source", "manual", "duration", d.String())
	l.notify(e, false)
	return e, nil
}

// Unban removes a ban.
func (l *List) Unban(target string) error {
	e, err := parseTarget(target)
	if err != nil {
		return err
	}
	l.mu.Lock()
	found := l.removeLocked(e)
	delete(l.history, e.Target)
	l.mu.Unlock()
	if !found {
		return ErrNotFound
	}
	l.persist(e, true)
	l.log.Info("client unbanned", "target", e.Target)
	e.Source = "manual"
	l.notify(e, true)
	return nil
}

// removeLocked drops the entry matching e's target; caller holds the
// write lock.
func (l *List) removeLocked(e *Entry) bool {
	switch {
	case e.isNet:
		for i, p := range l.prefixes {
			if p.prefix == e.prefix {
				l.prefixes = append(l.prefixes[:i], l.prefixes[i+1:]...)
				return true
			}
		}
	case e.isFP:
		if _, ok := l.fps[e.fp]; ok {
			delete(l.fps, e.fp)
			l.hasFP.Store(len(l.fps) > 0)
			return true
		}
	default:
		if _, ok := l.addrs[e.addr]; ok {
			delete(l.addrs, e.addr)
			return true
		}
	}
	return false
}

func parseTarget(s string) (*Entry, error) {
	s = strings.TrimSpace(s)
	if fp, ok := strings.CutPrefix(s, FingerprintPrefix); ok {
		if len(fp) < 10 || len(fp) > 64 || strings.Trim(fp, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
			return nil, fmt.Errorf("bad fingerprint %q", fp)
		}
		return &Entry{Target: FingerprintPrefix + fp, fp: fp, isFP: true}, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q", s)
		}
		p = p.Masked()
		if p.Bits() < 8 && p.Addr().Is4() || p.Bits() < 32 && p.Addr().Is6() {
			return nil, fmt.Errorf("refusing to ban %s: prefix too wide", p)
		}
		if p.Addr().IsLoopback() || p.Addr().IsUnspecified() {
			return nil, fmt.Errorf("refusing to ban %s", p)
		}
		return &Entry{Target: p.String(), prefix: p, isNet: true}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil, fmt.Errorf("bad address %q", s)
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return nil, fmt.Errorf("refusing to ban %s", a)
	}
	return &Entry{Target: a.String(), addr: a}, nil
}

// insertLocked adds or extends an entry; caller holds the write lock.
func (l *List) insertLocked(e *Entry, now time.Time) {
	if e.isFP {
		if old, ok := l.fps[e.fp]; ok {
			if old.Until.After(e.Until) {
				e.Until = old.Until
			}
		} else if len(l.fps) >= maxFingerprintBans {
			var soonest *Entry
			for k, f := range l.fps {
				if !f.Until.After(now) {
					delete(l.fps, k)
				} else if soonest == nil || f.Until.Before(soonest.Until) {
					soonest = f
				}
			}
			if len(l.fps) >= maxFingerprintBans && soonest != nil {
				delete(l.fps, soonest.fp)
			}
		}
		l.fps[e.fp] = e
		l.hasFP.Store(true)
		l.total++
		return
	}
	if e.isNet {
		for i, p := range l.prefixes {
			if p.prefix == e.prefix {
				e.Count = p.Count + 1
				l.prefixes[i] = e
				return
			}
		}
		if len(l.prefixes) >= 1024 {
			l.evictLocked(now)
		}
		l.prefixes = append(l.prefixes, e)
		l.total++
		return
	}
	if old, ok := l.addrs[e.addr]; ok {
		if old.Until.After(e.Until) {
			e.Until = old.Until
		}
	} else if len(l.addrs) >= l.max {
		l.evictLocked(now)
	}
	l.addrs[e.addr] = e
	l.total++
}

// evictLocked removes expired entries and, if still full, the soonest
// expiring ones.
func (l *List) evictLocked(now time.Time) {
	for k, e := range l.addrs {
		if !e.Until.After(now) {
			delete(l.addrs, k)
		}
	}
	live := l.prefixes[:0]
	for _, e := range l.prefixes {
		if e.Until.After(now) {
			live = append(live, e)
		}
	}
	l.prefixes = live
	if len(l.addrs) < l.max {
		return
	}
	// Drop the 1% soonest to expire.
	es := make([]*Entry, 0, len(l.addrs))
	for _, e := range l.addrs {
		es = append(es, e)
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Until.Before(es[j].Until) })
	n := max(len(es)/100, 1)
	for _, e := range es[:n] {
		delete(l.addrs, e.addr)
	}
}

// Entries returns a snapshot of active bans sorted by expiry.
func (l *List) Entries() []Entry {
	now := l.now()
	l.mu.RLock()
	out := make([]Entry, 0, len(l.addrs)+len(l.prefixes)+len(l.fps))
	for _, e := range l.addrs {
		if e.Until.After(now) {
			out = append(out, *e)
		}
	}
	for _, e := range l.prefixes {
		if e.Until.After(now) {
			out = append(out, *e)
		}
	}
	for _, e := range l.fps {
		if e.Until.After(now) {
			out = append(out, *e)
		}
	}
	l.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// Stats returns counts for the management API.
func (l *List) Stats() (active int, total uint64) {
	now := l.now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, e := range l.addrs {
		if e.Until.After(now) {
			active++
		}
	}
	for _, e := range l.prefixes {
		if e.Until.After(now) {
			active++
		}
	}
	for _, e := range l.fps {
		if e.Until.After(now) {
			active++
		}
	}
	return active, l.total
}

func (l *List) purgeLoop() {
	defer l.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.Purge()
		}
	}
}

// Purge removes expired entries from memory and from the state file.
func (l *List) Purge() {
	now := l.now()
	var expired []string
	l.mu.Lock()
	for k, e := range l.addrs {
		if !e.Until.After(now) {
			delete(l.addrs, k)
			expired = append(expired, e.Target)
		}
	}
	live := l.prefixes[:0]
	for _, e := range l.prefixes {
		if e.Until.After(now) {
			live = append(live, e)
		} else {
			expired = append(expired, e.Target)
		}
	}
	l.prefixes = live
	for k, e := range l.fps {
		if !e.Until.After(now) {
			delete(l.fps, k)
			expired = append(expired, e.Target)
		}
	}
	l.hasFP.Store(len(l.fps) > 0)
	for _, t := range l.triggers {
		t.mu.Lock()
		for k, w := range t.windows {
			if now.Sub(w.start) > t.cfg.Window.D() {
				delete(t.windows, k)
			}
		}
		t.mu.Unlock()
	}
	l.mu.Unlock()
	if l.db != nil && len(expired) > 0 {
		_ = l.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucket)
			if b == nil {
				return nil
			}
			for _, k := range expired {
				_ = b.Delete([]byte(k))
			}
			return nil
		})
	}
}

// Close stops the purge loop and closes the state file. It is idempotent.
func (l *List) Close() {
	l.closeMu.Do(func() {
		close(l.stop)
		l.wg.Wait()
		if l.db != nil {
			_ = l.db.Close()
		}
	})
}

func (l *List) persist(e *Entry, remove bool) {
	if l.db == nil {
		return
	}
	err := l.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}
		if remove {
			return b.Delete([]byte(e.Target))
		}
		v, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put([]byte(e.Target), v)
	})
	if err != nil {
		l.log.Error("ban state write failed", "err", err.Error())
	}
}

func (l *List) load() error {
	now := l.now()
	return l.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				l.log.Warn("skipping corrupt ban entry", "key", string(k))
				return nil
			}
			if !e.Until.After(now) {
				return nil
			}
			parsed, err := parseTarget(e.Target)
			if err != nil {
				return nil
			}
			e.addr, e.prefix, e.isNet, e.fp, e.isFP = parsed.addr, parsed.prefix, parsed.isNet, parsed.fp, parsed.isFP
			l.insertLocked(&e, now)
			return nil
		})
	})
}
