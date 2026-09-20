// Package limits implements the resource protections of the data plane:
// keyed token bucket rate limiting, per-IP connection limiting and global
// concurrency limiting. All structures are bounded in memory; an attacker
// who spreads traffic over many keys cannot make the proxy allocate without
// limit.
package limits

import (
	"github.com/rom/xproxy/internal/bound"
	"sort"
	"sync"
	"time"
)

// bucket is a token bucket stored as a lazily refilled level.
//
// With cluster sharing, peers report the rate at which they are consuming
// the same key. The bucket refills at the configured rate minus the sum of
// fresh peer rates, so the configured rate becomes an approximate cluster
// wide rate for that key (docs/AMR.md, AMR-021). Stale reports are ignored.
type bucket struct {
	tokens   float64
	last     time.Time
	consumed float64 // tokens taken since the last Flush
	total    float64 // tokens taken over the bucket's life (quota reporting)
	peers    []peerRate
	// Sliding window state (window limiters): the count of the current
	// window, the count of the previous one and when the current window
	// started. The estimate is prev weighted by the part of the previous
	// window still inside the sliding one, plus cur.
	winStart time.Time
	cur      float64
	prev     float64
}

type peerRate struct {
	peer string
	rate float64
	at   time.Time
}

// KeyedLimiter is a sharded map of token buckets keyed by string, or of
// sliding window counters when built with NewWindowLimiter.
type KeyedLimiter struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	// window and limit define a sliding window limiter (window > 0):
	// at most limit requests in any window of that length, estimated
	// from the current and the previous fixed window.
	window time.Duration
	limit  float64
	shards [64]shard
	now    func() time.Time
	// peerStale is how long a peer report stays effective. Zero disables
	// peer accounting.
	peerStale time.Duration
	// overflow counts decisions made without a bucket because a shard was
	// full of active keys.
	overflow bound.Notice
}

// Overflow returns the number of decisions made on a full shard.
func (l *KeyedLimiter) Overflow() uint64 { return l.overflow.Total() }

// PeerReport is one key's consumption as seen by a peer.
type PeerReport struct {
	Key  string
	Rate float64 // tokens per second
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewKeyedLimiter creates a limiter allowing rate tokens per second with the
// given burst. maxKeys bounds the number of tracked keys per shard; when the
// bound is reached, stale buckets are evicted and if none are stale the
// request is allowed through with a full bucket (fail-open on the memory
// bound, fail-closed on the rate). This keeps memory bounded at
// 64*maxKeys buckets.
func NewKeyedLimiter(rate float64, burst int, maxKeys int) *KeyedLimiter {
	if maxKeys <= 0 {
		maxKeys = 4096
	}
	l := &KeyedLimiter{rate: rate, burst: float64(burst), maxKeys: maxKeys, now: time.Now}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
	}
	return l
}

// NewWindowLimiter creates a sliding window limiter allowing limit
// requests per window for each key, with the same key bound as
// NewKeyedLimiter. The estimate weights the previous window's count by
// its overlap with the sliding window, so the error is bounded by the
// unevenness of arrivals within one window and no burst above limit is
// admitted at a window edge.
func NewWindowLimiter(limit float64, window time.Duration, maxKeys int) *KeyedLimiter {
	l := NewKeyedLimiter(limit/window.Seconds(), int(limit), maxKeys)
	l.window, l.limit = window, limit
	return l
}

// Window returns the sliding window length, 0 for a token bucket.
func (l *KeyedLimiter) Window() time.Duration { return l.window }

func fnv(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// Allow consumes one token for key and reports whether it was available.
func (l *KeyedLimiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN consumes n tokens for key.
func (l *KeyedLimiter) AllowN(key string, n float64) bool {
	return l.AllowFallback(key, nil, n)
}

// AllowFallback consumes n tokens for key. When key is not tracked and its
// shard is full of active keys, the decision is made on fallback instead
// (the client address for a header keyed limit), so that a client rotating
// key values cannot obtain a fresh burst per value once the table is full.
// With no fallback the request is allowed untracked, bounded by burst; the
// per-connection and concurrency limits still hold.
func (l *KeyedLimiter) AllowFallback(key string, fallbacks []string, n float64) bool {
	now := l.now()
	var b *bucket
	var sh *shard
	for {
		sh = &l.shards[fnv(key)%uint32(len(l.shards))]
		sh.mu.Lock()
		var ok bool
		if b, ok = sh.buckets[key]; ok {
			break
		}
		if len(sh.buckets) >= l.maxKeys {
			l.evict(sh, now)
		}
		if len(sh.buckets) < l.maxKeys {
			b = &bucket{tokens: l.burst, last: now}
			sh.buckets[key] = b
			break
		}
		sh.mu.Unlock()
		l.overflow.Hit(nil, "rate limit key table full; decisions for new keys fall back to a coarser key", "table", "rate_limit_keys", "max_per_shard", l.maxKeys)
		// Fall back to something coarser — the client address, then its
		// network — rather than admit. Admitting made the bound itself
		// the bypass: rotate source addresses until the table is full
		// and every new key was then free, which is cheap over IPv6.
		for len(fallbacks) > 0 && (fallbacks[0] == "" || fallbacks[0] == key) {
			fallbacks = fallbacks[1:]
		}
		if len(fallbacks) == 0 {
			// Nothing coarser is left and the table is genuinely full:
			// refuse. This is the one direction that cannot be turned
			// into a way past the limit.
			return false
		}
		key, fallbacks = fallbacks[0], fallbacks[1:]
	}
	defer sh.mu.Unlock()
	if l.window > 0 {
		return l.allowWindow(b, now, n)
	}
	l.refill(b, now)
	if b.tokens >= n {
		b.tokens -= n
		b.consumed += n
		b.total += n
		return true
	}
	return false
}

// allowWindow decides on a sliding window counter. Fresh peer reports
// count as their rate over one window.
func (l *KeyedLimiter) allowWindow(b *bucket, now time.Time, n float64) bool {
	est := l.windowEstimate(b, now)
	if est+n > l.limit {
		return false
	}
	b.cur += n
	b.consumed += n
	b.total += n
	return true
}

// windowEstimate rolls the fixed windows forward and returns the
// estimated count in the sliding window ending now, peers included.
func (l *KeyedLimiter) windowEstimate(b *bucket, now time.Time) float64 {
	if b.winStart.IsZero() {
		b.winStart = now
	}
	elapsed := now.Sub(b.winStart)
	switch {
	case elapsed >= 2*l.window || elapsed < 0:
		b.prev, b.cur, b.winStart = 0, 0, now
		elapsed = 0
	case elapsed >= l.window:
		b.prev, b.cur = b.cur, 0
		b.winStart = b.winStart.Add(l.window)
		elapsed -= l.window
	}
	b.last = now
	weight := 1 - float64(elapsed)/float64(l.window)
	est := b.prev*weight + b.cur
	if len(b.peers) > 0 {
		live := b.peers[:0]
		for _, p := range b.peers {
			if now.Sub(p.at) <= l.peerStale {
				est += p.rate * l.window.Seconds()
				live = append(live, p)
			}
		}
		b.peers = live
	}
	return est
}

// refill credits tokens for the time since the last update, at the
// configured rate reduced by fresh peer consumption.
func (l *KeyedLimiter) refill(b *bucket, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	rate := l.rate
	if len(b.peers) > 0 {
		live := b.peers[:0]
		for _, p := range b.peers {
			if now.Sub(p.at) <= l.peerStale {
				rate -= p.rate
				live = append(live, p)
			}
		}
		b.peers = live
		if rate < 0 {
			rate = 0
		}
	}
	b.tokens += elapsed * rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
}

// SetPeerStale sets how long a peer report influences refill. It must be
// called before peers report.
func (l *KeyedLimiter) SetPeerStale(d time.Duration) {
	l.peerStale = d
}

// ReportPeer records that peer is consuming the listed keys at the given
// rates. Unknown keys get a bucket so that traffic arriving here later is
// limited from the start. Reports for a full shard are dropped.
func (l *KeyedLimiter) ReportPeer(peer string, reports []PeerReport) {
	if l.peerStale <= 0 {
		return
	}
	now := l.now()
	for _, r := range reports {
		// A peer reports what it has served, so it can legitimately
		// claim the whole policy rate and leave nothing for this node:
		// that is distributed limiting working. What it cannot do is
		// claim more. Without the clamp a single message carrying an
		// absurd rate denies the key on every other node for the whole
		// peer_stale window, and repeating it makes that permanent.
		if r.Rate > l.rate {
			r.Rate = l.rate
		}
		if r.Rate < 0 {
			r.Rate = 0
		}
		sh := &l.shards[fnv(r.Key)%uint32(len(l.shards))]
		sh.mu.Lock()
		b, ok := sh.buckets[r.Key]
		if !ok {
			if len(sh.buckets) >= l.maxKeys {
				l.evict(sh, now)
			}
			if len(sh.buckets) >= l.maxKeys {
				sh.mu.Unlock()
				continue
			}
			b = &bucket{tokens: l.burst, last: now}
			sh.buckets[r.Key] = b
		}
		// Settle the bucket at the old rate before changing peer input.
		if l.window == 0 {
			l.refill(b, now)
		}
		found := false
		for i := range b.peers {
			if b.peers[i].peer == peer {
				b.peers[i].rate, b.peers[i].at = r.Rate, now
				found = true
				break
			}
		}
		if !found && len(b.peers) < 64 {
			b.peers = append(b.peers, peerRate{peer: peer, rate: r.Rate, at: now})
		}
		sh.mu.Unlock()
	}
}

// Flush returns the tokens consumed per key since the previous Flush and
// resets the counters. At most limit keys are returned, preferring the
// largest consumers.
func (l *KeyedLimiter) Flush(limit int) map[string]float64 {
	out := make(map[string]float64)
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, b := range sh.buckets {
			if b.consumed > 0 {
				out[k] = b.consumed
				b.consumed = 0
			}
		}
		sh.mu.Unlock()
	}
	if limit > 0 && len(out) > limit {
		type kv struct {
			k string
			v float64
		}
		all := make([]kv, 0, len(out))
		for k, v := range out {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
		out = make(map[string]float64, limit)
		for _, e := range all[:limit] {
			out[e.k] = e.v
		}
	}
	return out
}

// evict removes buckets that have been idle long enough to be full again
// (two windows for a sliding window, whose counts are then zero).
// evictScan bounds one eviction pass. A full scan per miss was O(n)
// work any client could trigger with every new key, which is the
// amplification a bounded table is supposed to prevent.
const evictScan = 256

// evict frees room in a full shard without scanning it whole: at most
// evictScan entries are examined and the expired ones among them are
// dropped. A live bucket is never evicted to make room, because that
// is the bypass itself — a client rotating keys would evict somebody
// else's bucket and receive a fresh burst every time. A shard of live
// buckets stays full, and AllowFallback then decides on a coarser key.
func (l *KeyedLimiter) evict(sh *shard, now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	if l.window > 0 {
		full = 2 * l.window
	}
	seen := 0
	for k, b := range sh.buckets {
		if now.Sub(b.last) >= full {
			delete(sh.buckets, k)
		}
		if seen++; seen >= evictScan {
			break
		}
	}
}

// Len returns the number of tracked keys (for metrics and tests).
func (l *KeyedLimiter) Len() int {
	n := 0
	for i := range l.shards {
		l.shards[i].mu.Lock()
		n += len(l.shards[i].buckets)
		l.shards[i].mu.Unlock()
	}
	return n
}

// SetMaxKeysForTest lowers the per shard key bound; tests use it to fill
// the table quickly.
func (l *KeyedLimiter) SetMaxKeysForTest(n int) { l.maxKeys = n }

// KeyUsage is one key's consumption for quota reporting.
type KeyUsage struct {
	Key    string  `json:"key"`
	Total  float64 `json:"total"`
	Tokens float64 `json:"tokens"`
}

// Top returns the n keys that consumed the most tokens over their
// bucket's life, most first, with the tokens they have left now.
func (l *KeyedLimiter) Top(n int) []KeyUsage {
	now := l.now()
	var all []KeyUsage
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, b := range sh.buckets {
			if b.total <= 0 {
				continue
			}
			left := 0.0
			if l.window > 0 {
				left = max(l.limit-l.windowEstimate(b, now), 0)
			} else {
				l.refill(b, now)
				left = b.tokens
			}
			all = append(all, KeyUsage{Key: k, Total: b.total, Tokens: left})
		}
		sh.mu.Unlock()
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Total != all[j].Total {
			return all[i].Total > all[j].Total
		}
		return all[i].Key < all[j].Key
	})
	if n > 0 && len(all) > n {
		all = all[:n]
	}
	return all
}
