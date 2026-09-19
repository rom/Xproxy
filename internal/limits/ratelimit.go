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
}

type peerRate struct {
	peer string
	rate float64
	at   time.Time
}

// KeyedLimiter is a sharded map of token buckets keyed by string.
type KeyedLimiter struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	shards  [64]shard
	now     func() time.Time
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
	return l.AllowFallback(key, "", n)
}

// AllowFallback consumes n tokens for key. When key is not tracked and its
// shard is full of active keys, the decision is made on fallback instead
// (the client address for a header keyed limit), so that a client rotating
// key values cannot obtain a fresh burst per value once the table is full.
// With no fallback the request is allowed untracked, bounded by burst; the
// per-connection and concurrency limits still hold.
func (l *KeyedLimiter) AllowFallback(key, fallback string, n float64) bool {
	now := l.now()
	sh := &l.shards[fnv(key)%uint32(len(l.shards))]
	sh.mu.Lock()
	b, ok := sh.buckets[key]
	if !ok {
		if len(sh.buckets) >= l.maxKeys {
			l.evict(sh, now)
		}
		if len(sh.buckets) >= l.maxKeys {
			sh.mu.Unlock()
			l.overflow.Hit(nil, "rate limit key table full; decisions for new keys fall back to the shared key or the burst", "table", "rate_limit_keys", "max_per_shard", l.maxKeys)
			if fallback != "" && fallback != key {
				return l.AllowFallback(fallback, "", n)
			}
			return n <= l.burst
		}
		b = &bucket{tokens: l.burst, last: now}
		sh.buckets[key] = b
	}
	defer sh.mu.Unlock()
	l.refill(b, now)
	if b.tokens >= n {
		b.tokens -= n
		b.consumed += n
		b.total += n
		return true
	}
	return false
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
		l.refill(b, now)
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

// evict removes buckets that have been idle long enough to be full again.
func (l *KeyedLimiter) evict(sh *shard, now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range sh.buckets {
		if now.Sub(b.last) >= full {
			delete(sh.buckets, k)
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
			l.refill(b, now)
			all = append(all, KeyUsage{Key: k, Total: b.total, Tokens: b.tokens})
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
