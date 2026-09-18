// Package limits implements the resource protections of the data plane:
// keyed token bucket rate limiting, per-IP connection limiting and global
// concurrency limiting. All structures are bounded in memory; an attacker
// who spreads traffic over many keys cannot make the proxy allocate without
// limit.
package limits

import (
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
}

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
	now := l.now()
	sh := &l.shards[fnv(key)%uint32(len(l.shards))]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b, ok := sh.buckets[key]
	if !ok {
		if len(sh.buckets) >= l.maxKeys {
			l.evict(sh, now)
		}
		if len(sh.buckets) >= l.maxKeys {
			// Still full: every tracked key is active. Allow but do not
			// track; the per-connection and concurrency limits still hold.
			return n <= l.burst
		}
		b = &bucket{tokens: l.burst, last: now}
		sh.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens >= n {
		b.tokens -= n
		b.consumed += n
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
