// Package limits implements the resource protections of the data plane:
// keyed token bucket rate limiting, per-IP connection limiting and global
// concurrency limiting. All structures are bounded in memory; an attacker
// who spreads traffic over many keys cannot make the proxy allocate without
// limit.
package limits

import (
	"sync"
	"time"
)

// bucket is a token bucket stored as a lazily refilled level.
type bucket struct {
	tokens float64
	last   time.Time
}

// KeyedLimiter is a sharded map of token buckets keyed by string.
type KeyedLimiter struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	shards  [64]shard
	now     func() time.Time
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
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
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
