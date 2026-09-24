package dns

import (
	"container/list"
	"sync"
	"time"
)

type cacheKey struct {
	name  string
	typ   uint16
	class uint16
}

type cacheEntry struct {
	key    cacheKey
	resp   []byte // response with the transaction id zeroed
	qEnd   int
	hdr    Header
	stored time.Time
	ttl    time.Duration
	elem   *list.Element
	// refreshing says a prefetch has claimed this entry. The claim
	// lives on the entry rather than in a table of its own, so it is
	// bounded by the cache and cannot be grown by a client asking for
	// names that are not in it.
	refreshing bool
}

// Cache is a bounded LRU of responses keyed by question.
type Cache struct {
	mu      sync.Mutex
	max     int
	entries map[cacheKey]*cacheEntry
	lru     *list.List
	// stale is how long an expired entry is kept so it can be served
	// when the upstream has nothing (RFC 8767). 0 keeps nothing.
	stale  time.Duration
	Hits   uint64
	Misses uint64
	// Stales counts the answers served after they expired.
	Stales uint64
}

// NewCache bounds the cache at max entries.
func NewCache(max int) *Cache {
	if max < 1 {
		max = 1
	}
	return &Cache{max: max, entries: map[cacheKey]*cacheEntry{}, lru: list.New()}
}

// Resize changes the bound, evicting the oldest entries over it.
func (c *Cache) Resize(max int) {
	if max < 1 {
		max = 1
	}
	c.mu.Lock()
	c.max = max
	for c.lru.Len() > c.max {
		c.evictOldest()
	}
	c.mu.Unlock()
}

// SetStale sets how long an expired entry is kept for serve-stale. It
// is part of the reloadable policy rather than of the cache's
// construction, because the cache survives a reload.
func (c *Cache) SetStale(d time.Duration) {
	c.mu.Lock()
	c.stale = d
	c.mu.Unlock()
}

// Len is the number of entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Put stores a response for q with ttl.
func (c *Cache) Put(q Question, resp []byte, qEnd int, hdr Header, ttl time.Duration, now time.Time) {
	if ttl <= 0 {
		return
	}
	k := cacheKey{q.Name, q.Type, q.Class}
	stored := make([]byte, len(resp))
	copy(stored, resp)
	SetID(stored, 0)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[k]; ok {
		e.resp, e.qEnd, e.hdr, e.stored, e.ttl = stored, qEnd, hdr, now, ttl
		e.refreshing = false
		c.lru.MoveToFront(e.elem)
		return
	}
	for c.lru.Len() >= c.max {
		c.evictOldest()
	}
	e := &cacheEntry{key: k, resp: stored, qEnd: qEnd, hdr: hdr, stored: now, ttl: ttl}
	e.elem = c.lru.PushFront(e)
	c.entries[k] = e
}

func (c *Cache) evictOldest() {
	if el := c.lru.Back(); el != nil {
		e := el.Value.(*cacheEntry)
		delete(c.entries, e.key)
		c.lru.Remove(el)
	}
}

// Get returns a copy of the cached response for q with TTLs reduced by
// the age and the given transaction id, or nil.
func (c *Cache) Get(q Question, id uint16, now time.Time) ([]byte, int) {
	k := cacheKey{q.Name, q.Type, q.Class}
	c.mu.Lock()
	e, ok := c.entries[k]
	if !ok {
		c.Misses++
		c.mu.Unlock()
		return nil, 0
	}
	age := now.Sub(e.stored)
	if age >= e.ttl {
		// An expired entry is kept for the serve-stale window rather
		// than dropped: it is the only answer this resolver will have if
		// the upstream is unreachable, and it is worth more then than
		// the space it occupies. It is not returned here -- a stale
		// answer is the last resort, not a cache hit -- so this still
		// counts as a miss and the upstream is still asked.
		if age >= e.ttl+c.stale {
			delete(c.entries, k)
			c.lru.Remove(e.elem)
		}
		c.Misses++
		c.mu.Unlock()
		return nil, 0
	}
	c.lru.MoveToFront(e.elem)
	c.Hits++
	out := make([]byte, len(e.resp))
	copy(out, e.resp)
	qEnd, hdr := e.qEnd, e.hdr
	c.mu.Unlock()
	SetID(out, id)
	AdjustTTL(out, qEnd, hdr, uint32(age.Seconds())) //nolint:gosec // age < ttl, bounded by config
	return out, qEnd
}

// Stale returns an expired entry kept inside the serve-stale window,
// with every TTL rewritten to ttl seconds, or nil.
//
// The TTL is rewritten rather than adjusted because an expired entry has
// no TTL left to adjust: RFC 8767 section 4 asks for a short one so the
// client comes back soon, and 30 seconds is the value it recommends.
// Serving the original TTL would tell a client to keep an answer this
// resolver already knows is out of date.
func (c *Cache) Stale(q Question, id uint16, now time.Time, ttl uint32) ([]byte, int) {
	k := cacheKey{q.Name, q.Type, q.Class}
	c.mu.Lock()
	e, ok := c.entries[k]
	if !ok || c.stale <= 0 {
		c.mu.Unlock()
		return nil, 0
	}
	age := now.Sub(e.stored)
	if age < e.ttl || age >= e.ttl+c.stale {
		c.mu.Unlock()
		return nil, 0
	}
	c.Stales++
	out := make([]byte, len(e.resp))
	copy(out, e.resp)
	qEnd, hdr := e.qEnd, e.hdr
	c.mu.Unlock()
	SetID(out, id)
	SetTTL(out, qEnd, hdr, ttl)
	return out, qEnd
}

// Remaining reports the share of a live entry's TTL still to run. It is
// the prefetch decision and deliberately not a lookup: it moves nothing
// in the LRU and counts neither a hit nor a miss.
func (c *Cache) Remaining(q Question, now time.Time) (float64, bool) {
	k := cacheKey{q.Name, q.Type, q.Class}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || e.ttl <= 0 {
		return 0, false
	}
	age := now.Sub(e.stored)
	if age >= e.ttl {
		return 0, false
	}
	return 1 - float64(age)/float64(e.ttl), true
}

// Refreshing claims the right to refresh an entry before it expires,
// and reports false when somebody else already holds the claim or the
// entry has gone. The claim is released by the Put that replaces the
// entry, or by Refreshed when the refresh came back with nothing.
func (c *Cache) Refreshing(q Question) bool {
	k := cacheKey{q.Name, q.Type, q.Class}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || e.refreshing {
		return false
	}
	e.refreshing = true
	return true
}

// Refreshed releases a claim that produced nothing.
func (c *Cache) Refreshed(q Question) {
	k := cacheKey{q.Name, q.Type, q.Class}
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		e.refreshing = false
	}
	c.mu.Unlock()
}

// Drop removes one entry, for an answer the policy no longer allows.
func (c *Cache) Drop(q Question) {
	k := cacheKey{q.Name, q.Type, q.Class}
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		delete(c.entries, k)
		c.lru.Remove(e.elem)
	}
	c.mu.Unlock()
}

// Purge drops every entry.
func (c *Cache) Purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.lru.Len()
	c.entries = map[cacheKey]*cacheEntry{}
	c.lru.Init()
	return n
}
