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
}

// Cache is a bounded LRU of responses keyed by question.
type Cache struct {
	mu      sync.Mutex
	max     int
	entries map[cacheKey]*cacheEntry
	lru     *list.List
	Hits    uint64
	Misses  uint64
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
		delete(c.entries, k)
		c.lru.Remove(e.elem)
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
