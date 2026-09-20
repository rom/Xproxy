// Package cache is an in-memory HTTP response cache with a byte bound,
// LRU eviction, per object size limit and Vary support. It is owned by
// the server (not by a configuration generation) so reloads keep it.
package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one stored response.
type Entry struct {
	Status    int
	Header    http.Header
	Body      []byte
	Stored    time.Time
	Expires   time.Time
	Host      string
	Path      string
	key       string
	primary   string // the key without the Vary suffix, for the vary index
	size      int64
	elem      *list.Element
	varyNames []string // response Vary header names, kept on the primary entry
}

// SetVary records the response's Vary header names for the entry.
func (e *Entry) SetVary(names []string) { e.varyNames = names }

// Age returns seconds since the entry was stored.
func (e *Entry) Age(now time.Time) int { return int(now.Sub(e.Stored).Seconds()) }

// Fresh reports whether the entry may still be served.
func (e *Entry) Fresh(now time.Time) bool { return now.Before(e.Expires) }

// Cache is the store.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*Entry // full key (primary + vary) to entry
	vary    map[string][]string
	// varyRefs counts the stored entries behind each vary index record.
	// Without it the index grew for every distinct primary key ever
	// stored and only a full purge cleared it, so eviction held the byte
	// bound while unauthenticated traffic — one request per query string,
	// against any origin that sends "Vary: Accept-Encoding" — retained
	// the index for good.
	varyRefs map[string]int
	lru      *list.List
	bytes    int64
	maxBytes int64
	maxObj   int64
	now      func() time.Time

	Hits, Misses, Stores, Evictions, Purges atomic.Uint64
}

// New creates a cache bounded to maxBytes in total and maxObject per
// entry.
func New(maxBytes, maxObject int64) *Cache {
	return &Cache{entries: map[string]*Entry{}, vary: map[string][]string{}, varyRefs: map[string]int{}, lru: list.New(), maxBytes: maxBytes, maxObj: maxObject, now: time.Now}
}

// Resize changes the bounds (reload) and evicts to fit.
func (c *Cache) Resize(maxBytes, maxObject int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxBytes, c.maxObj = maxBytes, maxObject
	c.evictLocked(0)
}

// MaxObject returns the per entry bound.
func (c *Cache) MaxObject() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxObj
}

// Key derives the primary key of a request: method, host, path and the
// selected query and header values.
func Key(method, host, path, query string, headerValues []string) string {
	h := sha256.New()
	for _, part := range append([]string{method, host, path, query}, headerValues...) {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// varyKey extends a primary key with the request's values of the Vary
// headers a stored response named.
func varyKey(primary string, names []string, req http.Header) string {
	if len(names) == 0 {
		return primary
	}
	h := sha256.New()
	h.Write([]byte(primary))
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(strings.Join(req.Values(n), ",")))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns a fresh entry for the request, honouring Vary.
func (c *Cache) Get(primary string, req http.Header) (*Entry, bool) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	key := varyKey(primary, c.vary[primary], req)
	e, ok := c.entries[key]
	if !ok {
		c.Misses.Add(1)
		return nil, false
	}
	if !e.Fresh(now) {
		c.removeLocked(e)
		c.Misses.Add(1)
		return nil, false
	}
	c.lru.MoveToFront(e.elem)
	c.Hits.Add(1)
	return e, true
}

// Put stores a response under the primary key with the response's Vary
// names resolved against the request. Oversized objects are dropped.
func (c *Cache) Put(primary string, req http.Header, e *Entry) bool {
	e.size = int64(len(e.Body)) + 256
	for k, vs := range e.Header {
		e.size += int64(len(k))
		for _, v := range vs {
			e.size += int64(len(v))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The bounds are read here rather than before the lock: Resize
	// writes them on a reload, and a request storing an entry while a
	// reload changes the size was a genuine data race.
	if e.size > c.maxObj || e.size > c.maxBytes {
		return false
	}
	if len(e.varyNames) > 0 {
		c.vary[primary] = e.varyNames
	} else {
		delete(c.vary, primary)
		delete(c.varyRefs, primary)
	}
	key := varyKey(primary, e.varyNames, req)
	if old, ok := c.entries[key]; ok {
		c.removeLocked(old)
	}
	e.key, e.primary = key, primary
	c.evictLocked(e.size)
	e.elem = c.lru.PushFront(e)
	c.entries[key] = e
	if len(e.varyNames) > 0 {
		c.varyRefs[primary]++
	}
	c.bytes += e.size
	c.Stores.Add(1)
	return true
}

func (c *Cache) removeLocked(e *Entry) {
	delete(c.entries, e.key)
	c.lru.Remove(e.elem)
	c.bytes -= e.size
	// The vary index outlives no entry: the last one to go takes it.
	if len(e.varyNames) > 0 {
		c.varyRefs[e.primary]--
		if c.varyRefs[e.primary] <= 0 {
			delete(c.varyRefs, e.primary)
			delete(c.vary, e.primary)
		}
	}
}

// evictLocked frees room for need bytes.
func (c *Cache) evictLocked(need int64) {
	for c.bytes+need > c.maxBytes && c.lru.Len() > 0 {
		back := c.lru.Back()
		c.removeLocked(back.Value.(*Entry))
		c.Evictions.Add(1)
	}
}

// Purge removes entries whose host equals host (or all hosts when "")
// and whose path starts with prefix. It returns the number removed.
func (c *Cache) Purge(host, prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.entries {
		if (host == "" || e.Host == host) && strings.HasPrefix(e.Path, prefix) {
			c.removeLocked(e)
			n++
		}
	}
	if host == "" && prefix == "" {
		c.vary = map[string][]string{}
		c.varyRefs = map[string]int{}
	}
	c.Purges.Add(uint64(n)) //nolint:gosec // non-negative
	return n
}

// Stats is the management view.
type Stats struct {
	Entries   int    `json:"entries"`
	Bytes     int64  `json:"bytes"`
	MaxBytes  int64  `json:"max_bytes"`
	MaxObject int64  `json:"max_object_bytes"`
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Stores    uint64 `json:"stores"`
	Evictions uint64 `json:"evictions"`
	Purged    uint64 `json:"purged"`
}

// Stats returns counters and sizes.
func (c *Cache) Stats() Stats {
	// maxBytes and maxObj are written by Resize on a reload, so they are
	// read under the lock like everything else here: a word-sized read
	// racing a word-sized write is benign in practice and undefined
	// under the Go memory model, and there was no test that reloaded
	// under load to catch it.
	c.mu.Lock()
	n, b, maxBytes, maxObj := len(c.entries), c.bytes, c.maxBytes, c.maxObj
	c.mu.Unlock()
	return Stats{Entries: n, Bytes: b, MaxBytes: maxBytes, MaxObject: maxObj, Hits: c.Hits.Load(), Misses: c.Misses.Load(),
		Stores: c.Stores.Load(), Evictions: c.Evictions.Load(), Purged: c.Purges.Load()}
}

// Directives are the parsed Cache-Control values that matter here.
type Directives struct {
	NoStore, NoCache, Private, Public bool
	MaxAge                            int // -1 when absent
	SMaxAge                           int // -1 when absent
}

// ParseCacheControl parses a Cache-Control header value list.
func ParseCacheControl(values []string) Directives {
	d := Directives{MaxAge: -1, SMaxAge: -1}
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(strings.ToLower(tok))
			name, arg, _ := strings.Cut(tok, "=")
			arg = strings.Trim(arg, `"`)
			switch name {
			case "no-store":
				d.NoStore = true
			case "no-cache":
				d.NoCache = true
			case "private":
				d.Private = true
			case "public":
				d.Public = true
			case "max-age":
				d.MaxAge = atoi(arg)
			case "s-maxage":
				d.SMaxAge = atoi(arg)
			}
		}
	}
	return d
}

func atoi(s string) int {
	n := 0
	if s == "" {
		return -1
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 1 << 30
		}
	}
	return n
}

// HopByHop are headers never stored or replayed.
var HopByHop = map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Set-Cookie": true, "X-Request-Id": true}

// StorableHeader copies the response headers worth replaying.
func StorableHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if HopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// VaryNames returns the header names of a Vary value, or ok=false for
// "*" (never cacheable).
func VaryNames(values []string) (names []string, ok bool) {
	for _, v := range values {
		for _, n := range strings.Split(v, ",") {
			n = strings.TrimSpace(n)
			if n == "*" {
				return nil, false
			}
			if n != "" {
				names = append(names, http.CanonicalHeaderKey(n))
			}
		}
	}
	return names, true
}
