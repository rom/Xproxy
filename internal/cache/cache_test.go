package cache

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func entry(host, path, body string, ttl time.Duration, now time.Time) *Entry {
	return &Entry{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte(body), Stored: now, Expires: now.Add(ttl), Host: host, Path: path}
}

func TestStoreAndBounds(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(2000, 800)
	c.now = func() time.Time { return now }
	k := Key("GET", "h", "/a", "", nil)
	if _, ok := c.Get(k, nil); ok {
		t.Fatal("empty hit")
	}
	if !c.Put(k, nil, entry("h", "/a", "aaa", time.Minute, now)) {
		t.Fatal("put")
	}
	e, ok := c.Get(k, nil)
	if !ok || string(e.Body) != "aaa" || e.Age(now.Add(5*time.Second)) != 5 {
		t.Fatalf("get %v %v", e, ok)
	}
	// Expired entries are misses and removed.
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get(k, nil); ok {
		t.Fatal("stale hit")
	}
	if st := c.Stats(); st.Entries != 0 || st.Misses != 2 || st.Hits != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Per object bound.
	if c.Put(k, nil, entry("h", "/big", strings.Repeat("x", 1000), time.Minute, now)) {
		t.Fatal("oversized object stored")
	}
	// Total bound with LRU eviction: three ~600 byte objects into 2000.
	for _, p := range []string{"/1", "/2", "/3"} {
		c.Put(Key("GET", "h", p, "", nil), nil, entry("h", p, strings.Repeat("y", 300), time.Minute, now))
	}
	c.Get(Key("GET", "h", "/1", "", nil), nil) // /1 most recently used; /2 is now the oldest
	c.Put(Key("GET", "h", "/4", "", nil), nil, entry("h", "/4", strings.Repeat("z", 300), time.Minute, now))
	st := c.Stats()
	if st.Bytes > 2000 || st.Evictions == 0 {
		t.Fatalf("bound %+v", st)
	}
	if _, ok := c.Get(Key("GET", "h", "/2", "", nil), nil); ok {
		t.Fatal("least recently used entry survived")
	}
	if _, ok := c.Get(Key("GET", "h", "/1", "", nil), nil); !ok {
		t.Fatal("recently used entry evicted")
	}
	// Purge by host and prefix.
	if n := c.Purge("other", "/"); n != 0 {
		t.Fatalf("purged %d from other host", n)
	}
	if n := c.Purge("h", "/"); n == 0 || c.Stats().Entries != 0 {
		t.Fatalf("purge all: %d, %+v", n, c.Stats())
	}
	c.Resize(100, 50)
	if c.MaxObject() != 50 {
		t.Fatal("resize")
	}
}

func TestVary(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(1<<20, 1<<16)
	c.now = func() time.Time { return now }
	k := Key("GET", "h", "/v", "", nil)
	gz := http.Header{"Accept-Encoding": {"gzip"}}
	plain := http.Header{}
	e := entry("h", "/v", "gzip-body", time.Minute, now)
	e.varyNames = []string{"Accept-Encoding"}
	c.Put(k, gz, e)
	if got, ok := c.Get(k, gz); !ok || string(got.Body) != "gzip-body" {
		t.Fatal("vary hit")
	}
	if _, ok := c.Get(k, plain); ok {
		t.Fatal("vary miss expected for a different Accept-Encoding")
	}
	e2 := entry("h", "/v", "plain-body", time.Minute, now)
	e2.varyNames = []string{"Accept-Encoding"}
	c.Put(k, plain, e2)
	if got, ok := c.Get(k, gz); !ok || string(got.Body) != "gzip-body" {
		t.Fatal("both variants should be stored")
	}
	if got, ok := c.Get(k, plain); !ok || string(got.Body) != "plain-body" {
		t.Fatal("plain variant")
	}
}

func TestHelpers(t *testing.T) {
	d := ParseCacheControl([]string{"public, max-age=60", "s-maxage=\"120\""})
	if !d.Public || d.MaxAge != 60 || d.SMaxAge != 120 || d.NoStore {
		t.Fatalf("%+v", d)
	}
	d = ParseCacheControl([]string{"no-store, private, no-cache, max-age=abc"})
	if !d.NoStore || !d.Private || !d.NoCache || d.MaxAge != -1 {
		t.Fatalf("%+v", d)
	}
	if names, ok := VaryNames([]string{"accept-encoding, User-Agent"}); !ok || len(names) != 2 || names[0] != "Accept-Encoding" {
		t.Fatalf("vary names %v %v", names, ok)
	}
	if _, ok := VaryNames([]string{"*"}); ok {
		t.Fatal("Vary: * accepted")
	}
	h := StorableHeader(http.Header{"Set-Cookie": {"a=b"}, "Connection": {"close"}, "Content-Type": {"text/html"}, "X-Request-Id": {"1"}})
	if len(h) != 1 || h.Get("Content-Type") != "text/html" {
		t.Fatalf("storable %v", h)
	}
}

// The Vary index used to grow for every distinct primary key ever
// stored: eviction held the byte bound but nothing dropped the index,
// and only a whole-cache purge cleared it. Any origin that sends
// "Vary: Accept-Encoding" — which is nearly all of them — turned each
// unauthenticated request for a fresh query string into a permanent
// couple of hundred bytes.
func TestVaryIndexIsBoundedByTheEntries(t *testing.T) {
	c := New(8<<10, 4<<10)
	req := http.Header{"Accept-Encoding": {"gzip"}}
	for i := 0; i < 2000; i++ {
		e := &Entry{Status: 200, Header: http.Header{"Vary": {"Accept-Encoding"}}, Body: []byte("hello"),
			Stored: time.Now(), Expires: time.Now().Add(time.Minute), Host: "a", Path: "/x"}
		e.SetVary([]string{"Accept-Encoding"})
		c.Put("p"+strconv.Itoa(i), req, e)
	}
	c.mu.Lock()
	entries, vary, refs := len(c.entries), len(c.vary), len(c.varyRefs)
	c.mu.Unlock()
	if vary != entries || refs != entries {
		t.Fatalf("index %d and refs %d against %d entries", vary, refs, entries)
	}
	// Purging the survivors empties it too.
	c.Purge("a", "/")
	c.mu.Lock()
	vary, refs = len(c.vary), len(c.varyRefs)
	c.mu.Unlock()
	if vary != 0 || refs != 0 {
		t.Fatalf("index %d and refs %d after a purge", vary, refs)
	}
}
