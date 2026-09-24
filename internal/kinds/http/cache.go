package http

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/config"
)

// cacheKey builds the primary key for a request under a route policy, or
// "" when the request is not cacheable at all.
func cacheKey(rc *config.RouteCache, r *http.Request, host, path string, hadCookie bool) string {
	ok := false
	for _, m := range rc.Methods {
		if m == r.Method {
			ok = true
		}
	}
	if !ok || r.Header.Get("Authorization") != "" || r.Header.Get("Range") != "" {
		return ""
	}
	// Only a request whose wire path is the routing path is cached: the
	// upstream receives the path as sent, so "//x", "/./x", "/a/../x", a
	// percent-encoded or a Unicode-folded spelling may draw a different
	// answer (a 404, a redirect) that must not fill the entry every
	// visitor of the canonical "/x" reads.
	if r.URL.RawPath != "" || r.URL.Path != path {
		return ""
	}
	// Request filters may remove authentication cookies before this lookup.
	// Preserve the cache isolation decision made from the client request while
	// also refusing cookies introduced or retained by a filter.
	if !rc.Cookies && (hadCookie || r.Header.Get("Cookie") != "") {
		return ""
	}
	query := ""
	switch rc.Query {
	case "all":
		query = r.URL.RawQuery
	case "listed":
		q := r.URL.Query()
		names := append([]string(nil), rc.QueryParams...)
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			for _, v := range q[n] {
				b.WriteString(url.QueryEscape(n) + "=" + url.QueryEscape(v) + "&")
			}
		}
		query = b.String()
	}
	vals := make([]string, 0, len(rc.Headers))
	for _, h := range rc.Headers {
		vals = append(vals, strings.Join(r.Header.Values(h), ","))
	}
	// HEAD shares GET's entry. The raw Host (port and case included) is
	// part of the key: the upstream sees it verbatim and may bake it into
	// links or redirects, so "example.com:1337" must not fill the entry
	// every normal visitor of "example.com" reads (cache poisoning).
	return cache.Key("GET", host+"\x00"+strings.ToLower(r.Host), path, query, vals)
}

// serveCached writes a hit. Conditional requests get 304. The route's
// response header operations run on the hit as they do on a miss, with
// this request's values.
func (s *engine) serveCached(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute, e *cache.Entry) {
	h := rw.Header()
	for k, vs := range e.Header {
		// Clip the capacity. The entry is shared by every hit, and the
		// response operations below end in Header.Add, which appends:
		// with spare capacity that append writes into the entry's own
		// backing array, so one client's expanded template value (a
		// cookie, a certificate field, an address) lands in another
		// client's response.
		h[k] = vs[:len(vs):len(vs)]
	}
	cr.respOps.apply(h, &tvars{r: r, st: st})
	now := time.Now()
	h.Set("Age", strconv.Itoa(e.Age(now)))
	h.Set("X-Cache", "HIT")
	st.cache = "hit"
	if etag := e.Header.Get("Etag"); etag != "" && etagMatches(r.Header.Get("If-None-Match"), etag) {
		rw.WriteHeader(http.StatusNotModified)
		return
	}
	if lm := e.Header.Get("Last-Modified"); lm != "" {
		if ims := r.Header.Get("If-Modified-Since"); ims != "" {
			if t1, err1 := http.ParseTime(lm); err1 == nil {
				if t2, err2 := http.ParseTime(ims); err2 == nil && !t1.After(t2) {
					rw.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(e.Body)))
	rw.WriteHeader(e.Status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write(e.Body)
	}
}

func etagMatches(inm, etag string) bool {
	if inm == "" {
		return false
	}
	if inm == "*" {
		return true
	}
	for _, t := range strings.Split(inm, ",") {
		if strings.TrimSpace(t) == etag {
			return true
		}
	}
	return false
}

// storable decides whether an upstream response may be cached under the
// route policy and returns its lifetime.
func storable(rc *config.RouteCache, r *http.Request, resp *http.Response, maxObject int64) (time.Duration, bool) {
	ok := false
	for _, st := range rc.Statuses {
		if st == resp.StatusCode {
			ok = true
		}
	}
	if !ok || resp.Header.Get("Set-Cookie") != "" {
		return 0, false
	}
	if resp.ContentLength > maxObject {
		return 0, false
	}
	if _, ok := cache.VaryNames(resp.Header.Values("Vary")); !ok {
		return 0, false
	}
	ttl := rc.TTL.D()
	if rc.IgnoreCacheControl {
		return ttl, true
	}
	d := cache.ParseCacheControl(resp.Header.Values("Cache-Control"))
	if d.NoStore || d.NoCache || (d.Private && !d.Public) {
		return 0, false
	}
	if r.Header.Get("Authorization") != "" && !d.Public {
		return 0, false
	}
	switch {
	case d.SMaxAge >= 0:
		ttl = time.Duration(d.SMaxAge) * time.Second
	case d.MaxAge >= 0:
		ttl = time.Duration(d.MaxAge) * time.Second
	default:
		if exp := resp.Header.Get("Expires"); exp != "" {
			if t, err := http.ParseTime(exp); err == nil {
				ttl = time.Until(t)
			}
		}
	}
	if ttl <= 0 {
		return 0, false
	}
	// The lifetime comes from the upstream, so it needs the ceiling the
	// configuration already has: validation refuses a route cache.ttl
	// above a year, and an Expires header in the year 9999 or a
	// max-age of 1e12 would otherwise make an entry permanent for the
	// life of the process, so one bad answer never heals.
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	return ttl, true
}

// maxCacheTTL is the longest a cached response may live, whatever the
// upstream asked for. It matches the bound the configuration validator
// puts on routes[].cache.ttl.
const maxCacheTTL = 366 * 24 * time.Hour

// cachingBody buffers an upstream body as it streams to the client and
// stores the entry when the body ends cleanly within the object bound.
type cachingBody struct {
	io.ReadCloser
	buf   bytes.Buffer
	limit int64
	over  bool
	done  bool
	store func(body []byte)
}

func (b *cachingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && !b.over {
		if int64(b.buf.Len()+n) > b.limit {
			b.over = true
			b.buf.Reset()
		} else {
			b.buf.Write(p[:n])
		}
	}
	if err == io.EOF && !b.over && !b.done {
		b.done = true
		b.store(b.buf.Bytes())
	}
	return n, err
}
