package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Honeytokens: credentials that exist only to be stolen.
//
// A decoy hands out a password, an API key, a connection string. Until
// something watches for their use, the bait has no hook: the scanner
// reads the file, and the proxy learns nothing more than that the file
// was read. A token registered here closes that: nothing legitimate
// ever sends one, so a request presenting one is not a signal to weigh
// against others. It is an attacker replaying what they read, and the
// only question is what to do about it.
//
// The value is not a secret. Its purpose is to be read, so it is
// compared as an ordinary string; what is kept out of the logs is not
// the value's confidentiality but the noise — the logs name the token,
// which is what tells an operator which plant was found.

// maxCandidates bounds the strings examined per request. A client
// chooses how many headers, cookies and parameters it sends, so the
// work this does is a client-chosen number unless it is capped.
const maxCandidates = 256

// maxContainsBytes bounds the value scanned for a "contains" token. A
// substring search is linear in the value, and the value is the
// client's to make as long as the header limits allow.
const maxContainsBytes = 8 << 10

// credentialPrefixes are stripped before an exact comparison, so a
// token planted as a bearer token is found whether the client sends it
// bare or in the scheme it was planted with.
var credentialPrefixes = []string{"Bearer ", "bearer ", "Token ", "token ", "Basic ", "basic ", "ApiKey ", "apikey "}

// honeytoken is one compiled plant.
type honeytoken struct {
	cfg    *config.Honeytoken
	values map[string]bool // exact match
	list   []string        // contains match
	// headers, when set, narrows the header search to these names,
	// lower case.
	headers                               map[string]bool
	inHeaders, inCookies, inQuery, inPath bool
	hits                                  *atomic.Uint64
	last                                  *atomic.Int64
}

func (h *honeytoken) wants(field string) bool {
	switch field {
	case "headers":
		return h.inHeaders
	case "cookies":
		return h.inCookies
	case "query":
		return h.inQuery
	case "path":
		return h.inPath
	}
	return false
}

// honeytokens is the table the request path consults.
type honeytokens struct {
	list []*honeytoken
	// exact maps a planted value to its token, so one map lookup per
	// candidate string answers for the whole table however many tokens
	// it holds.
	exact map[string]*honeytoken
	// contains holds the tokens matched by substring, which are scanned
	// one by one and are therefore kept few.
	contains []*honeytoken
	// longest is the longest planted value; a candidate shorter than it
	// can still match a shorter value, but one longer than it cannot be
	// an exact match for anything.
	longest int
}

// honeytokenCounters keep hits per token name for the process lifetime,
// so a reload does not reset the count of a plant that has been found.
type honeytokenCounters struct {
	mu   sync.Mutex
	hits map[string]*atomic.Uint64
	last map[string]*atomic.Int64
}

func (hc *honeytokenCounters) get(name string) (*atomic.Uint64, *atomic.Int64) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.hits == nil {
		hc.hits = map[string]*atomic.Uint64{}
		hc.last = map[string]*atomic.Int64{}
	}
	h, ok := hc.hits[name]
	if !ok {
		h = &atomic.Uint64{}
		hc.hits[name] = h
		hc.last[name] = &atomic.Int64{}
	}
	return h, hc.last[name]
}

// newHoneytokens compiles the configured tokens, reading any values
// file. A file that cannot be read fails the load rather than leaving a
// plant that quietly watches for nothing.
func newHoneytokens(list []config.Honeytoken, counters *honeytokenCounters) (*honeytokens, error) {
	if len(list) == 0 {
		return nil, nil
	}
	t := &honeytokens{exact: map[string]*honeytoken{}}
	for i := range list {
		c := &list[i]
		if !c.IsEnabled() {
			continue
		}
		hits, last := counters.get(c.Name)
		h := &honeytoken{cfg: c, values: map[string]bool{}, hits: hits, last: last}
		for _, f := range c.In {
			switch f {
			case "headers":
				h.inHeaders = true
			case "cookies":
				h.inCookies = true
			case "query":
				h.inQuery = true
			case "path":
				h.inPath = true
			}
		}
		if len(c.Headers) > 0 {
			h.headers = map[string]bool{}
			for _, n := range c.Headers {
				h.headers[strings.ToLower(n)] = true
			}
		}
		values := slicesClone(c.Values)
		if c.ValuesFile != "" {
			fromFile, err := readTokenValues(c.ValuesFile)
			if err != nil {
				return nil, fmt.Errorf("honeytokens[%d] (%s): %w", i, c.Name, err)
			}
			values = append(values, fromFile...)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("honeytokens[%d] (%s): no planted values", i, c.Name)
		}
		for _, v := range values {
			if len(v) > t.longest {
				t.longest = len(v)
			}
			if c.Match == "contains" {
				h.list = append(h.list, v)
				continue
			}
			h.values[v] = true
			if other, dup := t.exact[v]; dup {
				return nil, fmt.Errorf("honeytokens[%d] (%s): the same value is planted as %q", i, c.Name, other.cfg.Name)
			}
			t.exact[v] = h
		}
		if len(h.list) > 0 {
			t.contains = append(t.contains, h)
		}
		t.list = append(t.list, h)
	}
	if len(t.list) == 0 {
		return nil, nil
	}
	return t, nil
}

func slicesClone(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// readTokenValues reads one value per line, ignoring blanks and
// comments. The file holds planted credentials, which are fake by
// construction, so it is read like any other list.
func readTokenValues(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // operator supplied path from the configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<16)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < 8 {
			return nil, fmt.Errorf("%s: a planted value must be at least 8 characters", path)
		}
		out = append(out, line)
		if len(out) > 4096 {
			return nil, fmt.Errorf("%s: more than 4096 values", path)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// check looks for a planted value in the request. It returns the token
// that was found and the field it was found in, or nil.
func (t *honeytokens) check(r *http.Request, path string) (*honeytoken, string) {
	if t == nil {
		return nil, ""
	}
	n := 0
	var found *honeytoken
	var where string
	// visit is called with each candidate string and the field it came
	// from; it stops the walk once something is found.
	visit := func(field, name, value string) bool {
		if found != nil || value == "" {
			return false
		}
		n++
		if n > maxCandidates {
			return true
		}
		if h := t.match(field, name, value); h != nil {
			found, where = h, field
			return true
		}
		return false
	}

	if path != "" {
		// The whole path, and each segment: a planted value reaches us
		// either as a URL somebody found and followed, or as an
		// identifier inside one.
		if visit("path", "", path) {
			return found, where
		}
		for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
			if visit("path", "", seg) {
				return found, where
			}
		}
	}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if lower == "cookie" {
			continue // cookies are walked as cookies, below
		}
		for _, v := range values {
			if visit("headers", lower, v) {
				return found, where
			}
			for _, p := range credentialPrefixes {
				if rest, ok := strings.CutPrefix(v, p); ok {
					if visit("headers", lower, rest) {
						return found, where
					}
					// Basic carries the credential base64 encoded; the
					// planted half is inside it.
					if strings.EqualFold(p, "basic ") {
						if user, pass, ok := decodeBasic(rest); ok {
							if visit("headers", lower, user) || visit("headers", lower, pass) {
								return found, where
							}
						}
					}
					break
				}
			}
		}
	}
	for _, c := range r.Cookies() {
		if visit("cookies", c.Name, c.Value) {
			return found, where
		}
	}
	if q := r.URL.RawQuery; q != "" && len(q) <= maxContainsBytes {
		values, err := url.ParseQuery(q)
		if err == nil {
			for name, vs := range values {
				for _, v := range vs {
					if visit("query", name, v) {
						return found, where
					}
				}
			}
		}
	}
	return found, where
}

// match answers for one candidate string.
func (t *honeytokens) match(field, name, value string) *honeytoken {
	if len(value) <= t.longest {
		if h, ok := t.exact[value]; ok && h.admits(field, name) {
			return h
		}
	}
	if len(value) > maxContainsBytes {
		return nil
	}
	for _, h := range t.contains {
		if !h.admits(field, name) {
			continue
		}
		for _, v := range h.list {
			if strings.Contains(value, v) {
				return h
			}
		}
	}
	return nil
}

// admits reports whether this token looks in that field, and in that
// header if it narrows them.
func (h *honeytoken) admits(field, name string) bool {
	if !h.wants(field) {
		return false
	}
	if field == "headers" && h.headers != nil && !h.headers[name] {
		return false
	}
	return true
}

// decodeBasic splits a base64 Basic credential. A value that is not one
// is not an error here: the header was simply not what it looked like.
func decodeBasic(v string) (user, pass string, ok bool) {
	if len(v) > 1024 {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

// HoneytokenStatus is one row of the management view.
type HoneytokenStatus struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Action      string    `json:"action"`
	Match       string    `json:"match"`
	Values      int       `json:"values"`
	Fields      []string  `json:"fields"`
	Hits        uint64    `json:"hits"`
	LastHit     time.Time `json:"last_hit,omitempty"`
}

func (t *honeytokens) status() []HoneytokenStatus {
	if t == nil {
		return nil
	}
	out := make([]HoneytokenStatus, 0, len(t.list))
	for _, h := range t.list {
		st := HoneytokenStatus{
			Name: h.cfg.Name, Description: h.cfg.Description,
			Action: h.cfg.Action, Match: h.cfg.Match,
			Values: len(h.values) + len(h.list), Fields: h.cfg.In,
			Hits: h.hits.Load(),
		}
		if ns := h.last.Load(); ns != 0 {
			st.LastHit = time.Unix(0, ns)
		}
		out = append(out, st)
	}
	return out
}

// honeytokenHit records a found plant and answers the request. It
// returns true when the request is finished — a blocked one — and
// false when the token only logs and the request goes on.
//
// The value is never logged. What an operator needs is which plant was
// found and where, and a log line carrying the credential would put it
// in a second place it does not belong.
func (s *Server) honeytokenHit(rw *responseWriter, r *http.Request, st *reqState, h *honeytoken, where string) bool {
	now := time.Now()
	h.hits.Add(1)
	h.last.Store(now.UnixNano())
	s.stats.HoneytokenHits.Add(1)
	st.extra = append(st.extra, "honeytoken", h.cfg.Name)
	s.logs.SecurityEvent(r.Context(), "honeytoken", "honeytoken",
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "route", st.route, "user_agent", r.UserAgent(),
		"token", h.cfg.Name, "field", where, "description", h.cfg.Description,
		"action", h.cfg.Action)
	if d := h.cfg.MarkFor(); d > 0 {
		s.marks.add(st.clientIP, "honeytoken:"+h.cfg.Name, d, now)
	}
	if h.cfg.Action != "block" {
		return false
	}
	st.denied = "honeytoken:" + h.cfg.Name
	s.denyDetail(rw, r, st, h.cfg.Status, "honeytoken", h.cfg.Name)
	return true
}

// Honeytokens reports the configured plants with their counters.
func (s *Server) Honeytokens() []HoneytokenStatus {
	rt := s.rt.Load()
	if rt == nil {
		return nil
	}
	return rt.honeytokens.status()
}
