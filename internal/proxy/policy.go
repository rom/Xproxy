package proxy

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// Positive security model per route (routes[].policy) and virtual
// patches (virtual_patches). Both run right after route matching, before
// rate limits, filters and the WAF: a request outside the policy or
// matching a patch is refused with a terse status and a security event,
// and never reaches the more expensive stages.

// compiledPolicy is a route's policy with its sets and patterns built.
type compiledPolicy struct {
	cfg     *config.RoutePolicy
	methods map[string]bool
	allow   string // the Allow header value
	types   []string
	query   map[string]*queryRule
}

type queryRule struct {
	cfg *config.QueryParamPolicy
	re  *regexp.Regexp
	set map[string]bool
}

func compilePolicy(p *config.RoutePolicy) *compiledPolicy {
	if p == nil {
		return nil
	}
	cp := &compiledPolicy{cfg: p, types: p.ContentTypes}
	if len(p.Methods) > 0 {
		cp.methods = map[string]bool{}
		for _, m := range p.Methods {
			cp.methods[m] = true
		}
		sorted := append([]string(nil), p.Methods...)
		sort.Strings(sorted)
		cp.allow = strings.Join(sorted, ", ")
	}
	if len(p.Query) > 0 {
		cp.query = make(map[string]*queryRule, len(p.Query))
		for i := range p.Query {
			q := &p.Query[i]
			r := &queryRule{cfg: q}
			if q.Pattern != "" {
				r.re = regexp.MustCompile("^(?:" + q.Pattern + ")$")
			}
			if q.Type == "enum" {
				r.set = make(map[string]bool, len(q.Values))
				for _, v := range q.Values {
					r.set[v] = true
				}
			}
			cp.query[q.Name] = r
		}
	}
	return cp
}

// policyResult is a refusal: the status and a short detail for the log.
type policyResult struct {
	status int
	detail string
}

// check evaluates the request against the policy; nil means admitted.
func (cp *compiledPolicy) check(r *http.Request) *policyResult {
	p := cp.cfg
	if cp.methods != nil && !cp.methods[r.Method] {
		return &policyResult{status: http.StatusMethodNotAllowed, detail: "method:" + r.Method}
	}
	if p.MaxURILength > 0 && len(r.RequestURI) > p.MaxURILength {
		return &policyResult{status: http.StatusRequestURITooLong, detail: "uri_length"}
	}
	if p.MaxHeaders > 0 || p.MaxHeaderBytes > 0 {
		n, size := 0, 0
		for k, vs := range r.Header {
			for _, v := range vs {
				n++
				size += len(k) + len(v) + 4
			}
		}
		if p.MaxHeaders > 0 && n > p.MaxHeaders {
			return &policyResult{status: http.StatusRequestHeaderFieldsTooLarge, detail: "header_count:" + strconv.Itoa(n)}
		}
		if p.MaxHeaderBytes > 0 && size > p.MaxHeaderBytes {
			return &policyResult{status: http.StatusRequestHeaderFieldsTooLarge, detail: "header_bytes:" + strconv.Itoa(size)}
		}
	}
	hasBody := r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody
	if hasBody && (len(cp.types) > 0 || p.RequireContentType) {
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			if p.RequireContentType {
				return &policyResult{status: http.StatusUnsupportedMediaType, detail: "content_type:missing"}
			}
		} else if len(cp.types) > 0 {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil || !mediaAllowed(cp.types, mt) {
				return &policyResult{status: http.StatusUnsupportedMediaType, detail: "content_type:" + trim(ct, 64)}
			}
		}
	}
	if p.MaxQueryBytes > 0 && len(r.URL.RawQuery) > p.MaxQueryBytes {
		return &policyResult{status: http.StatusRequestURITooLong, detail: "query_bytes:" + strconv.Itoa(len(r.URL.RawQuery))}
	}
	if cp.query == nil && p.MaxQueryParams == 0 {
		return nil
	}
	if r.URL.RawQuery == "" {
		for name, q := range cp.query {
			if q.cfg.Required {
				return &policyResult{status: http.StatusBadRequest, detail: "query:" + name + ":missing"}
			}
		}
		return nil
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return &policyResult{status: http.StatusBadRequest, detail: "query:malformed"}
	}
	if p.MaxQueryParams > 0 {
		n := 0
		for _, vs := range values {
			n += len(vs)
		}
		if n > p.MaxQueryParams {
			return &policyResult{status: http.StatusBadRequest, detail: "query_params:" + strconv.Itoa(n)}
		}
	}
	if cp.query == nil {
		return nil
	}
	for name, vs := range values {
		q, known := cp.query[name]
		if !known {
			if p.DenyUnknown {
				return &policyResult{status: http.StatusBadRequest, detail: "query:" + trim(name, 64) + ":unknown"}
			}
			continue
		}
		if len(vs) > q.cfg.MaxRepeat {
			return &policyResult{status: http.StatusBadRequest, detail: "query:" + name + ":repeated"}
		}
		for _, v := range vs {
			if reason := q.check(v); reason != "" {
				return &policyResult{status: http.StatusBadRequest, detail: "query:" + name + ":" + reason}
			}
		}
	}
	for name, q := range cp.query {
		if q.cfg.Required {
			if _, ok := values[name]; !ok {
				return &policyResult{status: http.StatusBadRequest, detail: "query:" + name + ":missing"}
			}
		}
	}
	return nil
}

// check validates one value; "" means it passes.
func (q *queryRule) check(v string) string {
	c := q.cfg
	if c.MaxLength > 0 && len(v) > c.MaxLength {
		return "too_long"
	}
	switch c.Type {
	case "int":
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return "not_int"
		}
	case "number":
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return "not_number"
		}
	case "bool":
		if v != "true" && v != "false" && v != "1" && v != "0" {
			return "not_bool"
		}
	case "uuid":
		if !isUUID(v) {
			return "not_uuid"
		}
	case "enum":
		if !q.set[v] {
			return "not_allowed"
		}
	}
	if q.re != nil && !q.re.MatchString(v) {
		return "pattern"
	}
	return ""
}

func isUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// mediaAllowed matches a media type against exact types and type/*.
func mediaAllowed(allowed []string, mt string) bool {
	for _, a := range allowed {
		if a == mt || a == "*/*" {
			return true
		}
		if prefix, ok := strings.CutSuffix(a, "/*"); ok && strings.HasPrefix(mt, prefix+"/") {
			return true
		}
	}
	return false
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// compiledPatch is a virtual patch with its patterns built.
type compiledPatch struct {
	cfg     *config.VirtualPatch
	hosts   []string
	routes  map[string]bool
	methods map[string]bool
	pathREs []*regexp.Regexp
	query   []patchMatcher
	headers []patchMatcher
	cookies []patchMatcher
	bodyRE  *regexp.Regexp
	expires time.Time
	// hits and lastHit are shared across generations through the
	// server's patch table.
	hits    *atomic.Uint64
	lastHit *atomic.Int64
}

type patchMatcher struct {
	name string
	re   *regexp.Regexp
}

func compileMatchers(list []config.PatchMatch, lowerName bool) []patchMatcher {
	out := make([]patchMatcher, 0, len(list))
	for _, m := range list {
		pm := patchMatcher{name: m.Name}
		if lowerName {
			pm.name = http.CanonicalHeaderKey(m.Name)
		}
		if m.Pattern != "" {
			pm.re = regexp.MustCompile(m.Pattern)
		}
		out = append(out, pm)
	}
	return out
}

// patchCounters keeps hit counters per patch id for the process
// lifetime, so a reload does not reset them.
type patchCounters struct {
	mu   sync.Mutex
	hits map[string]*atomic.Uint64
	last map[string]*atomic.Int64
}

func (pc *patchCounters) get(id string) (*atomic.Uint64, *atomic.Int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.hits == nil {
		pc.hits = map[string]*atomic.Uint64{}
		pc.last = map[string]*atomic.Int64{}
	}
	h, ok := pc.hits[id]
	if !ok {
		h = &atomic.Uint64{}
		pc.hits[id] = h
		pc.last[id] = &atomic.Int64{}
	}
	return h, pc.last[id]
}

func compilePatches(list []config.VirtualPatch, counters *patchCounters) []*compiledPatch {
	out := make([]*compiledPatch, 0, len(list))
	for i := range list {
		p := &list[i]
		cp := &compiledPatch{cfg: p, hosts: p.Hosts,
			query: compileMatchers(p.Query, false), headers: compileMatchers(p.Headers, true), cookies: compileMatchers(p.Cookies, false)}
		if len(p.Routes) > 0 {
			cp.routes = map[string]bool{}
			for _, r := range p.Routes {
				cp.routes[r] = true
			}
		}
		if len(p.Methods) > 0 {
			cp.methods = map[string]bool{}
			for _, m := range p.Methods {
				cp.methods[m] = true
			}
		}
		for _, re := range p.PathRegex {
			cp.pathREs = append(cp.pathREs, regexp.MustCompile("^(?:"+re+")$"))
		}
		if p.Body != nil {
			cp.bodyRE = regexp.MustCompile(p.Body.Pattern)
		}
		if p.Expires != "" {
			cp.expires, _ = config.ParsePatchExpiry(p.Expires)
		}
		cp.hits, cp.lastHit = counters.get(p.ID)
		out = append(out, cp)
	}
	return out
}

// active reports whether the patch applies at now.
func (cp *compiledPatch) active(now time.Time) bool {
	return cp.cfg.IsEnabled() && (cp.expires.IsZero() || now.Before(cp.expires))
}

// hostMatches matches an exact host or a single-label wildcard.
func hostMatches(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		rest, ok := strings.CutSuffix(host, "."+suffix)
		return ok && rest != "" && !strings.Contains(rest, ".")
	}
	return pattern == host
}

// selects reports whether the cheap selectors (host, route, method,
// path) admit the request; the body condition is checked separately.
func (cp *compiledPatch) selects(r *http.Request, host, path, route string) bool {
	if cp.routes != nil && !cp.routes[route] {
		return false
	}
	if cp.methods != nil && !cp.methods[r.Method] {
		return false
	}
	if len(cp.hosts) > 0 {
		ok := false
		for _, h := range cp.hosts {
			if hostMatches(h, host) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(cp.cfg.Paths) > 0 {
		ok := false
		for _, p := range cp.cfg.Paths {
			if strings.HasPrefix(path, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(cp.pathREs) > 0 {
		ok := false
		for _, re := range cp.pathREs {
			if re.MatchString(path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(cp.query) > 0 {
		values := r.URL.Query()
		for _, m := range cp.query {
			if !matchValues(m, values[m.name]) {
				return false
			}
		}
	}
	for _, m := range cp.headers {
		if !matchValues(m, r.Header.Values(m.name)) {
			return false
		}
	}
	if len(cp.cookies) > 0 {
		for _, m := range cp.cookies {
			var vals []string
			for _, c := range r.Cookies() {
				if c.Name == m.name {
					vals = append(vals, c.Value)
				}
			}
			if !matchValues(m, vals) {
				return false
			}
		}
	}
	return true
}

func matchValues(m patchMatcher, vals []string) bool {
	if len(vals) == 0 {
		return false
	}
	if m.re == nil {
		return true
	}
	for _, v := range vals {
		if m.re.MatchString(v) {
			return true
		}
	}
	return false
}

// bodyMatches buffers the body up to the limit and matches it; the
// body is replayed for the upstream. A body of another media type does
// not match; a body the patch could not read decides by over_limit,
// which treats it as matching by default.
func (cp *compiledPatch) bodyMatches(r *http.Request) bool {
	b := cp.cfg.Body
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return false
	}
	if len(b.ContentTypes) > 0 {
		// A media type Go refuses is still read as its type by the
		// origin; see netutil.MediaType.
		if !mediaAllowed(b.ContentTypes, netutil.MediaType(r.Header.Get("Content-Type"))) {
			return false
		}
	}
	if r.ContentLength > b.MaxBytes {
		return b.MatchesOverLimit()
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, b.MaxBytes+1))
	rest := r.Body
	r.Body = &joinedBody{Reader: io.MultiReader(bytes.NewReader(data), rest), closer: rest}
	if err != nil || int64(len(data)) > b.MaxBytes {
		return b.MatchesOverLimit()
	}
	return cp.bodyRE.Match(data)
}

type joinedBody struct {
	io.Reader
	closer io.Closer
}

func (j *joinedBody) Close() error { return j.closer.Close() }

// PatchStatus is the management view of one virtual patch.
type PatchStatus struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Action      string    `json:"action"`
	Status      int       `json:"status"`
	Enabled     bool      `json:"enabled"`
	Expired     bool      `json:"expired"`
	Expires     time.Time `json:"expires,omitempty"`
	Hits        uint64    `json:"hits"`
	LastHit     time.Time `json:"last_hit,omitempty"`
	Routes      []string  `json:"routes,omitempty"`
	Hosts       []string  `json:"hosts,omitempty"`
	Paths       []string  `json:"paths,omitempty"`
	Methods     []string  `json:"methods,omitempty"`
}

// VirtualPatches lists the configured patches with their counters.
func (s *Server) VirtualPatches() []PatchStatus {
	rt := s.rt.Load()
	now := time.Now()
	out := make([]PatchStatus, 0, len(rt.patches))
	for _, cp := range rt.patches {
		st := PatchStatus{ID: cp.cfg.ID, Description: cp.cfg.Description, Action: cp.cfg.Action, Status: cp.cfg.Status, Enabled: cp.cfg.IsEnabled(),
			Expired: !cp.expires.IsZero() && !now.Before(cp.expires), Expires: cp.expires, Hits: cp.hits.Load(),
			Routes: cp.cfg.Routes, Hosts: cp.cfg.Hosts, Paths: cp.cfg.Paths, Methods: cp.cfg.Methods}
		if ns := cp.lastHit.Load(); ns != 0 {
			st.LastHit = time.Unix(0, ns)
		}
		out = append(out, st)
	}
	return out
}
