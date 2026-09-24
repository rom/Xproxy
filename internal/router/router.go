// Package router matches incoming requests to configured routes.
//
// Matching is host first, then longest path prefix (a regular expression
// counts as its literal prefix and, at equal length, beats a plain
// prefix), then the number of header and cookie conditions (more first),
// then priority. Methods and conditions are filters: an entry whose
// method set or conditions do not match is skipped. Host matching supports exact names and single-label wildcards
// ("*.example.com" matches "a.example.com" but not "example.com" or
// "a.b.example.com"). Exact hosts win over wildcards, and both win over
// catch-all routes with no hosts.
//
// The router is immutable once built, so lookups need no locking and a
// reload simply swaps the pointer.
package router

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/expr"
)

// Route is a compiled route ready for matching.
type Route struct {
	Cfg   *config.Route
	Index int // position in the configuration, for logging
}

type entry struct {
	path     string          // prefix, or the literal prefix of regex
	regex    *regexp.Regexp  // non-nil: the whole path must match
	conds    []condition     // header and cookie conditions, all must hold
	when     *expr.Expr      // routes[].when, evaluated against the request env
	methods  map[string]bool // nil means any
	priority int
	route    *Route
	grpc     *grpcMatch // non-nil restricts the entry to gRPC requests
}

// condition is one compiled header or cookie match.
type condition struct {
	name   string
	cookie bool
	kind   condKind
	value  string
	re     *regexp.Regexp
}

type condKind int

const (
	condExact condKind = iota
	condPrefix
	condRegex
	condPresent
	condAbsent
)

func compileConds(ms []config.HeaderMatch, cookie bool) []condition {
	out := make([]condition, 0, len(ms))
	for _, m := range ms {
		c := condition{name: m.Name, cookie: cookie}
		if !cookie {
			c.name = http.CanonicalHeaderKey(m.Name)
		}
		switch {
		case m.Exact != "":
			c.kind, c.value = condExact, m.Exact
		case m.Prefix != "":
			c.kind, c.value = condPrefix, m.Prefix
		case m.Regex != "":
			c.kind, c.re = condRegex, regexp.MustCompile("^(?:"+m.Regex+")$") // validated
		case m.Present != nil && !*m.Present:
			c.kind = condAbsent
		default:
			c.kind = condPresent
		}
		out = append(out, c)
	}
	return out
}

// holds evaluates the condition against the request headers.
func (c *condition) holds(hdr http.Header) bool {
	var v string
	var present bool
	if c.cookie {
		if ck, err := (&http.Request{Header: hdr}).Cookie(c.name); err == nil {
			v, present = ck.Value, true
		}
	} else if vs := hdr[c.name]; len(vs) > 0 {
		v, present = vs[0], true
	}
	switch c.kind {
	case condExact:
		return present && v == c.value
	case condPrefix:
		return present && strings.HasPrefix(v, c.value)
	case condRegex:
		return present && c.re.MatchString(v)
	case condAbsent:
		return !present
	default:
		return present
	}
}

func condsHold(cs []condition, hdr http.Header) bool {
	for i := range cs {
		if !cs[i].holds(hdr) {
			return false
		}
	}
	return true
}

// condCount is the number of conditions for specificity: header and
// cookie matches plus one for a when expression.
func (e *entry) condCount() int {
	n := len(e.conds)
	if e.when != nil {
		n++
	}
	return n
}

// grpcMatch selects gRPC requests by service or Service/Method. Empty
// sets match every gRPC request.
type grpcMatch struct {
	services map[string]bool
	methods  map[string]bool
}

// grpcRank orders entries of equal path and priority: 2 for listed
// services or methods, 1 for any gRPC request, 0 for a plain entry.
func (e *entry) grpcRank() int {
	switch {
	case e.grpc == nil:
		return 0
	case len(e.grpc.services) == 0 && len(e.grpc.methods) == 0:
		return 1
	default:
		return 2
	}
}

func (g *grpcMatch) matches(path string) bool {
	if len(g.services) == 0 && len(g.methods) == 0 {
		return true
	}
	p := strings.TrimPrefix(path, "/")
	svc, method, ok := strings.Cut(p, "/")
	if !ok || svc == "" || method == "" || strings.Contains(method, "/") {
		return false
	}
	return g.services[svc] || g.methods[svc+"/"+method]
}

type hostTable struct {
	// entries sorted by len(path) desc, then priority desc, then index asc.
	entries []entry
}

// Router is an immutable set of compiled routes.
type Router struct {
	exact    map[string]*hostTable
	wildcard map[string]*hostTable // key is the suffix after "*."
	catchAll *hostTable
	count    int
}

// New compiles routes. The configuration must already be validated.
func New(routes []config.Route) *Router {
	r := &Router{
		exact:    map[string]*hostTable{},
		wildcard: map[string]*hostTable{},
		catchAll: &hostTable{},
	}
	for i := range routes {
		rc := &routes[i]
		cr := &Route{Cfg: rc, Index: i}
		r.count++
		var methods map[string]bool
		if len(rc.Methods) > 0 {
			methods = make(map[string]bool, len(rc.Methods))
			for _, m := range rc.Methods {
				methods[m] = true
			}
		}
		var gm *grpcMatch
		if rc.GRPC != nil {
			gm = &grpcMatch{services: map[string]bool{}, methods: map[string]bool{}}
			for _, sv := range rc.GRPC.Services {
				gm.services[sv] = true
			}
			for _, m := range rc.GRPC.Methods {
				gm.methods[m] = true
			}
		}
		tables := r.tablesFor(rc.Hosts)
		conds := append(compileConds(rc.Headers, false), compileConds(rc.Cookies, true)...)
		var when *expr.Expr
		if rc.When != "" {
			when = expr.MustParse(rc.When, config.ExprVars(), config.CaptureNames(rc)...) // validated
		}
		add := func(e entry) {
			e.conds, e.methods, e.priority, e.route, e.grpc, e.when = conds, methods, rc.Priority, cr, gm, when
			for _, t := range tables {
				t.entries = append(t.entries, e)
			}
		}
		for _, p := range rc.Paths {
			add(entry{path: normalisePath(p)})
		}
		for _, p := range rc.PathRegex {
			// The literal prefix comes from the bare pattern: a leading
			// anchor hides it from LiteralPrefix.
			lit, _ := regexp.MustCompile("(?:" + strings.TrimPrefix(p, "^") + ")").LiteralPrefix() // validated
			add(entry{path: lit, regex: regexp.MustCompile("^(?:" + p + ")$")})
		}
	}
	for _, t := range r.exact {
		sortEntries(t.entries)
	}
	for _, t := range r.wildcard {
		sortEntries(t.entries)
	}
	sortEntries(r.catchAll.entries)
	return r
}

func (r *Router) tablesFor(hosts []string) []*hostTable {
	if len(hosts) == 0 {
		return []*hostTable{r.catchAll}
	}
	out := make([]*hostTable, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(h)
		var m map[string]*hostTable
		if strings.HasPrefix(h, "*.") {
			h = h[2:]
			m = r.wildcard
		} else {
			m = r.exact
		}
		t, ok := m[h]
		if !ok {
			t = &hostTable{}
			m[h] = t
		}
		out = append(out, t)
	}
	return out
}

func sortEntries(es []entry) {
	sort.SliceStable(es, func(i, j int) bool {
		if len(es[i].path) != len(es[j].path) {
			return len(es[i].path) > len(es[j].path)
		}
		if ci, cj := es[i].condCount(), es[j].condCount(); ci != cj {
			return ci > cj // conditioned entries first
		}
		if (es[i].regex != nil) != (es[j].regex != nil) {
			return es[i].regex != nil // a pattern is more specific than its literal prefix
		}
		if es[i].priority != es[j].priority {
			return es[i].priority > es[j].priority
		}
		if ri, rj := es[i].grpcRank(), es[j].grpcRank(); ri != rj {
			return ri > rj // named services beat any-gRPC, which beats plain
		}
		return es[i].route.Index < es[j].route.Index
	})
}

// Len returns the number of routes.
func (r *Router) Len() int { return r.count }

// Match returns the route for host, path and method, or nil.
//
// host must already be lower-cased and stripped of any port. path must be
// the cleaned request path (see netutil.CleanPath).
func (r *Router) Match(host, path, method string) *Route {
	return r.MatchRequest(host, path, method, false, nil, nil)
}

// MatchRequest is Match with the gRPC flag of the request (routes with
// a grpc section only match gRPC requests, and only for their services
// and methods), its headers for header and cookie conditions and the
// variable environment for when expressions (a nil env fails every
// expression).
func (r *Router) MatchRequest(host, path, method string, grpc bool, hdr http.Header, env expr.Env) *Route {
	if t, ok := r.exact[host]; ok {
		if m := t.match(path, method, grpc, hdr, env); m != nil {
			return m
		}
	}
	if i := strings.IndexByte(host, '.'); i > 0 && i < len(host)-1 {
		if t, ok := r.wildcard[host[i+1:]]; ok {
			if m := t.match(path, method, grpc, hdr, env); m != nil {
				return m
			}
		}
	}
	return r.catchAll.match(path, method, grpc, hdr, env)
}

func (t *hostTable) match(path, method string, grpc bool, hdr http.Header, env expr.Env) *Route {
	for i := range t.entries {
		e := &t.entries[i]
		var captures []string
		if e.regex != nil {
			if !strings.HasPrefix(path, e.path) {
				continue
			}
			captures = e.regex.FindStringSubmatch(path)
			if captures == nil {
				continue
			}
		} else if !prefixMatch(path, e.path) {
			continue
		}
		if e.methods != nil && !e.methods[method] {
			continue
		}
		if e.grpc != nil && (!grpc || !e.grpc.matches(path)) {
			continue
		}
		if len(e.conds) > 0 && !condsHold(e.conds, hdr) {
			continue
		}
		whenEnv := env
		if env != nil && len(captures) > 0 {
			whenEnv = captureEnv{Env: env, values: captures, names: e.regex.SubexpNames()}
		}
		if e.when != nil && (whenEnv == nil || !e.when.Eval(whenEnv)) {
			continue
		}
		return e.route
	}
	return nil
}

// captureEnv exposes the current candidate's path-regex groups while a when
// expression is evaluated. The selected route has not yet been returned, so
// the request environment cannot contain these captures itself.
type captureEnv struct {
	expr.Env
	values []string
	names  []string
}

func (e captureEnv) Resolve(name, arg string) (string, bool) {
	if name != "capture" {
		return e.Env.Resolve(name, arg)
	}
	if n, err := strconv.Atoi(arg); err == nil {
		if n >= 0 && n < len(e.values) {
			return e.values[n], true
		}
		return "", false
	}
	for i, captureName := range e.names {
		if captureName == arg && i < len(e.values) {
			return e.values[i], true
		}
	}
	return "", false
}

// prefixMatch reports whether path is under prefix at a segment boundary.
// "/api" matches "/api" and "/api/x" but not "/apix".
func prefixMatch(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	if prefix[len(prefix)-1] == '/' {
		return true
	}
	return path[len(prefix)] == '/'
}

func normalisePath(p string) string {
	if p == "" {
		return "/"
	}
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return strings.TrimRight(p, "/")
	}
	return p
}
