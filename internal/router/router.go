// Package router matches incoming requests to configured routes.
//
// Matching is host first, then longest path prefix, then method, then
// priority. Host matching supports exact names and single-label wildcards
// ("*.example.com" matches "a.example.com" but not "example.com" or
// "a.b.example.com"). Exact hosts win over wildcards, and both win over
// catch-all routes with no hosts.
//
// The router is immutable once built, so lookups need no locking and a
// reload simply swaps the pointer.
package router

import (
	"sort"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// Route is a compiled route ready for matching.
type Route struct {
	Cfg   *config.Route
	Index int // position in the configuration, for logging
}

type entry struct {
	path     string
	methods  map[string]bool // nil means any
	priority int
	route    *Route
	grpc     *grpcMatch // non-nil restricts the entry to gRPC requests
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
		for _, p := range rc.Paths {
			e := entry{path: normalisePath(p), methods: methods, priority: rc.Priority, route: cr, grpc: gm}
			for _, t := range tables {
				t.entries = append(t.entries, e)
			}
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
	return r.MatchRequest(host, path, method, false)
}

// MatchRequest is Match with the gRPC flag of the request: routes with
// a grpc section only match gRPC requests, and only for their services
// and methods.
func (r *Router) MatchRequest(host, path, method string, grpc bool) *Route {
	if t, ok := r.exact[host]; ok {
		if m := t.match(path, method, grpc); m != nil {
			return m
		}
	}
	if i := strings.IndexByte(host, '.'); i > 0 && i < len(host)-1 {
		if t, ok := r.wildcard[host[i+1:]]; ok {
			if m := t.match(path, method, grpc); m != nil {
				return m
			}
		}
	}
	return r.catchAll.match(path, method, grpc)
}

func (t *hostTable) match(path, method string, grpc bool) *Route {
	for i := range t.entries {
		e := &t.entries[i]
		if !prefixMatch(path, e.path) {
			continue
		}
		if e.methods != nil && !e.methods[method] {
			continue
		}
		if e.grpc != nil && (!grpc || !e.grpc.matches(path)) {
			continue
		}
		return e.route
	}
	return nil
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
