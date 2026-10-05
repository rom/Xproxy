package admin

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The interface is one page of JavaScript with a navigation bar in the
// HTML beside it, and nothing at run time checks that the two agree. A
// link to a view nobody wrote lands the reader on the overview with no
// error at all, and a view nobody linked cannot be reached -- both of
// which are the kind of mistake that ships and is found by a user. So the
// parity is a test, in both directions, and so is every endpoint the page
// reads.

var (
	navLink  = regexp.MustCompile(`href="#([a-z0-9-]+)"`)
	jsLink   = regexp.MustCompile(`href: '#([a-z0-9-]+)'`)
	viewDecl = regexp.MustCompile(`(?m)^views\.([a-zA-Z0-9_]+) = `)
	apiPath  = regexp.MustCompile(`'(/api/[a-z0-9/_-]+)`)
)

func staticFile(t *testing.T, name string) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// navSection is the navigation bar's markup on its own, so a link
// elsewhere in the document is not read as a menu entry.
func navSection(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, `<nav id="nav">`)
	if i < 0 {
		t.Fatal("no navigation bar in index.html")
	}
	rest := html[i:]
	j := strings.Index(rest, "</nav>")
	if j < 0 {
		t.Fatal("the navigation bar is not closed")
	}
	return rest[:j]
}

func TestTheNavigationAndTheViewsAgree(t *testing.T) {
	html := staticFile(t, "index.html")
	js := staticFile(t, "app.js")
	views := map[string]bool{}
	for _, m := range viewDecl.FindAllStringSubmatch(js, -1) {
		views[m[1]] = true
	}
	if len(views) < 10 {
		t.Fatalf("found %d views, so the pattern has stopped matching the page", len(views))
	}
	// Reachable is linked from the menu or from another view's page.
	reachable := map[string]bool{}
	for _, m := range navLink.FindAllStringSubmatch(navSection(t, html), -1) {
		reachable[m[1]] = true
		if !views[m[1]] {
			t.Errorf("the navigation links #%s, which no view renders", m[1])
		}
	}
	for _, m := range jsLink.FindAllStringSubmatch(js, -1) {
		reachable[m[1]] = true
		if !views[m[1]] {
			t.Errorf("a view links #%s, which no view renders", m[1])
		}
	}
	for name := range views {
		if !reachable[name] {
			t.Errorf("views.%s is linked from nowhere, so nothing reaches it", name)
		}
	}
}

// Every /api path the page fetches has to be a route the server serves. A
// view reading an endpoint nobody registered shows an error where a table
// should be, in that one view, which is exactly where nobody looks.
func TestEveryEndpointThePageReadsIsServed(t *testing.T) {
	js := staticFile(t, "app.js")
	s := &Server{mux: http.NewServeMux()}
	s.routes()
	// The static file server is registered on "GET /", so every path
	// matches something. A path is served only when the pattern that
	// matched is not that catch-all.
	served := func(path string) bool {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			_, pattern := s.mux.Handler(httptest.NewRequest(method, path, nil))
			if pattern != "" && pattern != "GET /" {
				return true
			}
		}
		return false
	}
	missing := map[string]bool{}
	for _, m := range apiPath.FindAllStringSubmatch(js, -1) {
		// A literal ending in a slash is a path the page completes with a
		// value -- /api/logs/ plus the stream -- so it is probed with a
		// segment in place of that value, against the {stream} wildcard.
		path := m[1]
		if strings.HasSuffix(path, "/") {
			path += "x"
		}
		if !served(path) {
			missing[path] = true
		}
	}
	if len(missing) == 0 {
		return
	}
	paths := make([]string, 0, len(missing))
	for p := range missing {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	t.Errorf("the page reads endpoints nothing serves: %s", strings.Join(paths, ", "))
}
