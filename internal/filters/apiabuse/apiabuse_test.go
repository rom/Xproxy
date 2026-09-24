package apiabuse

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func build(t *testing.T, opts filter.Options) *Filter {
	t.Helper()
	f, err := filtertest.Build("api_abuse", "abuse", opts)
	if err != nil {
		t.Fatal(err)
	}
	// A built filter joins the status registry, as one built by a
	// generation does; closing it is what that generation's teardown
	// does, and a test that skipped it would leave the registry holding
	// a filter nothing reaches.
	t.Cleanup(func() { _ = f.(*Filter).Close() })
	return f.(*Filter)
}

// ask sends one request for an object and, when status is not 0, one
// answer with that status.
func ask(f *Filter, id string, status int) filtertest.Result {
	r := httptest.NewRequest(http.MethodGet, "http://api.test/api/orders/"+id, nil)
	var resp *http.Response
	if status != 0 {
		resp = &http.Response{StatusCode: status, Header: http.Header{}}
	}
	return filtertest.Run(f, r, resp)
}

// The sequence a WAF cannot see: one caller reading many objects.
func TestManyObjectsOnOneEndpointIsEnumeration(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 10, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	// Ten objects is within the policy, and the eleventh is not. The
	// identifiers are deliberately scattered so that only the count can
	// be what raised it.
	for i, id := range []string{"7", "913", "42", "1288", "3", "77", "512", "64", "900", "11"} {
		if res := ask(f, id, http.StatusOK); res.Request.Deny {
			t.Fatalf("object %d of ten was refused: %+v", i+1, res.Request)
		}
	}
	res := ask(f, "4242", http.StatusOK)
	if !res.Request.Deny || res.Request.Reason != "api_abuse" {
		t.Fatalf("the eleventh object was allowed: %+v", res.Request)
	}
	if !strings.Contains(res.Request.Detail, SignalEnumeration) {
		t.Errorf("detail %q, want the enumeration signal", res.Request.Detail)
	}
	// The same object again is not a new object, so a caller re-reading
	// what it already read stays inside the policy -- which is what makes
	// this a count of objects rather than of requests.
	fresh := build(t, filter.Options{"max_objects": 3, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}})
	for i := 0; i < 50; i++ {
		if res := ask(fresh, "77", http.StatusOK); len(res.Attrs) != 0 {
			t.Fatalf("request %d for the same object raised %v", i, res.Attrs)
		}
	}
	if fresh.Status().Flagged != 0 {
		t.Errorf("re-reading one object was flagged: %+v", fresh.Status())
	}
}

// Consecutive identifiers are a different fact from many identifiers: a
// catalogue read in order is a scrape.
func TestConsecutiveIdentifiersAreASequentialScan(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 0, "refused": map[string]any{"min_requests": 0},
		"sequential": map[string]any{"min": 10, "density": 0.8}, "action": "block"})
	var denied bool
	for i := 1000; i < 1012; i++ {
		if res := ask(f, fmt.Sprint(i), http.StatusOK); res.Request.Deny {
			denied = true
			if !strings.Contains(res.Request.Detail, SignalSequential) {
				t.Errorf("detail %q, want the sequential signal", res.Request.Detail)
			}
			break
		}
	}
	if !denied {
		t.Error("a walk of twelve consecutive identifiers was not noticed")
	}
	// Scattered identifiers over a wide span are not a walk, however many
	// there are: the density is what separates a scrape from a busy
	// dashboard.
	sparse := build(t, filter.Options{"max_objects": 0, "refused": map[string]any{"min_requests": 0},
		"sequential": map[string]any{"min": 10, "density": 0.8}})
	for i := 0; i < 20; i++ {
		ask(sparse, fmt.Sprint(i*1000), http.StatusOK)
	}
	if sparse.Status().Flagged != 0 {
		t.Errorf("twenty scattered identifiers were called a walk: %+v", sparse.Status())
	}
	// And identifiers that are not numbers at all cannot be a walk.
	uuids := build(t, filter.Options{"max_objects": 0, "refused": map[string]any{"min_requests": 0},
		"sequential": map[string]any{"min": 5, "density": 0.5}})
	for i := 0; i < 20; i++ {
		ask(uuids, fmt.Sprintf("018f3c%02x-0000-7000-8000-000000000000", i), http.StatusOK)
	}
	if uuids.Status().Flagged != 0 {
		t.Errorf("unordered identifiers were called a walk: %+v", uuids.Status())
	}
}

// The BOLA shape: most of what this caller asks for is not theirs.
func TestRefusedLookupsAreTheProbingSignal(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 0, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 10, "share": 0.5}, "action": "block"})
	// Nine refusals is below the minimum number of requests, so nothing
	// is decided yet: a handful of 404s is an ordinary day.
	for i := 0; i < 9; i++ {
		if res := ask(f, fmt.Sprint(5000+i), http.StatusNotFound); res.Request.Deny {
			t.Fatalf("request %d was refused before the minimum: %+v", i, res.Request)
		}
	}
	if f.Status().Flagged != 0 {
		t.Fatalf("flagged below min_requests: %+v", f.Status())
	}
	// The tenth takes it over, and the next request is refused.
	ask(f, "5009", http.StatusForbidden)
	res := ask(f, "5010", 0)
	if !res.Request.Deny || !strings.Contains(res.Request.Detail, SignalRefused) {
		t.Fatalf("the caller was not flagged for probing: %+v", res.Request)
	}
	// A caller whose lookups mostly succeed is not probing, however many
	// it makes.
	ok := build(t, filter.Options{"max_objects": 0, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 10, "share": 0.5}})
	for i := 0; i < 30; i++ {
		status := http.StatusOK
		if i%5 == 0 {
			status = http.StatusNotFound
		}
		ask(ok, fmt.Sprint(i), status)
	}
	if ok.Status().Flagged != 0 {
		t.Errorf("a caller with a fifth of its lookups refused was flagged: %+v", ok.Status())
	}
}

// Each caller is counted on its own, and each endpoint too: one busy
// endpoint must not flag a caller on another, and one caller's walk must
// not flag everybody.
func TestCallersAndEndpointsAreCountedApart(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 5, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	send := func(ip, path string) filtertest.Result {
		r := httptest.NewRequest(http.MethodGet, "http://api.test"+path, nil)
		info := &filter.Info{ClientIP: mustAddr(ip)}
		return filtertest.RunWithInfo(f, info, r, &http.Response{StatusCode: 200, Header: http.Header{}})
	}
	for i := 0; i < 6; i++ {
		send("198.51.100.10", fmt.Sprintf("/api/orders/%d", i))
	}
	if res := send("198.51.100.10", "/api/orders/99"); !res.Request.Deny {
		t.Fatal("the busy caller was not flagged")
	}
	// Another caller on the same endpoint.
	if res := send("198.51.100.11", "/api/orders/1"); res.Request.Deny {
		t.Errorf("another caller was refused for the first one's reading: %+v", res.Request)
	}
	// The same caller on another endpoint.
	if res := send("198.51.100.10", "/api/invoices/1"); res.Request.Deny {
		t.Errorf("the caller was refused on an endpoint it had not touched: %+v", res.Request)
	}
}

// An authenticated caller is one caller whatever address it arrives
// from, which is the whole reason this filter belongs after the identity
// filters in the chain.
func TestAnIdentityIsOneCallerFromAnyAddress(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 5, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	send := func(ip, user, id string) filtertest.Result {
		r := httptest.NewRequest(http.MethodGet, "http://api.test/api/orders/"+id, nil)
		ctx, ident := filter.WithIdentity(r.Context())
		_ = ident
		r = r.WithContext(ctx)
		filter.SetIdentity(ctx, "jwt", user)
		return filtertest.RunWithInfo(f, &filter.Info{ClientIP: mustAddr(ip)}, r,
			&http.Response{StatusCode: 200, Header: http.Header{}})
	}
	for i := 0; i < 6; i++ {
		// Every request from a different address, all the same account.
		send(fmt.Sprintf("203.0.113.%d", i+1), "alice", fmt.Sprint(i))
	}
	if res := send("203.0.113.99", "alice", "999"); !res.Request.Deny {
		t.Error("an account reading through six addresses was not counted as one caller")
	}
	if res := send("203.0.113.99", "bob", "1"); res.Request.Deny {
		t.Errorf("another account was refused for alice's reading: %+v", res.Request)
	}
}

// The window turns over: a caller flagged this morning is not flagged
// now, and the counts start again.
func TestTheWindowTurnsOver(t *testing.T) {
	f := build(t, filter.Options{"window": "1m", "max_objects": 3, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	now := time.Now()
	f.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		ask(f, fmt.Sprint(i), http.StatusOK)
	}
	if res := ask(f, "100", http.StatusOK); !res.Request.Deny {
		t.Fatal("the caller was not flagged inside the window")
	}
	now = now.Add(2 * time.Minute)
	if res := ask(f, "101", http.StatusOK); res.Request.Deny {
		t.Errorf("a caller stayed flagged into a new window: %+v", res.Request)
	}
}

// log watches and says so without refusing anything; challenge asks the
// client to prove it is a browser.
func TestTheActionIsWhatTheOperatorAskedFor(t *testing.T) {
	logging := build(t, filter.Options{"max_objects": 2, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}})
	for i := 0; i < 4; i++ {
		if res := ask(logging, fmt.Sprint(i), http.StatusOK); res.Request.Deny {
			t.Fatalf("the log action refused a request: %+v", res.Request)
		}
	}
	if logging.Status().Flagged == 0 {
		t.Error("the log action noticed nothing")
	}
	if logging.Status().Blocked != 0 || logging.Status().Challenged != 0 {
		t.Errorf("the log action acted: %+v", logging.Status())
	}
	// The access log line says which signals were raised.
	res := ask(logging, "999", http.StatusOK)
	if len(res.Attrs) == 0 || !strings.Contains(fmt.Sprint(res.Attrs...), SignalEnumeration) {
		t.Errorf("attributes %v, want the signal", res.Attrs)
	}

	chal := build(t, filter.Options{"max_objects": 2, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "challenge"})
	for i := 0; i < 4; i++ {
		ask(chal, fmt.Sprint(i), http.StatusOK)
	}
	res = ask(chal, "999", http.StatusOK)
	if !res.Request.Deny || !res.Request.Challenge {
		t.Errorf("the challenge action did not ask for a challenge: %+v", res.Request)
	}
	if chal.Status().Challenged == 0 {
		t.Errorf("challenges were not counted: %+v", chal.Status())
	}
}

// Paths outside the configured prefixes are not watched at all, which is
// how a route mixing an object API with everything else is configured.
func TestOnlyTheConfiguredPathsAreWatched(t *testing.T) {
	f := build(t, filter.Options{"paths": []any{"/api/orders/"}, "max_objects": 2,
		"sequential": map[string]any{"min": 0}, "refused": map[string]any{"min_requests": 0}, "action": "block"})
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://api.test/static/%d", i), nil)
		if res := filtertest.Run(f, r, &http.Response{StatusCode: 200, Header: http.Header{}}); res.Request.Deny {
			t.Fatalf("a path outside the prefixes was refused: %+v", res.Request)
		}
	}
	if f.Status().Requests != 0 {
		t.Errorf("%d requests outside the prefixes were counted", f.Status().Requests)
	}
	for i := 0; i < 3; i++ {
		ask(f, fmt.Sprint(i), http.StatusOK)
	}
	if res := ask(f, "99", http.StatusOK); !res.Request.Deny {
		t.Error("a watched path was not watched")
	}
}

// The table is bounded, and a full table drops the oldest caller rather
// than stopping the filter noticing the next one.
func TestTheSubjectTableIsBounded(t *testing.T) {
	f := build(t, filter.Options{"max_subjects": 16, "max_objects": 2, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	for i := 0; i < 64; i++ {
		r := httptest.NewRequest(http.MethodGet, "http://api.test/api/orders/1", nil)
		filtertest.RunWithInfo(f, &filter.Info{ClientIP: mustAddr(fmt.Sprintf("198.51.100.%d", i+1))}, r,
			&http.Response{StatusCode: 200, Header: http.Header{}})
	}
	st := f.Status()
	if st.Subjects > 16 {
		t.Errorf("%d subjects held, want at most 16", st.Subjects)
	}
	if st.Dropped == 0 {
		t.Error("the evictions were not counted")
	}
	// And the filter still notices the newest caller.
	last := "198.51.100.200"
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://api.test/api/orders/%d", i), nil)
		filtertest.RunWithInfo(f, &filter.Info{ClientIP: mustAddr(last)}, r, &http.Response{StatusCode: 200, Header: http.Header{}})
	}
	r := httptest.NewRequest(http.MethodGet, "http://api.test/api/orders/77", nil)
	if res := filtertest.RunWithInfo(f, &filter.Info{ClientIP: mustAddr(last)}, r, nil); !res.Request.Deny {
		t.Error("a full table stopped the filter noticing")
	}
}

// Options this proxy cannot act on are load errors.
func TestOptionsAreCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		opts filter.Options
		want string
	}{
		{filter.Options{"window": "nonsense"}, "window"},
		{filter.Options{"window": "10ms"}, "between 1s and 24h"},
		{filter.Options{"max_objects": -1}, "max_objects"},
		{filter.Options{"max_subjects": 2}, "max_subjects"},
		{filter.Options{"sequential": map[string]any{"density": 2}}, "density"},
		{filter.Options{"sequential": map[string]any{"min": 1}}, "sequential.min"},
		{filter.Options{"refused": map[string]any{"share": 0}}, "share"},
		{filter.Options{"action": "tarpit"}, "action"},
		{filter.Options{"paths": []any{"api/"}}, "must start with /"},
		{filter.Options{"nonsense": 1}, "options"},
		// Every signal off is a filter that would watch and say nothing.
		{filter.Options{"max_objects": 0, "sequential": map[string]any{"min": 0},
			"refused": map[string]any{"min_requests": 0}}, "say nothing"},
	} {
		if _, err := filtertest.Build("api_abuse", "abuse", tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error %v, want one about %q", tc.opts, err, tc.want)
		}
	}
	// And the defaults load.
	f := build(t, filter.Options{})
	if f.Name() != "api_abuse:abuse" {
		t.Errorf("name %q", f.Name())
	}
}

// A path with no identifier in it has no object to count, so a route of
// plain collection endpoints is watched without ever raising anything.
func TestAPathWithNoObjectCountsNoObject(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 2, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest(http.MethodGet, "http://api.test/api/orders", nil)
		if res := filtertest.Run(f, r, &http.Response{StatusCode: 200, Header: http.Header{}}); res.Request.Deny {
			t.Fatalf("a collection endpoint was refused: %+v", res.Request)
		}
	}
}

// mustAddr parses an address for the tests.
func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// Re-reading one object is not a walk, however many times it is read. It
// is the ordinary page refresh, and counting requests rather than objects
// made twenty of them look like a walk of twenty.
func TestRereadingOneObjectIsNotAWalk(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 0, "refused": map[string]any{"min_requests": 0},
		"sequential": map[string]any{"min": 10, "density": 0.8}, "action": "block"})
	for i := 0; i < 40; i++ {
		if res := ask(f, "4711", http.StatusOK); res.Request.Deny {
			t.Fatalf("read %d of one object was called a walk: %+v", i+1, res.Request)
		}
	}
	if st := f.Status(); st.Flagged != 0 || st.Objects != 1 {
		t.Errorf("forty reads of one object: %+v", st)
	}
}

// Past the bound on identifiers held, the count keeps going as a lower
// bound rather than the memory: the caller is still flagged, and the
// status says how much is held and how much could only be counted.
func TestTheObjectSetIsBoundedAndTheCountStaysRight(t *testing.T) {
	f := build(t, filter.Options{"max_objects": maxObjectsHeld + 100, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	// Enough distinct identifiers to fill the set and go past it, but
	// scattered so that only the count can raise anything.
	denied := false
	for i := 0; i < maxObjectsHeld+200; i++ {
		if res := ask(f, fmt.Sprint(100000+i*7), http.StatusOK); res.Request.Deny {
			denied = true
			break
		}
	}
	if !denied {
		t.Error("a caller past the threshold was not flagged once the set was full")
	}
	st := f.Status()
	if st.Objects > maxObjectsHeld {
		t.Errorf("%d identifiers held, want at most %d", st.Objects, maxObjectsHeld)
	}
	if st.Overflowed == 0 {
		t.Error("the identifiers past the bound were not counted")
	}
}

// An identifier no API issues is not counted, so a path carrying
// something absurd cannot fill the set.
func TestAnAbsurdIdentifierIsNotCounted(t *testing.T) {
	f := build(t, filter.Options{"max_objects": 1, "sequential": map[string]any{"min": 0},
		"refused": map[string]any{"min_requests": 0}, "action": "block"})
	for i := 0; i < 5; i++ {
		id := strings.Repeat("a", maxIDLen+1) + fmt.Sprint(i)
		if res := ask(f, id, http.StatusOK); res.Request.Deny {
			t.Fatalf("a %d character identifier was counted: %+v", len(id), res.Request)
		}
	}
	if st := f.Status(); st.Objects != 0 {
		t.Errorf("absurd identifiers were held: %+v", st)
	}
	// Two ordinary ones do raise it, so the filter is watching.
	ask(f, "1", http.StatusOK)
	if res := ask(f, "2", http.StatusOK); !res.Request.Deny {
		t.Error("two ordinary identifiers past a bound of one were not flagged")
	}
}

// The identifier is read from the path by the template's shape, bounded
// by the shorter of the two. PathTemplate always keeps the segment count,
// so this is an invariant rather than a case -- and a template from
// anywhere else must not be able to index past the path.
func TestTheIdentifierIsReadWithinBothShapes(t *testing.T) {
	for _, tc := range []struct{ path, template, want string }{
		{"/api/orders/4711", "/api/orders/*", "4711"},
		{"/api/orders/4711/items/9", "/api/orders/*/items/*", "9"},
		{"/api/orders", "/api/orders", ""},
		// A template longer than the path: nothing to read, and nothing
		// to index past the end of.
		{"/api", "/api/orders/*", ""},
		{"", "", ""},
	} {
		if got := lastVariable(tc.path, tc.template); got != tc.want {
			t.Errorf("lastVariable(%q, %q) = %q, want %q", tc.path, tc.template, got, tc.want)
		}
	}
}
