package http

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/metrics"
)

// recorder collects what a plane emits, so a test can ask whether a
// metric family exists rather than trusting that somebody wired it.
type recorder struct {
	values map[string]float64
	labels map[string]metrics.Labels
}

func newRecorder() *recorder {
	return &recorder{values: map[string]float64{}, labels: map[string]metrics.Labels{}}
}

func (r *recorder) Counter(name, _ string, l metrics.Labels, v float64) {
	r.values[name] = v
	r.labels[name] = l
}
func (r *recorder) Gauge(name, help string, l metrics.Labels, v float64)                { r.Counter(name, help, l, v) }
func (r *recorder) Histogram(string, string, metrics.Labels, metrics.HistogramSnapshot) {}

// End to end: a caller reading one object after another on one endpoint
// is refused, a caller reading the same object is not, and the counters
// the operator watches it with are emitted.
func TestAnObjectWalkIsRefusedAndCounted(t *testing.T) {
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
filters:
  - name: abuse
    kind: api_abuse
    options:
      window: 1m
      max_objects: 3
      sequential: {min: 0}
      refused: {min_requests: 0}
      action: block
      paths: ["/api/"]
routes:
  - {name: api, hosts: [api.test], upstream: app, filters: [abuse]}
`, b.addr())
	srv, url := startServer(t, yaml)
	get := func(path string) int {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, url+path, nil)
		r.Host = "api.test"
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// Three distinct objects are within the bound; the fourth is one
	// past it, and a bound crossed on the way in refuses that request
	// rather than the one after it.
	for i := 1001; i <= 1003; i++ {
		if code := get(fmt.Sprintf("/api/orders/%d", i)); code != http.StatusOK {
			t.Fatalf("/api/orders/%d answered %d, want 200", i, code)
		}
	}
	if code := get("/api/orders/1004"); code != http.StatusForbidden {
		t.Errorf("the fourth object answered %d, want 403", code)
	}
	// Another endpoint is another subject: one busy endpoint does not
	// refuse a caller on the next.
	if code := get("/api/items/7"); code != http.StatusOK {
		t.Errorf("a first request on another endpoint answered %d, want 200", code)
	}
	// A path outside the filter's prefixes is not counted at all.
	if code := get("/health"); code != http.StatusOK {
		t.Errorf("an uncovered path answered %d, want 200", code)
	}

	rec := newRecorder()
	srv.Collect(rec)
	for _, name := range []string{
		"xproxy_api_abuse_requests_total", "xproxy_api_abuse_flagged_total",
		"xproxy_api_abuse_blocked_total", "xproxy_api_abuse_challenged_total",
		"xproxy_api_abuse_dropped_total", "xproxy_api_abuse_subjects",
		"xproxy_api_abuse_objects", "xproxy_api_abuse_overflowed",
	} {
		if _, ok := rec.values[name]; !ok {
			t.Errorf("%s is not emitted", name)
			continue
		}
		if rec.labels[name]["filter"] != "abuse" {
			t.Errorf("%s is not labelled with the filter: %v", name, rec.labels[name])
		}
	}
	if got := rec.values["xproxy_api_abuse_blocked_total"]; got != 1 {
		t.Errorf("blocked %v, want 1", got)
	}
	if got := rec.values["xproxy_api_abuse_requests_total"]; got != 5 {
		t.Errorf("counted %v requests, want the 5 under /api/", got)
	}
	if got := rec.values["xproxy_api_abuse_subjects"]; got != 2 {
		t.Errorf("%v subjects, want one per endpoint", got)
	}
	if got := rec.values["xproxy_api_abuse_objects"]; got != 5 {
		t.Errorf("%v objects held, want the four orders and the item", got)
	}
	// The refusal is a deny event the ban list sees under its own reason.
	if n := srv.Stats().DeniedFilter; n == 0 {
		t.Error("the refusal was not counted as a filter denial")
	}
}

// The documented fallback: an action of challenge with nothing to
// challenge with is the refusal, not a request served. An operator
// reading "challenge" must not believe a walk is being let through
// while it is being refused, nor the other way round.
func TestAChallengeWithNoChallengerRefuses(t *testing.T) {
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
filters:
  - name: abuse
    kind: api_abuse
    options:
      max_objects: 2
      sequential: {min: 0}
      refused: {min_requests: 0}
      action: challenge
routes:
  - {name: api, hosts: [api.test], upstream: app, filters: [abuse]}
`, b.addr())
	_, url := startServer(t, yaml)
	get := func(path string) int {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, url+path, nil)
		r.Host = "api.test"
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i := 501; i <= 502; i++ {
		if code := get(fmt.Sprintf("/api/orders/%d", i)); code != http.StatusOK {
			t.Fatalf("/api/orders/%d answered %d, want 200", i, code)
		}
	}
	if code := get("/api/orders/503"); code != http.StatusForbidden {
		t.Errorf("a challenge with no challenger answered %d, want 403", code)
	}
}
