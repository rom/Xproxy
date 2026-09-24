package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/shed"
)

const earlyDataYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: default, hosts: [default.test], upstream: app}
  - {name: allowed, hosts: [allow.test], upstream: app, early_data: allow}
  - {name: refused, hosts: [reject.test], upstream: app, early_data: reject}
`

// A request that arrived in the TLS handshake can be replayed by whoever
// captured it. The default policy takes that for a safe method and answers
// 425 to anything else, which is what tells the client to send it again on
// the finished connection.
func TestEarlyDataIsRefusedForWhatCannotBeReplayed(t *testing.T) {
	b := newBackend(t, "app")
	_, url := startServer(t, fmt.Sprintf(earlyDataYAML, b.addr()))
	send := func(method, host string, early bool) int {
		r, _ := http.NewRequest(method, url+"/x", strings.NewReader("body"))
		r.Host = host
		if early {
			r.Header.Set("Early-Data", "1")
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for _, tc := range []struct {
		name, method, host string
		early              bool
		want               int
	}{
		{"a GET on early data", http.MethodGet, "default.test", true, http.StatusOK},
		{"a HEAD on early data", http.MethodHead, "default.test", true, http.StatusOK},
		{"a POST on early data", http.MethodPost, "default.test", true, http.StatusTooEarly},
		{"a PUT on early data", http.MethodPut, "default.test", true, http.StatusTooEarly},
		{"a POST on a finished handshake", http.MethodPost, "default.test", false, http.StatusOK},
		{"a POST where the route allows early data", http.MethodPost, "allow.test", true, http.StatusOK},
		{"a GET where the route refuses all of it", http.MethodGet, "reject.test", true, http.StatusTooEarly},
		{"a GET with no early data where the route refuses it", http.MethodGet, "reject.test", false, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := send(tc.method, tc.host, tc.early); got != tc.want {
				t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// Early-Data is a statement about how a request reached the first hop, and
// only that hop can make it. A client's own must decide nothing and must
// not reach the backend, which cannot tell it from the proxy's.
func TestAClientsOwnEarlyDataHeaderCountsForNothing(t *testing.T) {
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: default, upstream: app}
`, b.addr())
	_, url := startServer(t, yaml)
	// No trusted_proxies, so this peer's word counts for nothing: the
	// POST is served rather than refused.
	r, _ := http.NewRequest(http.MethodPost, url+"/x", strings.NewReader("body"))
	r.Header.Set("Early-Data", "1")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200: an untrusted peer's Early-Data decided the request", resp.StatusCode)
	}
	if got := b.last.Load().Header.Get("Early-Data"); got != "" {
		t.Errorf("the backend was told Early-Data: %q", got)
	}
}

// Trailers, where a route does not want them: neither the announcement nor
// the fields reach the client, because an announcement with nothing behind
// it leaves a client waiting.
func TestTrailersCanBeStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
		w.Header().Set("X-Checksum", "abc123")
	}))
	t.Cleanup(srv.Close)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: pass, hosts: [pass.test], upstream: app}
  - {name: strip, hosts: [strip.test], upstream: app, trailers: strip}
`, strings.TrimPrefix(srv.URL, "http://"))
	_, url := startServer(t, yaml)
	for _, tc := range []struct {
		host string
		want string
	}{
		{"pass.test", "abc123"},
		{"strip.test", ""},
	} {
		resp, body := get(t, url+"/x", "Host", tc.host)
		if body != "body" {
			t.Fatalf("%s: body %q", tc.host, body)
		}
		if got := resp.Trailer.Get("X-Checksum"); got != tc.want {
			t.Errorf("%s: trailer %q, want %q", tc.host, got, tc.want)
		}
		if tc.want == "" && resp.Header.Get("Trailer") != "" {
			t.Errorf("%s: the announcement stayed: %q", tc.host, resp.Header.Get("Trailer"))
		}
	}
}

// RFC 9218: a client may say its own request is less urgent, and that is
// all it may say. The parser is the whole of what a client controls here,
// so it is driven directly.
func TestAPriorityHeaderOnlyEverLowers(t *testing.T) {
	for _, tc := range []struct {
		header  string
		stated  bool
		urgency int
		inc     bool
	}{
		{"", false, 3, false},
		{"u=0", true, 0, false},
		{"u=7", true, 7, false},
		{"u=5, i", true, 5, true},
		{"i=?0, u=2", true, 2, false},
		{"u=3;q=0.5", true, 3, false},
		{"i", true, 3, true},
		{"u=8", false, 3, false},
		{"u=-1", false, 3, false},
		{"u=x", false, 3, false},
		{"urgency=1", false, 3, false},
		{strings.Repeat("u=7,", 40), false, 3, false},
	} {
		got := parsePriority(tc.header)
		if got.stated != tc.stated || got.urgency != tc.urgency || got.incremental != tc.inc {
			t.Errorf("parsePriority(%q) = %+v, want stated=%v urgency=%d incremental=%v", tc.header, got, tc.stated, tc.urgency, tc.inc)
		}
	}
	// The lowering table, and the fact that nothing raises.
	for _, tc := range []struct {
		header string
		from   shed.Class
		want   shed.Class
	}{
		{"u=0", shed.Normal, shed.Normal},
		{"u=0", shed.Low, shed.Low},
		{"u=3", shed.High, shed.High},
		{"u=4", shed.High, shed.Normal},
		{"u=5", shed.Normal, shed.Low},
		{"u=5", shed.Low, shed.Low},
		{"u=7", shed.Critical, shed.Low},
		{"u=6", shed.High, shed.Low},
		{"", shed.Normal, shed.Normal},
		{"u=9", shed.Normal, shed.Normal},
	} {
		if got := parsePriority(tc.header).lower(tc.from); got != tc.want {
			t.Errorf("%q lowers %s to %s, want %s", tc.header, tc.from, got, tc.want)
		}
	}
	// No urgency raises anything: every value, from every class.
	for u := 0; u <= 7; u++ {
		for _, from := range []shed.Class{shed.Low, shed.Normal, shed.High, shed.Critical} {
			if got := parsePriority(fmt.Sprintf("u=%d", u)).lower(from); got > from {
				t.Errorf("u=%d raised %s to %s", u, from, got)
			}
		}
	}
}

// And end to end: the header is read on a route that asks for it, ignored
// on one that does not, and forwarded either way.
func TestTheUrgencyIsReadOnlyWhereTheRouteAsksForIt(t *testing.T) {
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
shedding: {target_latency: 100ms}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: reads, hosts: [reads.test], upstream: app, client_priority: lower, priority_class: high}
  - {name: ignores, hosts: [ignores.test], upstream: app, priority_class: high}
`, b.addr())
	_, url := startServer(t, yaml)
	for _, host := range []string{"reads.test", "ignores.test"} {
		resp, _ := get(t, url+"/x", "Host", host, "Priority", "u=7")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", host, resp.StatusCode)
		}
		if got := b.last.Load().Header.Get("Priority"); got != "u=7" {
			t.Errorf("%s: the upstream was sent Priority %q", host, got)
		}
	}
}
