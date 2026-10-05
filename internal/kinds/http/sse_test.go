package http

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
)

// End to end: a client, this proxy and an application emitting an event stream.
//
// The application below is a real SSE server rather than a byte stream: it sets
// the Content-Type, flushes per event, and can be told to send a particular
// sequence. That matters because a test that wrote raw octets would pass
// against a guard that never attached -- attaching is decided on the response's
// Content-Type, which is the first thing worth proving.

// sseApp is an application that emits whatever the test asked for.
func sseApp(t *testing.T, body func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		body(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// raw emits exactly these octets and flushes, which is how a test states a
// stream whose framing is the point.
func raw(s string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, s)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// sseProxy puts the proxy in front of an application with the given guard.
func sseProxy(t *testing.T, origin, guard string) *proxy.Server {
	t.Helper()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(origin, "http://"))
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: "%s:%s"}]
routes:
  - name: events
    paths: [/]
%s
    upstream: app
`, host, port, guard)
	s, _ := startServer(t, yaml)
	return s
}

// get asks for the stream and returns what the client actually received.
func stream(t *testing.T, s *proxy.Server, header ...string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+s.Addrs()["main"]+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// An ordinary stream is untouched in substance and re-emitted in form. A guard
// that broke a working dashboard would be worse than none.
func TestAnEventStreamIsCarriedAndItsEventsCounted(t *testing.T) {
	app := sseApp(t, raw("event: price\ndata: 42\nid: 7\n\ndata: plain\n\n"))
	s := sseProxy(t, app.URL, "    sse_guard: {}")
	code, body := stream(t, s)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{"event: price", "data: 42", "id: 7", "data: plain"} {
		if !strings.Contains(body, want) {
			t.Errorf("the client did not receive %q:\n%s", want, body)
		}
	}
	sn := s.Stats()
	if sn.SSEStreams != 1 {
		t.Errorf("sse_streams = %d, want 1", sn.SSEStreams)
	}
	if sn.SSEEvents != 2 {
		t.Errorf("sse_events = %d, want 2", sn.SSEEvents)
	}
}

// The guard attaches on the response's Content-Type, so a route with a guard
// that answers something else is an ordinary response and is not touched.
func TestAResponseThatIsNotAnEventStreamIsNotGuarded(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"not":"a stream"}`)
	}))
	t.Cleanup(app.Close)
	s := sseProxy(t, app.URL, "    sse_guard: {max_event_bytes: 64}")
	code, body := stream(t, s)
	if code != http.StatusOK || body != `{"not":"a stream"}` {
		t.Fatalf("status %d body %q", code, body)
	}
	if n := s.Stats().SSEStreams; n != 0 {
		t.Errorf("the guard attached to a response that is not a stream (%d)", n)
	}
}

// The event list. deny is checked first and no entry in allow overrides it,
// and a name neither list covers gets unknown_events.
func TestOnlyTheEventsTheRouteNamesCross(t *testing.T) {
	for _, c := range []struct {
		name    string
		stream  string
		guard   string
		carried []string
		absent  []string
		reason  string
	}{{
		name:    "a named event crosses",
		stream:  "event: price\ndata: 1\n\n",
		guard:   "      allow_events: [price]",
		carried: []string{"event: price"},
	}, {
		name:   "a name no list covers is refused once allow_events names any",
		stream: "event: price\ndata: 1\n\nevent: admin-notice\ndata: 2\n\n",
		guard:  "      allow_events: [price]",
		// The first event crossed; the stream ended at the second, so the
		// client has the one and not the other.
		carried: []string{"event: price"},
		absent:  []string{"admin-notice"},
		reason:  "event_not_allowed",
	}, {
		name:   "deny_events wins over allow_events",
		stream: "event: price\ndata: 1\n\n",
		guard:  "      allow_events: [price]\n      deny_events: [price]",
		absent: []string{"event: price"},
		reason: "event_denied",
	}, {
		name:    "an unnamed event is message, which is the name a rule uses",
		stream:  "data: 1\n\n",
		guard:   "      allow_events: [message]",
		carried: []string{"data: 1"},
	}, {
		name:    "observe carries it and says so",
		stream:  "event: surprise\ndata: 1\n\n",
		guard:   "      allow_events: [price]\n      unknown_events: observe",
		carried: []string{"event: surprise"},
	}} {
		t.Run(c.name, func(t *testing.T) {
			app := sseApp(t, raw(c.stream))
			s := sseProxy(t, app.URL, "    sse_guard:\n"+c.guard)
			_, body := stream(t, s)
			for _, want := range c.carried {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q:\n%s", want, body)
				}
			}
			for _, no := range c.absent {
				if strings.Contains(body, no) {
					t.Errorf("the client received %q:\n%s", no, body)
				}
			}
			if c.reason != "" && s.Stats().Refusals["http"]["sse_"+c.reason] == 0 {
				t.Errorf("%s was not counted: %v", c.reason, s.Stats().Refusals["http"])
			}
		})
	}
}

// The bound that makes a stream finite. An event stream has no length and
// nothing else in HTTP bounds one, so without these a single GET is an
// open-ended channel.
func TestTheStreamTotalsEndTheStream(t *testing.T) {
	many := strings.Repeat("data: x\n\n", 10)
	app := sseApp(t, raw(many))
	s := sseProxy(t, app.URL, "    sse_guard: {max_events: 3}")
	_, body := stream(t, s)
	if n := strings.Count(body, "data: x"); n != 3 {
		t.Errorf("%d events reached the client, want 3:\n%s", n, body)
	}
	if s.Stats().Refusals["http"]["sse_too_many_events"] == 0 {
		t.Errorf("too_many_events was not counted: %v", s.Stats().Refusals["http"])
	}
}

// An event past the bound ends the stream rather than being truncated: half an
// event delivered as whole is worse than none.
func TestAnEventPastTheBoundIsNotTruncated(t *testing.T) {
	big := strings.Repeat("y", 400)
	app := sseApp(t, raw("data: small\n\ndata: "+big+"\n\ndata: after\n\n"))
	s := sseProxy(t, app.URL, "    sse_guard: {max_event_bytes: 100}")
	_, body := stream(t, s)
	if !strings.Contains(body, "data: small") {
		t.Errorf("the event inside the bound did not cross:\n%s", body)
	}
	if strings.Contains(body, "y") {
		t.Errorf("part of the oversize event reached the client:\n%s", body)
	}
	if strings.Contains(body, "after") {
		t.Error("the stream continued past a refusal")
	}
	if s.Stats().Refusals["http"]["sse_event_too_large"] == 0 {
		t.Errorf("event_too_large was not counted: %v", s.Stats().Refusals["http"])
	}
}

// A per-name bound is where the keepalive and the report get different answers.
// One max_event_bytes for the stream is the bound of its largest event, which
// is the bound that lets every other event be that large too.
func TestAPerNameBoundIsTighterThanTheStreams(t *testing.T) {
	app := sseApp(t, raw("event: heartbeat\ndata: "+strings.Repeat("h", 200)+"\n\n"))
	s := sseProxy(t, app.URL, `    sse_guard:
      max_event_bytes: 65536
      allow_events: [heartbeat, report]
      events:
        - {name: heartbeat, max_bytes: 32}`)
	_, body := stream(t, s)
	if strings.Contains(body, "heartbeat") {
		t.Errorf("an oversize heartbeat crossed:\n%s", body)
	}
	if s.Stats().Refusals["http"]["sse_event_too_large"] == 0 {
		t.Errorf("event_too_large was not counted: %v", s.Stats().Refusals["http"])
	}
}

// A comment is how a stream stays alive through an intermediary that would time
// it out, so it crosses by default and is counted -- a silent stream and a busy
// one must not look the same.
func TestAKeepaliveCommentCrossesAndIsCounted(t *testing.T) {
	app := sseApp(t, raw(": keepalive\n\ndata: x\n\n"))
	s := sseProxy(t, app.URL, "    sse_guard: {}")
	_, body := stream(t, s)
	if !strings.HasPrefix(body, ":\n\n") {
		t.Errorf("the comment did not cross:\n%q", body)
	}
	if n := s.Stats().SSEComments; n != 1 {
		t.Errorf("sse_comments = %d, want 1", n)
	}
	// And a route that wants nothing but named events turns them off.
	app2 := sseApp(t, raw(": keepalive\n\ndata: x\n\n"))
	s2 := sseProxy(t, app2.URL, "    sse_guard: {allow_comments: false}")
	_, body2 := stream(t, s2)
	if strings.Contains(body2, ":\n\n") {
		t.Errorf("a comment crossed with allow_comments: false:\n%q", body2)
	}
	if !strings.Contains(body2, "data: x") {
		t.Errorf("the event after the comment did not cross:\n%q", body2)
	}
}

// Last-Event-ID is the one piece of client input on this protocol and it
// reaches the application as a cursor, so the route decides what may be
// claimed. A cursor that does not pass is removed rather than refused: the
// client gets the stream from the beginning, which is what a client with no
// cursor gets.
func TestWhatAReconnectMayClaimWithLastEventID(t *testing.T) {
	for _, c := range []struct {
		name  string
		guard string
		send  string
		want  string
	}{
		{name: "an admitted cursor reaches the application",
			guard: `      last_event_id_pattern: "[0-9]{1,19}"`, send: "4321", want: "4321"},
		{name: "a cursor of the wrong shape does not",
			guard: `      last_event_id_pattern: "[0-9]{1,19}"`, send: "../../etc/passwd", want: ""},
		{name: "a cursor past the bound does not",
			guard: "      max_id_bytes: 4", send: "123456789", want: ""},
		{name: "no cursor crosses at all where the route says so",
			guard: "      allow_last_event_id: false", send: "4321", want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			seen := make(chan string, 1)
			app := sseApp(t, func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Last-Event-ID")
				_, _ = io.WriteString(w, "data: x\n\n")
			})
			s := sseProxy(t, app.URL, "    sse_guard:\n"+c.guard)
			if _, body := stream(t, s, "Last-Event-ID", c.send); !strings.Contains(body, "data: x") {
				t.Fatalf("the stream did not arrive: %q", body)
			}
			if got := <-seen; got != c.want {
				t.Errorf("the application saw Last-Event-ID %q, want %q", got, c.want)
			}
			if c.want == "" && s.Stats().SSECursorsStripped == 0 {
				t.Error("the stripped cursor was not counted")
			}
		})
	}
}

// The pattern list reads what is leaving, which is the direction an
// exfiltration channel runs in. An event stream is the well-shaped place to put
// data that is not meant to go: arbitrary text, chunked, under a Content-Type a
// dashboard uses, and nothing about it malformed.
func TestADenyPatternReadsWhatIsLeaving(t *testing.T) {
	app := sseApp(t, raw("data: ordinary\n\ndata: 4111111111111111\n\ndata: after\n\n"))
	s := sseProxy(t, app.URL, `    sse_guard:
      deny_patterns: ["[0-9]{13,19}"]`)
	_, body := stream(t, s)
	if !strings.Contains(body, "ordinary") {
		t.Errorf("the ordinary event did not cross:\n%s", body)
	}
	if strings.Contains(body, "4111111111111111") {
		t.Errorf("the matched event reached the client:\n%s", body)
	}
	if strings.Contains(body, "after") {
		t.Error("the stream continued past a refusal")
	}
	if s.Stats().Refusals["http"]["sse_pattern"] == 0 {
		t.Errorf("pattern was not counted: %v", s.Stats().Refusals["http"])
	}
}

// A schema per event name, and the refusal that matters: an event too large to
// have been inspected whole cannot be validated, so it is refused rather than
// passed. A check that silently stops applying above a size the sender chooses
// is not a check, and the sender here is the thing being checked.
func TestASchemaAppliesPerNameAndRefusesWhatItCannotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "price.json")
	doc := `{"type":"object","required":["v"],"properties":{"v":{"type":"number"}}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	guard := `    sse_guard:
      allow_events: [price]
      max_inspect_bytes: 64
      events:
        - {name: price, schema_file: ` + path + `}`

	app := sseApp(t, raw(`event: price`+"\n"+`data: {"v":42}`+"\n\n"))
	s := sseProxy(t, app.URL, guard)
	if _, body := stream(t, s); !strings.Contains(body, `{"v":42}`) {
		t.Errorf("an event matching its schema did not cross:\n%s", body)
	}

	app2 := sseApp(t, raw(`event: price`+"\n"+`data: {"v":"not a number"}`+"\n\n"))
	s2 := sseProxy(t, app2.URL, guard)
	if _, body := stream(t, s2); strings.Contains(body, "not a number") {
		t.Errorf("an event its schema refuses crossed:\n%s", body)
	}
	if s2.Stats().Refusals["http"]["sse_schema"] == 0 {
		t.Errorf("schema was not counted: %v", s2.Stats().Refusals["http"])
	}

	app3 := sseApp(t, raw(`event: price`+"\n"+`data: {"v":1,"pad":"`+strings.Repeat("p", 200)+`"}`+"\n\n"))
	s3 := sseProxy(t, app3.URL, guard)
	if _, body := stream(t, s3); strings.Contains(body, "pad") {
		t.Errorf("an event too large to validate crossed:\n%s", body)
	}
	if s3.Stats().Refusals["http"]["sse_not_inspectable"] == 0 {
		t.Errorf("not_inspectable was not counted: %v", s3.Stats().Refusals["http"])
	}
}

// A retry floor rewrites rather than refuses, because the stream itself is
// fine: `retry: 0` from a misconfigured application is a fleet of browsers
// reconnecting as fast as they can.
func TestARetryFloorIsRewrittenRatherThanRefused(t *testing.T) {
	app := sseApp(t, raw("retry: 0\ndata: x\n\nretry: 30000\ndata: y\n\n"))
	s := sseProxy(t, app.URL, "    sse_guard: {min_retry: 5s}")
	_, body := stream(t, s)
	if !strings.Contains(body, "retry: 5000") {
		t.Errorf("the floor was not applied:\n%s", body)
	}
	if !strings.Contains(body, "retry: 30000") {
		t.Errorf("a retry above the floor was changed:\n%s", body)
	}
	if !strings.Contains(body, "data: x") || !strings.Contains(body, "data: y") {
		t.Errorf("an event was refused rather than rewritten:\n%s", body)
	}
}

// monitor_only reports what it would refuse and carries everything, which is
// how an estate finds out what its own streams send before a bound is set.
func TestMonitorOnlyCarriesTheEventAndSaysWhatItWouldHaveDone(t *testing.T) {
	app := sseApp(t, raw("event: surprise\ndata: 1\n\ndata: 2\n\n"))
	s := sseProxy(t, app.URL, `    sse_guard:
      allow_events: [price]
      monitor_only: true`)
	_, body := stream(t, s)
	if !strings.Contains(body, "event: surprise") {
		t.Errorf("monitor_only refused an event:\n%s", body)
	}
	if !strings.Contains(body, "data: 2") {
		t.Errorf("monitor_only ended the stream:\n%s", body)
	}
	if s.Stats().Refusals["http"]["sse_event_not_allowed"] != 0 {
		t.Error("monitor_only counted a refusal")
	}
}

// A stream whose framing this proxy cannot read is the one violation that
// stands in monitor_only too: forwarding it raw would mean forwarding octets
// nobody decided about, which is not what shadow mode is for.
func TestAStreamThatCannotBeReadIsNotForwardedEvenInShadowMode(t *testing.T) {
	app := sseApp(t, raw("data: ok\n\nevent: a\x01b\ndata: 2\n\n"))
	s := sseProxy(t, app.URL, "    sse_guard: {monitor_only: true}")
	_, body := stream(t, s)
	if !strings.Contains(body, "data: ok") {
		t.Errorf("the readable event did not cross:\n%s", body)
	}
	if strings.Contains(body, "data: 2") {
		t.Errorf("a stream with an unreadable event went on in shadow mode:\n%s", body)
	}
	if s.Stats().Refusals["http"]["sse_control_character"] == 0 {
		t.Errorf("control_character was not counted: %v", s.Stats().Refusals["http"])
	}
}

// All three of the standard's line terminators arrive from real servers, and a
// proxy that handled only LF would hold a bare-CR stream open and deliver
// nothing -- which looks exactly like an application that has stopped.
func TestAStreamWithBareCRTerminatorsIsReadAndReEmitted(t *testing.T) {
	app := sseApp(t, raw("event: tick\rdata: 1\r\r"))
	s := sseProxy(t, app.URL, "    sse_guard: {}")
	_, body := stream(t, s)
	if !strings.Contains(body, "event: tick") || !strings.Contains(body, "data: 1") {
		t.Errorf("a bare-CR stream did not come through:\n%q", body)
	}
	// Re-emitted in the one spelling, which is the point of writing events out
	// rather than splicing: the client cannot read the framing differently
	// from the way the policy did.
	if strings.Contains(body, "\r") {
		t.Errorf("the re-emitted stream still carries a CR:\n%q", body)
	}
}

// compression: refuse answers the request rather than quietly changing what the
// client asked for.
func TestCompressionRefuseAnswersTheRequest(t *testing.T) {
	app := sseApp(t, raw("data: x\n\n"))
	s := sseProxy(t, app.URL, "    sse_guard: {compression: refuse}")
	code, _ := stream(t, s, "Accept-Encoding", "gzip")
	if code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", code)
	}
	if s.Stats().SSEViolations == 0 {
		t.Error("the refusal was not counted")
	}
}

// strip, the default, removes the offer so the application sends the stream in
// the clear -- which is what makes the rest of the policy possible, because a
// compressed stream cannot be read without being inflated.
func TestCompressionStripRemovesTheOfferBeforeTheApplicationSeesIt(t *testing.T) {
	seen := make(chan string, 1)
	app := sseApp(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Accept-Encoding")
		_, _ = io.WriteString(w, "data: x\n\n")
	})
	s := sseProxy(t, app.URL, "    sse_guard: {}")
	if _, body := stream(t, s, "Accept-Encoding", "gzip"); !strings.Contains(body, "data: x") {
		t.Fatalf("the stream did not arrive: %q", body)
	}
	if got := <-seen; got != "" {
		t.Errorf("the application was offered %q", got)
	}
}

// The request side applies to a request that asked for a stream, not to every
// request on the route: a route serving a page and a stream under one path is
// ordinary, and stripping Accept-Encoding from the page would make this proxy
// the reason the page is uncompressed.
func TestTheEncodingPolicyAppliesOnlyToARequestThatAskedForAStream(t *testing.T) {
	seen := make(chan string, 1)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>a page</p>")
	}))
	t.Cleanup(app.Close)
	s := sseProxy(t, app.URL, "    sse_guard: {}")
	req, _ := http.NewRequest(http.MethodGet, "http://"+s.Addrs()["main"]+"/", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := <-seen; got == "" {
		t.Error("Accept-Encoding was stripped from a request that did not ask for a stream")
	}
}

// The cursor policy is the other half of that decision and it goes the other
// way, because the two are gated on different things. What makes a response a
// stream is its Content-Type, so an application that answers a path with
// text/event-stream answers it that way for a client that sent no Accept header
// at all -- and a cursor check gated on Accept would be one a client opts out
// of by leaving a header out.
func TestTheCursorPolicyDoesNotDependOnTheAcceptHeader(t *testing.T) {
	seen := make(chan string, 1)
	app := sseApp(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Last-Event-ID")
		_, _ = io.WriteString(w, "data: x\n\n")
	})
	s := sseProxy(t, app.URL, `    sse_guard:
      last_event_id_pattern: "[0-9]{1,19}"`)
	req, _ := http.NewRequest(http.MethodGet, "http://"+s.Addrs()["main"]+"/", nil)
	// No Accept header at all, which is a client asking for whatever the path
	// answers with -- and this path answers with a stream.
	req.Header.Set("Last-Event-ID", "' UNION SELECT secret FROM audit--")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := <-seen; got != "" {
		t.Errorf("the application saw Last-Event-ID %q from a request with no Accept header", got)
	}
	if s.Stats().SSECursorsStripped == 0 {
		t.Error("the stripped cursor was not counted")
	}
}

// A cursor pattern with alternation is anchored on every branch. `|` has the
// lowest precedence there is, so a pattern wrapped by adding "^" and "$" to its
// ends would be anchored only at the ends -- "starts with the first branch, or
// ends with the last" -- which admits an identifier with a legal one at one end
// and anything at all after it.
func TestACursorPatternWithAlternationIsAnchoredOnEveryBranch(t *testing.T) {
	seen := make(chan string, 1)
	app := sseApp(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Last-Event-ID")
		_, _ = io.WriteString(w, "data: x\n\n")
	})
	// An estate whose identifiers are either a counter or a ULID.
	s := sseProxy(t, app.URL, `    sse_guard:
      last_event_id_pattern: "[0-9]{1,19}|[0-9A-HJKMNP-TV-Z]{26}"`)
	if _, body := stream(t, s, "Last-Event-ID", "1' UNION SELECT secret FROM audit--"); !strings.Contains(body, "data: x") {
		t.Fatalf("the stream did not arrive: %q", body)
	}
	if got := <-seen; got != "" {
		t.Errorf("the application saw Last-Event-ID %q: the anchors bound to one branch", got)
	}
}

// Two cursors are a differential rather than a cursor: the first is one
// library's answer, the last another's, so a policy that checked one of them
// has checked a value the application need not be the one to use. Neither
// crosses.
func TestTwoCursorsOnOneRequestBothGo(t *testing.T) {
	seen := make(chan []string, 1)
	app := sseApp(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Values("Last-Event-ID")
		_, _ = io.WriteString(w, "data: x\n\n")
	})
	s := sseProxy(t, app.URL, `    sse_guard:
      last_event_id_pattern: "[0-9]{1,19}"`)
	req, _ := http.NewRequest(http.MethodGet, "http://"+s.Addrs()["main"]+"/", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Add("Last-Event-ID", "4321")
	req.Header.Add("Last-Event-ID", "../../etc/passwd")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := <-seen; len(got) != 0 {
		t.Errorf("the application saw Last-Event-ID %q", got)
	}
	if s.Stats().SSECursorsStripped == 0 {
		t.Error("the stripped cursors were not counted")
	}
}

// action: log carries the event and reports it, which is the second of the two
// answers this protocol allows.
func TestActionLogCarriesTheEventAndReportsIt(t *testing.T) {
	app := sseApp(t, raw("event: surprise\ndata: 1\n\ndata: 2\n\n"))
	s := sseProxy(t, app.URL, `    sse_guard:
      allow_events: [price]
      action: log`)
	_, body := stream(t, s)
	if !strings.Contains(body, "event: surprise") || !strings.Contains(body, "data: 2") {
		t.Errorf("action: log ended the stream:\n%s", body)
	}
}
