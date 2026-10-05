package filter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The chain is what the data plane actually calls: one Begin per
// request, then Request, then Response, then End. Its contract is that
// the first deny stops the chain, that a filter which declined to make
// an instance is simply not in it, and that End runs for everything
// that did — because a filter that buffered a body or took a slot
// releases it there.

// recorder is a filter that records which phases ran and can deny in
// either of them.
type recorder struct {
	name       string
	denyReq    bool
	denyResp   bool
	noInstance bool
	events     *[]string
}

func (f *recorder) Name() string { return f.name }

func (f *recorder) Begin(_ context.Context, _ *Info) Instance {
	*f.events = append(*f.events, f.name+":begin")
	if f.noInstance {
		return nil
	}
	return &recorderInstance{f: f}
}

type recorderInstance struct{ f *recorder }

func (in *recorderInstance) Request(*http.Request) Verdict {
	*in.f.events = append(*in.f.events, in.f.name+":request")
	if in.f.denyReq {
		return Verdict{Deny: true, Status: http.StatusForbidden, Reason: in.f.name, Detail: "request"}
	}
	return Continue
}

func (in *recorderInstance) Response(*http.Response) Verdict {
	*in.f.events = append(*in.f.events, in.f.name+":response")
	if in.f.denyResp {
		return Verdict{Deny: true, Status: http.StatusForbidden, Reason: in.f.name, Detail: "response"}
	}
	return Continue
}

func (in *recorderInstance) End() []any {
	*in.f.events = append(*in.f.events, in.f.name+":end")
	return []any{in.f.name, "ran"}
}

// TestChainOrder covers the plain path: every filter in configuration
// order, in every phase, with the log attributes concatenated in the
// same order so a reader can follow the chain down an access log line.
func TestChainOrder(t *testing.T) {
	var events []string
	chain := Chain{
		&recorder{name: "a", events: &events},
		&recorder{name: "b", events: &events},
		&recorder{name: "c", events: &events},
	}
	is := chain.Begin(context.Background(), &Info{})
	if len(is) != 3 {
		t.Fatalf("%d instances", len(is))
	}
	if v := is.Request(httptest.NewRequest("GET", "http://a/x", nil)); v.Deny {
		t.Fatalf("request: %+v", v)
	}
	if v := is.Response(&http.Response{StatusCode: 200, Header: http.Header{}}); v.Deny {
		t.Fatalf("response: %+v", v)
	}
	attrs := is.End()
	if fmt.Sprint(attrs) != "[a ran b ran c ran]" {
		t.Fatalf("attributes %v", attrs)
	}
	want := "a:begin b:begin c:begin a:request b:request c:request a:response b:response c:response a:end b:end c:end"
	if got := strings.Join(events, " "); got != want {
		t.Fatalf("order:\n got %s\nwant %s", got, want)
	}
}

// TestFirstDenyStops requires the chain to stop at the first deny and
// to carry that filter's verdict out unchanged: the reason is what the
// security log records and what a ban trigger counts.
func TestFirstDenyStops(t *testing.T) {
	var events []string
	chain := Chain{
		&recorder{name: "a", events: &events},
		&recorder{name: "b", denyReq: true, events: &events},
		&recorder{name: "c", events: &events},
	}
	is := chain.Begin(context.Background(), &Info{})
	v := is.Request(httptest.NewRequest("GET", "http://a/x", nil))
	if !v.Deny || v.Reason != "b" || v.Status != http.StatusForbidden {
		t.Fatalf("verdict %+v", v)
	}
	if strings.Contains(strings.Join(events, " "), "c:request") {
		t.Fatalf("the chain continued past a deny: %v", events)
	}
	// End still runs for every instance, including the ones that never
	// saw the request: that is where a filter releases what it took.
	is.End()
	joined := strings.Join(events, " ")
	for _, name := range []string{"a:end", "b:end", "c:end"} {
		if !strings.Contains(joined, name) {
			t.Fatalf("%s did not run after a deny: %v", name, events)
		}
	}
}

// TestResponseDenyStops is the same rule in the response phase, where a
// deny replaces a response the upstream already produced.
func TestResponseDenyStops(t *testing.T) {
	var events []string
	chain := Chain{
		&recorder{name: "a", events: &events},
		&recorder{name: "b", denyResp: true, events: &events},
		&recorder{name: "c", events: &events},
	}
	is := chain.Begin(context.Background(), &Info{})
	v := is.Response(&http.Response{StatusCode: 200, Header: http.Header{}})
	if !v.Deny || v.Reason != "b" || v.Detail != "response" {
		t.Fatalf("verdict %+v", v)
	}
	if strings.Contains(strings.Join(events, " "), "c:response") {
		t.Fatalf("the chain continued past a response deny: %v", events)
	}
}

// TestNilInstancesAreSkipped covers a filter that declines to take part
// in a request. It must not be in the chain at all rather than be a nil
// the other phases then call through.
func TestNilInstancesAreSkipped(t *testing.T) {
	var events []string
	chain := Chain{
		&recorder{name: "a", noInstance: true, events: &events},
		&recorder{name: "b", events: &events},
	}
	is := chain.Begin(context.Background(), &Info{})
	if len(is) != 1 {
		t.Fatalf("%d instances, want 1", len(is))
	}
	if v := is.Request(httptest.NewRequest("GET", "http://a/x", nil)); v.Deny {
		t.Fatalf("%+v", v)
	}
	if attrs := is.End(); fmt.Sprint(attrs) != "[b ran]" {
		t.Fatalf("attributes %v", attrs)
	}
}

// TestEmptyChain covers a route with no filters, which is most routes.
// Every phase must be safe on the nil the chain returns.
func TestEmptyChain(t *testing.T) {
	var is Instances
	if got := Chain(nil).Begin(context.Background(), &Info{}); got != nil {
		t.Fatalf("an empty chain produced %d instances", len(got))
	}
	if v := is.Request(httptest.NewRequest("GET", "http://a/x", nil)); v.Deny {
		t.Fatalf("%+v", v)
	}
	if v := is.Response(&http.Response{StatusCode: 200, Header: http.Header{}}); v.Deny {
		t.Fatalf("%+v", v)
	}
	if attrs := is.End(); attrs != nil {
		t.Fatalf("attributes %v", attrs)
	}
}

// TestBuffersBody covers the flag that charges the process-wide
// buffered body budget. An unregistered name must answer false rather
// than reserving memory for a filter that does not exist.
func TestBuffersBody(t *testing.T) {
	Register(Kind{
		Name: "test_buffers", Description: "buffers a body", BuffersBody: true,
		Validate: func(Options) error { return nil },
		New:      func(string, Options, Env) (Filter, error) { return nil, errors.New("not built in this test") },
	})
	Register(Kind{
		Name: "test_streams", Description: "streams",
		Validate: func(Options) error { return nil },
		New:      func(string, Options, Env) (Filter, error) { return nil, errors.New("not built in this test") },
	})
	if !BuffersBody("test_buffers") {
		t.Fatal("a kind that declares BuffersBody answered false")
	}
	if BuffersBody("test_streams") {
		t.Fatal("a streaming kind answered true")
	}
	for _, name := range []string{"", "no_such_kind", "TEST_BUFFERS"} {
		if BuffersBody(name) {
			t.Fatalf("the unregistered name %q reserved the body budget", name)
		}
	}
	// Both kinds are listed, in name order, with their descriptions.
	names := KindNames()
	if !sorted(names) {
		t.Fatalf("KindNames is not sorted: %v", names)
	}
	found := 0
	for _, k := range Kinds() {
		if strings.HasPrefix(k.Name, "test_") {
			found++
			if k.Description == "" {
				t.Fatalf("%s has no description", k.Name)
			}
		}
	}
	if found != 2 {
		t.Fatalf("found %d of the two registered test kinds", found)
	}
}

func sorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

// TestIdentityAny covers the identity an access log line names when
// several filters recorded one: the preferred kinds in order, then
// anything, then "".
func TestIdentityAny(t *testing.T) {
	ctx, id := WithIdentity(context.Background())
	if id.Any() != "" || id.Get("jwt") != "" {
		t.Fatal("a fresh identity is not empty")
	}
	SetIdentity(ctx, "basic", "alice")
	SetIdentity(ctx, "jwt", "bob")
	SetIdentity(ctx, "", "ignored")
	SetIdentity(ctx, "api_key", "")
	if got := id.Get("basic"); got != "alice" {
		t.Fatalf("basic is %q", got)
	}
	if got := id.Any("jwt", "basic"); got != "bob" {
		t.Fatalf("preferring jwt gave %q", got)
	}
	if got := id.Any("oidc", "basic"); got != "alice" {
		t.Fatalf("preferring an absent kind then basic gave %q", got)
	}
	if got := id.Any("oidc"); got != "alice" && got != "bob" {
		t.Fatalf("preferring only an absent kind gave %q", got)
	}
	// The last non-empty value for a kind wins.
	SetIdentity(ctx, "jwt", "carol")
	if got := id.Get("jwt"); got != "carol" {
		t.Fatalf("jwt is %q after a second set", got)
	}
	// A nil identity is what a context without one yields, and every
	// accessor takes it.
	var none *Identity
	if none.Get("jwt") != "" || none.Any("jwt") != "" {
		t.Fatal("a nil identity answered")
	}
	// Setting on a context without an identity is a no-op, not a panic.
	SetIdentity(context.Background(), "jwt", "mallory")
}

// RequestFrom names the filter that denied, so a caller can carry on from the
// next one rather than leaving the chain.
//
// This is what makes a satisfied challenge resumable. A filter that answers
// "challenge" has denied, so the chain stops at it; the data plane treats an
// already-verified client as admitted and has to continue from there. Leaving the
// chain entirely skipped every filter behind the challenge-issuing one, which by
// default is the WAF, the content scanners and any later authorisation filter --
// so provoking a challenge was a way past all of them.
func TestRequestFromResumesAfterTheFilterThatDenied(t *testing.T) {
	var events []string
	first := &recorder{name: "first", events: &events}
	middle := &recorder{name: "middle", denyReq: true, events: &events}
	last := &recorder{name: "last", denyReq: true, events: &events}
	is := Instances{first.Begin(context.Background(), nil),
		middle.Begin(context.Background(), nil), last.Begin(context.Background(), nil)}
	r := httptest.NewRequest("GET", "/", nil)

	v, at := is.RequestFrom(r, 0)
	if !v.Deny || v.Reason != "middle" || at != 1 {
		t.Fatalf("first pass gave %+v at %d, want middle at 1", v, at)
	}
	// Resuming past it reaches the filter behind it, which is the whole point:
	// the one that would otherwise never be asked.
	v, at = is.RequestFrom(r, at+1)
	if !v.Deny || v.Reason != "last" || at != 2 {
		t.Fatalf("resumed pass gave %+v at %d, want last at 2", v, at)
	}
	// And a chain nobody denies reports the end rather than a filter.
	clean := Instances{first.Begin(context.Background(), nil)}
	if v, at := clean.RequestFrom(r, 0); v.Deny || at != len(clean) {
		t.Errorf("a clean chain gave %+v at %d", v, at)
	}
	// Request is still the whole chain from the start.
	if v := is.Request(r); !v.Deny || v.Reason != "middle" {
		t.Errorf("Request gave %+v, want the first deny", v)
	}
	if !strings.Contains(strings.Join(events, " "), "last:request") {
		t.Errorf("the filter behind the denier was never asked: %v", events)
	}
}
