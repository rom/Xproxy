package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

type blockingBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("body closed")
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// writeGuest builds a hostile guest and returns its path.
func writeGuest(t *testing.T, s guestSpec) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hostile.wasm")
	if err := os.WriteFile(p, buildGuest(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// build loads a guest as a filter with the options a test chose.
func build(t *testing.T, s guestSpec, opts filter.Options) filter.Filter {
	t.Helper()
	if opts == nil {
		opts = filter.Options{}
	}
	opts["module"] = writeGuest(t, s)
	if _, ok := opts["timeout"]; !ok {
		opts["timeout"] = "2s"
	}
	f, err := filtertest.Build("wasm", "policy", opts)
	if err != nil {
		t.Fatalf("building the guest: %v", err)
	}
	t.Cleanup(func() { _ = f.(filter.Closer).Close() })
	return f
}

// TestGuestCannotForgeHeaders is the header half of the sandbox: a
// module is a piece of code somebody else wrote, and the one thing it
// must never be able to do is write a header name or value that splits
// the request.
func TestGuestCannotForgeHeaders(t *testing.T) {
	strs := []string{"x-evil\r\nx-admin", "1", "ok", "a\r\nb", "x-sp ace", "x-nul\x00", "x-colon:x", "", "x-marker", "x-ok"}
	f := build(t, guestSpec{
		strs: strs,
		code: func(o, l func(string) []byte) []byte {
			set := func(name, value string) []byte {
				return cat(i32c(0), o(name), l(name), o(value), l(value), callOp(1))
			}
			return cat(
				set("x-evil\r\nx-admin", "1"), // a newline in the name
				set("ok", "a\r\nb"),           // a newline in the value
				set("x-sp ace", "1"),          // a space in the name
				set("x-nul\x00", "1"),         // a NUL in the name
				set("x-colon:x", "1"),         // a colon in the name
				set("", "1"),                  // no name at all
				set("x-ok", "1"),              // and one that is fine
				i32c(0),
			)
		},
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("the guest denied: %+v", res.Request)
	}
	if r.Header.Get("X-Ok") != "1" {
		t.Fatalf("the legitimate header was not set: %v", r.Header)
	}
	if len(r.Header) != 1 {
		t.Fatalf("the guest set %d headers, want 1: %v", len(r.Header), r.Header)
	}
	for name, values := range r.Header {
		if strings.ContainsAny(name, " :\r\n\x00") {
			t.Errorf("header name %q reached the request", name)
		}
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n\x00") {
				t.Errorf("header value %q reached the request", v)
			}
		}
	}
	if r.Header.Get("X-Admin") != "" {
		t.Error("the split header appeared as its own header")
	}
}

// TestGuestPointersOutsideItsMemory calls every host function with
// pointers and lengths that do not describe anything the guest owns.
// The host must refuse each one and carry on, not read somebody else's
// memory and not crash.
func TestGuestPointersOutsideItsMemory(t *testing.T) {
	const wild = 0x7fff0000 // far past a one-page memory
	f := build(t, guestSpec{
		strs: []string{"x-marker", "1"},
		code: func(o, l func(string) []byte) []byte {
			return cat(
				// get with a name outside memory
				i32c(getRequestHeader), i32c(wild), i32c(64), callOp(0), opDrop,
				// get with a length that wraps past the end
				i32c(getRequestHeader), i32c(0), i32c(0x7fffffff), callOp(0), opDrop,
				// set_header with both halves outside memory
				i32c(0), i32c(wild), i32c(8), i32c(wild), i32c(8), callOp(1),
				// set_header with a valid name and a wild value
				i32c(0), o("x-marker"), l("x-marker"), i32c(wild), i32c(8), callOp(1),
				// remove_header outside memory
				i32c(0), i32c(wild), i32c(8), callOp(2),
				// deny with a wild reason and detail: the status still lands
				i32c(403), i32c(wild), i32c(8), i32c(wild), i32c(8), callOp(3),
				// log and log_attr outside memory
				i32c(1), i32c(wild), i32c(8), callOp(4),
				i32c(wild), i32c(8), i32c(wild), i32c(8), callOp(5),
				// set_body outside memory
				i32c(0), i32c(wild), i32c(64), callOp(6),
				i32c(0),
			)
		},
	}, nil)

	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("original"))
	res := filtertest.Run(f, r, nil)
	// deny() was reached with a status, so the request is denied, but
	// nothing the guest could not prove it owned came through.
	if !res.Request.Deny || res.Request.Status != 403 {
		t.Fatalf("verdict: %+v", res.Request)
	}
	if res.Request.Reason != "policy" {
		t.Errorf("an unreadable reason became %q", res.Request.Reason)
	}
	if res.Request.Detail != "" {
		t.Errorf("an unreadable detail became %q", res.Request.Detail)
	}
	if r.Header.Get("X-Marker") != "" {
		t.Errorf("a header with an unreadable value was set to %q", r.Header.Get("X-Marker"))
	}
	if len(res.Attrs) != 0 {
		t.Errorf("an unreadable attribute was logged: %v", res.Attrs)
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != "original" {
		t.Errorf("the body became %q", body)
	}
}

// TestGuestBudgets covers the two counters that bound what one call can
// do: header operations and log attributes. A module in a loop must not
// be able to fill a log line or rewrite a request header by header.
func TestGuestBudgets(t *testing.T) {
	f := build(t, guestSpec{
		strs:   []string{"x-pad", "1", "x-marker", "k", "v"},
		locals: oneI32Local,
		code: func(o, l func(string) []byte) []byte {
			return cat(
				countedLoop(int64(maxHeaderOps)+50,
					cat(i32c(0), o("x-pad"), l("x-pad"), o("1"), l("1"), callOp(1))),
				// past the budget, so this one is dropped
				i32c(0), o("x-marker"), l("x-marker"), o("1"), l("1"), callOp(1),
				i32c(0),
			)
		},
	}, nil)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if res := filtertest.Run(f, r, nil); res.Request.Deny {
		t.Fatalf("the guest denied: %+v", res.Request)
	}
	if r.Header.Get("X-Pad") != "1" {
		t.Fatal("the first header operations did not happen")
	}
	if r.Header.Get("X-Marker") != "" {
		t.Error("an operation past the budget was applied")
	}

	// The attribute budget, counted in key/value pairs.
	f2 := build(t, guestSpec{
		strs:   []string{"k", "v"},
		locals: oneI32Local,
		code: func(o, l func(string) []byte) []byte {
			return cat(
				countedLoop(int64(maxLogAttrs)+100,
					cat(o("k"), l("k"), o("v"), l("v"), callOp(5))),
				i32c(0),
			)
		},
	}, nil)
	res := filtertest.Run(f2, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
	if len(res.Attrs) != 2*maxLogAttrs {
		t.Fatalf("a flood of attributes produced %d values, want %d", len(res.Attrs), 2*maxLogAttrs)
	}
	for i := 0; i < len(res.Attrs); i += 2 {
		if res.Attrs[i] != "wasm_k" {
			t.Fatalf("attribute %d is %v", i, res.Attrs[i])
		}
	}
}

// TestGuestDenyIsClamped covers the verdict a module hands back: the
// status has to be an HTTP error, the reason has to be a label, and the
// detail has to be bounded, because all three reach the access log and
// the client.
func TestGuestDenyIsClamped(t *testing.T) {
	longDetail := strings.Repeat("d", 500)
	cases := []struct {
		name       string
		status     int64
		reason     string
		detail     string
		wantStatus int
		wantReason string
		wantDetail string
	}{
		{"zero", 0, "blocked", "", 403, "blocked", ""},
		{"below 400", 302, "blocked", "", 403, "blocked", ""},
		{"above 599", 700, "blocked", "", 403, "blocked", ""},
		{"a valid status", 451, "blocked", "why", 451, "blocked", "why"},
		{"a reason with a space", 451, "not allowed", "", 451, "policy", ""},
		{"a reason with a newline", 451, "a\nb", "", 451, "policy", ""},
		{"an oversize reason", 451, strings.Repeat("r", 100), "", 451, "policy", ""},
		{"an empty reason", 451, "", "", 451, "policy", ""},
		{"an oversize detail", 451, "blocked", longDetail, 451, "blocked", longDetail[:256]},
	}
	for _, tc := range cases {
		strs := []string{tc.reason, tc.detail, "pad"}
		f := build(t, guestSpec{
			strs: strs,
			code: func(o, l func(string) []byte) []byte {
				return cat(i32c(tc.status), o(tc.reason), l(tc.reason), o(tc.detail), l(tc.detail), callOp(3), i32c(1))
			},
		}, nil)
		res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
		if !res.Request.Deny {
			t.Errorf("%s: not denied", tc.name)
			continue
		}
		if res.Request.Status != tc.wantStatus || res.Request.Reason != tc.wantReason || res.Request.Detail != tc.wantDetail {
			t.Errorf("%s: %d %q %.20q, want %d %q %.20q", tc.name,
				res.Request.Status, res.Request.Reason, res.Request.Detail, tc.wantStatus, tc.wantReason, tc.wantDetail)
		}
	}
}

// TestGuestTrapsFailClosed covers every way a module can stop working
// mid-call. Each one is an error, the default verdict is a denial, and
// the filter keeps serving the next request.
func TestGuestTrapsFailClosed(t *testing.T) {
	specs := map[string]guestSpec{
		"a trap": {
			strs: []string{"x"},
			code: func(o, l func(string) []byte) []byte { return cat(opUnreachable, i32c(0)) },
		},
		"a store outside memory": {
			strs: []string{"x"},
			code: func(o, l func(string) []byte) []byte {
				return cat(i32c(0x7fff0000), i32c(1), opI32Store, i32c(0))
			},
		},
		"unbounded recursion": {
			strs: []string{"x"},
			code: func(o, l func(string) []byte) []byte { return cat(callOp(9), opDrop, i32c(0)) },
		},
		"an allocator that traps": {
			strs:       []string{"x"},
			allocTraps: true,
			code: func(o, l func(string) []byte) []byte {
				// A get of a value the host has to allocate for.
				return cat(i32c(getConfig), i32c(0), i32c(0), callOp(0), opDrop, i32c(0))
			},
		},
	}
	for name, spec := range specs {
		f := build(t, spec, filter.Options{"config": "tenant=acme"})
		res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
		switch name {
		case "an allocator that traps":
			// Allocation failing is the host's problem to survive, not the
			// guest's to be punished for: the call itself did not trap.
			if res.Request.Deny {
				t.Errorf("%s denied the request: %+v", name, res.Request)
			}
		default:
			if !res.Request.Deny || res.Request.Status != http.StatusInternalServerError || res.Request.Detail != "guest_error" {
				t.Errorf("%s gave %+v", name, res.Request)
			}
		}
		// Whatever happened, the next request is served.
		r2 := httptest.NewRequest(http.MethodGet, "/y", nil)
		_ = filtertest.Run(f, r2, nil)
		st := f.(interface{ Status() Status }).Status()
		if st.Calls < 2 {
			t.Errorf("%s: %d calls counted", name, st.Calls)
		}
	}

	// With on_error: allow, the same trap lets the request through and
	// labels it, so an operator can find the requests that went unchecked.
	f := build(t, guestSpec{
		strs: []string{"x"},
		code: func(o, l func(string) []byte) []byte { return cat(opUnreachable, i32c(0)) },
	}, filter.Options{"on_error": "allow"})
	res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
	if res.Request.Deny {
		t.Fatalf("on_error allow denied: %+v", res.Request)
	}
	if len(res.Attrs) != 2 || res.Attrs[0] != "wasm_error" || res.Attrs[1] != "allowed" {
		t.Fatalf("the unchecked request is not labelled: %v", res.Attrs)
	}
	if st := f.(interface{ Status() Status }).Status(); st.Errors == 0 {
		t.Error("the error was not counted")
	}
}

// TestGuestTimeoutAndConcurrency covers the two bounds that keep one
// module from taking the proxy's request goroutines with it: the per
// call deadline and the instance count.
func TestGuestTimeoutAndConcurrency(t *testing.T) {
	// A guest that never returns.
	spin := guestSpec{
		strs:   []string{"x"},
		locals: oneI32Local,
		code: func(o, l func(string) []byte) []byte {
			return cat(opLoop, opBr0, opEnd, i32c(0))
		},
	}
	f := build(t, spin, filter.Options{"timeout": "50ms", "instances": 2})
	var wg sync.WaitGroup
	denied := make([]bool, 8)
	for i := range denied {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
			denied[i] = res.Request.Deny
		}(i)
	}
	wg.Wait()
	for i, d := range denied {
		if !d {
			t.Errorf("request %d passed although the guest never returned", i)
		}
	}
	st := f.(interface{ Status() Status }).Status()
	if st.Calls != 8 {
		t.Errorf("%d calls counted", st.Calls)
	}
	if st.Timeouts == 0 {
		t.Error("no timeout counted")
	}
	if st.Timeouts+st.Errors != 8 {
		t.Errorf("%d timeouts and %d errors for 8 calls", st.Timeouts, st.Errors)
	}
	if st.Module == "" {
		t.Error("the status does not name the module")
	}

	// A well-behaved guest under the same concurrency: every request is
	// served, and the pool never holds more than the configured number.
	ok := build(t, guestSpec{
		strs: []string{"x-wasm", "1"},
		code: func(o, l func(string) []byte) []byte {
			return cat(i32c(0), o("x-wasm"), l("x-wasm"), o("1"), l("1"), callOp(1), i32c(0))
		},
	}, filter.Options{"instances": 2, "timeout": "2s"})
	var wg2 sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			if res := filtertest.Run(ok, r, nil); res.Request.Deny {
				t.Errorf("a well-behaved guest denied: %+v", res.Request)
			}
			if r.Header.Get("X-Wasm") != "1" {
				t.Error("the header was not set")
			}
		}()
	}
	wg2.Wait()
	st = ok.(interface{ Status() Status }).Status()
	if st.Calls != 64 || st.Errors != 0 || st.Timeouts != 0 {
		t.Errorf("counters after 64 calls: %+v", st)
	}
	if st.Pooled > 2 {
		t.Errorf("the pool holds %d instances for instances: 2", st.Pooled)
	}
}

// TestStringsPastTheBound covers the 64 KiB ceiling on anything crossing
// the boundary: a guest with a big memory must not be able to hand the
// host a megabyte to copy, per call, per request.
func TestStringsPastTheBound(t *testing.T) {
	const big = maxString + 1
	f := build(t, guestSpec{
		strs:  []string{"x-marker", "1", "x-ok"},
		pages: 4, // 256 KiB, so the pointers below are inside the guest
		code: func(o, l func(string) []byte) []byte {
			return cat(
				// a header name of 64 KiB + 1
				i32c(getRequestHeader), i32c(0), i32c(big), callOp(0), opDrop,
				// set_header with an oversize name, then with an oversize value
				i32c(0), i32c(0), i32c(big), o("1"), l("1"), callOp(1),
				i32c(0), o("x-marker"), l("x-marker"), i32c(0), i32c(big), callOp(1),
				// remove_header and log with an oversize string
				i32c(0), i32c(0), i32c(big), callOp(2),
				i32c(1), i32c(0), i32c(big), callOp(4),
				// an oversize attribute key and value
				i32c(0), i32c(big), o("1"), l("1"), callOp(5),
				// and a legitimate header, to prove the guest ran to the end
				i32c(0), o("x-ok"), l("x-ok"), o("1"), l("1"), callOp(1),
				i32c(0),
			)
		},
	}, nil)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("the guest denied: %+v", res.Request)
	}
	if r.Header.Get("X-Ok") != "1" {
		t.Fatal("the guest did not run to the end")
	}
	if len(r.Header) != 1 {
		t.Fatalf("%d headers were set: %v", len(r.Header), r.Header)
	}
	if len(res.Attrs) != 0 {
		t.Errorf("an oversize attribute was logged: %v", res.Attrs)
	}
}

// TestAllocatorThatLies covers a guest whose xproxy_alloc returns a
// pointer it does not own: the host writes nothing there and the value
// simply does not arrive.
func TestAllocatorThatLies(t *testing.T) {
	f := build(t, guestSpec{
		strs:     []string{"x-cfg", "x-ok", "1"},
		allocPtr: 0x7fff0000,
		code: func(o, l func(string) []byte) []byte {
			return cat(
				i32c(getConfig), i32c(0), i32c(0), callOp(0), opDrop,
				i32c(getRequestBody), i32c(0), i32c(0), callOp(0), opDrop,
				i32c(0), o("x-ok"), l("x-ok"), o("1"), l("1"), callOp(1),
				i32c(0),
			)
		},
	}, filter.Options{"config": "tenant=acme"})
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("body bytes"))
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("a lying allocator denied the request: %+v", res.Request)
	}
	if r.Header.Get("X-Ok") != "1" {
		t.Fatal("the guest did not run to the end")
	}
}

// TestBodyBoundaries covers the body the guest may see: exactly at the
// limit, one byte past it, a stream that fails mid-read, and a body the
// guest replaces.
func TestBodyBoundaries(t *testing.T) {
	// A guest that reads the body, publishes its state and echoes its
	// length into a header.
	spec := guestSpec{
		strs:   []string{"x-state", "x-len", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"},
		locals: cat(uleb(1), uleb(1), []byte{i64}),
		code: func(o, l func(string) []byte) []byte {
			return cat(
				i32c(getBodyState), i32c(0), i32c(0), callOp(0), opLocalSet0,
				i32c(0), o("x-state"), l("x-state"), opLocalGet0, i64c(32), opI64ShrU, opWrap, opLocalGet0, lenOf, callOp(1),
				i32c(getRequestBody), i32c(0), i32c(0), callOp(0), opLocalSet0,
				i32c(0), o("x-len"), l("x-len"), opLocalGet0, i64c(32), opI64ShrU, opWrap, opLocalGet0, lenOf, callOp(1),
				i32c(0),
			)
		},
	}
	f := build(t, spec, filter.Options{"body_limit": 16})

	for _, tc := range []struct {
		name  string
		body  string
		state string
		seen  int
	}{
		{"empty", "", "ok", 0},
		{"one byte", "a", "ok", 1},
		{"at the limit", strings.Repeat("a", 16), "ok", 16},
		{"one past the limit", strings.Repeat("a", 17), "too_large", 0},
		{"far past the limit", strings.Repeat("a", 1<<20), "too_large", 0},
	} {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(tc.body))
		res := filtertest.Run(f, r, nil)
		if res.Request.Deny {
			t.Errorf("%s: denied: %+v", tc.name, res.Request)
			continue
		}
		if got := r.Header.Get("X-State"); got != tc.state {
			t.Errorf("%s: body state %q want %q", tc.name, got, tc.state)
		}
		if got := len(r.Header.Get("X-Len")); got != tc.seen {
			t.Errorf("%s: the guest saw %d bytes want %d", tc.name, got, tc.seen)
		}
		// Whatever the guest saw, the upstream still gets the whole body.
		rest, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("%s: reading the restored body: %v", tc.name, err)
		}
		if string(rest) != tc.body {
			t.Errorf("%s: the upstream would see %d bytes of %d", tc.name, len(rest), len(tc.body))
		}
	}

	// A body that fails part way through: the guest sees "too_large"
	// (nothing it can trust) and the error still reaches the upstream
	// read rather than being swallowed into a short body.
	boom := errors.New("connection reset")
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Body = io.NopCloser(io.MultiReader(strings.NewReader("half"), &errReader{boom}))
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("a failing body denied the request: %+v", res.Request)
	}
	if got := r.Header.Get("X-State"); got != "too_large" {
		t.Errorf("a failing body reported state %q", got)
	}
	got, err := io.ReadAll(r.Body)
	if !errors.Is(err, boom) {
		t.Errorf("the read error became %v", err)
	}
	if string(got) != "half" {
		t.Errorf("the bytes read before the failure were lost: %q", got)
	}

	// With body_limit 0 the body is never touched: the state says so and
	// the stream is the original one.
	off := build(t, spec, filter.Options{"body_limit": 0})
	r = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("untouched"))
	original := r.Body
	if res := filtertest.Run(off, r, nil); res.Request.Deny {
		t.Fatalf("body_limit 0 denied: %+v", res.Request)
	}
	if got := r.Header.Get("X-State"); got != "disabled" {
		t.Errorf("body_limit 0 reported state %q", got)
	}
	if r.Body != original {
		t.Error("body_limit 0 still replaced the body")
	}
}

// TestResponseBodyAndHeaders covers the response phase, where the guest
// reads and replaces what the upstream sent.
func TestResponseBodyAndHeaders(t *testing.T) {
	f := build(t, guestSpec{
		strs:       []string{"x-rstate", "x-rlen", "replaced"},
		code:       func(o, l func(string) []byte) []byte { return cat(i32c(0)) },
		respLocals: cat(uleb(1), uleb(1), []byte{i64}),
		respCode: func(o, l func(string) []byte) []byte {
			return cat(
				i32c(getBodyState), i32c(0), i32c(0), callOp(0), opLocalSet1,
				i32c(1), o("x-rstate"), l("x-rstate"), opLocalGet1, i64c(32), opI64ShrU, opWrap, opLocalGet1, lenOf, callOp(1),
				i32c(getResponseBody), i32c(0), i32c(0), callOp(0), opLocalSet1,
				i32c(1), o("x-rlen"), l("x-rlen"), opLocalGet1, i64c(32), opI64ShrU, opWrap, opLocalGet1, lenOf, callOp(1),
				i32c(1), o("replaced"), l("replaced"), callOp(6),
				i32c(0),
			)
		},
	}, filter.Options{"body_limit": 32})

	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"7"}},
		Body: io.NopCloser(strings.NewReader("payload"))}
	res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), resp)
	if res.Response.Deny {
		t.Fatalf("the response phase denied: %+v", res.Response)
	}
	if got := resp.Header.Get("X-Rstate"); got != "ok" {
		t.Errorf("response body state %q", got)
	}
	if got := resp.Header.Get("X-Rlen"); got != "payload" {
		t.Errorf("the guest saw %q of the response body", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "replaced" {
		t.Fatalf("the replaced response body is %q (%v)", body, err)
	}
	// Replacing the body fixes the length and drops an encoding that no
	// longer describes the bytes.
	if resp.ContentLength != int64(len("replaced")) || resp.Header.Get("Content-Length") != "8" {
		t.Errorf("content length %d / %q", resp.ContentLength, resp.Header.Get("Content-Length"))
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Error("the stale content encoding survived the replacement")
	}

	// A response the guest cannot see: over the limit it reads nothing,
	// and a guest that only reads leaves the stream whole.
	readOnly := build(t, guestSpec{
		strs:       []string{"x-rstate", "x-rlen"},
		code:       func(o, l func(string) []byte) []byte { return cat(i32c(0)) },
		respLocals: cat(uleb(1), uleb(1), []byte{i64}),
		respCode: func(o, l func(string) []byte) []byte {
			return cat(
				i32c(getBodyState), i32c(0), i32c(0), callOp(0), opLocalSet1,
				i32c(1), o("x-rstate"), l("x-rstate"), opLocalGet1, i64c(32), opI64ShrU, opWrap, opLocalGet1, lenOf, callOp(1),
				i32c(getResponseBody), i32c(0), i32c(0), callOp(0), opLocalSet1,
				i32c(1), o("x-rlen"), l("x-rlen"), opLocalGet1, i64c(32), opI64ShrU, opWrap, opLocalGet1, lenOf, callOp(1),
				i32c(0),
			)
		},
	}, filter.Options{"body_limit": 32})
	big := strings.Repeat("p", 1000)
	resp2 := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(big))}
	if res := filtertest.Run(readOnly, httptest.NewRequest(http.MethodGet, "/x", nil), resp2); res.Response.Deny {
		t.Fatalf("an oversize response denied: %+v", res.Response)
	}
	if got := resp2.Header.Get("X-Rstate"); got != "too_large" {
		t.Errorf("an oversize response reported state %q", got)
	}
	if got := resp2.Header.Get("X-Rlen"); got != "" {
		t.Errorf("the guest read %d bytes of an oversize response", len(got))
	}
	rest, _ := io.ReadAll(resp2.Body)
	if string(rest) != big {
		t.Errorf("the client would see %d bytes of %d", len(rest), len(big))
	}
}

// TestSetBodyIsBounded covers the other direction: a guest must not be
// able to hand back more bytes than the limit allows.
func TestSetBodyIsBounded(t *testing.T) {
	f := build(t, guestSpec{
		pages: 4,
		strs:  []string{"x-ok", "1"},
		code: func(o, l func(string) []byte) []byte {
			return cat(
				// 200 KiB from the guest's own memory, past any limit
				i32c(0), i32c(0), i32c(200<<10), callOp(6),
				i32c(0), o("x-ok"), l("x-ok"), o("1"), l("1"), callOp(1),
				i32c(0),
			)
		},
	}, filter.Options{"body_limit": 1024})
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("original"))
	if res := filtertest.Run(f, r, nil); res.Request.Deny {
		t.Fatalf("denied: %+v", res.Request)
	}
	if r.Header.Get("X-Ok") != "1" {
		t.Fatal("the guest did not run to the end")
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != "original" {
		t.Fatalf("an oversize set_body replaced the body with %d bytes", len(body))
	}
	if r.ContentLength != int64(len("original")) {
		t.Errorf("the content length became %d", r.ContentLength)
	}
}

// TestOptionEdges covers the option schema at its boundaries, which is
// where an operator finds out whether a number was accepted or silently
// clamped.
func TestOptionEdges(t *testing.T) {
	mod := writeModule(t, 1, false)
	good := []filter.Options{
		{"module": mod},
		{"module": mod, "timeout": "1ms"},
		{"module": mod, "timeout": "10s"},
		{"module": mod, "memory_limit_pages": 1},
		{"module": mod, "memory_limit_pages": 16384},
		{"module": mod, "instances": 1},
		{"module": mod, "body_limit": 0},
		{"module": mod, "body_limit": 16 << 20},
		{"module": mod, "engine": "interpreter"},
		{"module": mod, "on_error": "allow"},
		{"module": mod, "config": strings.Repeat("c", maxString)},
	}
	for i, opts := range good {
		f, err := filtertest.Build("wasm", "x", opts)
		if err != nil {
			t.Errorf("case %d (%v) was refused: %v", i, opts, err)
			continue
		}
		_ = f.(filter.Closer).Close()
	}
	bad := map[string]filter.Options{
		"timeout under a millisecond":  {"module": mod, "timeout": "999us"},
		"timeout past ten seconds":     {"module": mod, "timeout": "10s1ms"},
		"timeout that is not one":      {"module": mod, "timeout": "soon"},
		"negative pages":               {"module": mod, "memory_limit_pages": -1},
		"pages past the ceiling":       {"module": mod, "memory_limit_pages": 16385},
		"instances past the ceiling":   {"module": mod, "instances": 1025},
		"a negative body limit":        {"module": mod, "body_limit": -1},
		"a body limit past 16 MiB":     {"module": mod, "body_limit": 16<<20 + 1},
		"an unknown engine":            {"module": mod, "engine": "jit"},
		"config past 64 KiB":           {"module": mod, "config": strings.Repeat("c", maxString+1)},
		"a module that is a directory": {"module": t.TempDir()},
	}
	for name, opts := range bad {
		if f, err := filtertest.Build("wasm", "x", opts); err == nil {
			_ = f.(filter.Closer).Close()
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestModulesThatAreNotGuests covers the load path: a file that is not a
// module, and modules that are but do not implement the contract.
func TestModulesThatAreNotGuests(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	full := testModule(1, false)
	files := map[string]string{
		"empty":                    write("empty.wasm", nil),
		"the header alone":         write("header.wasm", []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}),
		"a wrong version":          write("version.wasm", []byte{0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00}),
		"text, not wasm":           write("text.wasm", []byte("(module)")),
		"truncated":                write("trunc.wasm", full[:len(full)/2]),
		"a flipped section length": write("flipped.wasm", flip(full, 9)),
	}
	for name, path := range files {
		if f, err := filtertest.Build("wasm", "x", filter.Options{"module": path}); err == nil {
			_ = f.(filter.Closer).Close()
			t.Errorf("%s was loaded as a guest", name)
		}
	}
	// Truncation at every length: none of them loads, none of them
	// panics, and the runtime is closed either way.
	for n := 0; n < len(full); n += 7 {
		p := write(fmt.Sprintf("t%d.wasm", n), full[:n])
		if f, err := filtertest.Build("wasm", "x", filter.Options{"module": p}); err == nil {
			_ = f.(filter.Closer).Close()
			t.Errorf("the first %d bytes of the module loaded", n)
		}
	}
	// A module that compiles but does not export what the ABI needs.
	noMemory := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x16, 0x01, 0x12, 'x', 'p', 'r', 'o', 'x', 'y', '_', 'a', 'b', 'i', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00, 0x00,
		0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x01, 0x0b,
	}
	p := write("nomem.wasm", noMemory)
	_, err := filtertest.Build("wasm", "x", filter.Options{"module": p})
	if err == nil {
		t.Fatal("a module without xproxy_alloc was loaded")
	}
	if !strings.Contains(err.Error(), "xproxy_alloc") {
		t.Errorf("the error does not name the missing export: %v", err)
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x40
	return out
}

// TestFilterLifecycle covers the pieces around the calls: the name, the
// status view, and a close that can happen twice and while instances
// are out.
func TestFilterLifecycle(t *testing.T) {
	f := build(t, guestSpec{
		strs: []string{"x-ok", "1"},
		code: func(o, l func(string) []byte) []byte {
			return cat(i32c(0), o("x-ok"), l("x-ok"), o("1"), l("1"), callOp(1), i32c(0))
		},
	}, filter.Options{"instances": 4})
	if f.Name() != "policy" {
		t.Errorf("name %q", f.Name())
	}
	for i := 0; i < 10; i++ {
		filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
	}
	st := f.(interface{ Status() Status }).Status()
	if st.Calls != 10 || st.Denies != 0 || st.Errors != 0 {
		t.Errorf("counters: %+v", st)
	}
	if st.Pooled == 0 {
		t.Error("no instance was pooled after ten calls")
	}
	c := f.(filter.Closer)
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Closing again is not an error, and a call after close fails
	// closed rather than panicking.
	_ = c.Close()
	res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), nil)
	if !res.Request.Deny {
		t.Error("a call after close was allowed through")
	}
}

// TestBufferBodyDirectly covers the helper's own edges, which the guest
// cannot reach: no body at all, http.NoBody, and a limit of zero.
func TestBufferBodyDirectly(t *testing.T) {
	st, rc := bufferBody(context.Background(), nil, 100)
	if st.tooLarge || len(st.data) != 0 || rc != nil {
		t.Errorf("a nil body: %+v %v", st, rc)
	}
	st, rc = bufferBody(context.Background(), http.NoBody, 100)
	if st.tooLarge || len(st.data) != 0 || rc != http.NoBody {
		t.Errorf("http.NoBody: %+v", st)
	}
	st, rc = bufferBody(context.Background(), io.NopCloser(strings.NewReader("abc")), 0)
	if !st.tooLarge {
		t.Error("a limit of zero did not report too large")
	}
	rest, _ := io.ReadAll(rc)
	if string(rest) != "abc" {
		t.Errorf("the restored stream is %q", rest)
	}
	st, rc = bufferBody(context.Background(), io.NopCloser(bytes.NewReader(nil)), 10)
	if st.tooLarge || len(st.data) != 0 {
		t.Errorf("an empty body: %+v", st)
	}
	if rest, _ := io.ReadAll(rc); len(rest) != 0 {
		t.Errorf("an empty body restored %d bytes", len(rest))
	}
}

// TestBodyReadHonorsCallTimeout proves that a transport read entered by a
// host function is interrupted by the guest deadline rather than retaining
// the request and its module until a longer server timeout expires.
func TestBodyReadHonorsCallTimeout(t *testing.T) {
	f := build(t, guestSpec{
		code: func(_, _ func(string) []byte) []byte {
			return cat(i32c(getRequestBody), i32c(0), i32c(0), callOp(0), opDrop, i32c(0))
		},
	}, filter.Options{"timeout": "20ms"})
	body := &blockingBody{closed: make(chan struct{})}
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Body = body
	done := make(chan filtertest.Result, 1)
	go func() { done <- filtertest.Run(f, r, nil) }()
	select {
	case res := <-done:
		if !res.Request.Deny {
			t.Fatalf("timed-out body read was allowed: %+v", res.Request)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("body read outlived the WASM call timeout")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("timeout did not close the body")
	}
	if got := f.(interface{ Status() Status }).Status().Timeouts; got != 1 {
		t.Fatalf("timeouts = %d, want 1", got)
	}
}

// TestEveryGetKind walks the whole read side of the ABI. Every kind a
// guest can ask for has to come back as itself or as nothing — never as
// another request's value, and never as a header the guest did not set.
func TestEveryGetKind(t *testing.T) {
	kinds := []struct {
		kind int64
		name string
		want string
	}{
		{getMethod, "x-k-method", "POST"},
		{getPath, "x-k-path", "/a/b"},
		{getHost, "x-k-host", "guest.example"},
		{getQuery, "x-k-query", "q=1&r=2"},
		{getClientIP, "x-k-ip", "198.51.100.7"},
		{getRoute, "x-k-route", "test"},
		{getRequestID, "x-k-rid", "test"},
		{getConfig, "x-k-config", "tenant=acme"},
		{getCountry, "x-k-country", ""},
		{getJA4, "x-k-ja4", ""},
		{getResponseStatus, "x-k-status", ""}, // no response in the request phase
		{99, "x-k-unknown", ""},               // a kind this ABI does not define
	}
	strs := []string{"hdr", "x-in", "logged"}
	for _, k := range kinds {
		strs = append(strs, k.name)
	}
	f := build(t, guestSpec{
		strs:   strs,
		locals: cat(uleb(1), uleb(1), []byte{i64}),
		code: func(o, l func(string) []byte) []byte {
			var out []byte
			for _, k := range kinds {
				out = cat(out,
					i32c(k.kind), i32c(0), i32c(0), callOp(0), opLocalSet0,
					i32c(0), o(k.name), l(k.name),
					opLocalGet0, i64c(32), opI64ShrU, opWrap, opLocalGet0, lenOf, callOp(1))
			}
			// A named request header, and the four log levels.
			out = cat(out,
				i32c(getRequestHeader), o("x-in"), l("x-in"), callOp(0), opLocalSet0,
				i32c(0), o("hdr"), l("hdr"), opLocalGet0, i64c(32), opI64ShrU, opWrap, opLocalGet0, lenOf, callOp(1))
			for level := int64(0); level < 4; level++ {
				out = cat(out, i32c(level), o("logged"), l("logged"), callOp(4))
			}
			return cat(out, i32c(0))
		},
	}, filter.Options{"config": "tenant=acme"})

	r := httptest.NewRequest(http.MethodPost, "http://guest.example/a/b?q=1&r=2", strings.NewReader("body"))
	r.Header.Set("X-In", "value")
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("denied: %+v", res.Request)
	}
	for _, k := range kinds {
		if got := r.Header.Get(k.name); got != k.want {
			t.Errorf("%s came back as %q, want %q", k.name, got, k.want)
		}
	}
	if got := r.Header.Get("hdr"); got != "value" {
		t.Errorf("a named request header came back as %q", got)
	}
}

// TestDenyHeadersOnAResponse covers the one target that has no header
// map yet: a guest denying in the response phase sets headers on the
// replacement response.
func TestDenyHeadersOnAResponse(t *testing.T) {
	f := build(t, guestSpec{
		strs: []string{"x-deny-hdr", "1", "wasm_resp", "x-late"},
		code: func(o, l func(string) []byte) []byte { return cat(i32c(0)) },
		respCode: func(o, l func(string) []byte) []byte {
			return cat(
				// A header on the response itself, then the deny.
				i32c(1), o("x-late"), l("x-late"), o("1"), l("1"), callOp(1),
				i32c(502), o("wasm_resp"), l("wasm_resp"), i32c(0), i32c(0), callOp(3),
				i32c(1),
			)
		},
	}, nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody}
	res := filtertest.Run(f, httptest.NewRequest(http.MethodGet, "/x", nil), resp)
	if !res.Response.Deny || res.Response.Status != 502 || res.Response.Reason != "wasm_resp" {
		t.Fatalf("response verdict: %+v", res.Response)
	}
	if resp.Header.Get("X-Late") != "1" {
		t.Errorf("the header the guest set is missing: %v", resp.Header)
	}
}
