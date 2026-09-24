package wasm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func writeModule(t *testing.T, abi int64, withResponse bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "guest.wasm")
	if err := os.WriteFile(p, testModule(abi, withResponse), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGuest(t *testing.T) {
	mod := writeModule(t, 1, true)
	f, err := filtertest.Build("wasm", "policy", filter.Options{"module": mod, "config": "tenant=acme", "timeout": "200ms", "instances": 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.(filter.Closer).Close() })

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{"X-Hide": {"secret"}, "X-Keep": {"1"}}}
	res := filtertest.Run(f, r, resp)
	if res.Request.Deny || res.Response.Deny {
		t.Fatalf("plain request denied: %+v %+v", res.Request, res.Response)
	}
	if r.Header.Get("X-Wasm") != "1" || r.Header.Get("X-Cfg") != "hello" {
		t.Fatalf("headers not set: %v", r.Header)
	}
	if resp.Header.Get("X-Hide") != "" || resp.Header.Get("X-Keep") != "1" {
		t.Fatalf("response header ops: %v", resp.Header)
	}
	if len(res.Attrs) != 2 || res.Attrs[0] != "wasm_wasm_seen" || res.Attrs[1] != "1" {
		t.Fatalf("attrs: %v", res.Attrs)
	}
	// Deny from the request phase with status, reason and detail.
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Block", "yes")
	res = filtertest.Run(f, r, nil)
	if !res.Request.Deny || res.Request.Status != 451 || res.Request.Reason != "wasm_block" || res.Request.Detail != "header" {
		t.Fatalf("deny: %+v", res.Request)
	}
	// Deny from the response phase.
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	res = filtertest.Run(f, r, &http.Response{StatusCode: 500, Header: http.Header{}})
	if !res.Response.Deny || res.Response.Status != 502 || res.Response.Reason != "wasm_resp" {
		t.Fatalf("response deny: %+v", res.Response)
	}
	// A guest that never returns hits the timeout and fails closed; the
	// filter keeps working afterwards with a fresh instance.
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Slow", "1")
	res = filtertest.Run(f, r, nil)
	if !res.Request.Deny || res.Request.Status != 500 || res.Request.Detail != "guest_error" {
		t.Fatalf("timeout: %+v", res.Request)
	}
	r = httptest.NewRequest(http.MethodGet, "/again", nil)
	if res = filtertest.Run(f, r, nil); res.Request.Deny || r.Header.Get("X-Wasm") != "1" {
		t.Fatalf("after timeout: %+v", res.Request)
	}
	st := f.(*wasmFilter).Status()
	if st.Calls < 6 || st.Denies != 2 || st.Timeouts != 1 || st.Errors != 0 || st.Module != mod {
		t.Fatalf("status: %+v", st)
	}
	// on_error: allow lets the request through and labels it.
	fa, err := filtertest.Build("wasm", "lenient", filter.Options{"module": mod, "timeout": "50ms", "on_error": "allow"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fa.(filter.Closer).Close() })
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Slow", "1")
	res = filtertest.Run(fa, r, nil)
	if res.Request.Deny || len(res.Attrs) != 2 || res.Attrs[0] != "wasm_error" {
		t.Fatalf("on_error allow: %+v %v", res.Request, res.Attrs)
	}
	// Without an on_response export the response phase is a no-op.
	fr, err := filtertest.Build("wasm", "reqonly", filter.Options{"module": writeModule(t, 1, false)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.(filter.Closer).Close() })
	resp = &http.Response{StatusCode: 500, Header: http.Header{"X-Hide": {"1"}}}
	if res = filtertest.Run(fr, httptest.NewRequest(http.MethodGet, "/", nil), resp); res.Response.Deny || resp.Header.Get("X-Hide") != "1" {
		t.Fatal("response phase ran without an export")
	}
}

func TestAllocatorExhaustionFailsClosed(t *testing.T) {
	mod := writeModule(t, 1, false)
	f, err := filtertest.Build("wasm", "policy", filter.Options{"module": mod, "timeout": "200ms", "instances": 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.(filter.Closer).Close() })

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Block", strings.Repeat("x", 60_000))
		res := filtertest.Run(f, r, nil)
		if !res.Request.Deny {
			t.Fatalf("request %d allowed after allocator exhaustion: %+v", i+1, res.Request)
		}
		if i == 0 && res.Request.Status != 451 {
			t.Fatalf("first request did not reach guest policy: %+v", res.Request)
		}
		if i == 1 && (res.Request.Status != 500 || res.Request.Detail != "guest_error") {
			t.Fatalf("allocator exhaustion did not fail closed: %+v", res.Request)
		}
	}

	st := f.(*wasmFilter).Status()
	if st.Errors != 1 || st.Pooled != 0 {
		t.Fatalf("exhausted instance was not discarded: %+v", st)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		opts filter.Options
		want string
	}{
		{"no module", filter.Options{}, "module is required"},
		{"relative", filter.Options{"module": "x.wasm"}, "absolute path"},
		{"missing", filter.Options{"module": filepath.Join(dir, "nope.wasm")}, "module:"},
		{"abi", filter.Options{"module": writeModule(t, 2, false)}, "ABI version 2"},
		{"timeout", filter.Options{"module": writeModule(t, 1, false), "timeout": "1h"}, "timeout"},
		{"pages", filter.Options{"module": writeModule(t, 1, false), "memory_limit_pages": 1 << 20}, "memory_limit_pages"},
		{"instances", filter.Options{"module": writeModule(t, 1, false), "instances": -1}, "instances"},
		{"on_error", filter.Options{"module": writeModule(t, 1, false), "on_error": "retry"}, "on_error"},
		{"unknown option", filter.Options{"module": writeModule(t, 1, false), "bogus": 1}, "bogus"},
	}
	garbage := filepath.Join(dir, "garbage.wasm")
	_ = os.WriteFile(garbage, []byte("not wasm"), 0o600)
	cases = append(cases, struct {
		name string
		opts filter.Options
		want string
	}{"garbage", filter.Options{"module": garbage}, "compile"})
	for _, tc := range cases {
		_, err := filtertest.Build("wasm", "x", tc.opts)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v want %q", tc.name, err, tc.want)
		}
	}
}

// TestBodies reads, echoes and replaces bodies within the limit and
// leaves a body over the limit untouched.
func TestBodies(t *testing.T) {
	mod := writeModule(t, 1, true)
	f, err := filtertest.Build("wasm", "bodies", filter.Options{"module": mod, "body_limit": 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.(filter.Closer).Close() })
	// Read and echo back: the upstream sees the same bytes and the marker.
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("hello body"))
	r.Header.Set("X-Body", "1")
	res := filtertest.Run(f, r, nil)
	got, _ := io.ReadAll(r.Body)
	if res.Request.Deny || string(got) != "hello body" || r.Header.Get("X-Body-Seen") != "1" || r.Header.Get("X-Body-State") != "ok" || r.ContentLength != 10 {
		t.Fatalf("echo: %+v body=%q hdr=%v len=%d", res.Request, got, r.Header, r.ContentLength)
	}
	// Over the limit: nothing exposed, the stream passes through whole.
	r = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("z", 40)))
	r.Header.Set("X-Body", "1")
	res = filtertest.Run(f, r, nil)
	got, _ = io.ReadAll(r.Body)
	if res.Request.Deny || len(got) != 40 || r.Header.Get("X-Body-Seen") != "" || r.Header.Get("X-Body-State") != "too_large" {
		t.Fatalf("too large: %+v body=%d hdr=%v", res.Request, len(got), r.Header)
	}
	// Replace the request body.
	r = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("original"))
	r.Header.Set("X-Swap", "1")
	res = filtertest.Run(f, r, nil)
	got, _ = io.ReadAll(r.Body)
	if res.Request.Deny || string(got) != "swapped" || r.ContentLength != 7 || r.Header.Get("Content-Length") != "7" {
		t.Fatalf("swap: %+v body=%q", res.Request, got)
	}
	// Replace the response body.
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Resp-Swap", "1")
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(strings.NewReader("upstream"))}
	res = filtertest.Run(f, r, resp)
	got, _ = io.ReadAll(resp.Body)
	if res.Response.Deny || string(got) != "resp-swapped" || resp.ContentLength != 12 || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("response swap: %+v body=%q %v", res.Response, got, resp.Header)
	}
	// Body access disabled: the state says so and set_body is a no-op.
	fd, err := filtertest.Build("wasm", "nobody", filter.Options{"module": mod, "body_limit": 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fd.(filter.Closer).Close() })
	r = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("keep"))
	r.Header.Set("X-Body", "1")
	r.Header.Set("X-Swap", "1")
	filtertest.Run(fd, r, nil)
	got, _ = io.ReadAll(r.Body)
	if string(got) != "keep" || r.Header.Get("X-Body-State") != "disabled" || r.Header.Get("X-Body-Seen") != "" {
		t.Fatalf("disabled: %q %v", got, r.Header)
	}
	if _, err := filtertest.Build("wasm", "x", filter.Options{"module": mod, "body_limit": 1 << 30}); err == nil || !strings.Contains(err.Error(), "body_limit") {
		t.Fatalf("limit bound: %v", err)
	}
}
