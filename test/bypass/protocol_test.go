package bypass

import (
	"strings"
	"testing"
)

// TestProtocolAndLimits tries the request framing, header and size
// tricks that get past parsers or exhaust the proxy. Each must be
// refused before the backend, or (an accepted case) behave as the
// product documents.
func TestProtocolAndLimits(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	long := strings.Repeat("a", 2000)
	bigHdr := strings.Repeat("x", 9000)
	cases := []struct {
		name string
		text string
		want []int // acceptable statuses; 0 means the connection was closed
		// resolved marks framing the Go server normalises to a single
		// unambiguous request rather than rejecting: no desync reaches
		// the origin, so serving it is safe and the backend may see it.
		resolved bool
	}{
		// The Go server drops Content-Length when Transfer-Encoding is
		// present (RFC 9112), so the body is the empty chunked one and
		// the origin sees one unambiguous request; no smuggling desync.
		{"content-length with chunked (resolved to chunked)", "POST /search HTTP/1.1\r\nHost: app.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", []int{200}, true},
		{"two content-length headers", "POST /search HTTP/1.1\r\nHost: app.test\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd", []int{400, 0}, false},
		{"space before the header colon", "GET /x HTTP/1.1\r\nHost : app.test\r\n\r\n", []int{400, 0}, false},
		{"missing host header", "GET /x HTTP/1.1\r\n\r\n", []int{400, 0}, false},
		// Go accepts a bare LF as a line terminator and re-emits canonical
		// CRLF upstream, so the origin never sees the split line.
		{"bare LF line endings (canonicalised)", "GET /x HTTP/1.1\nHost: app.test\n\n", []int{200}, true},
		{"URI over the length limit", "GET /" + long + " HTTP/1.1\r\nHost: app.test\r\n\r\n", []int{414, 400, 0}, false},
		{"header block over the limit", "GET /x HTTP/1.1\r\nHost: app.test\r\nX-Big: " + bigHdr + "\r\n\r\n", []int{431, 400, 0}, false},
		{"NUL byte in the target", "GET /x\x00y HTTP/1.1\r\nHost: app.test\r\n\r\n", []int{400, 0}, false},
		{"CR in a header value", "GET /x HTTP/1.1\r\nHost: app.test\r\nX-Y: a\rb\r\n\r\n", []int{400, 0}, false},
	}
	for _, c := range cases {
		before := h.backend.hits.Load()
		status := h.raw(c.text)
		ok := false
		for _, w := range c.want {
			if status == w {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: status %d, want one of %v", c.name, status, c.want)
		}
		if !c.resolved && h.backend.hits.Load() != before {
			t.Errorf("%s: the backend saw the request", c.name)
		}
	}
	// A body over the configured limit is refused with 413.
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("POST", "/search", "198.51.100.60", strings.Repeat("a", 70000), "Content-Type", "text/plain"))
	if status != 413 {
		t.Errorf("oversize body: status %d, want 413", status)
	}
	h.denied("oversize body", before, status, 413)
}
