package httpx_test

import (
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/httpx"
)

// TestStripHopByHop removes the fixed list and whatever the message's
// own Connection header nominates, and leaves the rest of the message
// alone. Forwarding either kind hands the next hop a statement about a
// connection it is not on.
func TestStripHopByHop(t *testing.T) {
	h := http.Header{
		"Connection":        {"X-Custom, keep-alive"},
		"X-Custom":          {"1"},
		"Keep-Alive":        {"1"},
		"Transfer-Encoding": {"chunked"},
		"Accept":            {"*/*"},
	}
	httpx.StripHopByHop(h)
	if len(h) != 1 || h.Get("Accept") != "*/*" {
		t.Fatalf("after stripping: %v", h)
	}

	// An empty or whitespace-only nomination is skipped rather than
	// deleting a header named "".
	h = http.Header{"Connection": {" , close , "}, "Close": {"1"}, "Keep": {"1"}}
	httpx.StripHopByHop(h)
	if len(h) != 1 || h.Get("Keep") != "1" {
		t.Fatalf("after a padded list: %v", h)
	}

	// A message with no Connection header loses only the fixed list.
	h = http.Header{"Upgrade": {"websocket"}, "Accept": {"*/*"}}
	httpx.StripHopByHop(h)
	if len(h) != 1 || h.Get("Accept") != "*/*" {
		t.Fatalf("without a Connection header: %v", h)
	}
}
