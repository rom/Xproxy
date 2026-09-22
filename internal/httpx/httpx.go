// Package httpx holds the HTTP message rules that more than one
// listener kind needs, so each one does not carry its own reading of
// the specification.
//
// There is one rule here so far, and it is the one worth sharing: which
// headers belong to a single connection rather than to the message, and
// therefore must not be passed on.
package httpx

import (
	"net/http"
	"strings"
)

// HopByHop are the headers that describe one connection rather than the
// message it carries (RFC 9110 section 7.6.1). Forwarding one hands the
// next hop a statement about a connection it is not on, which is how a
// request ends up framed one way here and another way there.
var HopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// StripHopByHop removes them in either direction, together with
// whatever the message's own Connection header nominates. A sender may
// name its own single-connection headers there, and those are exactly
// as wrong to forward as the fixed list.
func StripHopByHop(h http.Header) {
	for _, c := range h.Values("Connection") {
		for _, name := range strings.Split(c, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range HopByHop {
		h.Del(name)
	}
}
