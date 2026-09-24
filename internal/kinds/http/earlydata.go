package http

import "net/http"

// Early data, RFC 8470.
//
// TLS 1.3 lets a client send its first request in the handshake, before
// the server has said anything. That saves a round trip and gives up the
// one guarantee a handshake provided: an attacker who captured those bytes
// can send them again, to this server or another, and the server cannot
// tell the copy from the original. For a GET that is a repeated read; for
// a POST it is a second order, a second transfer, a second anything.
//
// RFC 8470 is how the two halves say so across a proxy: the request
// carries `Early-Data: 1` when it arrived on early data and has not yet
// been confirmed, and a server that cannot decide whether replaying it is
// safe answers 425 Too Early, which tells the client to send it again on
// the finished connection.
//
// Go's TLS server does not accept early data, so the header only ever
// arrives from a terminator in front -- and only from that terminator is
// it worth anything. A client's own `Early-Data: 1` says nothing about how
// its request arrived, so it is removed before the backend sees it
// (see the director), and the decision below reads it only from a peer
// inside trusted_proxies.

// earlyDataPolicy values.
const (
	earlyDataSafeMethods = "safe_methods"
	earlyDataAllow       = "allow"
	earlyDataReject      = "reject"
)

// earlyData reports whether a request arrived as unconfirmed early data,
// as far as this proxy can know: the header, from a peer whose word for it
// counts.
func earlyData(r *http.Request, trustedPeer bool) bool {
	return trustedPeer && r.Header.Get("Early-Data") == "1"
}

// replaySafe is RFC 9110's safe methods: the ones whose repetition is by
// definition without effect on the origin. Everything else is refused on
// early data under the default policy, because this proxy cannot know what
// a second POST would do and the backend is not the one being asked.
func replaySafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// tooEarly decides whether this request must wait for the handshake to
// finish. The policy is per route, because whether a replay matters is a
// property of what the route does.
func tooEarly(policy, method string) bool {
	switch policy {
	case earlyDataAllow:
		return false
	case earlyDataReject:
		return true
	default:
		return !replaySafe(method)
	}
}
