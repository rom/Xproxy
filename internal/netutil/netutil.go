// Package netutil contains small, security sensitive helpers shared by the
// data plane: client IP derivation, path cleaning and host normalisation.
package netutil

import (
	"crypto/tls"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
)

// ParsePrefixes parses CIDR strings that have already been validated.
func ParsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// Contains reports whether addr is inside any prefix.
func Contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RemoteAddr extracts the peer address from a request.
func RemoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// ClientIP derives the client address. When the direct peer is inside
// trusted, the right-most untrusted entry of X-Forwarded-For is used, which
// is the only entry an attacker behind a trusted proxy cannot forge. When the
// peer is not trusted the header is ignored entirely.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := RemoteAddr(r)
	if len(trusted) == 0 || !Contains(trusted, peer) {
		return peer
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return peer
	}
	// Walk from the right; skip trusted hops.
	for i := len(xff) - 1; i >= 0; i-- {
		parts := strings.Split(xff[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			s := strings.TrimSpace(parts[j])
			if s == "" {
				continue
			}
			a, err := netip.ParseAddr(strings.Trim(s, "[]"))
			if err != nil {
				// A malformed hop means the chain cannot be trusted; fall
				// back to the peer rather than guessing.
				return peer
			}
			// A zone ("fe80::1%eth0") would make the address miss every
			// prefix match and key its own ban and rate-limit buckets.
			a = a.Unmap().WithZone("")
			if Contains(trusted, a) {
				continue
			}
			return a
		}
	}
	return peer
}

// CleanPath canonicalises a request path for routing: it resolves dot
// segments, collapses duplicate slashes and guarantees a leading slash. The
// original path is left untouched on the request; only routing decisions use
// the cleaned form, so that "/admin/../public" cannot bypass a route policy.
func CleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// Host normalises a Host header: lower-case, port removed, trailing dot
// removed. Returns "" for hosts that are not plausible DNS names or IP
// literals.
func Host(h string) string {
	if h == "" {
		return ""
	}
	// Reject non-ASCII before folding, not after. Unicode's simple
	// lower-case mapping sends U+0130 (Turkish dotted capital I) to
	// "i" and U+212A (Kelvin sign) to "k", so "\u0130nternal.test"
	// and "\u212aeys.example.com" would fold into names made only of
	// ASCII and pass the byte check below — a second spelling for a
	// host, routed by the folded name while the upstream reads the
	// one the client sent. An internationalised name travels as
	// punycode, which is ASCII already.
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return ""
		}
	}
	if strings.HasPrefix(h, "[") {
		// IPv6 literal: after the bracket only an optional ":port" may
		// follow, so "[::1]junk" cannot route as "[::1]" while the upstream
		// sees the whole value.
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return ""
		}
		if rest := h[end+1:]; rest != "" {
			if len(rest) < 2 || rest[0] != ':' || strings.Trim(rest[1:], "0123456789") != "" {
				return ""
			}
		}
		h = h[:end+1]
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 {
		// Only a numeric port may follow the name. Stripping whatever
		// came after the last colon would give "example.com:https" and
		// "example.com:" the routing key of "example.com", which is
		// the same second-spelling problem the bracketed branch above
		// refuses.
		if port := h[i+1:]; port == "" || strings.Trim(port, "0123456789") != "" {
			return ""
		}
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if len(h) > 253 {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		// A bracketed literal must be exactly one IPv6 address: nothing
		// else may carry ':' or brackets, so "host:443:x" cannot slip past
		// the exact-host table by stripping only its last port.
		if !strings.HasSuffix(h, "]") {
			return ""
		}
		if ip, err := netip.ParseAddr(h[1 : len(h)-1]); err != nil || !ip.Is6() {
			return ""
		}
		return h
	}
	if !labelsNonEmpty(h) {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		if !ok {
			return ""
		}
	}
	return h
}

// labelsNonEmpty reports a name whose every label carries at least one
// byte.
//
// One host must have one spelling. A single trailing root dot is the
// conventional absolute form and is stripped before this is called;
// every other empty label ("a..b", ".a.b", "a.b..") is not a host name.
// Admitting one would hand the same host a second routing key: it
// misses the exact table of its own route and falls through to the
// catch-all, where a deployment puts its permissive default, so the
// route's access lists, authentication filters, WAF profile, rate
// limits and policy would all be skipped by a client that merely typed
// an extra dot.
func labelsNonEmpty(name string) bool {
	if name == "" {
		return true // the caller decides what an empty name means
	}
	if name[0] == '.' || name[len(name)-1] == '.' {
		return false
	}
	return !strings.Contains(name, "..")
}

// MediaType returns the lower-cased media type of a Content-Type or
// Content-Disposition style header value, without its parameters.
//
// mime.ParseMediaType is stricter than the servers behind the proxy: a
// duplicate parameter name with two values ("application/json;
// charset=utf-8; charset=ascii"), junk after the subtype
// ("application/json/x") or a bare parameter ("application/json;q") make
// it return an empty type and an error, while the npm content-type
// parser, Jakarta, werkzeug and PHP all take the type and read the body.
// A consumer that threw the type away on the error therefore skipped its
// whole policy for the price of one stray character, so every one of
// them asks here instead and falls back to the token before the first
// semicolon.
func MediaType(value string) string {
	if mt, _, err := mime.ParseMediaType(value); err == nil && mt != "" {
		return mt
	}
	return strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
}

// AddrOf is the address part of a "host:port", or the zero Addr when
// there is not one. Listener kinds key bans, rate limits and policy on
// it, so a value that fails to parse has to be invalid rather than
// something that compares equal to another client's.
//
// The v4-mapped form is unmapped, so ::ffff:198.51.100.9 and
// 198.51.100.9 are the one client they are. A zone is kept: fe80::1%eth0
// and fe80::1%eth1 are different interfaces, and dropping the zone would
// put two clients in one bucket.
func AddrOf(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// PeerAddr is the address half of a net.Addr, or the zero Addr for a
// nil one or a form that carries no address (a Unix socket). It is
// AddrOf for callers holding the connection rather than a string.
func PeerAddr(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return AddrOf(a.String())
}

// TLSConn is the TLS connection c is, or carries underneath a wrapper.
//
// A plain `c.(*tls.Conn)` is the obvious spelling and it is wrong as soon as
// anything wraps the connection -- the pcapng capture's tap does, and so would a
// counter or a rate limiter. Go cannot forward a type assertion through a
// wrapper, so a wrapper exposes `Unwrap() net.Conn` and this follows it. A kind
// asking "is my client encrypted" has to go through here, or it will read a
// plaintext answer on a connection that is in fact TLS.
func TLSConn(c net.Conn) (*tls.Conn, bool) {
	for range 8 { // a bound rather than a loop, in case a wrapper unwraps to itself
		if c == nil {
			return nil, false
		}
		if tc, ok := c.(*tls.Conn); ok {
			return tc, true
		}
		u, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			return nil, false
		}
		c = u.Unwrap()
	}
	return nil, false
}
