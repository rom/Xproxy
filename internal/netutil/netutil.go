// Package netutil contains small, security sensitive helpers shared by the
// data plane: client IP derivation, path cleaning and host normalisation.
package netutil

import (
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
