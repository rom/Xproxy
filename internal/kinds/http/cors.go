package http

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// compiledCORS is a route's Cross-Origin Resource Sharing policy.
type compiledCORS struct {
	any         bool // allow_origins is "*"
	exact       map[string]bool
	patterns    []string // wildcard host patterns, e.g. https://*.example.com
	methods     string   // Access-Control-Allow-Methods value
	reflectHdrs bool     // allow_headers is "*" or empty: reflect the request
	headers     string   // Access-Control-Allow-Headers value when fixed
	expose      string
	credentials bool
	maxAge      string
}

func newCORS(c *config.RouteCORS) *compiledCORS {
	cc := &compiledCORS{
		exact:       map[string]bool{},
		methods:     strings.Join(c.AllowMethods, ", "),
		expose:      strings.Join(c.ExposeHeaders, ", "),
		credentials: c.AllowCredentials,
		maxAge:      strconv.Itoa(int(c.MaxAge.D().Seconds())),
	}
	for _, o := range c.AllowOrigins {
		switch {
		case o == "*":
			cc.any = true
		case strings.Contains(o, "*"):
			cc.patterns = append(cc.patterns, o)
		default:
			cc.exact[o] = true
		}
	}
	if len(c.AllowHeaders) == 0 || (len(c.AllowHeaders) == 1 && c.AllowHeaders[0] == "*") {
		cc.reflectHdrs = true
	} else {
		cc.headers = strings.Join(c.AllowHeaders, ", ")
	}
	return cc
}

// allowedOrigin reports whether origin is permitted and returns the
// value to echo in Access-Control-Allow-Origin ("*" for the any policy
// without credentials, else the exact origin).
func (cc *compiledCORS) allowedOrigin(origin string) (string, bool) {
	if origin == "" {
		return "", false
	}
	if cc.any {
		// Validation refuses "*" with credentials; if that ever slipped
		// through, fail closed rather than reflect an arbitrary origin with
		// credentials, which would hand every site a credentialed read.
		if cc.credentials {
			return "", false
		}
		return "*", true
	}
	if cc.exact[origin] {
		return origin, true
	}
	for _, p := range cc.patterns {
		if matchOriginPattern(p, origin) {
			return origin, true
		}
	}
	return "", false
}

// matchOriginPattern matches an origin against a "scheme://*.suffix"
// pattern: the scheme must be equal and the host must end in the suffix
// after the wildcard label.
func matchOriginPattern(pattern, origin string) bool {
	ps, ph, ok := splitOrigin(pattern)
	if !ok {
		return false
	}
	os, oh, ok := splitOrigin(origin)
	if !ok || ps != os {
		return false
	}
	star := strings.IndexByte(ph, '*')
	if star < 0 {
		return ph == oh
	}
	prefix, suffix := ph[:star], ph[star+1:]
	if !strings.HasPrefix(oh, prefix) || !strings.HasSuffix(oh, suffix) {
		return false
	}
	// The wildcard stands for one or more host labels: not empty, and none
	// of the characters that would end the host part of an origin.
	mid := oh[len(prefix) : len(oh)-len(suffix)]
	return mid != "" && !strings.ContainsAny(mid, "/?#@\\:")
}

func splitOrigin(o string) (scheme, host string, ok bool) {
	i := strings.Index(o, "://")
	if i < 0 {
		return "", "", false
	}
	return o[:i], o[i+3:], true
}

// preflight answers a CORS preflight OPTIONS request. It returns true
// when it wrote a response (the request must not be routed further).
func (cc *compiledCORS) preflight(rw http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodOptions || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	origin := r.Header.Get("Origin")
	h := rw.Header()
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	allow, ok := cc.allowedOrigin(origin)
	if !ok {
		// Not an allowed origin: answer 204 without the CORS headers, so
		// the browser blocks it.
		rw.WriteHeader(http.StatusNoContent)
		return true
	}
	h.Set("Access-Control-Allow-Origin", allow)
	if cc.credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	h.Set("Access-Control-Allow-Methods", cc.methods)
	if cc.reflectHdrs {
		if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
			h.Set("Access-Control-Allow-Headers", req)
		}
	} else if cc.headers != "" {
		h.Set("Access-Control-Allow-Headers", cc.headers)
	}
	h.Set("Access-Control-Max-Age", cc.maxAge)
	h.Set("Content-Length", "0")
	rw.WriteHeader(http.StatusNoContent)
	return true
}

// apply adds the CORS response headers to an actual (non-preflight)
// cross-origin response.
func (cc *compiledCORS) apply(h http.Header, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	allow, ok := cc.allowedOrigin(origin)
	if !ok {
		return
	}
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Origin", allow)
	if cc.credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if cc.expose != "" {
		h.Set("Access-Control-Expose-Headers", cc.expose)
	}
}

// stripUpstreamCORS removes CORS response headers an upstream may have
// set, so the route's own policy (already written to the client's
// ResponseWriter) is the only one.
func stripUpstreamCORS(h http.Header) {
	h.Del("Access-Control-Allow-Origin")
	h.Del("Access-Control-Allow-Credentials")
	h.Del("Access-Control-Expose-Headers")
}
