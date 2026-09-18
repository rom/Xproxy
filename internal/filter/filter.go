// Package filter defines the per-route middleware interface of xproxy.
//
// A Filter is configured once per runtime generation. For every request on
// a route that uses it, Begin returns an Instance that sees the request,
// optionally the response, and is closed when the exchange ends. Instances
// carry per request state (a WAF transaction, a scanner session); Filters
// carry shared state (compiled rules, connection pools).
//
// The interface is deliberately small. It is proven by the built-in
// filters (WAF in this phase, ICAP and JWT in later phases) before it is
// declared stable for external middleware in 1.0 (docs/AMR.md, AMR-013).
package filter

import (
	"context"
	"net/http"
	"net/netip"
)

// Info describes the request to a filter.
type Info struct {
	RequestID string
	ClientIP  netip.Addr
	Route     string
	Host      string
	Path      string
	Method    string
	TLS       bool
	// Country is the ISO code from the geoip database, or "" when there
	// is no database or the address is unknown.
	Country string
	// JA3 and JA4 are the TLS client fingerprints of the connection, or
	// "" for plaintext listeners.
	JA3 string
	JA4 string
	// ALPN is the protocol list the client offered in its ClientHello.
	ALPN []string
	// ChallengeVerified is true when the client carries a valid browser
	// challenge cookie (false when no challenge is configured).
	ChallengeVerified bool
}

// Verdict is a filter decision.
type Verdict struct {
	// Deny stops the request with Status. Reason is the security log
	// reason (for example "waf"); Detail is free text for the log.
	Deny   bool
	Status int
	Reason string
	Detail string
	// Attrs are extra structured attributes for the security log.
	Attrs []any
	// Headers are set on the deny response (for example WWW-Authenticate).
	Headers map[string]string
	// Response, when set on a deny, is sent to the client as is (status,
	// headers and a bounded body), for example a scanner's block page.
	Response *http.Response
	// Challenge asks the data plane to serve the browser challenge instead
	// of the status page, when a challenge is configured and the client is
	// not yet verified; otherwise the verdict is a plain deny.
	Challenge bool
}

// Continue is the verdict that lets a request proceed.
var Continue = Verdict{}

// Filter creates per request instances.
type Filter interface {
	Name() string
	Begin(ctx context.Context, info *Info) Instance
}

// Instance handles one request. Response may be nil for request-only
// filters (declare it and return Continue). End is always called.
type Instance interface {
	// Request inspects and may modify r (including replacing r.Body with a
	// buffered copy). It runs after limits and before the route action.
	Request(r *http.Request) Verdict
	// Response inspects and may modify resp before it reaches the client.
	Response(resp *http.Response) Verdict
	// End is called when the exchange finishes; it returns attributes for
	// the access log (for example matched rule identifiers) or nil.
	End() []any
}

// Chain runs several filters in order.
type Chain []Filter

// Begin creates instances for all filters.
func (c Chain) Begin(ctx context.Context, info *Info) Instances {
	if len(c) == 0 {
		return nil
	}
	out := make(Instances, 0, len(c))
	for _, f := range c {
		if in := f.Begin(ctx, info); in != nil {
			out = append(out, in)
		}
	}
	return out
}

// Instances is the per request view of a chain.
type Instances []Instance

// Request runs every instance until one denies.
func (is Instances) Request(r *http.Request) Verdict {
	for _, in := range is {
		if v := in.Request(r); v.Deny {
			return v
		}
	}
	return Continue
}

// Response runs every instance until one denies.
func (is Instances) Response(resp *http.Response) Verdict {
	for _, in := range is {
		if v := in.Response(resp); v.Deny {
			return v
		}
	}
	return Continue
}

// End closes every instance and concatenates their log attributes.
func (is Instances) End() []any {
	var out []any
	for _, in := range is {
		out = append(out, in.End()...)
	}
	return out
}
