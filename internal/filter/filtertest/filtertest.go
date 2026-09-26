// Package filtertest runs a filter against one request the way the data
// plane does, for tests of extensions.
package filtertest

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/rom/xproxy/internal/filter"
)

// Result is what one exchange produced.
type Result struct {
	Request  filter.Verdict // verdict of the request phase
	Response filter.Verdict // verdict of the response phase (zero when the request was denied or resp was nil)
	Attrs    []any          // attributes returned by End
}

// Build constructs a filter of a registered kind with options, as the
// data plane would, validating first.
func Build(kind, name string, opts filter.Options) (filter.Filter, error) {
	return BuildWithEnv(kind, name, opts, filter.Env{})
}

// BuildWithEnv is Build for a filter that uses something the data plane hands
// it: the event bus, or the imported threat lists. A zero Env gets the
// discarding logger Build uses, and a Log already set is kept.
func BuildWithEnv(kind, name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
	k, ok := filter.Lookup(kind)
	if !ok {
		return nil, filter.ErrUnknownKind
	}
	if err := k.Validate(opts); err != nil {
		return nil, err
	}
	if env.Log == nil {
		env.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return k.New(name, opts, env)
}

// Run begins an instance for r, runs the request phase, then the response
// phase with resp (when not nil and the request passed), and End.
func Run(f filter.Filter, r *http.Request, resp *http.Response) Result {
	return RunWithInfo(f, nil, r, resp)
}

// RunWithInfo is Run with the request description a filter sees, for
// the filters that decide on something outside the request itself: the
// client address, the fingerprint, the country. A nil info gets the
// default one.
func RunWithInfo(f filter.Filter, info *filter.Info, r *http.Request, resp *http.Response) Result {
	base := &filter.Info{RequestID: "test", ClientIP: netip.MustParseAddr("198.51.100.7"), Route: "test",
		Host: r.Host, Path: r.URL.Path, Method: r.Method, TLS: r.TLS != nil}
	if info != nil {
		if info.ClientIP.IsValid() {
			base.ClientIP = info.ClientIP
		}
		if info.Country != "" {
			base.Country = info.Country
		}
		if info.JA4 != "" {
			base.JA4 = info.JA4
		}
	}
	in := f.Begin(context.Background(), base)
	if in == nil {
		return Result{}
	}
	var res Result
	res.Request = in.Request(r)
	if !res.Request.Deny && resp != nil {
		res.Response = in.Response(resp)
	}
	res.Attrs = in.End()
	return res
}
