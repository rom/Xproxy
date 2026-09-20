package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/originsig"
	"github.com/rom/xproxy/internal/upstream"
)

// OriginCheckResult is one endpoint's origin-lock probe.
type OriginCheckResult struct {
	Upstream       string `json:"upstream"`
	Endpoint       string `json:"endpoint"`
	UnsignedStatus int    `json:"unsigned_status,omitempty"`
	SignedStatus   int    `json:"signed_status,omitempty"`
	UnsignedError  string `json:"unsigned_error,omitempty"`
	SignedError    string `json:"signed_error,omitempty"`
	// Verdict is enforced, not_enforced, inconclusive or unreachable.
	Verdict string `json:"verdict"`
}

// OriginCheck probes the origins directly (not through the proxy) to verify
// that origin-lock is enforced: an unsigned request is refused while a
// validly signed one is accepted. It covers every upstream with an
// origin_signature, or just the named one. host overrides the Host header
// sent (default: the endpoint host); path is the request target (default
// "/"). Only upstreams that sign are probed; naming one without a signature
// is an error.
func (s *Server) OriginCheck(upstreamName, host, path string) ([]OriginCheckResult, error) {
	rt := s.rt.Load()
	if path == "" {
		path = "/"
	}
	names := make([]string, 0, len(rt.pools))
	if upstreamName != "" {
		p, ok := rt.pools[upstreamName]
		if !ok {
			return nil, fmt.Errorf("unknown upstream %q", upstreamName)
		}
		if rt.signers[upstreamName] == nil {
			return nil, fmt.Errorf("upstream %q has no origin_signature", upstreamName)
		}
		_ = p
		names = append(names, upstreamName)
	} else {
		for name := range rt.pools {
			if rt.signers[name] != nil {
				names = append(names, name)
			}
		}
		sort.Strings(names)
	}
	var out []OriginCheckResult
	for _, name := range names {
		pool, signer := rt.pools[name], rt.signers[name]
		for _, e := range pool.Endpoints() {
			out = append(out, s.originProbe(pool, signer, e.Address, host, path))
		}
	}
	return out, nil
}

// originProbe sends an unsigned and a signed request to one endpoint and
// judges whether the origin enforces the signature.
func (s *Server) originProbe(pool *upstream.Pool, signer *originsig.Signer, endpoint, host, path string) OriginCheckResult {
	res := OriginCheckResult{Upstream: pool.Name, Endpoint: endpoint}
	h := host
	if h == "" {
		if hp, _, err := net.SplitHostPort(endpoint); err == nil {
			h = hp
		} else {
			h = endpoint
		}
	}
	res.UnsignedStatus, res.UnsignedError = originStatus(s.originRequest(pool, nil, endpoint, h, path))
	res.SignedStatus, res.SignedError = originStatus(s.originRequest(pool, signer, endpoint, h, path))
	res.Verdict = originVerdict(res.UnsignedStatus, res.UnsignedError, res.SignedStatus, res.SignedError)
	return res
}

// originRequest sends one probe to endpoint over the pool's transport,
// signing it when signer is not nil, and returns the status or an error.
func (s *Server) originRequest(pool *upstream.Pool, signer *originsig.Signer, endpoint, host, path string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Build the target structurally: an operator-supplied path is never
	// spliced into a URL string, where "@" or "?" could retarget the probe.
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return 0, fmt.Errorf("path %q must start with / and carry no query or fragment", path)
	}
	target := &url.URL{Scheme: pool.Scheme, Host: endpoint, Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Host = host
	reqID := newRequestID()
	req.Header.Set("X-Request-Id", reqID)
	req.Header.Set("X-Real-Ip", "127.0.0.1")
	req.Header.Set("User-Agent", "xproxy-origin-check")
	if signer != nil {
		signer.Sign(req, time.Now(), "127.0.0.1", reqID, "")
	}
	resp, err := pool.RoundTripper().RoundTrip(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func originStatus(status int, err error) (int, string) {
	if err != nil {
		return 0, err.Error()
	}
	return status, ""
}

// originVerdict judges a probe pair. An origin that serves the unsigned
// request has not enforced the lock; one that refuses it but accepts the
// signed request enforces it; anything else is inconclusive or unreachable.
func originVerdict(unsigned int, unsignedErr string, signed int, signedErr string) string {
	switch {
	case unsignedErr != "" && signedErr != "":
		return "unreachable"
	case unsignedErr == "" && unsigned < 400:
		return "not_enforced"
	case signedErr == "" && signed < 400:
		return "enforced"
	default:
		return "inconclusive"
	}
}
