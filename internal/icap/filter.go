package icap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

// Filter returns a per-route filter over this service.
func (s *Service) Filter(rc *config.RouteICAP) filter.Filter {
	return &icapFilter{s: s, scanReq: rc.ScansRequests(), scanResp: rc.ScansResponses()}
}

type icapFilter struct {
	s        *Service
	scanReq  bool
	scanResp bool
}

func (f *icapFilter) Name() string { return "icap:" + f.s.cfg.Name }

func (f *icapFilter) Begin(ctx context.Context, info *filter.Info) filter.Instance {
	return &instance{f: f, ctx: ctx, info: info}
}

type instance struct {
	f     *icapFilter
	ctx   context.Context
	info  *filter.Info
	req   *http.Request // the request as sent upstream, for RESPMOD
	attrs []any
}

// readBody buffers a body up to the service limit. The second result is
// true when the body exceeded the limit.
func (in *instance) readBody(rc io.ReadCloser, declared int64) ([]byte, bool, error) {
	limit := in.f.s.cfg.MaxBody
	if rc == nil || rc == http.NoBody {
		return nil, false, nil
	}
	if declared > limit {
		return nil, true, nil
	}
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return nil, true, nil
	}
	return b, false, nil
}

func (in *instance) failure(err error, phase string) filter.Verdict {
	in.attrs = append(in.attrs, "icap_service", in.f.s.cfg.Name, "icap_error", err.Error())
	if in.f.s.cfg.Fail == "open" {
		in.f.s.Bypassed.Add(1)
		in.attrs = append(in.attrs, "icap_bypassed", true)
		return filter.Continue
	}
	return filter.Verdict{Deny: true, Status: http.StatusBadGateway, Reason: "icap", Detail: phase + "_unavailable", Headers: map[string]string{"Retry-After": "5"}}
}

func (in *instance) overLimit(phase string) filter.Verdict {
	if in.f.s.cfg.BodyLimitAction == "bypass" {
		in.f.s.Bypassed.Add(1)
		in.attrs = append(in.attrs, "icap_service", in.f.s.cfg.Name, "icap_bypassed", true)
		return filter.Continue
	}
	return filter.Verdict{Deny: true, Status: http.StatusRequestEntityTooLarge, Reason: "icap", Detail: phase + "_body_too_large"}
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	in.req = r
	if !in.f.scanReq {
		return filter.Continue
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, over, err := in.readBody(r.Body, r.ContentLength)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return filter.Verdict{Deny: true, Status: http.StatusRequestEntityTooLarge, Reason: "body_size"}
			}
			return filter.Verdict{Deny: true, Status: http.StatusBadRequest, Reason: "icap", Detail: "reading request body"}
		}
		if over {
			return in.overLimit("request")
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	v, err := in.f.s.Reqmod(in.ctx, r, body)
	if err != nil {
		return in.failure(err, "reqmod")
	}
	in.attrs = append(in.attrs, "icap_service", in.f.s.cfg.Name, "icap_verdict", v.Kind.String())
	switch v.Kind {
	case Replaced:
		return filter.Verdict{Deny: true, Status: v.Response.StatusCode, Reason: "icap", Detail: "blocked", Response: v.Response}
	case ModifiedRequest:
		// Apply the modified method, path and headers in place; the host
		// and scheme stay ours so the scanner cannot redirect upstream.
		r.Method = v.Request.Method
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery = v.Request.URL.Path, v.Request.URL.RawPath, v.Request.URL.RawQuery
		for k := range r.Header {
			if !protectedHeader(k) {
				r.Header.Del(k)
			}
		}
		for k, vs := range v.Request.Header {
			if !protectedHeader(k) {
				r.Header[k] = vs
			}
		}
		r.Body = v.Request.Body
		r.ContentLength = v.Request.ContentLength
	}
	return filter.Continue
}

// protectedHeader lists headers a scanner may not rewrite.
func protectedHeader(k string) bool {
	switch k {
	case "Host", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "X-Request-Id", "Authorization", "Cookie":
		return true
	}
	return false
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	if !in.f.scanResp {
		return filter.Continue
	}
	body, over, err := in.readBody(resp.Body, resp.ContentLength)
	if err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusBadGateway, Reason: "icap", Detail: "reading response body"}
	}
	if over {
		// The bytes were not consumed when the declared length was over the
		// limit; otherwise the body is gone and the choice was made above.
		return in.overLimit("response")
	}
	v, err := in.f.s.Respmod(in.ctx, in.req, resp, body)
	if err != nil {
		if in.f.s.cfg.Fail == "open" {
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
		return in.failure(err, "respmod")
	}
	in.attrs = append(in.attrs, "icap_service", in.f.s.cfg.Name, "icap_verdict", v.Kind.String())
	if v.Kind == ModifiedResponse {
		if v.Response.StatusCode >= 400 && resp.StatusCode < 400 {
			// A scanner turning a success into an error is a block.
			return filter.Verdict{Deny: true, Status: v.Response.StatusCode, Reason: "icap", Detail: "blocked", Response: v.Response}
		}
		resp.StatusCode = v.Response.StatusCode
		resp.Status = v.Response.Status
		resp.Header = v.Response.Header
		resp.Body = v.Response.Body
		resp.ContentLength = v.Response.ContentLength
		return filter.Continue
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", itoa(len(body)))
	return filter.Continue
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (in *instance) End() []any { return in.attrs }
