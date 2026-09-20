package icap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// TestBypassKeepsWholeBody: body_limit_action bypass on a body without a
// declared length used to hand the upstream the stream from byte limit+2
// on; the bytes read while measuring are put back.
func TestBypassKeepsWholeBody(t *testing.T) {
	s := &Service{cfg: config.ICAPService{Name: "av", MaxBody: 8, BodyLimitAction: "bypass"}}
	in := &instance{f: &icapFilter{s: s, scanReq: true, scanResp: true}}
	payload := strings.Repeat("0123456789", 5)
	r := httptest.NewRequest("POST", "http://h.test/up", strings.NewReader(payload))
	r.ContentLength = -1 // chunked: the length is unknown up front
	if v := in.Request(r); v.Deny {
		t.Fatalf("bypass denied: %+v", v)
	}
	if got, _ := io.ReadAll(r.Body); string(got) != payload {
		t.Fatalf("request body after bypass: %q", got)
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(payload)), ContentLength: -1}
	if v := in.Response(resp); v.Deny {
		t.Fatalf("response bypass denied: %+v", v)
	}
	if got, _ := io.ReadAll(resp.Body); string(got) != payload {
		t.Fatalf("response body after bypass: %q", got)
	}
	// A declared length over the limit consumes nothing.
	r = httptest.NewRequest("POST", "http://h.test/up", strings.NewReader(payload))
	r.ContentLength = int64(len(payload))
	if v := in.Request(r); v.Deny {
		t.Fatalf("declared bypass denied: %+v", v)
	}
	if got, _ := io.ReadAll(r.Body); string(got) != payload {
		t.Fatalf("declared body after bypass: %q", got)
	}
}
