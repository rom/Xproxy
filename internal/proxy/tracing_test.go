package proxy

import (
	"fmt"
	"strings"
	"testing"
)

func TestTracingPropagation(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
tracing: {sample_percent: 100}
upstreams:
  - name: app
    endpoints: [{address: %q}]
routes:
  - name: web
    upstream: app
`, a.addr())
	s, url := startServer(t, yaml)
	// A new trace: the upstream receives a traceparent naming our span.
	get(t, url+"/x")
	tp := a.last.Load().Header.Get("Traceparent")
	if !strings.HasPrefix(tp, "00-") || !strings.HasSuffix(tp, "-01") || len(tp) != 55 {
		t.Fatalf("traceparent to upstream: %q", tp)
	}
	// An incoming context is continued: same trace id, our span as parent,
	// tracestate passed through, the client's sampled flag not trusted.
	get(t, url+"/x", "Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", "Tracestate", "vendor=1")
	tp = a.last.Load().Header.Get("Traceparent")
	if !strings.HasPrefix(tp, "00-4bf92f3577b34da6a3ce929d0e0e4736-") || strings.Contains(tp, "00f067aa0ba902b7") || !strings.HasSuffix(tp, "-01") {
		t.Fatalf("continued traceparent: %q", tp)
	}
	if a.last.Load().Header.Get("Tracestate") != "vendor=1" {
		t.Fatalf("tracestate: %q", a.last.Load().Header.Get("Tracestate"))
	}
	if st := s.Tracing(); st == nil || st.Started != 2 || st.Sampled != 2 || st.Endpoint != "" {
		t.Fatalf("status %+v", st)
	}
	// Propagation off: the client's header is stripped, nothing added.
	cfg := mustParse(t, yaml)
	off := false
	cfg.Tracing.Propagate = &off
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	get(t, url+"/x", "Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if h := a.last.Load().Header; h.Get("Traceparent") != "" || h.Get("Tracestate") != "" {
		t.Fatalf("headers with propagation off: %v", h)
	}
	// Tracing removed on reload: no header, status nil.
	cfg = mustParse(t, yaml)
	cfg.Tracing = nil
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	get(t, url+"/x")
	if a.last.Load().Header.Get("Traceparent") != "" || s.Tracing() != nil {
		t.Fatal("tracing survived removal")
	}
}
