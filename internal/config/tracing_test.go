package config

import (
	"strings"
	"testing"
)

func TestTracingValidation(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
%s
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - name: r
    upstream: app
`
	cfg, err := Parse([]byte(strings.Replace(base, "%s", "tracing: {otlp: {endpoint: https://otel.test:4318/v1/traces}}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	tr := cfg.Tracing
	if !tr.IsEnabled() || tr.Sample() != 100 || !tr.Propagates() || tr.TrustIncoming || tr.OTLP.Batch != 512 || tr.OTLP.Queue != 8192 || tr.OTLP.Interval.D().Seconds() != 5 || !tr.OTLP.Compresses() || tr.OTLP.ServiceName != "xproxy" {
		t.Fatalf("defaults %+v %+v", tr, tr.OTLP)
	}
	if c, err := Parse([]byte(strings.Replace(base, "%s", "tracing: {sample_percent: 10, propagate: false, trust_incoming: true}", 1))); err != nil || c.Tracing.Sample() != 10 || c.Tracing.Propagates() || !c.Tracing.TrustIncoming {
		t.Fatalf("explicit: %v %+v", err, c.Tracing)
	}
	bad := []struct{ snippet, want string }{
		{"tracing: {sample_percent: 101}", "sample_percent"},
		{"tracing: {otlp: {endpoint: http://otel.test/v1/traces}}", "https URL"},
		{"tracing: {otlp: {endpoint: https://otel.test/v1/traces, queue: -1}}", "otlp.queue"},
		{"tracing: {otlp: {endpoint: ''}}", "must be a URL"},
	}
	for _, c := range bad {
		_, err := Parse([]byte(strings.Replace(base, "%s", c.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.snippet, err, c.want)
		}
	}
}
