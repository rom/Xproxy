package http

import (
	"log/slog"
	"reflect"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/otlp"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/version"
)

// newTracer builds the tracer for a tracing section.
func newTracer(t *config.Tracing, log *slog.Logger) (*tracing.Tracer, error) {
	cfg := tracing.Config{SamplePercent: t.Sample(), Propagate: t.Propagates(), TrustIncoming: t.TrustIncoming}
	if o := t.OTLP; o != nil {
		cfg.Export = &otlp.Config{Endpoint: o.Endpoint, Timeout: o.Timeout.D(), Headers: o.Headers, CAFile: o.CAFile,
			ServiceName: o.ServiceName, Attributes: o.Attributes, Compress: o.Compresses(), Version: version.Version}
		cfg.Batch, cfg.Interval, cfg.Queue = o.Batch, o.Interval.D(), o.Queue
	}
	return tracing.New(cfg, log.With("component", "tracing"))
}

func sameTracing(a, b *config.Tracing) bool { return reflect.DeepEqual(a, b) }
