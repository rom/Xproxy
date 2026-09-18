package logging

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// multiHandler fans a record out to several handlers.
type multiHandler []slog.Handler

func (m multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, rec slog.Record) error {
	var first error
	for _, h := range m {
		if !h.Enabled(ctx, rec.Level) {
			continue
		}
		if err := h.Handle(ctx, rec.Clone()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(name)
	}
	return out
}

// lineSink receives one rendered JSON line per record together with its
// level and stream name. Journald and syslog implement it.
type lineSink interface {
	emit(level slog.Level, stream string, line []byte, rec slog.Record)
}

// lineHandler renders records to JSON with the standard handler and hands
// the line to a sink. A shared, locked buffer keeps the renderer allocation
// free of per record buffers; handlers derived with WithAttrs share it.
type lineHandler struct {
	shared *lineShared
	inner  slog.Handler
	stream string
	sink   lineSink
	level  slog.Level
}

type lineShared struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newLineHandler(sink lineSink, level slog.Level) *lineHandler {
	sh := &lineShared{}
	return &lineHandler{
		shared: sh,
		inner:  slog.NewJSONHandler(&sh.buf, &slog.HandlerOptions{Level: level}),
		sink:   sink,
		level:  level,
	}
}

func (h *lineHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *lineHandler) Handle(ctx context.Context, rec slog.Record) error {
	h.shared.mu.Lock()
	h.shared.buf.Reset()
	err := h.inner.Handle(ctx, rec)
	line := make([]byte, h.shared.buf.Len())
	copy(line, h.shared.buf.Bytes())
	h.shared.mu.Unlock()
	if err != nil {
		return err
	}
	h.sink.emit(rec.Level, h.stream, bytes.TrimRight(line, "\n"), rec)
	return nil
}

func (h *lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.inner = h.inner.WithAttrs(attrs)
	for _, a := range attrs {
		if a.Key == "stream" {
			nh.stream = a.Value.String()
		}
	}
	return &nh
}

func (h *lineHandler) WithGroup(name string) slog.Handler {
	nh := *h
	nh.inner = h.inner.WithGroup(name)
	return &nh
}

// dropCounter counts messages a sink could not deliver.
type dropCounter struct{ n atomic.Uint64 }

func (d *dropCounter) inc()         { d.n.Add(1) }
func (d *dropCounter) Load() uint64 { return d.n.Load() }
func syslogSeverity(l slog.Level) int { // RFC 5424 severities
	switch {
	case l >= slog.LevelError:
		return 3
	case l >= slog.LevelWarn:
		return 4
	case l >= slog.LevelInfo:
		return 6
	default:
		return 7
	}
}
