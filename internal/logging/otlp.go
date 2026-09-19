package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/otlp"
)

// otlpSink ships log records to an OpenTelemetry collector as OTLP/HTTP
// JSON. Records queue without blocking the request path; a full queue
// drops and counts; a batching goroutine pushes by size and interval.
type otlpSink struct {
	client   *otlp.Client
	batch    int
	interval time.Duration
	queue    chan otlpRecord
	stop     chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
	log      *slog.Logger

	sent, dropped, pushes, failed atomic.Uint64
	mu                            sync.Mutex
	lastErr                       string
	lastSent                      time.Time
}

type otlpRecord struct {
	Time           string     `json:"timeUnixNano"`
	ObservedTime   string     `json:"observedTimeUnixNano"`
	SeverityNumber int        `json:"severityNumber"`
	SeverityText   string     `json:"severityText"`
	Body           otlp.Value `json:"body"`
	Attributes     []otlp.KV  `json:"attributes,omitempty"`
	TraceID        string     `json:"traceId,omitempty"`
	SpanID         string     `json:"spanId,omitempty"`
}

// OTLPStatus is the management view of the log exporter.
type OTLPStatus struct {
	Endpoint  string    `json:"endpoint"`
	Sent      uint64    `json:"records_sent"`
	Dropped   uint64    `json:"records_dropped"`
	Pushes    uint64    `json:"pushes"`
	Failed    uint64    `json:"pushes_failed"`
	Queued    int       `json:"queued"`
	LastSent  time.Time `json:"last_sent,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

func newOTLPSink(cfg otlp.Config, batch, queue int, interval time.Duration, log *slog.Logger) (*otlpSink, error) {
	c, err := otlp.New(cfg)
	if err != nil {
		return nil, err
	}
	s := &otlpSink{client: c, batch: batch, interval: interval, queue: make(chan otlpRecord, queue), stop: make(chan struct{}), log: log}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

func severity(l slog.Level) (int, string) {
	switch {
	case l >= slog.LevelError:
		return 17, "ERROR"
	case l >= slog.LevelWarn:
		return 13, "WARN"
	case l >= slog.LevelInfo:
		return 9, "INFO"
	default:
		return 5, "DEBUG"
	}
}

// emit implements lineSink: the record's attributes become OTLP
// attributes, the message the body, and the stream an attribute.
func (s *otlpSink) emit(level slog.Level, stream string, _ []byte, rec slog.Record) {
	num, text := severity(level)
	msg := rec.Message
	r := otlpRecord{Time: otlp.Nanos(rec.Time), ObservedTime: otlp.Nanos(time.Now()), SeverityNumber: num, SeverityText: text,
		Body: otlp.Value{StringValue: &msg}, Attributes: []otlp.KV{otlp.String("xproxy.stream", stream)}}
	rec.Attrs(func(a slog.Attr) bool {
		r.Attributes = append(r.Attributes, otlpAttr("", a)...)
		switch a.Key {
		case "trace_id":
			r.TraceID = a.Value.String()
		case "span_id":
			r.SpanID = a.Value.String()
		}
		return true
	})
	select {
	case s.queue <- r:
	default:
		s.dropped.Add(1)
	}
}

func otlpAttr(prefix string, a slog.Attr) []otlp.KV {
	key := prefix + a.Key
	switch a.Value.Kind() {
	case slog.KindGroup:
		var out []otlp.KV
		for _, g := range a.Value.Group() {
			out = append(out, otlpAttr(key+".", g)...)
		}
		return out
	case slog.KindInt64:
		return []otlp.KV{otlp.Int(key, a.Value.Int64())}
	case slog.KindUint64:
		return []otlp.KV{otlp.Int(key, int64(a.Value.Uint64()))} //nolint:gosec // counters fit
	case slog.KindBool:
		return []otlp.KV{otlp.Bool(key, a.Value.Bool())}
	case slog.KindFloat64:
		return []otlp.KV{otlp.Float(key, a.Value.Float64())}
	default:
		return []otlp.KV{otlp.String(key, a.Value.String())}
	}
}

func (s *otlpSink) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	batch := make([]otlpRecord, 0, s.batch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		body, _ := json.Marshal(map[string]any{
			"resourceLogs": []any{map[string]any{
				"resource": map[string]any{"attributes": s.client.Resource()},
				"scopeLogs": []any{map[string]any{
					"scope":      map[string]any{"name": "xproxy", "version": s.client.Config().Version},
					"logRecords": batch,
				}},
			}},
		})
		ctx, cancel := context.WithTimeout(context.Background(), s.client.Config().Timeout)
		err := s.client.Post(ctx, body)
		cancel()
		s.pushes.Add(1)
		s.mu.Lock()
		if err != nil {
			s.failed.Add(1)
			s.dropped.Add(uint64(len(batch))) //nolint:gosec // bounded by batch
			s.lastErr = err.Error()
			s.log.Warn("log export failed", "endpoint", s.client.Config().Endpoint, "err", err.Error())
		} else {
			s.sent.Add(uint64(len(batch))) //nolint:gosec // bounded by batch
			s.lastSent = time.Now()
			s.lastErr = ""
		}
		s.mu.Unlock()
		batch = batch[:0]
	}
	for {
		select {
		case <-s.stop:
			for {
				select {
				case r := <-s.queue:
					batch = append(batch, r)
					if len(batch) >= s.batch {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		case r := <-s.queue:
			batch = append(batch, r)
			if len(batch) >= s.batch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *otlpSink) close() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
}

func (s *otlpSink) status() OTLPStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return OTLPStatus{Endpoint: s.client.Config().Endpoint, Sent: s.sent.Load(), Dropped: s.dropped.Load(), Pushes: s.pushes.Load(),
		Failed: s.failed.Load(), Queued: len(s.queue), LastSent: s.lastSent, LastError: s.lastErr}
}
