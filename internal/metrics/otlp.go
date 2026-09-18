package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Collector receives the metric families of one collection. The
// Prometheus Encoder and the OTLP exporter both implement it, so one
// collection function feeds both.
type Collector interface {
	Counter(name, help string, labels Labels, value float64)
	Gauge(name, help string, labels Labels, value float64)
	Histogram(name, help string, labels Labels, h HistogramSnapshot)
}

// OTLPConfig configures the push exporter.
type OTLPConfig struct {
	Endpoint    string
	Interval    time.Duration
	Timeout     time.Duration
	Headers     map[string]string
	CAFile      string
	ServiceName string
	Attributes  map[string]string
	Compress    bool
	Version     string
}

// OTLPStatus is the management view.
type OTLPStatus struct {
	Endpoint  string    `json:"endpoint"`
	Interval  string    `json:"interval"`
	Sent      uint64    `json:"sent"`
	Failed    uint64    `json:"failed"`
	LastSent  time.Time `json:"last_sent"`
	LastError string    `json:"last_error"`
	LastBytes int       `json:"last_bytes"`
	Metrics   int       `json:"metrics"`
}

// OTLPExporter pushes the collection as OTLP/HTTP with JSON encoding
// (the OpenTelemetry protocol's JSON mapping) on an interval. Counters
// are cumulative monotonic sums since process start, gauges are gauges
// and histograms are cumulative explicit bucket histograms.
type OTLPExporter struct {
	cfg    OTLPConfig
	source func(Collector)
	log    *slog.Logger
	client *http.Client
	start  time.Time

	mu     sync.Mutex
	status OTLPStatus
	sent   atomic.Uint64
	failed atomic.Uint64
	stop   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

// NewOTLPExporter builds an exporter; source runs a collection into the
// given Collector.
func NewOTLPExporter(cfg OTLPConfig, source func(Collector), log *slog.Logger) (*OTLPExporter, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("otlp ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("otlp ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "xproxy"
	}
	e := &OTLPExporter{cfg: cfg, source: source, log: log, start: time.Now(), stop: make(chan struct{}),
		client: &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 2 * cfg.Interval, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}}
	e.status = OTLPStatus{Endpoint: cfg.Endpoint, Interval: cfg.Interval.String()}
	return e, nil
}

// Start pushes every interval until Stop.
func (e *OTLPExporter) Start() {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(e.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-e.stop:
				return
			case <-t.C:
				if err := e.Push(context.Background()); err != nil {
					e.log.Warn("otlp export failed", "endpoint", e.cfg.Endpoint, "err", err.Error())
				}
			}
		}
	}()
}

// Stop ends the loop and sends one final push so counters are current.
func (e *OTLPExporter) Stop() {
	e.once.Do(func() { close(e.stop) })
	e.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.Timeout)
	defer cancel()
	_ = e.Push(ctx)
}

// Status reports counters and the last error.
func (e *OTLPExporter) Status() OTLPStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.status
	st.Sent, st.Failed = e.sent.Load(), e.failed.Load()
	return st
}

// Push runs one collection and sends it.
func (e *OTLPExporter) Push(ctx context.Context) error {
	body, n := e.Encode(time.Now())
	err := e.send(ctx, body)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.Metrics = n
	e.status.LastBytes = len(body)
	if err != nil {
		e.failed.Add(1)
		e.status.LastError = err.Error()
		return err
	}
	e.sent.Add(1)
	e.status.LastSent = time.Now()
	e.status.LastError = ""
	return nil
}

func (e *OTLPExporter) send(ctx context.Context, body []byte) error {
	var rd io.Reader = bytes.NewReader(body)
	if e.cfg.Compress {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(body)
		_ = gz.Close()
		rd = &buf
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xproxy-otlp/1")
	if e.cfg.Compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// OTLP JSON shapes (opentelemetry-proto JSON mapping: 64 bit integers
// as strings, enums as numbers).
type otlpKV struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpValue struct {
	StringValue string `json:"stringValue"`
}

type otlpPoint struct {
	Attributes    []otlpKV  `json:"attributes,omitempty"`
	StartTime     string    `json:"startTimeUnixNano,omitempty"`
	Time          string    `json:"timeUnixNano"`
	AsDouble      *float64  `json:"asDouble,omitempty"`
	Count         string    `json:"count,omitempty"`
	Sum           *float64  `json:"sum,omitempty"`
	BucketCounts  []string  `json:"bucketCounts,omitempty"`
	ExplicitBound []float64 `json:"explicitBounds,omitempty"`
}

type otlpSum struct {
	Temporality int         `json:"aggregationTemporality"`
	Monotonic   bool        `json:"isMonotonic"`
	Points      []otlpPoint `json:"dataPoints"`
}

type otlpGauge struct {
	Points []otlpPoint `json:"dataPoints"`
}

type otlpHistogram struct {
	Temporality int         `json:"aggregationTemporality"`
	Points      []otlpPoint `json:"dataPoints"`
}

type otlpMetric struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Sum         *otlpSum       `json:"sum,omitempty"`
	Gauge       *otlpGauge     `json:"gauge,omitempty"`
	Histogram   *otlpHistogram `json:"histogram,omitempty"`
}

const cumulative = 2

// otlpCollector accumulates one collection into OTLP metrics.
type otlpCollector struct {
	start, now string
	order      []string
	metrics    map[string]*otlpMetric
}

func attrs(l Labels) []otlpKV {
	if len(l) == 0 {
		return nil
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]otlpKV, 0, len(keys))
	for _, k := range keys {
		out = append(out, otlpKV{Key: k, Value: otlpValue{StringValue: l[k]}})
	}
	return out
}

func (c *otlpCollector) metric(name, help string) *otlpMetric {
	m, ok := c.metrics[name]
	if !ok {
		m = &otlpMetric{Name: name, Description: help}
		c.metrics[name] = m
		c.order = append(c.order, name)
	}
	return m
}

func (c *otlpCollector) Counter(name, help string, labels Labels, value float64) {
	m := c.metric(name, help)
	if m.Sum == nil {
		m.Sum = &otlpSum{Temporality: cumulative, Monotonic: true}
	}
	v := value
	m.Sum.Points = append(m.Sum.Points, otlpPoint{Attributes: attrs(labels), StartTime: c.start, Time: c.now, AsDouble: &v})
}

func (c *otlpCollector) Gauge(name, help string, labels Labels, value float64) {
	m := c.metric(name, help)
	if m.Gauge == nil {
		m.Gauge = &otlpGauge{}
	}
	v := value
	m.Gauge.Points = append(m.Gauge.Points, otlpPoint{Attributes: attrs(labels), Time: c.now, AsDouble: &v})
}

func (c *otlpCollector) Histogram(name, help string, labels Labels, h HistogramSnapshot) {
	m := c.metric(name, help)
	if m.Histogram == nil {
		m.Histogram = &otlpHistogram{Temporality: cumulative}
	}
	counts := make([]string, 0, len(h.Counts)+1)
	var inBounds uint64
	for _, n := range h.Counts {
		counts = append(counts, strconv.FormatUint(n, 10))
		inBounds += n
	}
	over := uint64(0)
	if h.Count > inBounds {
		over = h.Count - inBounds
	}
	counts = append(counts, strconv.FormatUint(over, 10))
	sum := h.Sum
	m.Histogram.Points = append(m.Histogram.Points, otlpPoint{Attributes: attrs(labels), StartTime: c.start, Time: c.now,
		Count: strconv.FormatUint(h.Count, 10), Sum: &sum, BucketCounts: counts, ExplicitBound: h.Bounds})
}

// Encode runs the collection and returns the OTLP/JSON request body and
// the number of metrics in it.
func (e *OTLPExporter) Encode(now time.Time) ([]byte, int) {
	c := &otlpCollector{start: strconv.FormatInt(e.start.UnixNano(), 10), now: strconv.FormatInt(now.UnixNano(), 10), metrics: map[string]*otlpMetric{}}
	e.source(c)
	ms := make([]*otlpMetric, 0, len(c.order))
	for _, n := range c.order {
		ms = append(ms, c.metrics[n])
	}
	res := []otlpKV{{Key: "service.name", Value: otlpValue{StringValue: e.cfg.ServiceName}}}
	if e.cfg.Version != "" {
		res = append(res, otlpKV{Key: "service.version", Value: otlpValue{StringValue: e.cfg.Version}})
	}
	if host, err := os.Hostname(); err == nil {
		res = append(res, otlpKV{Key: "host.name", Value: otlpValue{StringValue: host}})
	}
	keys := make([]string, 0, len(e.cfg.Attributes))
	for k := range e.cfg.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, otlpKV{Key: k, Value: otlpValue{StringValue: e.cfg.Attributes[k]}})
	}
	body, _ := json.Marshal(map[string]any{
		"resourceMetrics": []any{map[string]any{
			"resource": map[string]any{"attributes": res},
			"scopeMetrics": []any{map[string]any{
				"scope":   map[string]any{"name": "xproxy", "version": e.cfg.Version},
				"metrics": ms,
			}},
		}},
	})
	return body, len(ms)
}
