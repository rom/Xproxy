package logging

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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
)

// siemSink ships log records to a SIEM's HTTP collector: Splunk HTTP
// Event Collector, Elastic and OpenSearch ingest endpoints, Microsoft
// Sentinel's data collector, or anything that takes newline delimited
// JSON, CEF or LEEF over HTTPS. Records queue without blocking the
// request path; a full queue drops and counts; a batching goroutine
// posts by size and interval and flushes at shutdown.
type siemSink struct {
	cfg       config.SIEM
	meta      siemMeta
	http      *http.Client
	auth      string
	queue     chan []byte
	queueFull bound.Notice
	stop      chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
	log       *slog.Logger

	sent, dropped, pushes, failed atomic.Uint64
	mu                            sync.Mutex
	lastErr                       string
	lastSent                      time.Time
}

// SIEMStatus is the management view of the sink.
type SIEMStatus struct {
	Endpoint  string    `json:"endpoint"`
	Format    string    `json:"format"`
	Sent      uint64    `json:"records_sent"`
	Dropped   uint64    `json:"records_dropped"`
	Pushes    uint64    `json:"pushes"`
	Failed    uint64    `json:"pushes_failed"`
	Queued    int       `json:"queued"`
	LastSent  time.Time `json:"last_sent,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

func newSIEMSink(cfg config.SIEM, log *slog.Logger) (*siemSink, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("siem ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("siem ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("siem client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	s := &siemSink{cfg: cfg, queue: make(chan []byte, cfg.Queue), stop: make(chan struct{}), log: log}
	if cfg.AuthFile != "" {
		data, err := os.ReadFile(cfg.AuthFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("siem auth_file: %w", err)
		}
		s.auth = strings.TrimSpace(string(data))
		if s.auth == "" {
			return nil, errors.New("siem auth_file is empty")
		}
	}
	s.meta = siemMeta{vendor: cfg.Vendor, product: cfg.Product, version: Version, hostname: cfg.Hostname}
	if s.meta.hostname == "" {
		s.meta.hostname, _ = os.Hostname()
	}
	s.http = &http.Client{Timeout: cfg.Timeout.D(),
		Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

// emit implements lineSink.
func (s *siemSink) emit(level slog.Level, stream string, line []byte, rec slog.Record) {
	var ev []byte
	switch s.cfg.Format {
	case "cef":
		ev = cefLine(s.meta, stream, level, rec)
	case "leef":
		ev = leefLine(s.meta, stream, level, rec)
	case "hec":
		ev = hecEnvelope(s.meta.hostname, stream, rec.Time, line)
	default:
		ev = append([]byte(nil), line...)
	}
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
		s.queueFull.Hit(s.log, "siem queue full; records are dropped", "table", "siem_queue")
	}
}

// hecEnvelope wraps a JSON line in the Splunk HTTP Event Collector
// event envelope.
func hecEnvelope(host, stream string, t time.Time, line []byte) []byte {
	env := struct {
		Time       string          `json:"time"`
		Host       string          `json:"host,omitempty"`
		Source     string          `json:"source"`
		SourceType string          `json:"sourcetype"`
		Event      json.RawMessage `json:"event"`
	}{Time: strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', 3, 64), Host: host, Source: "xproxy", SourceType: "xproxy:" + stream, Event: json.RawMessage(line)}
	b, err := json.Marshal(env)
	if err != nil {
		return line
	}
	return b
}

func (s *siemSink) contentType() string {
	switch s.cfg.Format {
	case "hec":
		return "application/json"
	case "json":
		return "application/x-ndjson"
	}
	return "text/plain; charset=utf-8"
}

func (s *siemSink) post(batch [][]byte) error {
	body := bytes.Join(batch, []byte("\n"))
	body = append(body, '\n')
	var rd io.Reader = bytes.NewReader(body)
	if s.cfg.Compresses() {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(body)
		_ = gz.Close()
		rd = &buf
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout.D())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", s.contentType())
	req.Header.Set("User-Agent", "xproxy-siem/1")
	if s.cfg.Compresses() {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if s.auth != "" {
		req.Header.Set("Authorization", s.auth)
	}
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
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

func (s *siemSink) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.Interval.D())
	defer ticker.Stop()
	batch := make([][]byte, 0, s.cfg.Batch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		err := s.post(batch)
		s.pushes.Add(1)
		s.mu.Lock()
		if err != nil {
			s.failed.Add(1)
			s.dropped.Add(uint64(len(batch))) //nolint:gosec // bounded by batch
			s.lastErr = err.Error()
			s.log.Warn("siem export failed", "endpoint", s.cfg.Endpoint, "err", err.Error())
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
					if len(batch) >= s.cfg.Batch {
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
			if len(batch) >= s.cfg.Batch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *siemSink) close() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
}

func (s *siemSink) status() SIEMStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SIEMStatus{Endpoint: s.cfg.Endpoint, Format: s.cfg.Format, Sent: s.sent.Load(), Dropped: s.dropped.Load(), Pushes: s.pushes.Load(),
		Failed: s.failed.Load(), Queued: len(s.queue), LastSent: s.lastSent, LastError: s.lastErr}
}
