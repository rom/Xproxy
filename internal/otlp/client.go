// Package otlp is the OTLP/HTTP client and the JSON shapes shared by the
// metrics, trace and log exporters: one bounded HTTP client with a
// pinned CA, gzip and fixed headers, no protobuf and no SDK.
package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

// Config is what every exporter needs to reach a collector.
type Config struct {
	Endpoint    string
	Timeout     time.Duration
	Headers     map[string]string
	CAFile      string
	ServiceName string
	Attributes  map[string]string
	Compress    bool
	Version     string
}

// Client posts OTLP/JSON bodies.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a client; it fails only on an unreadable CA file.
func New(cfg Config) (*Client, error) {
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
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout,
		Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}}, nil
}

// Config returns the configuration.
func (c *Client) Config() Config { return c.cfg }

// Post sends one JSON body to the endpoint.
func (c *Client) Post(ctx context.Context, body []byte) error {
	var rd io.Reader = bytes.NewReader(body)
	if c.cfg.Compress {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(body)
		_ = gz.Close()
		rd = &buf
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xproxy-otlp/1")
	if c.cfg.Compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
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

// KV is an OTLP attribute (opentelemetry-proto JSON mapping).
type KV struct {
	Key   string `json:"key"`
	Value Value  `json:"value"`
}

// Value is an AnyValue with the scalar kinds the proxy emits.
type Value struct {
	StringValue *string  `json:"stringValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"` // 64 bit integers travel as strings
	BoolValue   *bool    `json:"boolValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

// String, Int, Bool and Float build attributes.
func String(k, v string) KV { return KV{Key: k, Value: Value{StringValue: &v}} }
func Int(k string, v int64) KV {
	s := strconv.FormatInt(v, 10)
	return KV{Key: k, Value: Value{IntValue: &s}}
}
func Bool(k string, v bool) KV { return KV{Key: k, Value: Value{BoolValue: &v}} }
func Float(k string, v float64) KV {
	return KV{Key: k, Value: Value{DoubleValue: &v}}
}

// Resource builds the resource attributes: service.name,
// service.version, host.name and the configured extras in key order.
func (c *Client) Resource() []KV {
	res := []KV{String("service.name", c.cfg.ServiceName)}
	if c.cfg.Version != "" {
		res = append(res, String("service.version", c.cfg.Version))
	}
	if host, err := os.Hostname(); err == nil {
		res = append(res, String("host.name", host))
	}
	keys := make([]string, 0, len(c.cfg.Attributes))
	for k := range c.cfg.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, String(k, c.cfg.Attributes[k]))
	}
	return res
}

// Nanos formats a time as the protocol's nanosecond string.
func Nanos(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }
