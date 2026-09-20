package mgmt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
)

// serveMetrics writes the Prometheus exposition.
func (s *Server) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.proxy.WriteMetrics(w); err != nil {
		s.logs.Error.Warn("metrics write failed", "err", err.Error())
	}
}

// SeriesResponse is the body of GET /v1/series.
type SeriesResponse struct {
	IntervalSeconds float64       `json:"interval_seconds"`
	Names           []string      `json:"names"`
	Points          []SeriesPoint `json:"points"`
}

// SeriesPoint is one sample.
type SeriesPoint struct {
	Time   time.Time `json:"t"`
	Values []float64 `json:"v"`
}

// serveSeries returns sampled series. Query: since (RFC 3339 or seconds
// ago as "300s"), limit.
func (s *Server) serveSeries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var since time.Time
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		} else {
			writeJSON(w, 400, result{Error: "bad since"})
			return
		}
	}
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100000 {
			writeJSON(w, 400, result{Error: "bad limit"})
			return
		}
		limit = n
	}
	ser := s.proxy.Series()
	pts := ser.Since(since, limit)
	out := SeriesResponse{IntervalSeconds: ser.Interval().Seconds(), Names: ser.Names(), Points: make([]SeriesPoint, len(pts))}
	for i, p := range pts {
		out.Points[i] = SeriesPoint{Time: p.Time, Values: p.Values}
	}
	writeJSON(w, 200, out)
}

// MetricsListener serves only /metrics on a TCP address for scrapers, with
// an optional source allow list and optional TLS with client certificates.
type MetricsListener struct {
	cfg   config.Metrics
	http  *http.Server
	ln    net.Listener
	allow []netip.Prefix
	logs  *logging.Logs
	// aclDenied aggregates refusals: the listener has no other bound.
	aclDenied bound.Notice
}

// NewMetricsListener prepares the listener; Start binds it.
func NewMetricsListener(cfg config.Metrics, p *proxy.Server, logs *logging.Logs) (*MetricsListener, error) {
	m := &MetricsListener{cfg: cfg, allow: netutil.ParsePrefixes(cfg.AllowCIDRs), logs: logs}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if len(m.allow) > 0 && !netutil.Contains(m.allow, netutil.RemoteAddr(r)) {
			// Aggregated: this listener has no rate limit, no connection
			// cap and no ban ladder, so one record per refused request
			// would let anybody who can route to the port drive the log
			// volume and drown other records out of the export queues.
			m.aclDenied.Hit(logs.Error, "requests refused by the metrics access list are aggregated",
				"client_ip", netutil.RemoteAddr(r).String())
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = p.WriteMetrics(w)
	})
	m.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if t := cfg.TLS; t != nil {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("metrics tls: %w", err)
		}
		tc := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		if t.ClientCAFile != "" {
			pem, err := os.ReadFile(t.ClientCAFile) //nolint:gosec // validated configuration path
			if err != nil {
				return nil, fmt.Errorf("metrics client ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("metrics client ca file contains no certificates")
			}
			tc.ClientCAs = pool
			tc.ClientAuth = tls.RequireAndVerifyClientCert
		}
		m.http.TLSConfig = tc
	}
	return m, nil
}

// Start binds and serves in the background.
func (m *MetricsListener) Start() error {
	if m.cfg.Listen == "" {
		return nil
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", m.cfg.Listen)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	m.ln = ln
	useTLS := m.http.TLSConfig != nil
	m.logs.Error.Info("metrics listening", "address", ln.Addr().String(), "tls", useTLS)
	go func() {
		var err error
		if useTLS {
			err = m.http.ServeTLS(ln, "", "")
		} else {
			err = m.http.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.logs.Error.Error("metrics listener stopped", "err", err.Error())
		}
	}()
	return nil
}

// Addr returns the bound address or "".
func (m *MetricsListener) Addr() string {
	if m.ln == nil {
		return ""
	}
	return m.ln.Addr().String()
}

// Shutdown stops the listener.
func (m *MetricsListener) Shutdown(ctx context.Context) error {
	if m.ln == nil {
		return nil
	}
	return m.http.Shutdown(ctx)
}
