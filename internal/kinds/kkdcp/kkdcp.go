package kkdcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sesslimit"
)

// server is one kind: kkdcp listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	k    *config.KKDCPListener
	name string
	ln   net.Listener
	srv  *http.Server

	policy  *policy
	gate    *sesslimit.Gate
	limiter *limits.KeyedLimiter
	anomaly *anomaly.Detector
	// windows are the two behavioural bounds this kind has of its own: how
	// many different service principals a client asked for, and how many
	// pre-authentication failures it collected. Both are per client and
	// over a window, and both are the controls a KDC's own policy cannot
	// give -- it locks the account, which is what a sprayer wanted.
	services *window
	failures *window

	path        string
	logRequests bool
	alertOnDeny bool
	errorReply  bool
	maxMessage  int
	maxRequests int
	timeout     time.Duration

	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (proxy.Instance, error) {
	k := cfg.KKDCP
	p, err := compile(k)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{
		host: host, cfg: cfg, k: k, name: cfg.Name, policy: p,
		gate:        sesslimit.New(k.MaxSessions, k.MaxSessionsPerClient),
		path:        or(k.Path, "/KdcProxy"),
		logRequests: boolOr(k.LogRequests, true),
		alertOnDeny: boolOr(k.AlertOnDeny, true),
		errorReply:  k.DenyResponse != "status",
		maxMessage:  or(k.MaxMessageBytes, 128<<10),
		maxRequests: or(k.MaxRequestsPerConnection, 64),
		timeout:     or(k.UpstreamTimeout.D(), 10*time.Second),
	}
	t.ln = tls.NewListener(ln, tlsCfg)
	if k.RateLimit > 0 {
		burst := k.RateBurst
		if burst <= 0 {
			burst = k.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(k.RateLimit), burst, 4096)
	}
	if k.MaxDistinctServices > 0 {
		t.services = newWindow(k.MaxDistinctServices, or(k.ServiceWindow.D(), 5*time.Minute))
	}
	if k.MaxPreauthFailures > 0 {
		t.failures = newWindow(k.MaxPreauthFailures, or(k.FailureWindow.D(), 5*time.Minute))
	}
	if t.anomaly, err = anomaly.FromConfig(k.Anomaly, time.Now()); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", t.handle)
	t.srv = &http.Server{
		Handler: mux,
		// The bounds are the listener's rather than the library's defaults.
		// This is a listener whose whole purpose is to be reachable from the
		// open internet, and the three numbers below are what stop a client
		// that connects and says nothing from costing anything.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          nil,
	}
	return t, nil
}

// enforcing reports whether this listener acts on its policy or only records
// what it would have done.
func (t *server) enforcing() bool { return !t.k.MonitorOnly && !t.cfg.Shadowing() }

func (t *server) alerts() bool { return t.alertOnDeny }

func (t *server) serve() {
	if !t.sessions.Enter() {
		return
	}
	defer t.sessions.Leave()
	if err := t.srv.Serve(t.ln); err != nil && !t.sessions.Closing() &&
		!strings.Contains(err.Error(), "use of closed network connection") {
		t.host.Logs().Error.Error("kkdcp listener stopped", "listener", t.name, "error", err.Error())
	}
}

func (t *server) shutdown(ctx context.Context) {
	if !t.sessions.Close() {
		return
	}
	// Shutdown drains the connections that are mid-request and closes the
	// idle ones, which on this kind is what a reload wants: a request in
	// flight is a login somebody is waiting for.
	_ = t.srv.Shutdown(ctx)
	t.sessions.Wait(ctx)
}

// boolOr reads an optional boolean with a default.
func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// or returns a value or a default when it is zero.
func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// lower copies a list of names folded for comparison. Kerberos realms are
// conventionally upper case and principals are not, and both are compared
// case-insensitively here: a policy that admitted CORP.EXAMPLE and refused
// corp.example would have a bypass an attacker types rather than finds.
func lower(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return out
}
