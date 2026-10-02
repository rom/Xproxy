package tacacs

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sesslimit"
	wire "github.com/rom/xproxy/internal/tacacs"
	"github.com/rom/xproxy/internal/tlsconf"
)

// server is one kind: tacacs listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	c      *config.TACACSListener
	name   string
	ln     net.Listener
	tlsCfg *tls.Config

	upTLSMode string
	upTLSCfg  *tls.Config

	policy  *policy
	gate    *sesslimit.Gate
	limiter *limits.KeyedLimiter
	anomaly *anomaly.Detector
	// engineering recognises a configuration command and ties it to an
	// approved work order. Device administration is engineering activity:
	// a `configure terminal` on a core router is the same kind of change as
	// a PLC download, and this is the listener that can see it.
	engineering *engineering.Guard

	// key is what arriving bodies are de-obfuscated with, and upKey what
	// forwarded ones are obfuscated with. upKey is key unless the
	// configuration gave a second one, which is what makes this listener a
	// key boundary.
	key, upKey []byte

	logRequests bool
	logAcct     bool
	alertOnDeny bool
	fail        bool
	idle        time.Duration
	lifetime    time.Duration

	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	c := cfg.TACACS
	p, err := compile(c)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{
		host: host, cfg: cfg, c: c, name: cfg.Name, ln: ln, tlsCfg: tlsCfg,
		policy:      p,
		upTLSMode:   or(c.UpstreamTLSMode, "disable"),
		gate:        sesslimit.New(c.MaxSessions, c.MaxSessionsPerClient),
		logRequests: boolOr(c.LogRequests, true),
		logAcct:     boolOr(c.LogAccounting, true),
		alertOnDeny: boolOr(c.AlertOnDeny, true),
		fail:        c.DenyResponse != "drop",
		idle:        or(c.IdleTimeout.D(), 5*time.Minute),
		lifetime:    or(c.SessionTimeout.D(), time.Hour),
	}
	if t.key, err = loadKey(c.SecretFile); err != nil {
		return nil, fmt.Errorf("listener %s: secret_file: %w", cfg.Name, err)
	}
	if t.upKey = t.key; c.UpstreamSecretFile != "" {
		if t.upKey, err = loadKey(c.UpstreamSecretFile); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_secret_file: %w", cfg.Name, err)
		}
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(c.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	if boolOr(c.RequireTLS, false) && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: require_tls is set but the listener has no certificate", cfg.Name)
	}
	if c.RateLimit > 0 {
		burst := c.RateBurst
		if burst <= 0 {
			burst = c.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(c.RateLimit), burst, 4096)
	}
	if t.anomaly, err = anomaly.FromConfig(c.Anomaly, time.Now()); err != nil {
		return nil, err
	}
	if t.engineering, err = engineering.FromConfig(c.Engineering, "tacacs", cfg.Name,
		host.Access(), host.Logs().Error); err != nil {
		return nil, err
	}
	return t, nil
}

// loadKey reads the shared key: one line, with the trailing newline an
// editor leaves removed and nothing else trimmed.
//
// A TACACS+ key may contain spaces, and a loader that trimmed them would
// obfuscate with a different key than the one in the file -- which presents
// as every body arriving as noise, with no indication why.
func loadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own configuration
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return b, nil
}

// reading reports whether this listener can read a body. Without a key it
// reads the twelve-octet header and forwards what follows, which is a
// bound and an audit of sessions rather than a policy on commands.
func (t *server) reading() bool { return len(t.key) > 0 }

// enforcing reports whether this listener acts on its policy or only
// records what it would have done.
func (t *server) enforcing() bool { return !t.c.MonitorOnly && !t.cfg.Shadowing() }

// maxBody is the largest body this listener will read.
func (t *server) maxBody() int { return min(or(t.c.MaxBodyBytes, 32<<10), wire.MaxBody) }

// maxPerConn bounds the sessions one connection may carry.
func (t *server) maxPerConn() int { return or(t.c.MaxSessionsPerConnection, 64) }

func (t *server) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if t.sessions.Closing() {
				return
			}
			var ne net.Error
			if errorsAsTimeout(err, &ne) {
				continue
			}
			return
		}
		if !t.sessions.Enter() {
			// Accepted as the listener was shutting down. Serving it would
			// start a session nothing waits for.
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer guard()
			t.handle(c)
		}()
	}
}

func (t *server) shutdown(ctx context.Context) {
	if !t.sessions.Close() {
		return
	}
	_ = t.ln.Close()
	t.sessions.Wait(ctx)
}

func (t *server) alerts() bool { return t.alertOnDeny }

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

// lower copies a list of names folded for comparison. TACACS+ user names
// come from the same directories RADIUS's do and are matched the same way.
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
