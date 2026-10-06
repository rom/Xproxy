// Package pop3 serves a kind: pop3 listener: a POP3 and POP3S relay in
// front of a mailbox server.
//
// POP3 is the smaller of the two mailbox protocols and the one where the
// credential is least protected: `USER` names an identity and `PASS` sends
// the password in the clear on the next line, with no negotiation in
// between and nothing to inspect. Either the connection is encrypted by the
// time PASS arrives or the password has been published, which is why
// `require_tls` defaults on and is not shadowable.
//
// Four things are deliberate in the data path.
//
// **The relay knows whether a reply is one line or many.** `LIST` lists the
// whole mailbox and ends with a dot; `LIST 3` answers one line. Guess wrong
// and the two ends have desynchronised, which on this protocol means a
// client is shown somebody else's mail or none of its own. So the shape of
// every reply is derived from the command and its argument count, and the
// one case the protocol makes ambiguous has a test of its own.
//
// **The copying bound is a running total.** POP3 has no sequence set to
// measure: a client asks for one message at a time, and the only honest
// bound is the octets and messages counted as they pass.
// `max_retr_bytes` and `max_messages` are that, enforced mid-transfer by
// closing the connection -- because a bound that only applied to the next
// command would be a bound a client walks past one message at a time.
//
// **STLS is answered here.** The two legs are separate decisions, as they
// are on every other relay in this project; forwarding the upgrade would
// hand the client's session key to the server and leave this relay reading
// nothing.
//
// **The CAPA list is narrowed.** A mechanism the policy will refuse is
// removed from what the client reads, and STLS is removed where the
// connection is already TLS.
package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	wire "github.com/rom/xproxy/internal/pop3"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/tlsconf"
)

// server is one kind: pop3 listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	c      *config.POP3Listener
	name   string
	ln     net.Listener
	tlsCfg *tls.Config

	upTLSMode string
	upTLSCfg  *tls.Config

	policy  *policy
	gate    *sesslimit.Gate
	limiter *limits.KeyedLimiter
	anomaly *anomaly.Detector

	tlsMode       string
	logCommands   bool
	logRetrievals bool
	alertOnDeny   bool

	idle     time.Duration
	lifetime time.Duration
	maxLine  int
	maxResp  int

	sessions acceptgroup.Group
	open     atomic.Int64
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	c := cfg.POP3
	p, err := compile(c)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{
		host: host, cfg: cfg, c: c, name: cfg.Name, ln: ln, tlsCfg: tlsCfg,
		policy:        p,
		tlsMode:       tlsModeOf(c, tlsCfg),
		upTLSMode:     strings.ToLower(or(c.UpstreamTLSMode, "disable")),
		gate:          sesslimit.New(c.MaxSessions, c.MaxSessionsPerClient),
		logCommands:   boolOn(c.LogCommands),
		logRetrievals: boolOn(c.LogRetrievals),
		alertOnDeny:   boolOn(c.AlertOnDeny),
		idle:          or(c.IdleTimeout.D(), 10*time.Minute),
		lifetime:      or(c.SessionTimeout.D(), time.Hour),
		maxLine:       or(c.MaxLineBytes, wire.MaxAuthLine),
		maxResp:       or(c.MaxResponseBytes, wire.MaxReplyLine),
	}
	if t.tlsMode == "starttls" && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: tls_mode: starttls needs a tls section, because this relay terminates the upgrade itself", cfg.Name)
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(c.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	if c.RateLimit > 0 {
		t.limiter = limits.NewKeyedLimiter(float64(c.RateLimit), or(c.RateBurst, c.RateLimit), 65536)
	}
	if t.anomaly, err = anomaly.FromConfig(c.Anomaly, time.Now()); err != nil {
		return nil, err
	}
	return t, nil
}

// tlsModeOf reads the transport this listener serves.
func tlsModeOf(c *config.POP3Listener, tlsCfg *tls.Config) string {
	switch m := strings.ToLower(strings.TrimSpace(c.TLSMode)); m {
	case "implicit", "starttls", "none":
		return m
	}
	if tlsCfg != nil {
		return "implicit"
	}
	return "none"
}

func (t *server) enforcing() bool { return t.enforcement().Enforcing() }

// enforcement folds this listener's reasons not to enforce into one answer, so
// that the precedence, and the name a status view reports, are the same on
// every kind.
func (t *server) enforcement() config.Enforcement {
	e := config.Enforcement{Shadow: t.cfg.Shadowing(), MonitorOnly: t.c.MonitorOnly}
	return e
}

func (t *server) alerts() bool { return t.alertOnDeny }

func (t *server) maxConnections() int { return or(t.c.MaxConnections, 256) }

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
		if t.open.Add(1) > int64(t.maxConnections()) {
			t.open.Add(-1)
			t.host.Counters().Refuse("pop3", "max_connections")
			_ = c.Close()
			continue
		}
		if !t.sessions.Enter() {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer t.open.Add(-1)
			defer safe.Guard("pop3 session")
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

// errorsAsTimeout is errors.As against net.Error plus the timeout test.
func errorsAsTimeout(err error, ne *net.Error) bool {
	return errors.As(err, ne) && (*ne).Timeout()
}
