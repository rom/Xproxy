// Package imap serves a kind: imap listener: an IMAP and IMAPS relay in
// front of a mailbox server.
//
// A mailbox is the most complete record of what an organisation has said
// and been told that exists anywhere, and IMAP is the protocol for reading
// all of it with one credential. That makes this a different problem from
// the SMTP relay next to it: a submission proxy sees one message on its way
// out, and this sees a client asking for everything that has ever arrived.
//
// Five things are deliberate in the data path.
//
// **A password in the clear is refused by default.** LOGIN on port 143, and
// AUTHENTICATE with PLAIN or LOGIN, put a mailbox password on the wire
// where anybody on the path can read it. `require_tls` is the line that
// stops it and it is not shadowable: by the time a policy could be
// consulted the password has travelled. A listener with a certificate and
// `tls_mode: starttls` terminates the upgrade itself, which is how a client
// nobody can reconfigure gets TLS anyway.
//
// **The capability list is narrowed on the way out.** A mechanism the
// policy will refuse is removed from what the client is shown, and
// LOGINDISABLED is added where LOGIN will be refused -- RFC 3501 §6.2.3
// makes that the way a server says so, and a client that reads it asks for
// something else instead of sending a password into a refusal.
// COMPRESS=DEFLATE goes too, always: a deflated connection cannot be
// inspected, so advertising it would be offering to stop.
//
// **The bound is on the request, not on the answer.** `UID FETCH 1:*
// (BODY[])` is three dozen characters and every message in the mailbox, so
// `max_fetch_messages` counts what a sequence set *names* and refuses
// before the server reads a thing. An open-ended set is refused outright
// once that bound is set, because its size is the mailbox's rather than the
// client's.
//
// **A literal is decided on its declared size.** `APPEND INBOX {310}` says
// the next 310 octets are a message; RFC 7888's `{310+}` sends them without
// waiting for anyone to agree. So the decision is made on the command line,
// and a refused command's octets are read and dropped rather than left to
// desynchronise the connection.
//
// **A PREAUTH greeting is not carried.** It says the connection is
// authenticated before anybody claimed an identity, which would make every
// later decision here about a name this relay never saw.
package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/imap"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/tlsconf"
)

// server is one kind: imap listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	c      *config.IMAPListener
	name   string
	ln     net.Listener
	tlsCfg *tls.Config

	upTLSMode string
	upTLSCfg  *tls.Config

	policy  *policy
	gate    *sesslimit.Gate
	limiter *limits.KeyedLimiter
	anomaly *anomaly.Detector

	tlsMode     string
	logCommands bool
	logFetches  bool
	alertOnDeny bool

	idle      time.Duration
	lifetime  time.Duration
	maxIdle   time.Duration
	maxLine   int
	maxResp   int
	maxLits   int
	maxCmds   int
	preauthNo bool

	sessions acceptgroup.Group
	open     atomic.Int64
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	c := cfg.IMAP
	p, err := compile(c)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{
		host: host, cfg: cfg, c: c, name: cfg.Name, ln: ln, tlsCfg: tlsCfg,
		policy:      p,
		tlsMode:     tlsModeOf(c, tlsCfg),
		upTLSMode:   strings.ToLower(or(c.UpstreamTLSMode, "disable")),
		gate:        sesslimit.New(c.MaxSessions, c.MaxSessionsPerClient),
		logCommands: boolOr(c.LogCommands, true),
		logFetches:  boolOr(c.LogFetches, true),
		alertOnDeny: boolOr(c.AlertOnDeny, true),
		idle:        or(c.IdleTimeout.D(), 30*time.Minute),
		lifetime:    or(c.SessionTimeout.D(), 24*time.Hour),
		maxIdle:     or(c.MaxIdleDuration.D(), 30*time.Minute),
		maxLine:     or(c.MaxLineBytes, wire.MaxCommandLine),
		maxResp:     or(c.MaxResponseBytes, wire.MaxResponseLine),
		maxLits:     or(c.MaxLiterals, 8),
		maxCmds:     c.MaxCommands,
		preauthNo:   boolOr(c.RefusePreauth, true),
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

// tlsModeOf reads the transport the listener serves: implicit where it has a
// certificate and did not ask for the upgrade, starttls where it did, none
// where it has neither.
func tlsModeOf(c *config.IMAPListener, tlsCfg *tls.Config) string {
	switch m := strings.ToLower(strings.TrimSpace(c.TLSMode)); m {
	case "implicit", "starttls", "none":
		return m
	}
	if tlsCfg != nil {
		return "implicit"
	}
	return "none"
}

// enforcing reports whether this listener acts on its policy or only
// records what it would have done.
func (t *server) enforcing() bool { return !t.c.MonitorOnly && !t.cfg.Shadowing() }

func (t *server) alerts() bool { return t.alertOnDeny }

// maxConnections bounds the connections served at once.
func (t *server) maxConnections() int { return or(t.c.MaxConnections, 512) }

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
			t.host.Counters().Refuse("imap", "max_connections")
			_ = c.Close()
			continue
		}
		if !t.sessions.Enter() {
			t.open.Add(-1)
			// Accepted as the listener was shutting down; serving it would
			// start a session nothing waits for.
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer t.open.Add(-1)
			defer safe.Guard("imap session")
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
