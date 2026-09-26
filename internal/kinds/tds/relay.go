package tds

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/sqlkind"
	wire "github.com/rom/xproxy/internal/tdswire"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: tds listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	tc     *config.TDSListener
	policy *policy
	ln     net.Listener
	tlsCfg *tls.Config

	upTLSMode string
	upTLSCfg  *tls.Config

	// gate bounds the sessions held, altogether and per client address.
	gate *sesslimit.Gate

	// sessions tracks what has been accepted, so shutdown waits for it. A bare
	// WaitGroup would not do: its Add must not race its Wait, and an accept loop
	// Adds at exactly the moment a shutdown Waits.
	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	p, err := compile(cfg.TDS)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, tc: cfg.TDS, policy: p,
		ln: ln, tlsCfg: tlsCfg, upTLSMode: cfg.TDS.UpstreamTLSMode,
		gate: sesslimit.New(cfg.TDS.MaxSessions, cfg.TDS.MaxSessionsPerClient)}
	if t.upTLSMode == "" {
		t.upTLSMode = "require"
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(cfg.TDS.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	if p.requireTLS && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: require_tls is set but the listener has no certificate", cfg.Name)
	}
	return t, nil
}

func (t *server) enforcing() bool { return !t.tc.MonitorOnly }

func (t *server) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if t.sessions.Closing() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if !t.sessions.Enter() {
			// Accepted as the listener was shutting down. Serving it would start
			// a session nothing waits for, so it is closed instead.
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer safe.Guard("tds session")
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

var errRefused = errors.New("tds: refused")

// handle runs one connection.
func (t *server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	se := &session{t: t, ip: ip, client: c, size: 4096}

	if !t.admit(se) {
		return
	}
	defer t.release(se)

	hs := t.tc.HandshakeTimeout.D()
	if hs <= 0 {
		hs = 30 * time.Second
	}
	up, err := t.dial(se)
	if err != nil {
		t.deny(se.ip, "upstream_unavailable", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	se.up = up

	if err := t.handshake(se, hs); err != nil {
		return
	}
	t.relay(se)
}

// admit and release bound the sessions this listener holds, and the counting
// is internal/sesslimit's rather than this file's. Six kinds had their own copy
// and all six read a counter and then incremented it, so concurrent accepts
// could pass the bound; the shared gate takes the count under the lock that
// checked it.
func (t *server) admit(se *session) bool {
	ok, reason := t.gate.Enter(se.ip)
	if !ok {
		t.deny(se.ip, reason, "")
	}
	return ok
}

func (t *server) release(se *session) { t.gate.Leave(se.ip) }

// handshake runs the PRELOGIN negotiation on both legs and then the LOGIN7.
//
// The order matters. The relay negotiates with the *server* first, so that when
// it answers the client it can forward the server's own option table -- version,
// instance name, MARS -- with only the one option it decides rewritten. Answering
// the client first would mean inventing a table, and a client that reads the
// server's version out of it would be told about a server the relay had not
// spoken to yet.
func (t *server) handshake(se *session, hs time.Duration) error {
	_ = se.client.SetDeadline(time.Now().Add(hs))
	_ = se.up.SetDeadline(time.Now().Add(hs))
	defer func() {
		_ = se.client.SetDeadline(time.Time{})
		_ = se.up.SetDeadline(time.Time{})
	}()

	cli := wire.NewReader(se.client, t.policy.MaxMessage())
	first, err := cli.Next()
	if err != nil {
		t.deny(se.ip, "unreadable_prelogin", err.Error())
		return errRefused
	}
	if first.Type != wire.TypePreLogin {
		// A connection that does not begin with PRELOGIN is either speaking an
		// older protocol or not speaking TDS. Either way the relay has nothing
		// to negotiate and will not guess.
		t.deny(se.ip, "no_prelogin", wire.TypeName(first.Type))
		return errRefused
	}
	pre, err := wire.ParsePreLogin(first.Payload)
	if err != nil {
		t.deny(se.ip, "unreadable_prelogin", err.Error())
		return errRefused
	}

	answer, forced, d := t.policy.Encryption(pre.Encryption, t.tlsCfg != nil)
	if !d.Allow {
		t.refused(se, d, "prelogin")
		return errRefused
	}

	// The server's leg, first.
	upWant := t.policy.UpstreamEncryption(t.upTLSMode)
	upPre := wire.BuildPreLogin(pre.WithEncryption(upWant))
	if err := se.writeUp(wire.Frame(wire.TypePreLogin, 0, upPre, se.size)); err != nil {
		return err
	}
	srv := wire.NewReader(se.up, t.policy.MaxMessage())
	resp, err := srv.Next()
	if err != nil {
		t.deny(se.ip, "unreadable_upstream_prelogin", err.Error())
		return errRefused
	}
	sp, err := wire.ParsePreLogin(resp.Payload)
	if err != nil {
		t.deny(se.ip, "unreadable_upstream_prelogin", err.Error())
		return errRefused
	}
	se.spid = resp.SPID
	if d := t.policy.UpstreamAnswer(t.upTLSMode, sp.Encryption); !d.Allow {
		t.refused(se, d, "upstream_prelogin")
		return errRefused
	}
	if wire.Encrypted(sp.Encryption) {
		if err := t.upgradeUpstream(se, hs); err != nil {
			t.deny(se.ip, "upstream_tls_handshake_failed", err.Error())
			return errRefused
		}
	}

	// Now the client's. The server's table goes back with the one option the
	// relay decides replaced.
	out := wire.BuildPreLogin(sp.WithEncryption(answer))
	if err := se.writeClient(wire.Frame(wire.TypePreLogin, se.spid, out, se.size)); err != nil {
		return err
	}
	if forced {
		t.forcedEncryption(se, pre.Encryption)
	}
	if wire.Encrypted(answer) {
		if err := t.upgradeClient(se, hs); err != nil {
			t.deny(se.ip, "tls_handshake_failed", err.Error())
			return errRefused
		}
		cli = wire.NewReader(se.client, t.policy.MaxMessage())
	}
	srv = wire.NewReader(se.up, t.policy.MaxMessage())

	// The login.
	lp, err := cli.Next()
	if err != nil {
		t.deny(se.ip, "unreadable_login", err.Error())
		return errRefused
	}
	if lp.Type != wire.TypeLogin7 {
		if d := t.policy.Message(se.sess(), lp.Type); !d.Allow {
			t.refused(se, d, wire.TypeName(lp.Type))
			se.fatal(d)
			return errRefused
		}
		t.deny(se.ip, "no_login7", wire.TypeName(lp.Type))
		return errRefused
	}
	l, err := wire.ParseLogin7(lp.Payload)
	if err != nil {
		t.deny(se.ip, "unreadable_login", err.Error())
		return errRefused
	}
	se.mu.Lock()
	se.user, se.database, se.app = l.User, l.Database, l.AppName
	se.host, se.library, se.integrated = l.Hostname, l.Library, l.Integrated
	se.mu.Unlock()
	se.cliReader, se.srvReader = cli, srv

	if d := t.policy.Login(se.sess(), l); !d.Allow {
		t.refused(se, d, "connect")
		if t.enforcing() || d.Hard {
			se.fatal(d)
			return errRefused
		}
	}
	se.observe()

	return se.writeUp(wire.Frame(wire.TypeLogin7, 0, lp.Payload, se.size))
}

// upgradeClient terminates the client's TLS, with the handshake carried inside
// TDS packets until it completes.
func (t *server) upgradeClient(se *session, hs time.Duration) error {
	if t.tlsCfg == nil {
		return errors.New("tds: tls is required but the listener has no certificate")
	}
	tun := newTunnel(se.client, se.spid, se.size, t.policy.MaxMessage())
	tc := tls.Server(tun, t.tlsCfg)
	// The handshake carries its own deadline rather than borrowing the
	// connection's, so the bound applies to the handshake alone and there is no
	// deadline left set on a connection that goes on to be relayed.
	ctx, cancel := handshakeContext(hs)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	// The nesting inverts here: from now on TLS wraps TDS rather than the other
	// way round.
	tun.HandshakeDone()
	se.cmu.Lock()
	se.client = tc
	se.cmu.Unlock()
	se.mu.Lock()
	se.secure = true
	se.mu.Unlock()
	return nil
}

// upgradeUpstream does the same on the leg to the server.
func (t *server) upgradeUpstream(se *session, hs time.Duration) error {
	cfg := t.upTLSCfg.Clone()
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(se.up.RemoteAddr().String())
		if err != nil {
			host = se.up.RemoteAddr().String()
		}
		cfg.ServerName = host
	}
	tun := newTunnel(se.up, 0, se.size, t.policy.MaxMessage())
	tc := tls.Client(tun, cfg)
	ctx, cancel := handshakeContext(hs)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	tun.HandshakeDone()
	se.umu.Lock()
	se.up = tc
	se.umu.Unlock()
	se.mu.Lock()
	se.upSecure = true
	se.mu.Unlock()
	return nil
}

// handshakeContext bounds a TLS handshake.
//
// A context rather than a deadline on the connection: a deadline would have to
// be cleared afterwards, and a relay that forgot would kill a live session at an
// hour that looked like a network fault.
func handshakeContext(hs time.Duration) (context.Context, context.CancelFunc) {
	if hs <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), hs)
}

// dial opens the connection to the server.
func (t *server) dial(se *session) (net.Conn, error) {
	pool := t.host.Pool(t.tc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.tc.Upstream)
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: 10 * time.Second}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			continue
		}
		return c, nil
	}
	return nil, errors.New("no reachable tds endpoint")
}

// relay runs both directions once the connection is admitted.
func (t *server) relay(se *session) {
	if d := t.tc.SessionDuration.D(); d > 0 {
		_ = se.client.SetDeadline(time.Now().Add(d))
		_ = se.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("tds server reader")
		t.fromServer(se)
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("tds client reader")
		t.fromClient(se)
		_ = se.up.Close()
	}()
	wg.Wait()
}

// fromServer forwards the server's answers.
//
// Nothing is decided about them. The server's side of this protocol is result
// sets and tokens, and a relay with an opinion about those would be a data-loss
// filter rather than an access control -- a different product, and one that needs
// to understand every column type to avoid mangling a row.
func (t *server) fromServer(se *session) {
	for {
		p, err := se.srvReader.Next()
		if err != nil {
			return
		}
		if err := se.writeClient(wire.Frame(p.Type, p.SPID, p.Payload, se.size)); err != nil {
			return
		}
	}
}

// fromClient reads the client's messages and applies the policy.
func (t *server) fromClient(se *session) {
	for {
		if idle := t.tc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		p, err := se.cliReader.Next()
		if err != nil {
			return
		}
		ok, fatal := t.decide(se, p)
		if fatal {
			return
		}
		if !ok {
			continue
		}
		if err := se.writeUp(wire.Frame(p.Type, 0, p.Payload, se.size)); err != nil {
			return
		}
	}
}

// decide applies the policy to one client message.
func (t *server) decide(se *session, p wire.Packet) (ok, fatal bool) {
	if p.Reset {
		se.mu.Lock()
		se.resets++
		n := se.resets
		se.mu.Unlock()
		t.connectionReset(se, n)
	}
	d := t.policy.Message(se.sess(), p.Type)
	if !d.Allow {
		t.refused(se, d, wire.TypeName(p.Type))
		if t.enforcing() || d.Hard {
			if err := se.refuse(d); err != nil {
				return false, true
			}
			return false, false
		}
		return true, false
	}

	switch p.Type {
	case wire.TypeSQLBatch:
		text, err := wire.SQLText(p.Payload)
		if err != nil {
			// A batch whose text the relay could not decode. Forwarding it would
			// mean forwarding the one message on this protocol that carries
			// arbitrary SQL without having read any of it.
			hd := hardDeny("batch_unreadable", err.Error())
			t.refused(se, hd, "sql_batch")
			_ = se.refuse(hd)
			return false, false
		}
		return t.decideStatements(se, text, "sql_batch")

	case wire.TypeRPC:
		r, err := wire.ParseRPC(p.Payload)
		if err != nil {
			hd := hardDeny("rpc_unreadable", err.Error())
			t.refused(se, hd, "rpc")
			_ = se.refuse(hd)
			return false, false
		}
		proc := r.Procedure()
		if d := t.policy.Procedure(se.sess(), proc); !d.Allow {
			t.refused(se, d, proc)
			if t.enforcing() || d.Hard {
				if err := se.refuse(d); err != nil {
					return false, true
				}
				return false, false
			}
			return true, false
		}
		if r.HasStatement {
			// The statement inside sp_executesql gets the same policy a batch
			// gets. This is the point of the whole kind: without it the
			// statement policy would be inspecting the SET statements a driver
			// emits on connect and nothing an application runs.
			return t.decideStatements(se, r.Statement, proc)
		}
		return true, false
	}
	return true, false
}

// decideStatements classifies T-SQL and decides about every statement in it.
func (t *server) decideStatements(se *session, text, what string) (ok, fatal bool) {
	sts, lexed := sqlkind.Statements(sqlkind.TSQL, text, t.policy.MaxStatements(se.sess()))
	if !lexed {
		d := hardDeny("statement_unreadable", "")
		t.refused(se, d, what)
		_ = se.refuse(d)
		return false, false
	}
	for _, st := range sts {
		se.statements++
		d := t.policy.Statement(se.sess(), st, text)
		if d.Allow {
			continue
		}
		se.denied++
		t.refused(se, d, string(st.Kind))
		if t.enforcing() || d.Hard {
			if err := se.refuse(d); err != nil {
				return false, true
			}
			return false, false
		}
	}
	return true, false
}

// observe records what this connection said about the machine at the other end.
func (se *session) observe() {
	s := se.sess()
	se.t.host.ObserveAsset(assets.Observation{
		Proto:     "tds",
		Listener:  se.t.name,
		Addr:      se.ip,
		UserAgent: s.App,
		ClientID:  s.User,
		Hostname:  se.host,
	})
}
