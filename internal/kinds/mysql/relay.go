package mysql

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/sqlkind"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: mysql listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	mc     *config.MySQLListener
	policy *policy
	decoy  *decoy
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
	p, err := compile(cfg.MySQL)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, mc: cfg.MySQL, policy: p,
		ln: ln, tlsCfg: tlsCfg, upTLSMode: cfg.MySQL.UpstreamTLSMode,
		gate: sesslimit.New(cfg.MySQL.MaxSessions, cfg.MySQL.MaxSessionsPerClient)}
	if t.decoy, err = newDecoy(cfg.MySQL.Deception, cfg.Name); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	if t.upTLSMode == "" {
		t.upTLSMode = "require"
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(cfg.MySQL.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	if p.requireTLS && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: require_tls is set but the listener has no certificate", cfg.Name)
	}
	return t, nil
}

// enforcing says whether a policy decision here is applied or only written down.
//
// Two switches, and either is enough: this kind's own monitor_only, and the
// listener's policy: {mode: shadow}, which is the estate-wide spelling. This kind
// read only the first, so an operator who trialled its policy the way the
// reference documents got enforcement instead of a ledger.
func (t *server) enforcing() bool { return t.enforcement().Enforcing() }

// enforcement folds this listener's reasons not to enforce into one answer, so
// that the precedence, and the name a status view reports, are the same on
// every kind.
func (t *server) enforcement() config.Enforcement {
	e := config.Enforcement{Shadow: t.cfg.Shadowing(), MonitorOnly: t.mc.MonitorOnly}
	return e
}

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
			defer safe.Guard("mysql session")
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

var errRefused = errors.New("mysql: refused")

// handle runs one connection.
//
// MySQL's handshake runs the other way round from PostgreSQL's: the *server*
// speaks first, with a greeting that advertises its capabilities, and the client
// answers. That order is what makes the capability strip possible -- the relay
// reads the greeting, clears the bits the policy denies, and forwards the edited
// one, so the client negotiates against a narrower server than the real one.
func (t *server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	se := &session{t: t, ip: ip, client: c}

	if !t.admit(se) {
		return
	}
	defer t.release(se)

	hs := t.mc.HandshakeTimeout.D()
	if hs <= 0 {
		hs = 30 * time.Second
	}
	// A listener that is nothing but a fabricated server answers here, and
	// nothing is dialled: there is no server behind it to reach, which is also
	// why this is the one mode that needs no upstream. It speaks first, as the
	// protocol requires -- the greeting is the only packet a server sends
	// unprompted, and it is the packet every scanner reads.
	if d := t.decoy; d != nil && d.whole && d.admits(se.ip) {
		t.serveDecoy(se)
		return
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

// handshake reads the server's greeting, strips what the policy denies, forwards
// it, and decides about the client's answer.
func (t *server) handshake(se *session, hs time.Duration) error {
	_ = se.client.SetDeadline(time.Now().Add(hs))
	_ = se.up.SetDeadline(time.Now().Add(hs))
	defer func() {
		_ = se.client.SetDeadline(time.Time{})
		_ = se.up.SetDeadline(time.Time{})
	}()

	srv := wire.NewReader(se.up, t.policy.MaxMessage())
	srv.Lax()
	greet, err := srv.Next()
	if err != nil {
		t.deny(se.ip, "unreadable_greeting", err.Error())
		return errRefused
	}
	g, err := wire.ParseGreeting(greet.Payload)
	if err != nil {
		t.deny(se.ip, "unreadable_greeting", err.Error())
		return errRefused
	}
	se.serverCaps = g.Caps
	se.plugin = g.Plugin

	// A server that does not offer TLS cannot be made to, so a listener that
	// requires it has nothing to serve: refusing here is the honest answer, and
	// it names the server rather than the client.
	if t.policy.requireTLS && !g.Offers(wire.CapSSL) {
		t.deny(se.ip, "upstream_no_tls", g.Version)
		return errRefused
	}

	// Strip, and forward the edited greeting rather than the one that was read.
	payload := append([]byte(nil), greet.Payload...)
	cleared, err := wire.StripCaps(payload, t.policy.DenyCaps())
	if err != nil {
		t.deny(se.ip, "unreadable_greeting", err.Error())
		return errRefused
	}
	if cleared != 0 {
		se.stripped = cleared
		t.strippedCaps(se, cleared)
	}
	if err := se.writeClient(wire.Frame(greet.Seq, payload)); err != nil {
		return err
	}

	// The client's answer. With CLIENT_SSL it is the short 32-octet form,
	// followed by a TLS handshake and then the whole thing again.
	cli := wire.NewReader(se.client, t.policy.MaxMessage())
	cli.Lax()
	first, err := cli.Next()
	if err != nil {
		t.deny(se.ip, "unreadable_login", err.Error())
		return errRefused
	}
	l, err := wire.ParseLogin(first.Payload)
	if err != nil {
		t.deny(se.ip, "unreadable_login", err.Error())
		return errRefused
	}
	if l.SSLOnly {
		if t.tlsCfg == nil {
			t.deny(se.ip, "tls_required", "the listener has no certificate")
			return errRefused
		}
		if err := t.clearClaimedCaps(se, &first, l); err != nil {
			t.deny(se.ip, "unreadable_login", err.Error())
			return errRefused
		}
		// The short form goes upstream too, because the server has to know the
		// client is upgrading -- and then both legs are encrypted
		// independently.
		if err := se.upgrade(t.tlsCfg, first, hs); err != nil {
			t.deny(se.ip, "tls_handshake_failed", err.Error())
			return errRefused
		}
		cli = wire.NewReader(se.client, t.policy.MaxMessage())
		cli.Lax()
		if first, err = cli.Next(); err != nil {
			t.deny(se.ip, "unreadable_login", err.Error())
			return errRefused
		}
		if l, err = wire.ParseLogin(first.Payload); err != nil {
			t.deny(se.ip, "unreadable_login", err.Error())
			return errRefused
		}
	}
	if err := t.clearClaimedCaps(se, &first, l); err != nil {
		t.deny(se.ip, "unreadable_login", err.Error())
		return errRefused
	}
	se.clientCaps = l.Caps
	se.user, se.database = l.User, l.Database
	if l.Plugin != "" {
		se.plugin = l.Plugin
	}
	if l.Attrs != nil {
		se.program = l.Attrs["program_name"]
		if se.program == "" {
			se.program = l.Attrs["_client_name"]
		}
	}
	se.cliReader, se.srvReader = cli, srv

	// The estate's own authorisation policy first, because it is the broader
	// question: whether this account may reach this server at all, rather than
	// what the connection may then run. It is asked here because the login
	// packet is the first place an account appears -- this relay never sees the
	// password, only the handshake around it -- and before the login is
	// forwarded.
	if reason := t.admitByPolicy(se); reason != "" {
		se.fatal(Decision{Reason: reason}, first.Seq+1)
		return errRefused
	}
	d := t.policy.Login(se.sess(), l)
	if !d.Allow && (t.enforcing() || d.Hard) {
		t.refused(se, d, "connect")
		se.fatal(d, first.Seq+1)
		return errRefused
	}
	if !d.Allow {
		t.refused(se, d, "connect")
	}
	if d = t.policy.Auth(se.sess(), se.plugin); !d.Allow && (t.enforcing() || d.Hard) {
		t.refused(se, d, "auth")
		se.fatal(d, first.Seq+1)
		return errRefused
	} else if !d.Allow {
		t.refused(se, d, "auth")
	}
	se.observe()

	// Forward the login and let the authentication exchange run.
	if err := se.writeUp(wire.Frame(first.Seq, first.Payload)); err != nil {
		return err
	}
	return nil
}

// clearClaimedCaps takes the denied capabilities out of the client's handshake
// response before it is forwarded.
//
// Stripping the server's greeting is only half of it. The server decides what
// this connection may do by reading the client's capability field, not by
// intersecting it with the greeting it sent, so a client that sets
// CLIENT_LOCAL_FILES or CLIENT_MULTI_STATEMENTS has them whatever the greeting
// said -- and a client is whatever the peer wrote, not a cooperative driver. The
// bits are cleared here so that the server is told what the relay decided rather
// than what the peer asked for.
//
// Cleared rather than refused, for the reason StripCaps gives: Go's MySQL driver
// sets CLIENT_LOCAL_FILES unconditionally and gates the feature in its own
// configuration, so refusing would break ordinary applications. The event is
// recorded at deny level all the same, because a client whose bits had to be
// cleared read an edited greeting and overrode it.
//
// The packet is replaced with a copy: the payload belongs to the reader's buffer
// and the relay must not write through it.
func (t *server) clearClaimedCaps(se *session, p *wire.Packet, l *wire.Login) error {
	deny := t.policy.DenyCaps()
	if l.Caps&deny == 0 {
		return nil
	}
	payload := append([]byte(nil), p.Payload...)
	cleared, err := wire.ClearLoginCaps(payload, deny)
	if err != nil {
		return err
	}
	p.Payload = payload
	l.Caps &^= cleared
	se.claimed |= cleared
	t.overriddenCaps(se, cleared)
	return nil
}

// admitByPolicy is the estate's authorisation policy: the reason to refuse, or
// empty to carry on.
//
// The target is the upstream pool's name -- the server is chosen by balancer
// after this point -- and the user is the account the login packet named. MySQL
// gives the relay no principal and no group membership it could verify, so a
// rule about a team is a rule listing accounts, and what may be reached inside
// the server is the `mysql` policy's own business.
func (t *server) admitByPolicy(se *session) string {
	s := se.sess()
	return t.host.Authorization().Ask(authorization.Subject{
		Listener: t.name,
		Kind:     "mysql",
		Client:   se.ip,
		User:     s.User,
		Target:   t.mc.Upstream,
		Action:   authorization.ActionConnect,
	}, textsafe.Clip64(s.User), authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		// Record goes straight to wouldRefuse rather than through refused,
		// which would count a real refusal when the policy is shadowed and this
		// listener is not.
		Record: func(reason, rule, detail string) {
			t.wouldRefuse(Decision{Reason: reason, Rule: rule, Detail: detail}, "connect")
		},
		Deny: func(reason, rule, detail string) {
			t.refused(se, Decision{Reason: reason, Rule: rule, Detail: detail}, "connect")
		},
	})
}

// dial opens the connection to the server, upgrading the leg to TLS when the
// mode asks for it.
func (t *server) dial(se *session) (net.Conn, error) {
	pool := t.host.Pool(t.mc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.mc.Upstream)
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
	return nil, errors.New("no reachable mysql endpoint")
}

// relay runs both directions once the connection is admitted.
func (t *server) relay(se *session) {
	if d := t.mc.SessionDuration.D(); d > 0 {
		_ = se.client.SetDeadline(time.Now().Add(d))
		_ = se.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("mysql server reader")
		t.fromServer(se)
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("mysql client reader")
		t.fromClient(se)
		_ = se.up.Close()
	}()
	wg.Wait()
}

// fromServer forwards the server's answers, and refuses the one that asks the
// client for a file.
func (t *server) fromServer(se *session) {
	for {
		p, err := se.srvReader.Next()
		if err != nil {
			return
		}
		// The OK or error packet that ends the authentication exchange is what
		// tells the relay that the client's next packet is a command rather
		// than credential material.
		if !se.authed.Load() && len(p.Payload) > 0 &&
			(p.Payload[0] == wire.RespOK || p.Payload[0] == wire.RespErr) {
			se.authed.Store(true)
		}
		if path, ok := wire.LocalInfilePath(p.Payload); ok {
			d := t.policy.LocalInfile(se.sess(), path)
			if !d.Allow {
				// Hard, always: forwarding the request and writing down that it
				// was noticed means the file has already left the client.
				t.refused(se, d, "local_infile")
				// Answer the server with an empty file rather than closing, so
				// the connection survives and the statement simply fails --
				// which is what the client's driver reports.
				_ = se.writeUp(wire.Frame(p.Seq+1, nil))
				continue
			}
		}
		if err := se.writeClient(wire.Frame(p.Seq, p.Payload)); err != nil {
			return
		}
	}
}

// fromClient reads the client's commands and applies the policy.
func (t *server) fromClient(se *session) {
	for {
		if idle := t.mc.IdleTimeout.D(); idle > 0 {
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
		if err := se.writeUp(wire.Frame(p.Seq, p.Payload)); err != nil {
			return
		}
	}
}

// decide applies the policy to one client message.
func (t *server) decide(se *session, p wire.Packet) (ok, fatal bool) {
	// While the authentication exchange is still running the client's packets
	// are credential material rather than commands: a scramble's first octet is
	// not a command code, and a relay that read it as one would refuse every
	// connection using caching_sha2_password.
	//
	// The end of the exchange is not guessed at. The server says so, with the OK
	// packet that concludes it, and fromServer sets this when it sees one -- so
	// "is this a command" is answered by the protocol rather than by a sequence
	// number the relay hoped would be large enough.
	if !se.authed.Load() {
		return true, false
	}
	cmd, rest, has := p.Command()
	if !has {
		// A message with no command octet. The protocol defines none, and
		// forwarding it would mean forwarding something nobody decided about.
		t.deny(se.ip, "empty_command", "")
		return false, true
	}
	d := t.policy.Command(se.sess(), cmd)
	if !d.Allow {
		t.refused(se, d, wire.CommandName(cmd))
		if t.enforcing() || d.Hard {
			// The fabrication answers instead, for the clients it covers, and
			// only here: this is the path where the command has already been
			// kept from the server.
			if se.deceive(cmd, rest, p.Seq, d.Reason) {
				return false, false
			}
			if err := se.refuse(d, p.Seq+1); err != nil {
				return false, true
			}
			return false, false
		}
		return true, false
	}

	switch cmd {
	case wire.ComChangeUser:
		cu, err := wire.ReadChangeUser(rest, se.clientCaps)
		if err != nil {
			t.deny(se.ip, "unreadable_change_user", err.Error())
			return false, true
		}
		d = t.policy.ChangeUser(se.sess(), cu)
		if !d.Allow {
			t.refused(se, d, "change_user")
			if t.enforcing() || d.Hard {
				_ = se.refuse(d, p.Seq+1)
				return false, false
			}
		} else {
			// The identity has changed, so the policy's view of the session
			// changes with it -- otherwise every later decision is made about
			// the user who connected rather than the one now on the connection.
			se.setIdentity(cu.User, cu.Database, cu.Plugin)
			if ad := t.policy.Auth(se.sess(), cu.Plugin); !ad.Allow && (t.enforcing() || ad.Hard) {
				t.refused(se, ad, "auth")
				_ = se.refuse(ad, p.Seq+1)
				return false, false
			}
		}
		return true, false

	case wire.ComSetOption:
		on, readable := wire.SetOptionMultiStatements(rest)
		if d = t.policy.SetOption(se.sess(), on, readable); !d.Allow {
			t.refused(se, d, "set_option")
			if t.enforcing() || d.Hard {
				_ = se.refuse(d, p.Seq+1)
				return false, false
			}
		}
		return true, false

	case wire.ComQuery, wire.ComStmtPrepare:
		return t.decideStatements(se, string(rest), p.Seq)
	}
	return true, false
}

// decideStatements classifies a query's text and decides about every statement
// in it.
func (t *server) decideStatements(se *session, text string, seq byte) (ok, fatal bool) {
	sts, lexed := sqlkind.Statements(sqlkind.MySQL, text, t.policy.MaxStatements(se.sess()))
	if !lexed {
		d := hardDeny("statement_unreadable", "")
		t.refused(se, d, "lex")
		_ = se.refuse(d, seq+1)
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
			// The statement path is where the fabrication earns its place: the
			// reconnaissance of this protocol is all SELECTs and SHOWs, and a
			// refusal of one is a refusal the visitor learns from.
			if se.deceive(wire.ComQuery, []byte(text), seq, d.Reason) {
				return false, false
			}
			if err := se.refuse(d, seq+1); err != nil {
				return false, true
			}
			return false, false
		}
	}
	return true, false
}

// observe records what this connection said about the machine at the other end.
func (se *session) observe() {
	se.t.host.ObserveAsset(assets.Observation{
		Proto:     "mysql",
		Listener:  se.t.name,
		Addr:      se.ip,
		UserAgent: se.program,
		ClientID:  se.user,
	})
}

var _ = io.Discard
