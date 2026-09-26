package postgres

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
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	wire "github.com/rom/xproxy/internal/pgwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: postgres listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	pc     *config.PostgresListener
	policy *policy
	ln     net.Listener
	tlsCfg *tls.Config

	// upTLS is how the relay speaks to the server.
	upTLSMode string
	upTLSCfg  *tls.Config

	// gate bounds the sessions held, altogether and per client address.
	gate *sesslimit.Gate

	// sessions tracks what has been accepted, so shutdown waits for it. A bare
	// WaitGroup would not do: its Add must not race its Wait, and an accept loop
	// Adds at exactly the moment a shutdown Waits.
	sessions acceptgroup.Group
	done     chan struct{}
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	p, err := compile(cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, pc: cfg.Postgres,
		policy: p, ln: ln, tlsCfg: tlsCfg, done: make(chan struct{}),
		upTLSMode: cfg.Postgres.UpstreamTLSMode,
		gate:      sesslimit.New(cfg.Postgres.MaxSessions, cfg.Postgres.MaxSessionsPerClient)}
	if t.upTLSMode == "" {
		// A relay that terminated TLS from the client and then spoke plaintext
		// to the server would have moved the exposure rather than removed it.
		t.upTLSMode = "require"
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(cfg.Postgres.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	// A listener that requires TLS from its clients and has no certificate
	// cannot serve anybody: refusing at load is the honest place to say so,
	// because the alternative is every connection failing at handshake with a
	// message about a certificate in a log nobody is reading yet.
	if p.requireTLS && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: require_tls is set but the listener has no certificate", cfg.Name)
	}
	return t, nil
}

func (t *server) enforcing() bool { return !t.pc.MonitorOnly }

func (t *server) alerts() bool { return true }

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
			defer safe.Guard("postgres session")
			t.handle(c)
		}()
	}
}

func (t *server) shutdown(ctx context.Context) {
	if !t.sessions.Close() {
		return
	}
	close(t.done)
	_ = t.ln.Close()
	t.sessions.Wait(ctx)
}

// handle runs one connection through its three phases.
func (t *server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	se := &session{t: t, ip: ip, client: c}

	if !t.admit(se) {
		return
	}
	defer t.release(se)

	hs := t.pc.HandshakeTimeout.D()
	if hs <= 0 {
		hs = 30 * time.Second
	}
	if err := t.negotiate(se, hs); err != nil {
		if !errors.Is(err, errRefused) {
			t.deny(ip, "handshake_failed", err.Error())
		}
		return
	}
	t.relay(se)
}

var errRefused = errors.New("postgres: refused")

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

// negotiate handles the encryption request, which is the first thing a client
// sends and is not a startup packet.
//
// The relay answers it itself. Forwarding it would mean the *server's* answer
// decided whether this connection is readable by anybody on the path -- and
// that answer is one unsigned octet, which is exactly what a man in the middle
// rewrites. A client with libpq's default sslmode=prefer then continues in the
// clear without telling anybody.
func (t *server) negotiate(se *session, hs time.Duration) error {
	_ = se.client.SetDeadline(time.Now().Add(hs))
	defer func() { _ = se.client.SetDeadline(time.Time{}) }()

	rd := wire.NewReader(se.client, wire.FromClient, t.policy.maxMessage)
	s, raw, err := rd.ReadStartup()
	if err != nil {
		t.deny(se.ip, "unreadable_startup", err.Error())
		return errRefused
	}
	switch s.Code {
	case wire.SSLRequest:
		if t.tlsCfg == nil {
			// Nothing to upgrade to. Refusing the request is the one case
			// where answering 'N' is right, because the alternative is
			// promising an upgrade this listener cannot perform.
			if t.policy.requireTLS {
				t.deny(se.ip, "tls_required", "the listener has no certificate")
				return errRefused
			}
			if err := se.writeClient([]byte{wire.DenyTLS}); err != nil {
				return err
			}
			return t.afterNegotiate(se, hs)
		}
		if err := se.upgrade(t.tlsCfg, hs); err != nil {
			t.deny(se.ip, "tls_handshake_failed", err.Error())
			return errRefused
		}
		return t.afterNegotiate(se, hs)

	case wire.GSSEncRequest:
		// GSSAPI encryption is a thing this relay does not do, and the honest
		// answer is to say no rather than to accept and then not encrypt.
		// A client that asked will fall back to an SSLRequest, which is the
		// path the relay does support.
		if err := se.writeClient([]byte{wire.DenyTLS}); err != nil {
			return err
		}
		return t.afterNegotiate(se, hs)

	case wire.CancelRequest:
		d := t.policy.Cancel(&Session{IP: se.ip, At: time.Now()})
		if !d.Allow {
			t.refused(se, d, "cancel")
			return errRefused
		}
		// A cancel request is forwarded whole and the connection then closes,
		// which is what the protocol says happens: the server answers nothing.
		return t.forwardCancel(se, raw)

	case wire.Version3:
		// A startup packet with no encryption request at all: the client did
		// not even ask. That is sslmode=disable, and it is the case
		// require_tls exists for.
		return t.startupWith(se, s, raw, hs)
	}
	t.deny(se.ip, "unreadable_startup", "")
	return errRefused
}

// afterNegotiate reads the startup packet that follows an encryption exchange.
func (t *server) afterNegotiate(se *session, hs time.Duration) error {
	rd := wire.NewReader(se.client, wire.FromClient, t.policy.maxMessage)
	s, raw, err := rd.ReadStartup()
	if err != nil {
		t.deny(se.ip, "unreadable_startup", err.Error())
		return errRefused
	}
	if s.Code != wire.Version3 {
		// A second encryption request, or a cancel after an upgrade. Neither
		// is a thing a client legitimately does here, and forwarding it would
		// mean forwarding a message out of its place in the protocol.
		t.deny(se.ip, "startup_out_of_order", fmt.Sprintf("code %d", s.Code))
		return errRefused
	}
	return t.startupWith(se, s, raw, hs)
}

// startupWith decides about the identity in the startup packet and keeps it.
func (t *server) startupWith(se *session, s *wire.Startup, raw []byte, hs time.Duration) error {
	se.user = s.User()
	se.database = s.Database()
	se.app = s.Get("application_name")
	se.startupRaw = raw
	se.hs = hs
	// The estate's own authorisation policy first, because it is the broader
	// question: whether this role may reach this database at all, rather than
	// what the connection may then do. It is asked here because the startup
	// packet is the first and only place a role appears -- this relay never
	// sees the password -- and before the server is dialled.
	if reason := t.admitByPolicy(se); reason != "" {
		se.fatal(Decision{Reason: reason})
		return errRefused
	}
	d := t.policy.Startup(&Session{IP: se.ip, User: se.user, Database: se.database,
		App: se.app, Secure: se.secure, At: time.Now()}, s)
	if !d.Allow && (t.enforcing() || d.Hard) {
		t.refused(se, d, "connect")
		se.fatal(d)
		return errRefused
	}
	if !d.Allow {
		t.refused(se, d, "connect")
	}
	se.observe()
	return nil
}

// admitByPolicy is the estate's authorisation policy: the reason to refuse, or
// empty to carry on.
//
// The target is the upstream pool's name -- the server is chosen by balancer
// after this point -- and the user is the role the startup packet named. Neither
// a principal nor groups reaches a rule here: PostgreSQL gives the relay a role
// name and nothing it could verify about who holds it, so a rule about a team is
// a rule listing roles.
//
// A rule about the database is written with `not_targets` and `targets` on the
// pool, not on the database name: what may be reached inside the server is the
// `postgres` policy's own business, and it is the thing that can say what a
// database means.
//
// The refusal goes through this relay's own refused path, so a listener in
// shadow mode records it like every other decision here, and the policy's own
// shadow switch does the same on a listener that enforces.
func (t *server) admitByPolicy(se *session) string {
	return t.host.Authorization().Ask(authorization.Subject{
		Listener: t.name,
		Kind:     "postgres",
		Client:   se.ip,
		User:     se.user,
		Target:   t.pc.Upstream,
		Action:   authorization.ActionConnect,
	}, textsafe.Clip64(se.user), authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		// Record goes straight to wouldRefuse rather than through refused,
		// which would count a real refusal when the policy is shadowed and this
		// listener is not.
		Record: func(reason, rule, detail string) {
			t.wouldRefuse(se, Decision{Reason: reason, Rule: rule, Detail: detail}, "connect")
		},
		Deny: func(reason, rule, detail string) {
			t.refused(se, Decision{Reason: reason, Rule: rule, Detail: detail}, "connect")
		},
	})
}

// forwardCancel sends a cancel request on and closes.
func (t *server) forwardCancel(se *session, raw []byte) error {
	up, err := t.dial(se)
	if err != nil {
		return err
	}
	defer func() { _ = up.Close() }()
	_, err = up.Write(raw)
	return err
}

// dial opens the connection to the server, with TLS if the upstream leg wants
// it -- which means speaking the same eight-octet negotiation as a client,
// because that is the only way this protocol starts TLS.
func (t *server) dial(se *session) (net.Conn, error) {
	pool := t.host.Pool(t.pc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.pc.Upstream)
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
		if t.upTLSMode == "disable" {
			return c, nil
		}
		tc, err := t.upgradeUpstream(c, e.Address)
		if err != nil {
			_ = c.Close()
			pool.End(e, true, 0)
			t.host.Logs().Error.Warn("postgres upstream tls failed", "listener", t.name,
				"endpoint", e.Address, "error", err.Error())
			continue
		}
		return tc, nil
	}
	return nil, errors.New("no reachable postgres endpoint")
}

// upgradeUpstream asks the server for TLS the way a client does, and refuses a
// server that says no when the mode is require.
func (t *server) upgradeUpstream(c net.Conn, address string) (net.Conn, error) {
	req := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	var ans [1]byte
	if _, err := io.ReadFull(c, ans[:]); err != nil {
		return nil, err
	}
	switch ans[0] {
	case wire.AllowTLS:
		if t.upTLSCfg == nil {
			return nil, errors.New("postgres: upstream tls without a configuration")
		}
		cfg := t.upTLSCfg.Clone()
		if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			cfg.ServerName = host
		}
		tc := tls.Client(c, cfg)
		// A context rather than a deadline on the connection: a deadline would
		// have to be cleared afterwards, and a relay that forgot would kill a
		// live session at an hour that looked like a network fault.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tc, nil
	case wire.DenyTLS:
		if t.upTLSMode == "require" {
			// This is the downgrade, on the leg the relay controls. Refusing
			// it is the whole point of the setting.
			return nil, fmt.Errorf("postgres: %s refused tls and upstream_tls_mode is require", address)
		}
		return c, nil
	}
	return nil, fmt.Errorf("postgres: %s answered %q to an ssl request", address, ans[0])
}

// relay runs the two directions once a connection is admitted.
func (t *server) relay(se *session) {
	up, err := t.dial(se)
	if err != nil {
		t.deny(se.ip, "upstream_unavailable", err.Error())
		se.fatal(Decision{Reason: "upstream_unavailable"})
		return
	}
	defer func() { _ = up.Close() }()
	se.up = up

	// The startup packet goes on as the octets the client sent. Re-encoding it
	// would mean deciding about one message and forwarding another.
	if _, err := up.Write(se.startupRaw); err != nil {
		return
	}
	if d := t.pc.SessionDuration.D(); d > 0 {
		_ = se.client.SetDeadline(time.Now().Add(d))
		_ = up.SetDeadline(time.Now().Add(d))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("postgres session")
		t.fromServer(se)
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("postgres session")
		t.fromClient(se)
		_ = up.Close()
	}()
	wg.Wait()
}

// fromServer reads the backend's messages, which is where the relay learns
// whether authentication succeeded and by what method.
func (t *server) fromServer(se *session) {
	rd := wire.NewReader(se.up, wire.FromServer, t.policy.maxMessage)
	for {
		m, err := rd.Next()
		if err != nil {
			return
		}
		switch m.Type {
		case wire.MsgAuthentication:
			code, err := m.AuthRequest()
			if err != nil {
				t.deny(se.ip, "unreadable_message", "authentication")
				return
			}
			if code == wire.AuthOK {
				se.authed.Store(true)
			} else {
				d := t.policy.Auth(&Session{IP: se.ip, User: se.user,
					Database: se.database, Secure: se.secure, At: time.Now()}, code)
				if !d.Allow && (t.enforcing() || d.Hard) {
					t.refused(se, d, "auth")
					se.fatal(d)
					return
				}
				if !d.Allow {
					t.refused(se, d, "auth")
				}
			}
		case wire.MsgBackendKeyData:
			if pid, secret, err := m.BackendKey(); err == nil {
				se.backendPID.Store(pid)
				se.backendSecret.Store(secret)
			}
		case wire.MsgCopyInResponse, wire.MsgCopyOutResponse, wire.MsgCopyBothRespons:
			// A COPY is in progress: the stream now carries CopyData, which is
			// bulk data rather than messages a policy has anything to say
			// about. The decision was made on the statement.
			se.setCopy(true)
		case wire.MsgReadyForQuery:
			se.setCopy(false)
		}
		if err := se.writeClient(m.Raw()); err != nil {
			return
		}
	}
}

// fromClient reads the frontend's messages and applies the policy.
func (t *server) fromClient(se *session) {
	rd := wire.NewReader(se.client, wire.FromClient, t.policy.maxMessage)
	for {
		if idle := t.pc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		m, err := rd.Next()
		if err != nil {
			return
		}
		ok, fatal := t.decide(se, m)
		if fatal {
			return
		}
		if !ok {
			continue
		}
		if _, err := se.up.Write(m.Raw()); err != nil {
			return
		}
	}
}

// decide applies the policy to one frontend message. ok says forward it; fatal
// says end the connection.
func (t *server) decide(se *session, m wire.Message) (ok, fatal bool) {
	// While a COPY is in progress the client's messages are the data, and the
	// decision was already made on the statement that started it.
	if se.copying() && (m.Type == wire.MsgCopyData || m.Type == wire.MsgCopyDone || m.Type == wire.MsgCopyFail) {
		return true, false
	}
	switch m.Type {
	case wire.MsgPasswordMessage, wire.MsgSync, wire.MsgFlush, wire.MsgTerminate,
		wire.MsgClose, wire.MsgDescribe, wire.MsgCopyData, wire.MsgCopyDone, wire.MsgCopyFail:
		// The authentication answer and the housekeeping messages. None of
		// them names a statement, and a relay that had an opinion about a
		// Sync would be a relay that breaks every driver.
		return true, false

	case wire.MsgFunctionCall:
		d := t.policy.FunctionCall(se.sess())
		if !d.Allow && (t.enforcing() || d.Hard) {
			t.refused(se, d, "function_call")
			_ = se.refuse(d, "function_call")
			return false, false
		}
		if !d.Allow {
			t.refused(se, d, "function_call")
		}
		return true, false

	case wire.MsgQuery:
		text, err := m.QueryText()
		if err != nil {
			t.deny(se.ip, "unreadable_message", "query")
			return false, true
		}
		return t.decideStatements(se, text, "")

	case wire.MsgParse:
		p, err := m.ReadParse()
		if err != nil {
			t.deny(se.ip, "unreadable_message", "parse")
			return false, true
		}
		fwd, _ := t.decideStatements(se, p.Statement, p.Name)
		return fwd, false

	case wire.MsgBind:
		b, err := m.ReadBind()
		if err != nil {
			t.deny(se.ip, "unreadable_message", "bind")
			return false, true
		}
		// A Bind names a prepared statement the relay has already decided
		// about at Parse time. Deciding again here is what catches a client
		// that binds a statement the relay never saw -- which on a pooled
		// connection is how one application's prepared statement gets executed
		// by another.
		if st, known := se.recall(b.Statement); known {
			return t.decideOne(se, st, "")
		}
		return true, false

	case wire.MsgExecute:
		return true, false
	}
	// A frontend message this relay does not recognise. Forwarding it would
	// mean forwarding something nobody has decided about, on a protocol where
	// the client chose the octet -- so it is refused, and named.
	t.deny(se.ip, "unknown_message", m.Name())
	return false, true
}

// decideStatements classifies the text of a Query or a Parse and decides about
// every statement in it.
func (t *server) decideStatements(se *session, text, prepName string) (ok, fatal bool) {
	if !se.authed.Load() {
		// A statement before the server said AuthenticationOk. There is no
		// legitimate one, and forwarding it would mean asking the database to
		// run something for a connection it has not agreed to serve.
		t.deny(se.ip, "statement_before_auth", "")
		return false, true
	}
	maxStmt := t.policy.maxStatements
	if r := t.policy.match(se.sess()); r != nil && r.maxStmt > 0 {
		maxStmt = r.maxStmt
	}
	sts, lexed := wire.Statements(text, maxStmt)
	if !lexed {
		// Text the relay could not lex. The server would read a different
		// statement from the one the relay decided about, and disagreeing
		// about where a statement ends is how one gets past a relay.
		d := hardDeny("statement_unreadable", "")
		t.refused(se, d, "lex")
		_ = se.refuse(d, "")
		return false, false
	}
	for _, st := range sts {
		if fwd, f := t.decideOne(se, st, text); !fwd {
			return false, f
		}
	}
	if prepName != "" || len(sts) == 1 {
		// Remember what a prepared statement is, so a later Bind can be
		// decided for the statement it runs.
		se.remember(prepName, sts[0])
	}
	return true, false
}

// decideOne decides about one classified statement.
func (t *server) decideOne(se *session, st wire.Statement, text string) (ok, fatal bool) {
	se.statements++
	d := t.policy.Statement(se.sess(), st, text)
	if d.Allow {
		return true, false
	}
	se.denied++
	t.refused(se, d, string(st.Kind))
	if t.enforcing() || d.Hard {
		if err := se.refuse(d, string(st.Kind)); err != nil {
			return false, true
		}
		return false, false
	}
	return true, false
}

// sess builds the policy's view of this connection.
func (se *session) sess() *Session {
	return &Session{IP: se.ip, User: se.user, Database: se.database,
		App: se.app, Secure: se.secure, At: time.Now()}
}
