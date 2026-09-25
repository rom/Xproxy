package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/respwire"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: redis listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	rc     *config.RedisListener
	policy *policy
	ln     net.Listener
	tlsCfg *tls.Config

	upTLSMode string
	upTLSCfg  *tls.Config

	live      atomic.Int64
	perClient sync.Map

	// sessions tracks what has been accepted, so shutdown waits for it. A bare
	// WaitGroup would not do: its Add must not race its Wait, and an accept loop
	// Adds at exactly the moment a shutdown Waits.
	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	p, err := compile(cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, rc: cfg.Redis, policy: p,
		ln: ln, tlsCfg: tlsCfg, upTLSMode: cfg.Redis.UpstreamTLSMode}
	if t.upTLSMode == "" {
		// Unlike the three database kinds, the honest default here is off. Redis
		// has no in-protocol upgrade to negotiate, so the relay cannot discover
		// whether the server speaks TLS: requiring it by default would refuse
		// every upstream in the common deployment rather than protecting
		// anything.
		t.upTLSMode = "disable"
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(cfg.Redis.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	if p.requireTLS && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: require_tls is set but the listener has no certificate", cfg.Name)
	}
	return t, nil
}

func (t *server) enforcing() bool { return !t.rc.MonitorOnly }

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
			defer safe.Guard("redis session")
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

// handle runs one connection.
//
// There is no handshake to read. Redis begins with the client's first command, and
// TLS -- where it is used -- was established by the listener before this is called.
// So the connection is admitted or refused on what the relay already knows, and
// then every command is decided one at a time.
func (t *server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	se := &session{t: t, ip: ip, client: c}

	// TLS from the first octet, which is the only form this protocol has: Redis
	// defines no in-protocol upgrade, so a TLS listener is a separate port and the
	// handshake is the first thing on the connection. The kind terminates it
	// rather than the engine, as the ldap and iec104 kinds do for their implicit
	// mode -- and it has to, or `require_tls` would be a setting nothing could
	// ever satisfy.
	if t.tlsCfg != nil {
		if err := t.upgradeClient(se); err != nil {
			t.deny(se.ip, "tls_handshake", err.Error())
			return
		}
	}

	if d := t.policy.Connect(se.sess()); !d.Allow {
		t.refused(se, d, "connect")
		_ = se.refuse(d)
		return
	}
	if !t.admit(se) {
		return
	}
	defer t.release(se)

	up, err := t.dial(se)
	if err != nil {
		t.deny(se.ip, "upstream_unavailable", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	se.up = up
	se.observe()

	se.cliReader = wire.NewReader(se.client, t.policy.MaxMessage(),
		t.policy.MaxBulk(), t.policy.MaxElements())
	t.relay(se)
}

func (t *server) admit(se *session) bool {
	if max := t.rc.MaxSessions; max > 0 && t.live.Load() >= int64(max) {
		t.deny(se.ip, "too_many_sessions", "")
		return false
	}
	if per := t.rc.MaxSessionsPerClient; per > 0 {
		v, _ := t.perClient.LoadOrStore(se.ip, new(atomic.Int64))
		n := v.(*atomic.Int64)
		if n.Load() >= int64(per) {
			t.deny(se.ip, "too_many_sessions_per_client", "")
			return false
		}
		n.Add(1)
	}
	t.live.Add(1)
	return true
}

func (t *server) release(se *session) {
	t.live.Add(-1)
	if v, ok := t.perClient.Load(se.ip); ok {
		if n := v.(*atomic.Int64).Add(-1); n <= 0 {
			t.perClient.Delete(se.ip)
		}
	}
}

// dial opens the connection to the server, upgrading the leg when the mode asks.
func (t *server) dial(se *session) (net.Conn, error) {
	pool := t.host.Pool(t.rc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.rc.Upstream)
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
			if t.upTLSMode == "require" {
				return nil, err
			}
			// prefer: the operator asked for this explicitly, and it is the one
			// place on this kind where a failed upgrade is not a refusal.
			continue
		}
		return tc, nil
	}
	return nil, errors.New("no reachable redis endpoint")
}

// upgradeClient terminates the client's TLS.
func (t *server) upgradeClient(se *session) error {
	hs := t.rc.HandshakeTimeout.D()
	if hs <= 0 {
		hs = 30 * time.Second
	}
	tc := tls.Server(se.client, t.tlsCfg)
	// A context rather than a deadline on the connection: a deadline would have to
	// be cleared afterwards, and a relay that forgot would kill a live session at
	// an hour that looked like a network fault.
	ctx, cancel := context.WithTimeout(context.Background(), hs)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	se.client = tc
	se.mu.Lock()
	se.secure = true
	se.mu.Unlock()
	return nil
}

func (t *server) upgradeUpstream(c net.Conn, address string) (net.Conn, error) {
	cfg := t.upTLSCfg.Clone()
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		cfg.ServerName = host
	}
	tc := tls.Client(c, cfg)
	hs := t.rc.HandshakeTimeout.D()
	if hs <= 0 {
		hs = 30 * time.Second
	}
	// A context rather than a deadline on the connection: a deadline would have to
	// be cleared afterwards, and a relay that forgot would kill a live session at
	// an hour that looked like a network fault.
	ctx, cancel := context.WithTimeout(context.Background(), hs)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}

// relay runs both directions.
func (t *server) relay(se *session) {
	if d := t.rc.SessionDuration.D(); d > 0 {
		_ = se.client.SetDeadline(time.Now().Add(d))
		_ = se.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("redis server reader")
		t.fromServer(se)
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("redis client reader")
		t.fromClient(se)
		_ = se.up.Close()
	}()
	wg.Wait()
}

// fromServer forwards the server's replies, and reads one thing out of them: what
// the server said about a credential.
//
// Nothing else is decided. A Redis reply is the data, and a relay with an opinion
// about it would be a data-loss filter rather than an access control -- a different
// product. What it does need is the *outcome* of an AUTH, because "has this
// connection authenticated" cannot be answered from the client's side: a relay that
// took the attempt as the answer would treat a wrong password as a login, which is
// the whole of what require_auth exists to prevent.
func (t *server) fromServer(se *session) {
	buf := make([]byte, 32<<10)
	for {
		n, err := se.up.Read(buf)
		if n > 0 {
			t.readAuthOutcome(se, buf[:n])
			if werr := se.writeClient(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// readAuthOutcome looks at the first octet of a reply while a credential is in
// flight.
//
// Only while one is in flight, and only the first octet, which is the reply's type
// marker: `-` is an error and anything else is not. That is a deliberately small
// claim. A relay that tried to parse the server's whole reply stream would be
// writing a second protocol reader whose disagreements with the first are the
// interesting bugs; what this needs to know is one bit, and the type marker of the
// reply that follows an AUTH answers it.
//
// It can be wrong in one direction: a reply that arrives split across two reads
// could put the marker at the start of neither. That would leave `pending` set and
// the connection unauthenticated, so the next command is refused -- the safe
// direction, and the client's own retry resolves it.
func (t *server) readAuthOutcome(se *session, b []byte) {
	if len(b) == 0 {
		return
	}
	u := se.pending.Load()
	if u == nil {
		return
	}
	if b[0] == wire.TypeError {
		user := *u
		se.authFailed()
		t.authFailure(se, user)
		return
	}
	se.authOK()
}

// fromClient reads the client's commands and applies the policy.
func (t *server) fromClient(se *session) {
	max := t.policy.MaxCommands(se.sess())
	for {
		if idle := t.rc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		c, err := se.cliReader.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				// A message that is not RESP. The relay answers the way the
				// server would, because a client library reports a protocol
				// error and reconnects rather than hanging.
				t.deny(se.ip, "unreadable_command", err.Error())
				_ = se.writeClient(wire.Error("ERR", "Protocol error: "+err.Error()))
			}
			return
		}
		se.commands++
		if max > 0 && se.commands > max {
			d := hardDeny("too_many_commands", strconv.Itoa(max))
			t.refused(se, d, c.String())
			_ = se.refuse(d)
			return
		}
		ok, fatal := t.decide(se, c)
		if fatal {
			return
		}
		if !ok {
			continue
		}
		if err := se.writeUp(c.Raw); err != nil {
			return
		}
	}
}

// decide applies the policy to one command.
func (t *server) decide(se *session, c *wire.Command) (ok, fatal bool) {
	d := t.policy.Command(se.sess(), c)
	if !d.Allow {
		if d.Reason == "key_position_unknown" {
			t.keyPositionUnknown(se, c.String())
		}
		se.denied++
		t.refused(se, d, c.String())
		if t.enforcing() || d.Hard {
			if err := se.refuse(d); err != nil {
				return false, true
			}
			return false, false
		}
		return true, false
	}

	switch c.Name {
	case "AUTH", "HELLO":
		user, carries := credential(c)
		if !carries {
			// A HELLO without an AUTH clause is a protocol handshake and nothing
			// else, so there is no credential to expect an answer about.
			return true, false
		}
		if ad := t.policy.Auth(se.sess(), user); !ad.Allow {
			t.refused(se, ad, "auth")
			if t.enforcing() || ad.Hard {
				_ = se.refuse(ad)
				return false, false
			}
		}
		// Recorded as pending, confirmed only when the server accepts it.
		se.expectAuth(user)
		return true, false

	case "SELECT":
		if len(c.Args) != 1 {
			return true, false
		}
		db, err := strconv.Atoi(string(c.Args[0]))
		if err != nil {
			// Redis refuses this itself; the relay does not need to guess a
			// database number, and must not record one it invented.
			return true, false
		}
		if sd := t.policy.SelectDB(se.sess(), db); !sd.Allow {
			t.refused(se, sd, "select")
			if t.enforcing() || sd.Hard {
				_ = se.refuse(sd)
				return false, false
			}
		}
		se.setDatabase(db)
		return true, false
	}
	return true, false
}

// credential reads the user an AUTH or HELLO is authenticating as, and whether one
// is present at all.
//
// The forms differ and both are in use:
//
//	AUTH password                 no user named: Redis authenticates `default`
//	AUTH username password        the ACL form
//	HELLO 3 AUTH username password
//	HELLO 3                       no credential at all
//
// The password is never read. What the policy decides is which identity may be
// attempted, and the relay has no use for the secret -- holding one would put it a
// careless log line away from disk in exchange for nothing.
func credential(c *wire.Command) (user string, carries bool) {
	if c.Name == "AUTH" {
		switch len(c.Args) {
		case 1:
			return "default", true
		case 2:
			return wire.Clip(string(c.Args[0])), true
		}
		return "", false
	}
	// HELLO: find an AUTH token followed by two arguments.
	for i := 0; i+2 < len(c.Args); i++ {
		if equalFold(c.Args[i], "AUTH") {
			return wire.Clip(string(c.Args[i+1])), true
		}
	}
	return "", false
}

func equalFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		x, y := b[i], s[i]
		if x >= 'a' && x <= 'z' {
			x -= 32
		}
		if y >= 'a' && y <= 'z' {
			y -= 32
		}
		if x != y {
			return false
		}
	}
	return true
}

// observe records what this connection said about the machine at the other end.
func (se *session) observe() {
	se.t.host.ObserveAsset(assets.Observation{
		Proto:    "redis",
		Listener: se.t.name,
		Addr:     se.ip,
	})
}
