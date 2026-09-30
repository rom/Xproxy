package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/respwire"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
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
	p, err := compile(cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, rc: cfg.Redis, policy: p,
		ln: ln, tlsCfg: tlsCfg, upTLSMode: cfg.Redis.UpstreamTLSMode,
		gate: sesslimit.New(cfg.Redis.MaxSessions, cfg.Redis.MaxSessionsPerClient)}
	if t.decoy, err = newDecoy(cfg.Redis.Deception, cfg.Name); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
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

// enforcing says whether a policy decision here is applied or only written down.
//
// Two switches, and either is enough: this kind's own monitor_only, and the
// listener's policy: {mode: shadow}, which is the estate-wide spelling every
// other kind honours. This kind honoured only the first, so an operator who
// trialled a redis policy the documented way got enforcement.
func (t *server) enforcing() bool { return !t.rc.MonitorOnly && !t.cfg.Shadowing() }

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

// admitClient is the two questions this relay asks about a client before it
// carries anything for it: do the imported lists know this address, and does the
// estate's authorisation policy allow it here.
//
// Asked on the connection, where there is no name yet. Redis begins with the
// client's first command, so at this point the relay knows the address, the
// listener, the pool and the hour and nothing else -- and a rule naming users
// matches nobody here. The name arrives later and gets its own question, in
// admitUser below, which is the interesting one on this kind.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists: h.ThreatIntel(),
		// A behaviour pack holding this address out, where one is.
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "redis",
		Client:   ip,
		Target:   t.rc.Upstream,
		Action:   authorization.ActionConnect,
	}, t.admitGate(ip))
}

// admitUser is the estate's policy asked again, about the name -- and this is the
// one place on any relay here where the name has been *proven* before the policy
// sees it.
//
// Everywhere else a relay asks, the client's login is an assertion: postgres,
// mysql and tds are asked at the startup or login packet, before the server has
// said whether the password was right, so an allow rule there is a filter on a
// claim. Here the question is asked when the server's own answer to an AUTH or
// HELLO says the credential was accepted. So an allow rule keyed on `users` on
// this kind is an authenticated grant, which is worth saying out loud because it
// is not true of its siblings.
//
// The cost of that is where the refusal lands. The server has already seen the
// credential by the time this is asked -- it had to, or there would be nothing to
// prove the name -- so a refusal here does not keep the session off the server the
// way postgres's does. What it keeps off is every command of the client's: the
// acceptance is never forwarded and the connection ends. That is the same trade
// rdp and ftp make, and for the same reason: it is a fact about the protocol
// rather than a choice.
//
// The action is `session` rather than `connect`, and that distinction is the whole
// of what makes the two questions writable apart. The connection itself is
// `connect`, asked before any name exists, so a rule about people cannot match it
// and an estate covers it with `networks`. The authenticated session is `session`,
// and that is where a rule naming users belongs:
//
//   - {name: door,  allow: true, networks: ["10.0.0.0/8"], actions: [connect]}
//   - {name: staff, allow: true, users: [bob],             actions: [session]}
//
// Without two actions the second ask would be answered by whatever rule let the
// connection in, and the proven name would decide nothing.
func (t *server) admitUser(se *session) string {
	h := t.host
	s := se.sess()
	return t.host.Authorization().Ask(authorization.Subject{
		Listener: t.name,
		Kind:     "redis",
		Client:   se.ip,
		User:     s.User,
		Target:   t.rc.Upstream,
		Action:   authorization.ActionSession,
	}, s.User, authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("redis", reason)
			h.Shadow().Record("redis", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(se.ip, reason, detail) },
	})
}

// admitGate is what this kind lends internal/admit so a refusal made there is counted,
// logged and banned on exactly as one this file made itself.
func (t *server) admitGate(ip netip.Addr) admit.Gate {
	h := t.host
	return admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("redis", reason)
			h.Shadow().Record("redis", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	}
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
	// The imported lists and the estate's authorisation policy, after this
	// kind's own client list -- that is local policy about local clients, and a
	// feed must not overrule an allow rule an operator wrote -- and before the
	// server is dialled.
	if t.admitClient(se.ip) != "" {
		return
	}
	if !t.admit(se) {
		return
	}
	defer t.release(se)

	// A listener that is nothing but a fabricated server answers here, and
	// nothing is dialled: there is no server behind it to reach, which is also
	// why this is the one mode that needs no upstream.
	if d := t.decoy; d != nil && d.whole && d.admits(se.ip) {
		se.cliReader = wire.NewReader(se.client, t.policy.MaxMessage(),
			t.policy.MaxBulk(), t.policy.MaxElements())
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
	se.observe()

	se.cliReader = wire.NewReader(se.client, t.policy.MaxMessage(),
		t.policy.MaxBulk(), t.policy.MaxElements())
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
			if t.readAuthOutcome(se, buf[:n]) {
				// The estate's policy refused the name the server accepted. The
				// acceptance is not forwarded and the connection ends, so the
				// client never sees a login it may not use -- and nothing that
				// arrived in the same read is carried either, which is the safe
				// direction when a buffer may hold pipelined replies behind it.
				return
			}
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
//
// It reports whether the estate's policy refused the name the server has just
// accepted, in which case the caller must not forward the acceptance.
func (t *server) readAuthOutcome(se *session, b []byte) (refused bool) {
	if len(b) == 0 {
		return false
	}
	u := se.pending.Load()
	if u == nil {
		return false
	}
	if b[0] == wire.TypeError {
		user := *u
		se.authFailed()
		t.authFailure(se, user)
		return false
	}
	se.authOK()
	// The name is proven now, so the estate's policy is asked about it. This is
	// after the server accepted the credential, which is the only order the
	// protocol allows: a name nobody has checked is the thing the policy on the
	// database relays has to make do with, and here it does not have to.
	return t.admitUser(se) != ""
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
			// The fabrication answers instead, for the clients it covers, and
			// only here: this is the path where the command has already been
			// kept from the server.
			if answered, done := se.deceive(c, d.Reason); answered {
				return false, done
			}
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
