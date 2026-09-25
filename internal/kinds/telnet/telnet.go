// Package telnet is the telnet gateway listener kind.
//
// The proxy is a telnet server to the client and a telnet client to
// the target. Both directions are parsed, because every control here
// needs the parse: an option policy decides what a session may
// negotiate, a recording holds what was shown rather than what was
// negotiated, and a second factor is a prompt the proxy writes into
// the stream before the target is dialled at all.
package telnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/sessions"
	wire "github.com/rom/xproxy/internal/telnet"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/upstream"
)

type server struct {
	engine proxy.Host
	cfg    config.Listener
	t      *config.TelnetListener
	ln     net.Listener
	tlsCfg *tls.Config
	allow  []netip.Prefix
	// options is what a session may negotiate, by option byte.
	options  map[byte]bool
	recorder *sessionrec.Policy
	mfaGuard *mfa.Guard
	// grants is the just-in-time access guard, nil unless this listener
	// sets require_grant.
	grants *access.Guard

	// sessions is what a shutdown waits for. It is acceptgroup rather than
	// a bare WaitGroup because a connection can be accepted at the moment
	// shutdown begins, and a WaitGroup's Add must not race its Wait: the
	// failure is not a warning but a session that either is or is not
	// waited for depending on the scheduler.
	sessions acceptgroup.Group
	mu       sync.Mutex
	cons     map[net.Conn]struct{}
}

func newServer(engine proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	c := cfg.Telnet
	t := &server{engine: engine, cfg: cfg, t: c, ln: ln, tlsCfg: tc,
		options: map[byte]bool{}, cons: map[net.Conn]struct{}{}}
	for _, name := range c.AllowOptions {
		if o, ok := wire.OptionByName(strings.ToLower(strings.TrimSpace(name))); ok {
			t.options[o] = true
		}
	}
	for _, name := range c.DenyOptions {
		if o, ok := wire.OptionByName(strings.ToLower(strings.TrimSpace(name))); ok {
			delete(t.options, o)
		}
	}
	for _, p := range c.AllowClients {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("telnet allow_clients: %w", err)
		}
		t.allow = append(t.allow, pre)
	}
	t.recorder = sessionrec.New(c.Recording)
	if c.MFA != nil {
		store, err := mfa.Load(c.MFA.File)
		if err != nil {
			return nil, fmt.Errorf("telnet mfa: %w", err)
		}
		t.mfaGuard = mfa.NewGuard(store, c.MFA.Skew, mfa.Lockout{
			MaxFailures: c.MFA.MaxFailures,
			Window:      c.MFA.Window.D(),
			Duration:    c.MFA.Duration.D(),
			MaxUsers:    c.MFA.MaxUsers,
		})
	}
	t.grants = access.NewGuard(engine.Access(), cfg.Name, c.RequireGrant, engine.Logs().Error)
	return t, nil
}

func (t *server) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		if !t.admit(c) {
			_ = c.Close()
			continue
		}
		go func() {
			defer t.sessions.Leave()
			defer safe.Guard("telnet session")
			defer t.untrack(c)
			t.handle(c)
		}()
	}
}

// admit bounds the sessions on this listener.
func (t *server) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.sessions.Enter() {
		// Shutting down. The caller closes the connection rather than
		// serving it: a session started now is one nothing waits for.
		return false
	}
	if len(t.cons) >= t.t.MaxConnections {
		t.sessions.Leave()
		t.engine.Counters().TelnetRejected.Add(1)
		return false
	}
	t.cons[c] = struct{}{}
	return true
}

func (t *server) untrack(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.cons, c)
}

func (t *server) shutdown(ctx context.Context) {
	t.sessions.Close()
	t.mu.Lock()
	for c := range t.cons {
		_ = c.SetDeadline(time.Now())
	}
	t.mu.Unlock()
	t.sessions.Wait(ctx)
	if ctx.Err() == nil {
		return
	}
	// Out of time. The deadline above asked the sessions to end and they
	// have not, so the connections are closed under them -- and this
	// returns rather than waiting again, which is what it did before the
	// group replaced the WaitGroup: a shutdown that hangs on one session
	// is worse than one that stops asking.
	t.mu.Lock()
	for c := range t.cons {
		_ = c.Close()
	}
	t.mu.Unlock()
}

// deny feeds the ban ladder.
func (t *server) deny(ip netip.Addr, what, detail string) {
	t.engine.Counters().Refuse("telnet", what)
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "telnet_denied")
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "telnet_denied",
		"listener", t.cfg.Name, "client_ip", ip.String(), "what", what,
		"detail", textsafe.Clip256(detail))
}

// shadowed records a policy refusal a listener in shadow mode does not
// enforce, and says whether it was recorded rather than refused.
//
// Only policy reaches it. A ban, the connection limit, a rate limit, a
// failed second factor and anything the protocol parser could not read
// are refused in shadow mode too: a bastion that let somebody in because
// a new allow list was being trialled would be a bastion with a trial
// instead of a door.
func (t *server) shadowed(ip netip.Addr, what, detail string) bool {
	if !t.cfg.Shadowing() {
		return false
	}
	t.engine.Counters().WouldRefuse("telnet", what)
	t.engine.Shadow().Record("telnet", t.cfg.Name, what, "", detail)
	t.engine.Logs().SecurityEvent(context.Background(), "would_deny", "telnet_"+what,
		"listener", t.cfg.Name, "client_ip", ip.String(), "what", what,
		"detail", textsafe.Clip256(detail))
	return true
}

func (t *server) clientAllowed(ip netip.Addr) bool {
	if len(t.allow) == 0 {
		return true
	}
	for _, p := range t.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// session is one client and the target it reached.
type session struct {
	t      *server
	client net.Conn
	up     net.Conn
	ip     netip.Addr
	target string
	// user is the name the second factor was checked against, empty
	// where there is no factor. The target's own login is separate and
	// the proxy does not read it.
	user string
	rec  *sessionrec.Recording
	live *sessions.Session
	pool *upstream.Pool
	ep   *upstream.Endpoint
	// grant is the access grant this session was admitted under, and
	// pinned the one machine it names, when it names one rather than the
	// pool.
	grant  *access.Grant
	pinned string
	// cols and rows are the last window size the client announced,
	// which is what a player needs to draw the session at the width it
	// was seen.
	cols, rows int
	refused    atomic.Int64
}

// sessionID is the live table's identifier for this session, or empty when the
// table refused to register it.
func (se *session) sessionID() string {
	if se.live == nil {
		return ""
	}
	return se.live.ID
}

// admitByGrant is the just-in-time access decision: the reason to refuse, or
// empty to carry on. A shadowed listener records what it would have refused and
// carries on, which is how an estate turns this on without locking its
// operators out on the first evening.
func (se *session) admitByGrant() string {
	t := se.t
	if t.grants == nil {
		return ""
	}
	var addrs []string
	if pool := t.engine.Pool(t.t.Upstream); pool != nil {
		addrs = pool.Addresses()
	}
	adm := t.grants.Check(se.user, t.t.Upstream, addrs)
	if adm.Reason == "" {
		se.grant, se.pinned = adm.Grant, adm.Pinned
		return ""
	}
	if t.shadowed(se.ip, adm.Reason, textsafe.Clip64(se.user)) {
		return ""
	}
	t.deny(se.ip, adm.Reason, textsafe.Clip64(se.user))
	return adm.Reason
}

func (t *server) handle(client net.Conn) {
	s := t.engine
	start := time.Now()
	se := &session{t: t, client: client, ip: netutil.AddrOf(client.RemoteAddr().String()), cols: 80, rows: 24}
	s.Counters().TelnetSessions.Add(1)
	s.Counters().TelnetSessionsOpen.Add(1)
	defer s.Counters().TelnetSessionsOpen.Add(-1)
	defer func() { se.closeRecording() }()

	if !t.clientAllowed(se.ip) && !t.shadowed(se.ip, "client_refused", "") {
		s.Counters().TelnetRejected.Add(1)
		t.deny(se.ip, "client_refused", "")
		_ = client.Close()
		return
	}
	if bl := s.Bans(); bl != nil && se.ip.IsValid() && bl.Banned(se.ip) {
		s.Counters().TelnetRejected.Add(1)
		s.Counters().Refuse("telnet", "banned")
		_ = client.Close()
		return
	}

	// Listed from here, before the handshake: a session stuck in one is a
	// session an operator wants to see and be able to close. Closing the
	// client's socket is what ends it; the kind closes the target's leg in
	// its own deferred work.
	se.live = s.Sessions().Register(sessions.Info{
		Kind: "telnet", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer se.live.Done()
	if t.tlsCfg != nil {
		tc := tls.Server(client, t.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			_ = client.Close()
			return
		}
		client, se.client = tc, tc
	}
	defer func() { _ = se.client.Close() }()
	if t.t.SessionTimeout > 0 {
		timer := time.AfterFunc(t.t.SessionTimeout.D(), func() { _ = se.client.Close() })
		defer timer.Stop()
	}
	if t.t.Banner != "" {
		if _, err := se.client.Write(wire.EscapeData([]byte(t.t.Banner + "\r\n"))); err != nil {
			t.log(se, start, "write")
			return
		}
	}
	// The factor is asked for before the target is dialled, so a client
	// that cannot answer it never reaches the equipment at all.
	if t.mfaGuard != nil {
		if reason := se.askFactor(); reason != "" {
			t.log(se, start, reason)
			return
		}
	}
	// And the grant is checked after the factor, so the subject is the name
	// the factor was checked against. Telnet carries no identity of its own,
	// which is why require_grant needs the factor prompt.
	if reason := se.admitByGrant(); reason != "" {
		s.Counters().TelnetRejected.Add(1)
		_, _ = se.client.Write(wire.EscapeData([]byte("no access grant is in force\r\n")))
		t.log(se, start, reason)
		return
	}
	defer access.CloseAtExpiry(se.grant, func() { _ = se.client.Close() })()
	if err := se.connect(); err != nil {
		s.Logs().Error.Warn("telnet target unavailable", "listener", t.cfg.Name, "err", err.Error())
		_, _ = se.client.Write(wire.EscapeData([]byte("the target is unavailable\r\n")))
		t.log(se, start, "upstream_unavailable")
		return
	}
	defer func() {
		_ = se.up.Close()
		if se.ep != nil {
			se.pool.End(se.ep, false, time.Since(start))
		}
	}()
	se.openRecording()
	reason := se.relay()
	t.log(se, start, reason)
}

// connect dials a target from the pool, trying a few endpoints before
// giving up: one refused connection is not an unreachable estate.
func (se *session) connect() error {
	t := se.t
	pool := t.engine.Pool(t.t.Upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", t.t.Upstream)
	}
	se.pool = pool
	tried := map[*upstream.Endpoint]bool{}
	var lastErr error
	for i := 0; i < 3; i++ {
		ep, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if ep == nil {
			break
		}
		tried[ep] = true
		if se.pinned != "" && !strings.EqualFold(ep.Address, se.pinned) {
			// The grant names one machine, and this is another.
			lastErr = fmt.Errorf("the grant is for %s", se.pinned)
			continue
		}
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		conn, err := d.DialContext(context.Background(), "tcp", ep.Address)
		pool.Begin(ep)
		if err != nil {
			pool.End(ep, true, 0)
			lastErr = err
			continue
		}
		if t.t.ProxyProtocol {
			if _, err := conn.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
				pool.End(ep, true, 0)
				_ = conn.Close()
				lastErr = err
				continue
			}
		}
		se.up, se.ep, se.target = conn, ep, ep.Address
		se.live.Annotate(se.user, se.target, "")
		// The window is spent once a machine was actually reached: a
		// session that never got there did not use the access.
		t.grants.Use(se.grant, se.sessionID())
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no endpoint available")
	}
	return lastErr
}

func (t *server) log(se *session, start time.Time, reason string) {
	t.engine.Logs().Access.Info("telnet", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target, "reason", reason,
		"refused_options", se.refused.Load(), "duration_ms", time.Since(start).Milliseconds())
}

// relay copies both directions, deciding every option and recording
// what the target showed.
func (se *session) relay() string {
	t := se.t
	var wg sync.WaitGroup
	wg.Add(2)
	reason := make(chan string, 2)
	// Client to target: the direction that carries what a person typed
	// and the options they ask for.
	go func() {
		defer wg.Done()
		defer safe.Guard("telnet to target")
		reason <- se.pump(se.client, se.up, true)
		_ = se.up.Close()
	}()
	// Target to client: what the session showed.
	go func() {
		defer wg.Done()
		defer safe.Guard("telnet to client")
		reason <- se.pump(se.up, se.client, false)
		_ = se.client.Close()
	}()
	wg.Wait()
	close(reason)
	first := ""
	for r := range reason {
		if r != "" && first == "" {
			first = r
		}
	}
	if first == "" {
		first = "closed"
	}
	_ = t
	return first
}

// pump reads one direction, decides each event and writes on what it
// allows. fromClient says which side src is, which decides where a
// refusal is sent and whether the data is input or output.
func (se *session) pump(src, dst net.Conn, fromClient bool) string {
	t := se.t
	p := wire.NewParser(t.t.MaxSubnegotiation)
	buf := make([]byte, 32<<10)
	for {
		if t.t.IdleTimeout > 0 {
			_ = src.SetReadDeadline(time.Now().Add(t.t.IdleTimeout.D()))
		}
		n, err := src.Read(buf)
		if n > 0 {
			out, reason := se.decide(p, buf[:n], src, fromClient)
			if reason != "" {
				return reason
			}
			if len(out) > 0 {
				if _, werr := dst.Write(out); werr != nil {
					return "write"
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "closed"
			}
			return "read"
		}
	}
}

// decide turns one read into the bytes to forward, refusing the
// options policy does not allow and recording what was shown.
func (se *session) decide(p *wire.Parser, b []byte, src net.Conn, fromClient bool) ([]byte, string) {
	t := se.t
	var out []byte
	err := p.Feed(b, func(e wire.Event) error {
		switch e.Kind {
		case wire.Data:
			if fromClient {
				se.recordInput(e.Data)
			} else {
				se.recordOutput(e.Data)
			}
			out = append(out, wire.EscapeData(e.Data)...)
		case wire.Negotiate:
			if !t.options[e.Opt] && t.shadowed(se.ip, "option_refused", wire.OptionName(e.Opt)) {
				// Shadow mode: the negotiation is forwarded and the
				// ledger says the option list would have refused it.
				out = append(out, wire.Negotiation(e.Cmd, e.Opt)...)
			} else if !t.options[e.Opt] {
				// Refused here rather than forwarded, and the peer that
				// asked is answered so it stops asking. A refusal the
				// asker never hears is a negotiation that repeats.
				se.refused.Add(1)
				t.engine.Counters().TelnetOptionsRefused.Add(1)
				t.engine.Counters().Refuse("telnet", "option_refused")
				if ref, ok := wire.Refusal(e.Cmd, e.Opt); ok {
					if _, werr := src.Write(ref); werr != nil {
						return werr
					}
				}
				se.markRefusedOption(e.Cmd, e.Opt)
				return nil
			}
			out = append(out, wire.Negotiation(e.Cmd, e.Opt)...)
		case wire.Subneg:
			if !t.options[e.Opt] && t.shadowed(se.ip, "subnegotiation_refused", wire.OptionName(e.Opt)) {
				out = append(out, wire.Subnegotiation(e.Opt, e.Data)...)
			} else if !t.options[e.Opt] {
				se.refused.Add(1)
				t.engine.Counters().TelnetOptionsRefused.Add(1)
				t.engine.Counters().Refuse("telnet", "subnegotiation_refused")
				se.markRefusedOption(wire.SB, e.Opt)
				return nil
			}
			if e.Opt == wire.OptNAWS && fromClient {
				if c, r, ok := wire.NAWS(e.Data); ok && c > 0 && r > 0 {
					se.cols, se.rows = c, r
					se.rec.Resize(c, r)
				}
			}
			out = append(out, wire.Subnegotiation(e.Opt, e.Data)...)
		case wire.Command:
			out = append(out, wire.IAC, e.Cmd)
		}
		return nil
	})
	if err != nil {
		t.engine.Counters().TelnetRefused.Add(1)
		t.deny(se.ip, "telnet_malformed", err.Error())
		return nil, "malformed"
	}
	return out, ""
}

// markRefusedOption notes a refusal in the recording and the log, so
// an operator asked why a client's terminal behaves oddly can see that
// the proxy is why.
func (se *session) markRefusedOption(cmd, opt byte) {
	se.rec.Mark(fmt.Sprintf("xproxy: refused %s %s", wire.CommandName(cmd), wire.OptionName(opt)))
	se.t.engine.Logs().Access.Info("telnet_option_refused", "listener", se.t.cfg.Name,
		"client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
		"command", wire.CommandName(cmd), "option", wire.OptionName(opt))
}
