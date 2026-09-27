// Package rdp is the Remote Desktop gateway listener kind.
//
// The proxy terminates the connection sequence on both legs: it is an
// RDP server to the client and an RDP client to the desktop. That is
// what makes every control here possible. The security protocol is
// decided rather than observed; the virtual channel list is rewritten,
// so a session cannot carry a file the policy did not allow; a second
// factor is checked before the person's credential reaches the
// desktop; the credential that opens the desktop can be the gateway's
// rather than the person's; and what the session showed is recorded.
package rdp

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

type server struct {
	engine proxy.Host
	cfg    config.Listener
	v      *config.RDPListener
	ln     net.Listener
	tlsCfg *tls.Config
	upTLS  *tls.Config
	allow  []netip.Prefix
	// offered is the set of security protocols a client may use.
	offered uint32
	// upstreamProtocol is what this proxy asks a desktop for.
	upstreamProtocol uint32
	// channels is the set of static channel names a session may have,
	// and devices the redirection kinds, both lower case.
	channels map[string]bool
	devices  map[uint32]bool
	// dynamic decides the channels opened inside drdynvc, which the
	// static list above cannot see into.
	dynamic *dynamicPolicy
	// upUser, upDomain and upPassword are the credential this proxy
	// opens a desktop with, where an operator gave one.
	upUser, upDomain, upPassword string
	recorder                     *sessionrec.Policy
	mfaGuard                     *mfa.Guard
	// grants is the just-in-time access guard, nil unless this listener
	// sets require_grant.
	grants *access.Guard
	// legacyKey is what a client on the protocol's own encryption is
	// given in a certificate. One per listener rather than one per
	// session: a real server does the same, and drawing a key is the
	// one expensive thing in that exchange.
	legacyKey *rsa.PrivateKey

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
	c := cfg.RDP
	t := &server{engine: engine, cfg: cfg, v: c, ln: ln, tlsCfg: tc,
		channels: map[string]bool{}, devices: map[uint32]bool{},
		cons: map[net.Conn]struct{}{}}
	t.dynamic = compileDynamic(c.Channels)
	for _, name := range c.Security {
		if p, ok := rdp.ProtocolByName(strings.ToLower(strings.TrimSpace(name))); ok {
			t.offered |= protocolBit(p)
		}
	}
	if p, ok := rdp.ProtocolByName(strings.ToLower(strings.TrimSpace(c.UpstreamSecurity))); ok {
		t.upstreamProtocol = p
	}
	if c.Channels != nil {
		for _, name := range c.Channels.Allow {
			t.channels[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	if c.Devices != nil {
		for _, name := range c.Devices.Allow {
			if d, ok := rdp.DeviceTypeByName(name); ok {
				t.devices[d] = true
			}
		}
	}
	for _, p := range c.AllowClients {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("rdp allow_clients: %w", err)
		}
		t.allow = append(t.allow, pre)
	}
	var err error
	if t.upPassword, err = readSecret(c.UpstreamPasswordFile); err != nil {
		return nil, fmt.Errorf("rdp upstream_password_file: %w", err)
	}
	t.upUser, t.upDomain = c.UpstreamUser, c.UpstreamDomain
	if t.upstreamProtocol == rdp.ProtocolSSL || t.upstreamProtocol == rdp.ProtocolHybrid {
		uc, _, err := tlsconf.Client(c.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("rdp upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	if t.offered&legacyBit != 0 {
		if t.legacyKey, err = rdp.NewLegacyKey(); err != nil {
			return nil, fmt.Errorf("rdp legacy key: %w", err)
		}
	}
	t.recorder = sessionrec.New(c.Recording)
	if c.MFA != nil {
		store, err := mfa.Load(c.MFA.File)
		if err != nil {
			return nil, fmt.Errorf("rdp mfa: %w", err)
		}
		t.mfaGuard = mfa.NewGuard(store, c.MFA.Skew, mfa.Lockout{
			MaxFailures: c.MFA.MaxFailures, Window: c.MFA.Window.D(),
			Duration: c.MFA.Duration.D(), MaxUsers: c.MFA.MaxUsers,
		})
	}
	t.grants = access.NewGuard(engine.Access(), cfg.Name, c.RequireGrant, engine.Logs().Error)
	return t, nil
}

// protocolBit turns a protocol into the flag a client sets for it. The
// legacy protocol is zero on the wire, so it needs a bit of its own
// here to be a set member.
func protocolBit(p uint32) uint32 {
	if p == rdp.ProtocolRDP {
		return legacyBit
	}
	return p
}

// legacyBit stands for the legacy protocol inside this package, where
// the protocol's own value of zero cannot.
const legacyBit = 0x8000_0000

// readSecret reads a password file, refusing one anybody else can
// read.
func readSecret(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is mode %04o; it must not be readable by anyone else", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // an operator named this path
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
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
			defer safe.Guard("rdp session")
			defer t.untrack(c)
			t.handle(c)
		}()
	}
}

func (t *server) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.sessions.Enter() {
		// Shutting down. The caller closes the connection rather than
		// serving it: a session started now is one nothing waits for.
		return false
	}
	if len(t.cons) >= t.v.MaxConnections {
		t.sessions.Leave()
		t.engine.Counters().RDPRejected.Add(1)
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

func (t *server) deny(ip netip.Addr, what, detail string) {
	t.engine.Counters().Refuse("rdp", what)
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "rdp_denied")
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "rdp_denied",
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
	t.recordWouldDeny(ip, what, "", detail)
	return true
}

// recordWouldDeny writes a refusal that is not being enforced, for a caller
// that has already decided it is not enforcing it: the listener's own shadow
// mode above, or the estate's authorisation policy, which has a shadow switch
// of its own and must leave the same record on a listener that enforces. rule
// names the rule that decided, where the policy that decided names its rules.
func (t *server) recordWouldDeny(ip netip.Addr, what, rule, detail string) {
	t.engine.Counters().WouldRefuse("rdp", what)
	t.engine.Shadow().Record("rdp", t.cfg.Name, what, rule, detail)
	t.engine.Logs().SecurityEvent(context.Background(), "would_deny", "rdp_"+what,
		"listener", t.cfg.Name, "client_ip", ip.String(), "what", what,
		"detail", textsafe.Clip256(detail))
}

// authzGate lends the estate's authorisation policy this listener's own refusal
// machinery, so a refusal it makes is counted, logged and banned on exactly as
// one this listener made itself.
func (t *server) authzGate(ip netip.Addr) authorization.Gate {
	return authorization.Gate{
		Shadowing: t.cfg.Shadowing,
		Record:    func(reason, rule, detail string) { t.recordWouldDeny(ip, reason, rule, detail) },
		Deny: func(reason, _, detail string) {
			t.engine.Counters().RDPRefused.Add(1)
			t.deny(ip, reason, detail)
		},
	}
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

// session is one client, the desktop it reached, and what was agreed
// with each.
type session struct {
	t      *server
	client net.Conn
	up     net.Conn
	ip     netip.Addr
	target string
	// cookie is the routing token the client put in front of its
	// negotiation, which is the only identity available that early.
	cookie string
	// clientProtocol and upProtocol are what was settled on each leg.
	// They need not agree: a client on TLS can reach a desktop that
	// insists on network level authentication, and that is the point
	// of terminating both.
	clientProtocol uint32
	upProtocol     uint32
	// user and domain are who the credential said was connecting.
	user, domain string
	// grant is the access grant this session was admitted under. On this
	// protocol the credential arrives after the desktop has been dialled,
	// so the grant is checked against the machine already reached rather
	// than deciding which one to reach; see credential(). stopAtExpiry
	// stops the timer that closes the session when the window ends.
	grant        *access.Grant
	stopAtExpiry func()
	// asked and granted are the channels the client wanted and the
	// ones the policy let through, for the log. wanted is the same
	// length as the client's list with a name where the channel was
	// granted and an empty string where it was refused, which is what
	// lines the desktop's identifiers up with it.
	asked, granted, wanted []string
	// ioChannel is the channel the session itself runs on, and
	// channelName maps an identifier to what it carries.
	ioChannel   uint16
	channelName map[uint16]string
	// inert are the channel identifiers the gateway answered itself,
	// standing in for channels the desktop was never asked for.
	inert map[uint16]bool
	// pending collects a virtual channel message across its chunks,
	// since a gateway cannot filter half of one. It belongs to the
	// redirection channel travelling up.
	pending []byte
	// dvcDown and dvcUp collect the drdynvc messages of each direction.
	// They are separate from pending and from each other because all
	// three are reassembled at once: the redirection channel's messages
	// come up from the client while the dynamic channel's creates come
	// down from the desktop, and interleaving any two of them into one
	// buffer would splice two messages together.
	dvcDown, dvcUp []byte
	// dynamic is what this session knows about the channels inside its
	// drdynvc: the ones opened, and the ones refused, so that the data
	// which follows a refusal goes nowhere.
	dynamic *dynamicState
	// upMu guards the writes to the desktop, which two goroutines make:
	// the client's units travel up on one, and a refused dynamic channel
	// is answered from the one reading the desktop.
	upMu sync.Mutex
	// legacy is the desktop's leg when it uses the protocol's own
	// encryption rather than TLS, and nil when it does not.
	legacy *legacyLeg
	// clientLegacy is the same for the client's leg, where this
	// gateway is the server and holds the key.
	clientLegacy *legacyLeg
	// ended is closed when either direction of the relay stops.
	ended chan struct{}
	rec   *sessionrec.Recording
	live  *sessions.Session
	pool  *upstream.Pool
	ep    *upstream.Endpoint
}

func (t *server) handle(client net.Conn) {
	s := t.engine
	start := time.Now()
	se := &session{t: t, client: client, ip: netutil.AddrOf(client.RemoteAddr().String()),
		channelName: map[uint16]string{}, inert: map[uint16]bool{},
		dynamic: newDynamicState()}
	s.Counters().RDPSessions.Add(1)
	s.Counters().RDPSessionsOpen.Add(1)
	defer s.Counters().RDPSessionsOpen.Add(-1)
	defer func() { se.closeRecording() }()

	if !t.clientAllowed(se.ip) && !t.shadowed(se.ip, "client_refused", "") {
		s.Counters().RDPRejected.Add(1)
		t.deny(se.ip, "client_refused", "")
		_ = client.Close()
		return
	}
	if bl := s.Bans(); bl != nil && se.ip.IsValid() && bl.Banned(se.ip) {
		s.Counters().RDPRejected.Add(1)
		s.Counters().Refuse("rdp", "banned")
		_ = client.Close()
		return
	}

	// Listed from here, before the handshake: a session stuck in one is a
	// session an operator wants to see and be able to close. Closing the
	// client's socket is what ends it; the kind closes the target's leg in
	// its own deferred work.
	se.live = s.Sessions().Register(sessions.Info{
		Kind: "rdp", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer se.live.Done()
	defer func() { _ = se.client.Close() }()
	if t.v.SessionTimeout > 0 {
		timer := time.AfterFunc(t.v.SessionTimeout.D(), func() { _ = se.client.Close() })
		defer timer.Stop()
	}
	_ = se.client.SetDeadline(time.Now().Add(t.v.HandshakeTimeout.D()))

	reason := se.run(start)
	if se.stopAtExpiry != nil {
		se.stopAtExpiry()
	}
	t.log(se, start, reason)
}

// run does the whole session: the negotiation on each leg, the
// conference exchange with the channel policy applied, and the relay.
func (se *session) run(start time.Time) string {
	t := se.t
	// The client's negotiation, answered rather than forwarded: what
	// is agreed here decides what the gateway can see afterwards.
	if reason := se.clientNegotiate(); reason != "" {
		return reason
	}
	if err := se.connect(); err != nil {
		t.engine.Logs().Error.Warn("rdp desktop unavailable", "listener", t.cfg.Name, "err", err.Error())
		return "upstream_unavailable"
	}
	defer func() {
		_ = se.up.Close()
		if se.ep != nil {
			se.pool.End(se.ep, false, time.Since(start))
		}
	}()
	if reason := se.upstreamNegotiate(); reason != "" {
		return reason
	}
	if reason := se.conference(); reason != "" {
		return reason
	}
	// Past the connection sequence the deadlines are the session's.
	_ = se.client.SetDeadline(time.Time{})
	_ = se.up.SetDeadline(time.Time{})
	se.openRecording()
	return se.relay()
}

func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "domain", textsafe.Clip64(se.domain),
		"cookie", textsafe.Clip64(se.cookie), "target", se.target,
		"client_security", rdp.ProtocolName(se.clientProtocol),
		"upstream_security", rdp.ProtocolName(se.upProtocol),
		"channels_asked", strings.Join(se.asked, ","),
		"channels_granted", strings.Join(se.granted, ","),
		"dynamic_channels", strings.Join(se.dynamic.names(), ","),
		"reason", reason, "duration_ms", time.Since(start).Milliseconds()}
	t.engine.Logs().Access.Info("rdp", append(attrs, access.LogAttrs(se.grant)...)...)
}

// connect dials the desktop.
func (se *session) connect() error {
	t := se.t
	pool := t.engine.Pool(t.v.Upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", t.v.Upstream)
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
		conn, err := se.dial(ep)
		pool.Begin(ep)
		if err != nil {
			pool.End(ep, true, 0)
			lastErr = err
			continue
		}
		se.up, se.ep, se.target = conn, ep, ep.Address
		se.live.Annotate(se.user, se.target, "")
		_ = conn.SetDeadline(time.Now().Add(t.v.HandshakeTimeout.D()))
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no endpoint available")
	}
	return lastErr
}

func (se *session) dial(ep *upstream.Endpoint) (net.Conn, error) {
	t := se.t
	d := net.Dialer{Timeout: se.pool.Cfg.Timeouts.Connect.D()}
	conn, err := d.DialContext(context.Background(), "tcp", ep.Address)
	if err != nil {
		return nil, err
	}
	if t.v.ProxyProtocol {
		if _, err := conn.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}
