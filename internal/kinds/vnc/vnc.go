// Package vnc is the VNC gateway listener kind.
//
// The proxy terminates the RFB handshake on both legs: it is an RFB
// server to the client and an RFB client to the target. That is what
// makes every control here possible. The security type a client may
// use is decided rather than observed; the credential towards the
// target is the gateway's rather than the person's; a second factor is
// asked for before the target is dialled; and the session that follows
// is recorded, because by then the proxy is the one holding both ends
// of it.
package vnc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
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
	"github.com/rom/xproxy/internal/rfb"
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
	v      *config.VNCListener
	ln     net.Listener
	tlsCfg *tls.Config
	upTLS  *tls.Config
	allow  []netip.Prefix
	// offered is what this proxy offers a client, in the order it
	// prefers: strongest first.
	offered []uint8
	// subtypes are the VeNCrypt subtypes offered.
	subtypes []uint32
	// password is what this proxy answers its own vncauth challenge
	// with, and upPassword what it answers the target's with.
	password   string
	upPassword string
	recorder   *sessionrec.Policy
	// px is the policy over the pixel stream, built once.
	px       pixelPolicy
	mfaGuard *mfa.Guard
	// grants is the just-in-time access guard, nil unless this listener
	// sets require_grant.
	grants *access.Guard
	ssh    *sshDialer
	// rsaKey is this listener's own key for the rsa-aes types.
	rsaKey *rsa.PrivateKey

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
	c := cfg.VNC
	t := &server{engine: engine, cfg: cfg, v: c, ln: ln, tlsCfg: tc,
		cons: map[net.Conn]struct{}{}}
	for _, name := range c.SecurityTypes {
		if s, ok := rfb.SecurityByName(strings.ToLower(strings.TrimSpace(name))); ok {
			t.offered = append(t.offered, s)
		}
	}
	for _, name := range c.VeNCryptSubtypes {
		if s, ok := rfb.SubtypeByName(strings.ToLower(strings.TrimSpace(name))); ok {
			t.subtypes = append(t.subtypes, s)
		}
	}
	for _, p := range c.AllowClients {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("vnc allow_clients: %w", err)
		}
		t.allow = append(t.allow, pre)
	}
	var err error
	if t.password, err = readSecret(c.PasswordFile); err != nil {
		return nil, fmt.Errorf("vnc password_file: %w", err)
	}
	if slices.Contains(t.offered, rfb.SecVeNCrypt) {
		for _, subtype := range t.subtypes {
			if rfb.AuthAfterTLS(subtype) == rfb.SecVNCAuth && t.password == "" {
				return nil, errors.New("vnc password_file: a non-empty password is required for VNC-authenticated VeNCrypt subtypes")
			}
		}
	}
	if t.upPassword, err = readSecret(c.UpstreamPasswordFile); err != nil {
		return nil, fmt.Errorf("vnc upstream_password_file: %w", err)
	}
	if c.UpstreamTLSMode != "none" {
		uc, _, err := tlsconf.Client(c.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("vnc upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	if c.SSH != nil {
		if t.ssh, err = newSSHDialer(c.SSH); err != nil {
			return nil, fmt.Errorf("vnc ssh: %w", err)
		}
	}
	if c.RSAKeyFile != "" {
		if t.rsaKey, err = rfb.LoadRSAKey(c.RSAKeyFile); err != nil {
			return nil, fmt.Errorf("vnc rsa_key_file: %w", err)
		}
	}
	t.recorder = sessionrec.New(c.Recording, sessionrec.WithSecrets(engine.Secrets()))
	t.px = newPixelPolicy(c)
	if c.MFA != nil {
		store, err := mfa.Load(c.MFA.File)
		if err != nil {
			return nil, fmt.Errorf("vnc mfa: %w", err)
		}
		t.mfaGuard = mfa.NewGuard(store, c.MFA.Skew, mfa.Lockout{
			MaxFailures: c.MFA.MaxFailures, Window: c.MFA.Window.D(),
			Duration: c.MFA.Duration.D(), MaxUsers: c.MFA.MaxUsers,
		})
	}
	t.grants = access.NewGuard(engine.Access(), cfg.Name, c.RequireGrant, engine.Logs().Error)
	return t, nil
}

// readSecret reads a password file, refusing one anybody else can
// read: a VNC password is a shared secret for a whole desktop.
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
			defer safe.Guard("vnc session")
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
		t.engine.Counters().VNCRejected.Add(1)
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
	t.engine.Counters().Refuse("vnc", what)
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "vnc_denied")
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "vnc_denied",
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
	t.engine.Counters().WouldRefuse("vnc", what)
	t.engine.Shadow().Record("vnc", t.cfg.Name, what, rule, detail)
	t.engine.Logs().SecurityEvent(context.Background(), "would_deny", "vnc_"+what,
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
			t.engine.Counters().VNCRefused.Add(1)
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

// session is one client, the target it reached, and what was agreed
// with each.
type session struct {
	t      *server
	client net.Conn
	up     net.Conn
	ip     netip.Addr
	target string
	user   string
	// clientVersion and upVersion are what was settled on each leg.
	// They need not agree: a 3.3 client can reach a 3.8 server, and
	// the proxy is what makes that work.
	clientVersion rfb.Version
	upVersion     rfb.Version
	clientSec     uint8
	upSec         uint8
	clientSubtype uint32
	// factorUser and factorCode are what a plain VeNCrypt credential
	// carried: the name the enrolment is looked up by, and the code.
	factorUser string
	factorCode string
	// clientTightAuth is what a Tight client settled on, and upTight
	// whether the target's leg negotiated Tight: that type sends a
	// block after ServerInit which only that leg expects.
	clientTightAuth uint32
	upTight         bool
	// upNoResult records a target that sends no security result, which
	// Tight does when it asks for no authentication at all.
	upNoResult bool
	// factorDone records that the factor was checked during the
	// client's authentication, which is the only place it can be:
	// there is nowhere later in RFB to ask a question.
	factorDone bool
	// desktop is the name the target gave, for the log and the
	// recording's title.
	desktop       string
	width, height uint16
	// si is the target's ServerInit, whose pixel format is what every
	// length in the picture is measured in.
	si rfb.ServerInit
	// px is this session's state on the two pump goroutines.
	px   *pixels
	rec  *sessionrec.Recording
	live *sessions.Session
	pool *upstream.Pool
	ep   *upstream.Endpoint
	// grant is the access grant this session was admitted under, and
	// pinned the one machine it names, when it names one rather than the
	// pool.
	grant  *access.Grant
	pinned string
}

func (t *server) handle(client net.Conn) {
	s := t.engine
	start := time.Now()
	se := &session{t: t, client: client, ip: netutil.AddrOf(client.RemoteAddr().String()), px: newPixels()}
	s.Counters().VNCSessions.Add(1)
	s.Counters().VNCSessionsOpen.Add(1)
	defer s.Counters().VNCSessionsOpen.Add(-1)
	defer func() { se.closeRecording() }()

	if !t.clientAllowed(se.ip) && !t.shadowed(se.ip, "client_refused", "") {
		s.Counters().VNCRejected.Add(1)
		t.deny(se.ip, "client_refused", "")
		_ = client.Close()
		return
	}
	if bl := s.Bans(); bl != nil && se.ip.IsValid() && bl.Banned(se.ip) {
		s.Counters().VNCRejected.Add(1)
		s.Counters().Refuse("vnc", "banned")
		_ = client.Close()
		return
	}

	// The session is listed from here, before the handshake: one stuck in
	// a handshake is a session an operator wants to see and be able to
	// close. Closing the client's socket is what ends it -- both pumps
	// are reading it -- and the kind closes the target's leg in its own
	// deferred work.
	se.live = s.Sessions().Register(sessions.Info{
		Kind: "vnc", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer se.live.Done()
	// Only tls_mode: wrap makes the socket itself TLS. In the default
	// mode the same certificate is presented inside RFB instead, by
	// VeNCrypt or the tls security type.
	if t.tlsCfg != nil && t.v.TLSMode == "wrap" {
		tc := tls.Server(client, t.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			_ = client.Close()
			return
		}
		client, se.client = tc, tc
	}
	defer func() { _ = se.client.Close() }()
	if t.v.SessionTimeout > 0 {
		timer := time.AfterFunc(t.v.SessionTimeout.D(), func() { _ = se.client.Close() })
		defer timer.Stop()
	}
	// The handshake has a deadline of its own: a peer that never
	// finishes it is a connection held open for nothing.
	_ = se.client.SetDeadline(time.Now().Add(t.v.HandshakeTimeout.D()))

	reason := se.run(start)
	t.log(se, start, reason)
}

// run does the whole session: the client's handshake, the factor, the
// target's handshake, and the relay.
func (se *session) run(start time.Time) string {
	t := se.t
	// The client's half of the handshake, up to and including its
	// security result. The proxy is the server here.
	if reason := se.clientHandshake(); reason != "" {
		return reason
	}
	// rsa-aes-ne authenticates inside its channel and hands the
	// session back to a cleartext socket once the result is in.
	client, err := leaveChannel(se.client, se.clientSec)
	if err != nil {
		return "client_auth"
	}
	se.client = client
	if t.mfaGuard != nil && !se.factorDone {
		// The client authenticated with a type that carries no name,
		// so there was nothing to look an enrolment up by. Validation
		// makes sure a plain subtype is on offer; choosing another one
		// is the client declining to identify itself.
		se.factorFailed("no_identity")
		return "mfa_no_identity"
	}
	// ClientInit is read before the target is dialled, because it is
	// the last thing the client sends that the proxy must answer with
	// something the target gave it.
	ci, err := rfb.ReadClientInit(se.client)
	if err != nil {
		return "client_init"
	}
	// The grant is checked after the client has identified itself and
	// before the desktop is dialled, so a session with no grant never
	// reaches a machine.
	// The estate's own policy is asked first, because it is the broader
	// question: whether this person may be on this desktop at all, rather than
	// whether somebody approved a window for them today.
	if reason := se.admitByPolicy(); reason != "" {
		return reason
	}
	if reason := se.admitByGrant(); reason != "" {
		return reason
	}
	defer access.CloseAtExpiry(se.grant, func() { _ = se.client.Close() })()
	if err := se.connect(); err != nil {
		t.engine.Logs().Error.Warn("vnc target unavailable", "listener", t.cfg.Name, "err", err.Error())
		return "upstream_unavailable"
	}
	defer func() {
		_ = se.up.Close()
		if se.ep != nil {
			se.pool.End(se.ep, false, time.Since(start))
		}
	}()
	if reason := se.upstreamHandshake(ci); reason != "" {
		return reason
	}
	// Past the handshake the deadlines are the session's.
	_ = se.client.SetDeadline(time.Time{})
	_ = se.up.SetDeadline(time.Time{})
	se.openRecording()
	return se.relay()
}

func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target,
		"desktop", textsafe.Clip64(se.desktop),
		"client_version", se.clientVersion.String(), "client_security", rfb.SecurityName(se.clientSec),
		"upstream_version", se.upVersion.String(), "upstream_security", rfb.SecurityName(se.upSec),
		"width", se.width, "height", se.height, "view_only", t.v.ViewOnly,
		"reason", reason, "duration_ms", time.Since(start).Milliseconds()}
	t.engine.Logs().Access.Info("vnc", append(attrs, access.LogAttrs(se.grant)...)...)
}

// connect dials the target: through SSH where one is configured, and
// otherwise straight.
// sessionID is the live table's identifier for this session, or empty when the
// table refused to register it.
func (se *session) sessionID() string {
	if se.live == nil {
		return ""
	}
	return se.live.ID
}

// admitByGrant is the just-in-time access decision: the reason to refuse, or
// empty to carry on. The subject is the name the client authenticated with,
// which on this protocol is the plain credential's user or the name the factor
// prompt asked for -- which is why require_grant needs one of the two.
func (se *session) admitByGrant() string {
	t := se.t
	if t.grants == nil {
		return ""
	}
	var addrs []string
	if pool := t.engine.Pool(t.v.Upstream); pool != nil {
		addrs = pool.Addresses()
	}
	adm := t.grants.Check(se.user, t.v.Upstream, addrs)
	if adm.Reason == "" {
		se.grant, se.pinned = adm.Grant, adm.Pinned
		return ""
	}
	if t.shadowed(se.ip, adm.Reason, textsafe.Clip64(se.user)) {
		return ""
	}
	t.engine.Counters().VNCRefused.Add(1)
	t.deny(se.ip, adm.Reason, textsafe.Clip64(se.user))
	return adm.Reason
}

// admitByPolicy is the estate's authorisation policy, asked at the same point
// as the access grant: after the client has identified itself and before the
// desktop is dialled, so a refused session never reaches a machine.
//
// The user is the name the client authenticated with, which on this protocol is
// the plain credential's user or the name the factor prompt asked for; RFB has
// no principal and no groups the gateway could verify. The target is the
// upstream pool's name, because the machine is chosen by balancer after this
// point and the per-machine question is the access grant's.
func (se *session) admitByPolicy() string {
	t := se.t
	return t.engine.Authorization().Ask(authorization.Subject{
		Listener: t.cfg.Name,
		Kind:     "vnc",
		Client:   se.ip,
		User:     se.user,
		Target:   t.v.Upstream,
		Action:   authorization.ActionConnect,
	}, textsafe.Clip64(se.user), t.authzGate(se.ip))
}

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
		if se.pinned != "" && !strings.EqualFold(ep.Address, se.pinned) {
			// The grant names one machine, and this is another. Without this
			// the balancer would choose, which is access to whichever desktop
			// the pool felt like rather than the one somebody approved.
			lastErr = fmt.Errorf("the grant is for %s", se.pinned)
			continue
		}
		conn, err := se.dial(ep)
		pool.Begin(ep)
		if err != nil {
			pool.End(ep, true, 0)
			lastErr = err
			continue
		}
		se.up, se.ep, se.target = conn, ep, ep.Address
		// The window is spent once a machine was actually reached.
		t.grants.Use(se.grant, se.sessionID())
		se.live.Annotate(se.user, se.target, se.desktop)
		_ = conn.SetDeadline(time.Now().Add(t.v.HandshakeTimeout.D()))
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no endpoint available")
	}
	return lastErr
}

// dial reaches one endpoint.
func (se *session) dial(ep *upstream.Endpoint) (net.Conn, error) {
	t := se.t
	if t.ssh != nil {
		return t.ssh.dial(ep.Address)
	}
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

// relay copies both directions once both handshakes are done, keeping
// what the target showed.
func (se *session) relay() string {
	var wg sync.WaitGroup
	wg.Add(2)
	reason := make(chan string, 2)
	go func() {
		defer wg.Done()
		defer safe.Guard("vnc to target")
		reason <- se.pumpToTarget()
		_ = se.up.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("vnc to client")
		reason <- se.pumpToClient()
		_ = se.client.Close()
	}()
	wg.Wait()
	close(reason)
	for r := range reason {
		if r != "" && r != "closed" {
			return r
		}
	}
	return "closed"
}

// refuseClient counts a refusal and tells the client why, in the form
// the version it settled on allows. what is the counter's label; reason
// is the sentence the client is shown.
func (se *session) refuseClient(what, reason string) {
	se.t.engine.Counters().VNCRefused.Add(1)
	se.t.engine.Counters().Refuse("vnc", what)
	if se.clientVersion.AtLeast(rfb.V37) {
		_, _ = se.client.Write(rfb.SecurityFailure(reason))
		return
	}
	_, _ = se.client.Write(rfb.Security33(rfb.SecInvalid))
	_, _ = se.client.Write(rfb.String(reason))
}
