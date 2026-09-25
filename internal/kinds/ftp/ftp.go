package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/sftp"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server serves a kind: ftp listener. It speaks FTP to the client
// and FTP to the target, and it is one end of every data connection as
// well, because the address in a passive reply is the whole difference
// between a proxy and a suggestion.
type server struct {
	engine proxy.Host
	cfg    config.Listener
	f      *config.FTPListener
	ln     net.Listener
	tlsCfg *tls.Config
	upTLS  *tls.Config
	allow  []netip.Prefix
	verbs  map[string]bool
	policy *ftpPolicy
	// dataAddr is what passive replies advertise, when the
	// configuration names one.
	dataAddr netip.Addr
	loPort   int
	hiPort   int

	// recorder writes what a session did, when one is configured.
	recorder *sessionrec.Policy
	// mfaGuard holds the second factor's enrolments and its lockout.
	mfaGuard *mfa.Guard
	// grants is the just-in-time access guard, nil unless this listener
	// sets require_grant.
	grants *access.Guard

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
}

// ftpPolicy is what a session may name and what it may move.
type ftpPolicy struct {
	readOnly   bool
	allowPaths []string
	denyPaths  []string
	allowExt   map[string]bool
	denyExt    map[string]bool
	maxFile    int64
	yara       *streamscan.Guard
	templated  bool
}

func newServer(engine proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	f := cfg.FTP
	t := &server{engine: engine, cfg: cfg, f: f, ln: ln, tlsCfg: tc,
		verbs: map[string]bool{}, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	for _, c := range f.Commands {
		t.verbs[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	t.recorder = sessionrec.New(f.Recording)
	if f.MFA != nil {
		store, err := mfa.Load(f.MFA.File)
		if err != nil {
			return nil, fmt.Errorf("ftp mfa: %w", err)
		}
		t.mfaGuard = mfa.NewGuard(store, f.MFA.Skew, mfa.Lockout{
			MaxFailures: f.MFA.MaxFailures,
			Window:      f.MFA.Window.D(),
			Duration:    f.MFA.Duration.D(),
			MaxUsers:    f.MFA.MaxUsers,
		})
		// ACCT carries the code, so it has to be a verb this listener
		// relays even where the operator did not list it.
		t.verbs["ACCT"] = true
	}
	for _, c := range f.AllowClients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ftp allow_clients: %w", err)
		}
		t.allow = append(t.allow, p)
	}
	if f.UpstreamTLSMode != "none" {
		uc, _, err := tlsconf.Client(f.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("ftp upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	if f.DataAddress != "" {
		a, err := netip.ParseAddr(f.DataAddress)
		if err != nil {
			return nil, fmt.Errorf("ftp data_address: %w", err)
		}
		t.dataAddr = a
	}
	lo, hi, err := parsePortRange(f.DataPorts)
	if err != nil {
		return nil, fmt.Errorf("ftp data_ports: %w", err)
	}
	t.loPort, t.hiPort = lo, hi

	p := &ftpPolicy{readOnly: f.ReadOnly, allowPaths: f.AllowPaths, denyPaths: f.DenyPaths,
		maxFile: f.MaxFileBytes, allowExt: map[string]bool{}, denyExt: map[string]bool{}}
	for _, e := range f.AllowExtensions {
		p.allowExt[strings.ToLower(e)] = true
	}
	for _, e := range f.DenyExtensions {
		p.denyExt[strings.ToLower(e)] = true
	}
	for _, list := range [][]string{f.AllowPaths, f.DenyPaths} {
		for _, pattern := range list {
			if strings.Contains(pattern, "{user}") {
				p.templated = true
			}
		}
	}
	if f.YARA != nil {
		g, err := streamscan.New(f.YARA)
		if err != nil {
			return nil, err
		}
		p.yara = g
	}
	t.policy = p
	t.grants = access.NewGuard(engine.Access(), cfg.Name, f.RequireGrant, engine.Logs().Error)
	return t, nil
}

// parsePortRange reads "low-high". "0-0" is any free port, which is
// what a proxy with no firewall in front of it wants.
func parsePortRange(s string) (int, int, error) {
	if s == "" {
		return 0, 0, nil
	}
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, errors.New(`must be written "low-high"`)
	}
	l, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return 0, 0, err
	}
	h, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return 0, 0, err
	}
	if l == 0 && h == 0 {
		return 0, 0, nil
	}
	if l < 1 || h > 65535 || l > h {
		return 0, 0, errors.New("must be 1..65535 with low no higher than high")
	}
	return l, h, nil
}

func (t *server) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			var opErr *net.OpError
			if errors.As(err, &opErr) && strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if t.open.Add(1) > int64(t.f.MaxConnections) {
			t.open.Add(-1)
			t.engine.Counters().FTPRejected.Add(1)
			t.engine.Counters().Refuse("ftp", "max_connections")
			_, _ = c.Write(wire.Line(421, "too many connections, try again later"))
			_ = c.Close()
			continue
		}
		if !t.admit(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.wg.Done()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("ftp session")
			t.handle(c)
		}()
	}
}

func (t *server) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
	t.cons[c] = struct{}{}
	t.wg.Add(1)
	return true
}

func (t *server) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

func (t *server) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		_ = t.ln.Close()
	})
	finished := make(chan struct{})
	go func() { t.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		t.mu.Lock()
		for c := range t.cons {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-finished
	}
}

func (t *server) deny(ip netip.Addr, what, detail string) {
	t.engine.Counters().Refuse("ftp", what)
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "ftp"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "ftp_"+what, attrs...)
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "ftp_denied")
	}
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
	t.engine.Counters().WouldRefuse("ftp", what)
	t.engine.Shadow().Record("ftp", t.cfg.Name, what, "", detail)
	t.engine.Logs().SecurityEvent(context.Background(), "would_deny", "ftp_"+what,
		"listener", t.cfg.Name, "client_ip", ip.String(), "what", what,
		"detail", textsafe.Clip256(detail))
	return true
}

// session is one control connection and the control connection to
// the target that serves it.
type session struct {
	t      *server
	client net.Conn
	cr     *wire.Reader
	cw     *bufio.Writer
	up     net.Conn
	ur     *wire.Reader
	uw     *bufio.Writer
	pool   *upstream.Pool
	ep     *upstream.Endpoint

	ip     netip.Addr
	target string
	secure bool // the client's control connection is encrypted
	user   string
	authed bool
	// grant is the access grant this session was admitted under, and
	// grantChecked that the check has been made. On this protocol the login
	// arrives on a control connection that is already open, so the grant is
	// checked when the login completes rather than before the target is
	// dialled; see grantGate. stopAtExpiry stops the timer that closes the
	// session when the window ends.
	grant        *access.Grant
	grantChecked bool
	stopAtExpiry func()
	// prot is the data channel protection the client asked for: C for
	// clear, P for private.
	prot string
	// cwd is the working directory as the proxy has followed it, which
	// is what a relative path is resolved against before it is
	// matched.
	cwd      string
	errors   int
	upFailed bool
	// data is the arrangement for the next transfer, made by PASV,
	// EPSV, PORT or EPRT and used by the command that follows.
	data *dataConn
	// policy is the session's, with {user} resolved.
	policy *ftpPolicy
	// rec is this session's recording, when one is configured.
	rec  *sessionrec.Recording
	live *sessions.Session
	// mfa is where the second factor has got to.
	mfa mfaState
	// pending is a code taken off a PASS argument, waiting for the
	// target to accept the password it came with.
	pending string
	// restart is the offset a REST the server accepted set, and
	// pendingRestart the one a REST asked for while its reply is still
	// in flight. A marker applies to the next transfer only (RFC 3659
	// section 5), so both are cleared by the command that uses one and
	// by any command that is not a transfer.
	restart        int64
	pendingRestart int64
	// renameFrom is the path an RNFR the server accepted named. RNTO
	// without one is half a decision, and a proxy that relayed it would
	// be forwarding a rename it never saw the source of.
	renameFrom string
	// preLogin holds the dialogue until there is a login to name the
	// recording after; preLoginDropped counts what did not fit.
	preLogin        []preLoginEvent
	preLoginDropped int
}

func (t *server) handle(client net.Conn) {
	s := t.engine
	start := time.Now()
	se := &session{t: t, client: client, ip: netutil.AddrOf(client.RemoteAddr().String()),
		cwd: "/", prot: "C", policy: t.policy}
	s.Counters().FTPSessions.Add(1)
	s.Counters().FTPSessionsOpen.Add(1)
	defer s.Counters().FTPSessionsOpen.Add(-1)
	defer func() { se.closeData() }()
	// The recording is opened at login and closed here, so a session
	// that ends any way at all still leaves a complete file.
	defer func() { se.closeRecording() }()

	if !t.clientAllowed(se.ip) && !t.shadowed(se.ip, "client_refused", "") {
		s.Counters().FTPRejected.Add(1)
		t.deny(se.ip, "client_refused", "")
		_ = client.Close()
		return
	}
	if bl := s.Bans(); bl != nil && se.ip.IsValid() && bl.Banned(se.ip) {
		s.Counters().FTPRejected.Add(1)
		s.Counters().Refuse("ftp", "banned")
		_, _ = client.Write(wire.Line(421, "refused"))
		_ = client.Close()
		return
	}

	// Listed from here, before the handshake: a session stuck in one is a
	// session an operator wants to see and be able to close. Closing the
	// client's socket is what ends it; the kind closes the target's leg in
	// its own deferred work.
	se.live = s.Sessions().Register(sessions.Info{
		Kind: "ftp", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer se.live.Done()
	if t.f.SessionTimeout > 0 {
		timer := time.AfterFunc(t.f.SessionTimeout.D(), func() { _ = client.Close() })
		defer timer.Stop()
	}
	if t.f.TLSMode == "implicit" {
		tc := tls.Server(client, t.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			_ = client.Close()
			return
		}
		client, se.client, se.secure = tc, tc, true
	}
	defer func() { _ = se.client.Close() }()
	defer func() {
		if se.stopAtExpiry != nil {
			se.stopAtExpiry()
		}
	}()
	se.cr = wire.NewReader(bufio.NewReaderSize(se.client, t.f.MaxCommandLine+2), t.f.MaxCommandLine)
	se.cw = bufio.NewWriter(se.client)

	if err := se.connect(); err != nil {
		s.Logs().Error.Warn("ftp target unavailable", "listener", t.cfg.Name, "err", err.Error())
		_ = se.toClient(wire.Line(421, "service unavailable"))
		t.log(se, start, "upstream_unavailable")
		return
	}
	defer func() {
		_ = se.up.Close()
		if se.ep != nil {
			se.pool.End(se.ep, se.upFailed, time.Since(start))
		}
	}()

	// The target's greeting is read and answered with the proxy's own
	// when one is configured: a greeting that names the target's
	// software and version is a greeting that saves an attacker a
	// question.
	greet, err := wire.ReadReply(se.ur)
	if err != nil || greet.Code != 220 {
		_ = se.toClient(wire.Line(421, "service unavailable"))
		t.log(se, start, "upstream_greeting")
		return
	}
	if t.f.Banner != "" {
		greet = wire.Reply{Code: 220, Lines: []string{t.f.Banner}}
	}
	if err := se.toClient(greet.Format()); err != nil {
		t.log(se, start, "write")
		return
	}
	reason := se.loop()
	t.log(se, start, reason)
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

func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target, "tls", se.secure,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.engine.Logs().Access.Info("ftp", attrs...)
}

// connect opens the control connection to the target.
func (se *session) connect() error {
	t := se.t
	pool := t.engine.Pool(t.f.Upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", t.f.Upstream)
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
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		conn, err := d.DialContext(context.Background(), "tcp", ep.Address)
		pool.Begin(ep)
		if err != nil {
			pool.End(ep, true, 0)
			lastErr = err
			continue
		}
		if t.f.ProxyProtocol {
			if _, err := conn.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
				pool.End(ep, true, 0)
				_ = conn.Close()
				lastErr = err
				continue
			}
		}
		if t.f.UpstreamTLSMode == "implicit" {
			tc := tls.Client(conn, se.upstreamTLS(ep))
			if err := tc.HandshakeContext(context.Background()); err != nil {
				pool.End(ep, true, 0)
				_ = conn.Close()
				lastErr = err
				continue
			}
			conn = tc
		}
		se.up, se.ep, se.target = conn, ep, ep.Address
		se.live.Annotate(se.user, se.target, "")
		se.ur = wire.NewReader(bufio.NewReaderSize(conn, t.f.MaxCommandLine+2), t.f.MaxCommandLine)
		se.uw = bufio.NewWriter(conn)
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable endpoint")
	}
	return lastErr
}

func (se *session) upstreamTLS(ep *upstream.Endpoint) *tls.Config {
	tc := se.t.upTLS.Clone()
	if tc.ServerName == "" {
		host, _, err := net.SplitHostPort(ep.Address)
		if err == nil {
			tc.ServerName = host
		}
	}
	return tc
}

func (se *session) toClient(b []byte) error {
	se.recordLine(b)
	if _, err := se.cw.Write(b); err != nil {
		return err
	}
	return se.cw.Flush()
}

func (se *session) toUpstream(c wire.Command) error {
	if _, err := se.uw.Write(c.Format()); err != nil {
		se.upFailed = true
		return err
	}
	if err := se.uw.Flush(); err != nil {
		se.upFailed = true
		return err
	}
	return nil
}

// refuse answers the client without the target hearing the command, and
// counts it. Enough of them ends the session: a client walking a policy
// to find its edges is a client to stop talking to.
func (se *session) refuse(code int, text, what, detail string) bool {
	se.errors++
	se.t.engine.Counters().FTPRefused.Add(1)
	se.t.deny(se.ip, what, detail)
	if err := se.toClient(wire.Line(code, text)); err != nil {
		return false
	}
	return se.errors < se.t.f.MaxErrors
}

// loop reads commands until one of the two connections ends. It returns
// the reason for the access log.
func (se *session) loop() string {
	t := se.t
	for {
		if t.f.IdleTimeout > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(t.f.IdleTimeout.D()))
		}
		line, err := se.cr.ReadLine()
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrLineTooLong):
				se.t.engine.Counters().FTPRefused.Add(1)
				t.deny(se.ip, "line_too_long", "")
				_ = se.toClient(wire.Line(500, "command line too long"))
				return "line_too_long"
			case errors.Is(err, wire.ErrBareNewline), errors.Is(err, wire.ErrBareCR), errors.Is(err, wire.ErrTelnet):
				// Each of these is a way for the proxy and the target
				// to disagree about where a command ends, which is how
				// one command becomes two.
				se.t.engine.Counters().FTPRefused.Add(1)
				t.deny(se.ip, "malformed_line", err.Error())
				_ = se.toClient(wire.Line(500, "malformed command"))
				return "malformed_line"
			}
			return "client_closed"
		}
		cmd, err := wire.ParseCommand(line)
		if err != nil {
			if !se.refuse(500, "unrecognised command", "malformed_command", "") {
				return "too_many_errors"
			}
			continue
		}
		se.recordCommand(cmd)
		done, reason := se.command(cmd)
		if done {
			return reason
		}
	}
}

// command decides one command and relays what it allows.
func (se *session) command(c wire.Command) (bool, string) {
	t := se.t
	switch {
	case !wire.Known[c.Verb]:
		// A verb this proxy cannot name the effect of is a verb it
		// cannot hold to a policy.
		if !se.refuse(502, "command not implemented", "unknown_command", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	case !t.verbs[c.Verb]:
		if t.shadowed(se.ip, "command_refused", c.Verb) {
			// Shadow mode: the command goes to the server and the ledger
			// says the verb list would have refused it.
			break
		}
		if !se.refuse(502, "command not allowed", "command_refused", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	// Between the password and the second factor the session is not
	// logged in. Only the command that carries the code, and the ones
	// that end or describe the session, are allowed through.
	if se.mfa == mfaWanted && !mfaPreAuth[c.Verb] {
		if !se.refuse(530, "a one-time code is required first", "mfa_required", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	if c.Verb == "ACCT" && se.mfa == mfaWanted {
		if err := se.toClient(se.verifyFactor(strings.TrimSpace(c.Arg))); err != nil {
			return true, "write"
		}
		if se.mfa == mfaWanted {
			// Still owed: a wrong code counts against max_errors like
			// any other refusal.
			se.errors++
			if se.errors >= t.f.MaxErrors {
				return true, "too_many_errors"
			}
		}
		return false, ""
	}
	// Before TLS, only the commands that get to TLS or end the session.
	if t.f.RequireTLS && !se.secure && !ftpPreTLS[c.Verb] {
		if !se.refuse(534, "policy requires AUTH TLS first", "tls_required", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	if t.f.ReadOnly && wire.Writes[c.Verb] {
		if !se.refuse(532, "the server is read only through this proxy", "read_only", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	// A restart marker applies to the transfer that follows it and to
	// nothing else, and an RNFR to the RNTO that follows it. Anything
	// else in between clears them, which is what the server does too:
	// the alternative is a proxy holding half a pair that the server has
	// already forgotten.
	if !restartKeeps[c.Verb] && !wire.Transfers[c.Verb] {
		se.restart, se.pendingRestart = 0, 0
	}
	if c.Verb != "RNFR" && c.Verb != "RNTO" {
		se.renameFrom = ""
	}
	switch c.Verb {
	case "AUTH":
		return se.auth(c)
	case "CCC":
		// Clearing the control channel after AUTH TLS puts the rest of
		// the session, including every path, back in clear on the wire.
		if !se.refuse(534, "the control channel stays protected", "ccc_refused", "") {
			return true, "too_many_errors"
		}
		return false, ""
	case "PROT":
		se.prot = strings.ToUpper(strings.TrimSpace(c.Arg))
	case "PASV", "EPSV":
		return se.passive(c)
	case "PORT", "EPRT":
		return se.active(c)
	}
	// The path shape is read before the path policy, because a shape the
	// proxy and the server would disagree about makes the policy's answer
	// meaningless rather than wrong.
	if wire.Paths[c.Verb] && c.Arg != "" {
		if reason := pathShape(c.Arg); reason != "" {
			if !se.refuse(550, "the path cannot be used here", reason, textsafe.Clip256(c.Arg)) {
				return true, "too_many_errors"
			}
			return false, ""
		}
	}
	if wire.Paths[c.Verb] && c.Arg != "" {
		if reason := se.pathAllowed(c); reason != "" {
			if !se.refuse(550, "refused by policy", "path_refused", reason+" "+textsafe.Clip256(c.Arg)) {
				return true, "too_many_errors"
			}
			return false, ""
		}
	}
	if c.Verb == "REST" {
		return se.restartCmd(c)
	}
	if c.Verb == "RNTO" {
		return se.renameTo(c)
	}
	if wire.Transfers[c.Verb] {
		// A marker is spent by the transfer it was for, refused or not: a
		// client whose resumed upload was turned down has to ask again,
		// rather than the next transfer inheriting an offset.
		if reason := se.restartAllowed(c); reason != "" {
			detail := c.Verb + " at " + strconv.FormatInt(se.restart, 10)
			se.restart, se.pendingRestart = 0, 0
			if !se.refuse(451, "a resumed transfer cannot be inspected here", reason, detail) {
				return true, "too_many_errors"
			}
			return false, ""
		}
		done, reason := se.transfer(c)
		se.restart, se.pendingRestart = 0, 0
		return done, reason
	}
	if c.Verb == "PASS" && se.t.mfaGuard != nil {
		// A client with no ACCT of its own appends the code to the
		// password. The target must not see it, so it is taken off
		// here and checked once the password itself is accepted.
		pass, code := splitCode(c.Arg)
		se.pending = code
		c.Arg = pass
	}
	return se.relay(c)
}

// ftpPreTLS are the commands a session may send before the control
// connection is encrypted: the ones that get it there, and the ones
// that end it.
var ftpPreTLS = map[string]bool{
	"AUTH": true, "QUIT": true, "FEAT": true, "NOOP": true,
	"PBSZ": true, "PROT": true, "HELP": true,
}

// relay forwards a command and its reply, and follows the few replies
// that change what the proxy knows.
func (se *session) relay(c wire.Command) (bool, string) {
	if err := se.toUpstream(c); err != nil {
		_ = se.toClient(wire.Line(421, "the server connection ended"))
		return true, "upstream_write"
	}
	rep, err := wire.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(wire.Line(421, "the server connection ended"))
		return true, "upstream_read"
	}
	se.follow(c, rep)
	if se.mfa == mfaWanted && (c.Verb == "PASS" || c.Verb == "ACCT") {
		// A code appended to the password is checked now; otherwise
		// the client is asked for one with the 332 RFC 959 defines for
		// exactly this.
		out := wire.Line(332, se.factorPrompt())
		if se.pending != "" {
			code := se.pending
			se.pending = ""
			out = se.verifyFactor(code)
		}
		if reason, line := se.grantGate(); reason != "" {
			_ = se.toClient(line)
			return true, reason
		}
		if err := se.toClient(out); err != nil {
			return true, "write"
		}
		return false, ""
	}
	// The login is complete by here when there is no factor to wait for, so
	// this is where a session with no grant is refused: the control
	// connection is open and the target has seen nothing but a greeting.
	if reason, line := se.grantGate(); reason != "" {
		_ = se.toClient(line)
		return true, reason
	}
	if err := se.toClient(rep.Format()); err != nil {
		return true, "write"
	}
	if c.Verb == "QUIT" {
		return true, "quit"
	}
	return false, ""
}

// grantGate is the just-in-time access decision, made once, at the moment the
// session becomes logged in. It returns the reason to end the session and the
// reply to send, or "" to carry on.
//
// FTP dials the target before anybody has said who they are -- the greeting
// comes from the server -- so unlike the SSH and telnet gateways this cannot
// refuse before the target is reached. What it can do is refuse before any
// command of the person's is forwarded, which is what it does: the target has
// seen a connection and a login, and nothing else.
func (se *session) grantGate() (reason string, line []byte) {
	t := se.t
	if t.grants == nil || se.grantChecked || !se.authed || se.mfa == mfaWanted {
		return "", nil
	}
	se.grantChecked = true
	// The target is already dialled, so the only machine this session can be
	// about is the one it reached.
	adm := t.grants.Check(se.user, t.f.Upstream, []string{se.target})
	if adm.Reason == "" {
		se.grant = adm.Grant
		if se.grant != nil {
			t.grants.Use(se.grant, se.sessionID())
			se.stopAtExpiry = access.CloseAtExpiry(se.grant, func() { _ = se.client.Close() })
		}
		return "", nil
	}
	if t.shadowed(se.ip, adm.Reason, textsafe.Clip64(se.user)) {
		return "", nil
	}
	t.engine.Counters().FTPRefused.Add(1)
	t.deny(se.ip, adm.Reason, textsafe.Clip64(se.user))
	return adm.Reason, wire.Line(530, "no access grant is in force")
}

// sessionID is the live table's identifier for this session, or empty when the
// table refused to register it.
func (se *session) sessionID() string {
	if se.live == nil {
		return ""
	}
	return se.live.ID
}

// follow updates what the proxy knows from a reply it is passing on.
func (se *session) follow(c wire.Command, rep wire.Reply) {
	switch c.Verb {
	case "USER":
		se.user = c.Arg
		se.live.Annotate(c.Arg, "", "")
	case "PASS", "ACCT":
		if rep.Code >= 200 && rep.Code < 300 {
			se.authed = true
			se.resolvePolicy()
			se.openRecording()
			if se.mfa == mfaNotNeeded && se.wantsFactor() {
				// The password was right; the session is not logged in
				// until the factor is too.
				se.mfa = mfaWanted
			}
			se.t.engine.Logs().SecurityEvent(context.Background(), "allow", "ftp_login",
				"listener", se.t.cfg.Name, "client_ip", se.ip.String(),
				"user", textsafe.Clip64(se.user), "target", se.target, "tls", se.secure)
		} else if rep.Code >= 400 {
			se.t.engine.Counters().FTPAuthFailed.Add(1)
			se.t.deny(se.ip, "auth_failed", textsafe.Clip64(se.user))
		}
	case "REST":
		// 350 is the server saying it will honour the marker. Until it
		// does, the offset changes nothing about the next transfer.
		if rep.Code == 350 {
			se.restart = se.pendingRestart
		}
		se.pendingRestart = 0
	case "RNFR":
		if rep.Code == 350 {
			se.renameFrom = se.cleanArg(c.Arg)
		}
	case "RNTO":
		se.renameFrom = ""
	case "CWD", "XCWD":
		if rep.Code >= 200 && rep.Code < 300 {
			se.cwd = se.resolve(c.Arg)
		}
	case "CDUP", "XCUP":
		if rep.Code >= 200 && rep.Code < 300 {
			se.cwd = se.resolve("..")
		}
	}
}

// resolvePolicy substitutes {user} once the login is known. A name that
// could change what a pattern means refuses the session rather than
// being escaped into it, for the same reason it does on sftp.
func (se *session) resolvePolicy() {
	p := se.t.policy
	if !p.templated {
		return
	}
	if !textsafe.Component(se.user) {
		se.t.deny(se.ip, "identity_refused", textsafe.Clip256(se.user))
		_ = se.toClient(wire.Line(421, "this login cannot be used with the path policy here"))
		_ = se.client.Close()
		return
	}
	r := strings.NewReplacer("{user}", se.user)
	out := *p
	out.allowPaths = make([]string, len(p.allowPaths))
	for i, a := range p.allowPaths {
		out.allowPaths[i] = r.Replace(a)
	}
	out.denyPaths = make([]string, len(p.denyPaths))
	for i, d := range p.denyPaths {
		out.denyPaths[i] = r.Replace(d)
	}
	se.policy = &out
}

// resolve turns an argument into an absolute path, following the
// working directory the proxy has been keeping. A path that still
// climbs above the root after cleaning is left as it is and refused by
// the caller: what it means depends on a directory the proxy cannot
// see.
func (se *session) resolve(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return se.cwd
	}
	if !strings.HasPrefix(arg, "/") {
		arg = se.cwd + "/" + arg
	}
	return path.Clean(arg)
}

// pathAllowed applies the path and extension policy to a command's
// argument. It returns the reason to refuse, or empty.
func (se *session) pathAllowed(c wire.Command) string {
	p := se.policy
	clean, ok := sftp.CleanPath(se.resolve(c.Arg))
	if !ok {
		return "relative_path"
	}
	for _, d := range p.denyPaths {
		if sftp.MatchPath(d, clean) {
			return "path_denied"
		}
	}
	switch c.Verb {
	case "STOR", "STOU", "APPE", "RETR", "RNTO":
		if !ftpExtensionAllowed(p, clean) {
			return "extension"
		}
	}
	if len(p.allowPaths) == 0 {
		return ""
	}
	for _, a := range p.allowPaths {
		if sftp.MatchPath(a, clean) {
			return ""
		}
	}
	return "path_not_allowed"
}

// ftpExtensionAllowed reads every extension a name carries, not only
// the last, for the same reason the sftp policy does.
func ftpExtensionAllowed(p *ftpPolicy, name string) bool {
	if len(p.allowExt) == 0 && len(p.denyExt) == 0 {
		return true
	}
	parts := strings.Split(path.Base(name), ".")
	if len(parts) < 2 {
		return true
	}
	exts := parts[1:]
	for _, e := range exts {
		if p.denyExt[strings.ToLower(e)] {
			return false
		}
	}
	if len(p.allowExt) == 0 {
		return true
	}
	return p.allowExt[strings.ToLower(exts[len(exts)-1])]
}

// dataConn is one arrangement for a data connection: what the proxy
// listens on for one side, and what it will dial for the other.
type dataConn struct {
	// ln is the proxy's listener, open from the negotiation until the
	// transfer or the timeout.
	ln net.Listener
	// dial is the far side the proxy connects to once the near side
	// arrives.
	dial netip.AddrPort
	// active says the target connects to the proxy and the proxy
	// connects to the client, rather than the other way round.
	active bool
	// deadline bounds an arrangement nobody uses.
	deadline time.Time
}

func (se *session) closeData() {
	if se.data != nil {
		if se.data.ln != nil {
			_ = se.data.ln.Close()
		}
		se.data = nil
	}
}

// listenData opens the proxy's side of a data connection, inside the
// configured port range.
func (se *session) listenData() (net.Listener, error) {
	t := se.t
	host := se.localAddr()
	var lc net.ListenConfig
	ctx := context.Background()
	if t.loPort == 0 && t.hiPort == 0 {
		return lc.Listen(ctx, "tcp", net.JoinHostPort(host, "0"))
	}
	// A range is what lets a firewall in front of the proxy be narrow,
	// so it is walked until one is free rather than failing on the
	// first port somebody else holds.
	for p := t.loPort; p <= t.hiPort; p++ {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			return ln, nil
		}
	}
	return nil, errors.New("no free port in data_ports")
}

// localAddr is the address the proxy advertises and listens on: the one
// the configuration names, or the one this control connection arrived
// on, which is right unless the proxy is itself behind a NAT.
func (se *session) localAddr() string {
	if se.t.dataAddr.IsValid() {
		return se.t.dataAddr.String()
	}
	if ap, err := netip.ParseAddrPort(se.client.LocalAddr().String()); err == nil {
		return ap.Addr().String()
	}
	return "0.0.0.0"
}

// passive negotiates a passive transfer. The target's reply never
// reaches the client: its address is replaced with the proxy's, because
// forwarding it would tell the client to go round the proxy and take
// the transfer with it.
//
// The port the target announced is used; the address it announced is
// not. The proxy dials the host its control connection is already
// talking to, so a target that answers with an address of its choosing
// cannot send the proxy somewhere else.
func (se *session) passive(c wire.Command) (bool, string) {
	se.closeData()
	if err := se.toUpstream(c); err != nil {
		_ = se.toClient(wire.Line(421, "the server connection ended"))
		return true, "upstream_write"
	}
	rep, err := wire.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(wire.Line(421, "the server connection ended"))
		return true, "upstream_read"
	}
	var port int
	switch {
	case c.Verb == "PASV" && rep.Code == 227:
		ap, err := wire.ParsePASV(rep.Text())
		if err != nil {
			se.t.deny(se.ip, "upstream_address", textsafe.Clip256(rep.Text()))
			_ = se.toClient(wire.Line(425, "the server's passive reply could not be read"))
			return false, ""
		}
		port = int(ap.Port())
	case c.Verb == "EPSV" && rep.Code == 229:
		port, err = wire.ParseEPSV(rep.Text())
		if err != nil {
			se.t.deny(se.ip, "upstream_address", textsafe.Clip256(rep.Text()))
			_ = se.toClient(wire.Line(425, "the server's passive reply could not be read"))
			return false, ""
		}
	default:
		// The target refused, so there is nothing to rewrite.
		if err := se.toClient(rep.Format()); err != nil {
			return true, "write"
		}
		return false, ""
	}
	upAddr, err := netip.ParseAddrPort(se.up.RemoteAddr().String())
	if err != nil {
		_ = se.toClient(wire.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	ln, err := se.listenData()
	if err != nil {
		se.t.engine.Logs().Error.Warn("ftp data listener", "listener", se.t.cfg.Name, "err", err.Error())
		_ = se.toClient(wire.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	mine, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		_ = se.toClient(wire.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	se.data = &dataConn{ln: ln,
		dial:     netip.AddrPortFrom(upAddr.Addr(), uint16(port)), //nolint:gosec // bounded by the parser
		deadline: time.Now().Add(se.t.f.DataTimeout.D())}

	var out wire.Reply
	if c.Verb == "PASV" {
		nums, ok := wire.FormatPASV(mine)
		if !ok {
			// PASV cannot spell an IPv6 address; a client on IPv6
			// has to use EPSV, and saying so is better than sending
			// six numbers that mean nothing.
			_ = ln.Close()
			se.data = nil
			_ = se.toClient(wire.Line(522, "use EPSV; this address cannot be written as six octets"))
			return false, ""
		}
		out = wire.Reply{Code: 227, Lines: []string{"Entering Passive Mode (" + nums + ")"}}
	} else {
		out = wire.Reply{Code: 229, Lines: []string{"Entering Extended Passive Mode " + wire.FormatEPSV(int(mine.Port()))}}
	}
	if err := se.toClient(out.Format()); err != nil {
		return true, "write"
	}
	return false, ""
}

// active accepts PORT and EPRT, which ask the server to connect back to
// an address the client names. That is the bounce attack: a client that
// names somebody else's address has made the server, or here the proxy,
// open a connection on its behalf. It is off by default, and when it is
// on the address has to be the client's own.
func (se *session) active(c wire.Command) (bool, string) {
	se.closeData()
	if !se.t.f.AllowActive {
		if !se.refuse(502, "active mode is not available; use PASV or EPSV", "active_refused", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	var ap netip.AddrPort
	var err error
	if c.Verb == "PORT" {
		ap, err = wire.ParsePORT(c.Arg)
	} else {
		ap, err = wire.ParseEPRT(c.Arg)
	}
	if err != nil {
		if !se.refuse(501, "malformed address", "malformed_address", textsafe.Clip256(c.Arg)) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	if ap.Addr().Unmap() != se.ip.Unmap() {
		// The whole of the bounce attack is in this line.
		if !se.refuse(501, "the address must be your own", "bounce_refused", ap.String()) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	if ap.Port() < 1024 {
		// A client asking the proxy to connect to a privileged port of
		// its own is asking it to speak to something that is not an
		// FTP client.
		if !se.refuse(501, "the port must not be privileged", "bounce_refused", ap.String()) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	ln, err := se.listenData()
	if err != nil {
		_ = se.toClient(wire.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	mine, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		_ = se.toClient(wire.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	se.data = &dataConn{ln: ln, dial: ap, active: true,
		deadline: time.Now().Add(se.t.f.DataTimeout.D())}

	// The target is told the proxy's address, not the client's.
	var out wire.Command
	if c.Verb == "PORT" {
		nums, ok := wire.FormatPORT(mine)
		if !ok {
			_ = ln.Close()
			se.data = nil
			_ = se.toClient(wire.Line(522, "use EPRT; this address cannot be written as six octets"))
			return false, ""
		}
		out = wire.Command{Verb: "PORT", Arg: nums}
	} else {
		out = wire.Command{Verb: "EPRT", Arg: wire.FormatEPRT(mine)}
	}
	return se.relay(out)
}

// auth handles AUTH TLS on the client side. The reply is written before
// the handshake, and anything the client sent ahead of it is refused:
// bytes pipelined across the upgrade are read as plaintext by one side
// and as ciphertext by the other, which is the injection of
// CVE-2011-0411 in its FTP form.
func (se *session) auth(c wire.Command) (bool, string) {
	t := se.t
	mech := strings.ToUpper(strings.TrimSpace(c.Arg))
	if t.f.TLSMode != "starttls" || t.tlsCfg == nil || se.secure {
		if !se.refuse(534, "AUTH is not available here", "auth_refused", mech) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	if mech != "TLS" && mech != "TLS-C" && mech != "SSL" {
		if !se.refuse(504, "only AUTH TLS is available", "auth_refused", mech) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	// The target's leg is upgraded first, so a target that cannot do
	// TLS is found out before the client is told its connection is
	// protected.
	if t.f.UpstreamTLSMode == "starttls" {
		if err := se.upstreamAUTH(); err != nil {
			se.upFailed = true
			_ = se.toClient(wire.Line(431, "the server would not protect the connection"))
			return true, "upstream_auth"
		}
	}
	if n := se.cr.Buffered(); n > 0 {
		se.t.engine.Counters().FTPRefused.Add(1)
		t.deny(se.ip, "tls_pipelined", strconv.Itoa(n))
		_ = se.toClient(wire.Line(500, "data pipelined across AUTH"))
		return true, "tls_pipelined"
	}
	if err := se.toClient(wire.Line(234, "proceeding with TLS")); err != nil {
		return true, "write"
	}
	tc := tls.Server(se.client, t.tlsCfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return true, "tls_handshake"
	}
	se.client = tc
	se.secure = true
	se.cr = wire.NewReader(bufio.NewReaderSize(tc, t.f.MaxCommandLine+2), t.f.MaxCommandLine)
	se.cw = bufio.NewWriter(tc)
	// RFC 4217 section 4: the login starts again on the protected
	// connection, so nothing learned before it is carried over.
	se.user, se.authed = "", false
	return false, ""
}

// upstreamAUTH upgrades the target's leg.
func (se *session) upstreamAUTH() error {
	if err := se.toUpstream(wire.Command{Verb: "AUTH", Arg: "TLS"}); err != nil {
		return err
	}
	rep, err := wire.ReadReply(se.ur)
	if err != nil {
		return err
	}
	if rep.Code != 234 && rep.Code != 334 {
		return fmt.Errorf("the target answered AUTH TLS with %d", rep.Code)
	}
	if n := se.ur.Buffered(); n > 0 {
		return fmt.Errorf("the target sent %d octets after its AUTH reply", n)
	}
	tc := tls.Client(se.up, se.upstreamTLS(se.ep))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return err
	}
	se.up = tc
	se.ur = wire.NewReader(bufio.NewReaderSize(tc, se.t.f.MaxCommandLine+2), se.t.f.MaxCommandLine)
	se.uw = bufio.NewWriter(tc)
	return nil
}

// transfer relays a command that opens a data connection, and mediates
// that connection. The arrangement has to exist first: a transfer with
// no PASV, EPSV, PORT or EPRT in front of it is one the proxy has no
// way to be part of.
func (se *session) transfer(c wire.Command) (bool, string) {
	if se.data == nil {
		if !se.refuse(425, "use PASV, EPSV, PORT or EPRT first", "no_data_connection", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	data := se.data
	se.data = nil
	defer func() { _ = data.ln.Close() }()

	if err := se.toUpstream(c); err != nil {
		_ = se.toClient(wire.Line(421, "the server connection ended"))
		return true, "upstream_write"
	}
	rep, err := wire.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(wire.Line(421, "the server connection ended"))
		return true, "upstream_read"
	}
	if rep.Code >= 300 {
		// The target refused before any data moved.
		if err := se.toClient(rep.Format()); err != nil {
			return true, "write"
		}
		return false, ""
	}
	if err := se.toClient(rep.Format()); err != nil {
		return true, "write"
	}
	se.t.engine.Counters().FTPTransfers.Add(1)
	upload := wire.Uploads[c.Verb]
	n, cut := se.moveData(data, c, upload)
	se.t.engine.Logs().Access.Info("ftp_transfer", "listener", se.t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target, "command", c.Verb,
		"path", textsafe.Clip256(se.resolve(c.Arg)), "bytes", n, "cut", cut)
	se.recordTransfer(c.Verb, se.resolve(c.Arg), n, cut)

	// The target's own completion reply follows the transfer.
	fin, err := wire.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(wire.Line(426, "the transfer ended"))
		return true, "upstream_read"
	}
	if cut != "" {
		// The proxy stopped the transfer, so the target's "complete"
		// would be a lie to the client.
		if err := se.toClient(wire.Line(426, "transfer refused: "+cut)); err != nil {
			return true, "write"
		}
		return false, ""
	}
	if err := se.toClient(fin.Format()); err != nil {
		return true, "write"
	}
	return false, ""
}

// moveData accepts the near side, dials the far side, and copies. It
// returns the octets that crossed and the reason the transfer was cut,
// empty when it finished.
func (se *session) moveData(d *dataConn, c wire.Command, upload bool) (int64, string) {
	_ = d.ln.(*net.TCPListener).SetDeadline(d.deadline)
	near, err := d.ln.Accept()
	if err != nil {
		return 0, "no data connection arrived"
	}
	defer func() { _ = near.Close() }()
	// Only the side that arranged the connection may use it. On a
	// passive transfer that is the client; on an active one it is the
	// target.
	want := se.ip
	if d.active {
		if ap, err := netip.ParseAddrPort(se.up.RemoteAddr().String()); err == nil {
			want = ap.Addr()
		}
	}
	if ap, err := netip.ParseAddrPort(near.RemoteAddr().String()); err != nil || ap.Addr().Unmap() != want.Unmap() {
		se.t.deny(se.ip, "data_stranger", near.RemoteAddr().String())
		return 0, "the data connection came from somewhere else"
	}
	dialer := net.Dialer{Timeout: se.t.f.DataTimeout.D()}
	far, err := dialer.Dial("tcp", d.dial.String())
	if err != nil {
		return 0, "the far side of the data connection refused"
	}
	defer func() { _ = far.Close() }()

	// The proxy is one end of both connections, so it is also the one
	// that protects them. A session that asked for PROT P gets TLS on
	// both sides rather than an opaque tunnel, which is what keeps the
	// transfer both private and readable here.
	if se.prot == "P" {
		if se.secure && se.t.tlsCfg != nil {
			tc := tls.Server(near, se.t.tlsCfg)
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return 0, "the data connection would not start TLS"
			}
			near = tc
		}
		if se.t.upTLS != nil {
			tc := tls.Client(far, se.upstreamTLS(se.ep))
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return 0, "the server's data connection would not start TLS"
			}
			far = tc
		}
	}

	src, dst := near, far
	if !upload {
		src, dst = far, near
	}
	var scan *streamscan.Stream
	if upload && se.policy.yara != nil {
		scan = se.policy.yara.Stream("client")
	}
	// A listing is not a file; only the transfers that carry one are
	// worth a scanner's time.
	if svc := se.t.icapFor(upload); svc != nil && wire.Uploads[c.Verb] == upload && c.Verb != "LIST" && c.Verb != "NLST" && c.Verb != "MLSD" {
		n, reason := se.scanned(svc, dst, src, c, upload, scan)
		if reason != "" {
			se.t.engine.Counters().FTPRefused.Add(1)
			se.t.deny(se.ip, "transfer_cut", reason+" "+textsafe.Clip256(se.resolve(c.Arg)))
		}
		return n, reason
	}
	n, reason := se.copyData(dst, src, scan)
	if reason != "" {
		se.t.engine.Counters().FTPRefused.Add(1)
		se.t.deny(se.ip, "transfer_cut", reason+" "+textsafe.Clip256(se.resolve(c.Arg)))
	}
	return n, reason
}

// copyData copies one direction, holding it to the size bound and,
// where there are rules, reading what goes past. A transfer cannot be
// un-sent, so both act by ending the connection rather than by
// reporting afterwards.
func (se *session) copyData(dst io.Writer, src io.Reader, scan *streamscan.Stream) (int64, string) {
	buf := make([]byte, 32<<10)
	var total int64
	// The bound is about the file, so a resumed transfer is measured from
	// its offset: the file ends up the offset plus what crosses here, and
	// a bound on the bytes relayed would let two REST-offset halves each
	// be inside it. total itself stays the bytes this proxy carried,
	// which is what the log and the counters mean by it.
	max := se.policy.maxFile
	offset := se.restart
	for {
		n, err := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if max > 0 && offset+total > max {
				return total, "max_file_bytes"
			}
			if scan != nil && scan.Feed(buf[:n]) {
				se.ftpYARAReport(scan)
				return total, "yara"
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, ""
			}
		}
		if err != nil {
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			return total, ""
		}
	}
}

// ftpYARAReport records a match on an upload.
func (se *session) ftpYARAReport(scan *streamscan.Stream) {
	ms := scan.Matches()
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		names = append(names, m.Rule)
	}
	se.t.engine.Counters().YARAMatches.Add(1)
	se.t.engine.Logs().SecurityEvent(context.Background(), scan.Policy().Action, "yara_match",
		"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "proto", "ftp",
		"user", textsafe.Clip64(se.user), "target", se.target, "rules", strings.Join(names, ","))
	if bl := se.t.engine.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "yara")
	}
}
