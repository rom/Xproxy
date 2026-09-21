package proxy

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

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sftp"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// ftpServer serves a kind: ftp listener. It speaks FTP to the client
// and FTP to the target, and it is one end of every data connection as
// well, because the address in a passive reply is the whole difference
// between a proxy and a suggestion.
type ftpServer struct {
	s      *Server
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
	yara       *yaraGuard
	templated  bool
}

func newFTPServer(s *Server, cfg config.Listener, ln net.Listener, tc *tls.Config) (*ftpServer, error) {
	f := cfg.FTP
	t := &ftpServer{s: s, cfg: cfg, f: f, ln: ln, tlsCfg: tc,
		verbs: map[string]bool{}, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	for _, c := range f.Commands {
		t.verbs[strings.ToUpper(strings.TrimSpace(c))] = true
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
		g, err := newYARAGuard(f.YARA)
		if err != nil {
			return nil, err
		}
		p.yara = g
	}
	t.policy = p
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

func (t *ftpServer) serve() {
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
			t.s.stats.FTPRejected.Add(1)
			_, _ = c.Write(ftp.Line(421, "too many connections, try again later"))
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

func (t *ftpServer) admit(c net.Conn) bool {
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

func (t *ftpServer) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

func (t *ftpServer) shutdown(ctx context.Context) {
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

func (t *ftpServer) deny(ip netip.Addr, what, detail string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "ftp"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.s.logs.SecurityEvent(context.Background(), "deny", "ftp_"+what, attrs...)
	if bl := t.s.bans.Load(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "ftp_denied")
	}
}

// ftpSession is one control connection and the control connection to
// the target that serves it.
type ftpSession struct {
	t      *ftpServer
	client net.Conn
	cr     *ftp.Reader
	cw     *bufio.Writer
	up     net.Conn
	ur     *ftp.Reader
	uw     *bufio.Writer
	pool   *upstream.Pool
	ep     *upstream.Endpoint

	ip     netip.Addr
	target string
	secure bool // the client's control connection is encrypted
	user   string
	authed bool
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
	data *ftpData
	// policy is the session's, with {user} resolved.
	policy *ftpPolicy
}

func (t *ftpServer) handle(client net.Conn) {
	s := t.s
	start := time.Now()
	se := &ftpSession{t: t, client: client, ip: addrOf(client.RemoteAddr().String()),
		cwd: "/", prot: "C", policy: t.policy}
	s.stats.FTPSessions.Add(1)
	s.stats.FTPSessionsOpen.Add(1)
	defer s.stats.FTPSessionsOpen.Add(-1)
	defer func() { se.closeData() }()

	if !t.clientAllowed(se.ip) {
		s.stats.FTPRejected.Add(1)
		t.deny(se.ip, "client_refused", "")
		_ = client.Close()
		return
	}
	if bl := s.bans.Load(); bl != nil && se.ip.IsValid() && bl.Banned(se.ip) {
		s.stats.FTPRejected.Add(1)
		_, _ = client.Write(ftp.Line(421, "refused"))
		_ = client.Close()
		return
	}
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
	se.cr = ftp.NewReader(bufio.NewReaderSize(se.client, t.f.MaxCommandLine+2), t.f.MaxCommandLine)
	se.cw = bufio.NewWriter(se.client)

	if err := se.connect(); err != nil {
		s.logs.Error.Warn("ftp target unavailable", "listener", t.cfg.Name, "err", err.Error())
		_ = se.toClient(ftp.Line(421, "service unavailable"))
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
	greet, err := ftp.ReadReply(se.ur)
	if err != nil || greet.Code != 220 {
		_ = se.toClient(ftp.Line(421, "service unavailable"))
		t.log(se, start, "upstream_greeting")
		return
	}
	if t.f.Banner != "" {
		greet = ftp.Reply{Code: 220, Lines: []string{t.f.Banner}}
	}
	if err := se.toClient(greet.Format()); err != nil {
		t.log(se, start, "write")
		return
	}
	reason := se.loop()
	t.log(se, start, reason)
}

func (t *ftpServer) clientAllowed(ip netip.Addr) bool {
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

func (t *ftpServer) log(se *ftpSession, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", trimUser(se.user), "target", se.target, "tls", se.secure,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.s.logs.Access.Info("ftp", attrs...)
}

// connect opens the control connection to the target.
func (se *ftpSession) connect() error {
	t := se.t
	pool := t.s.rt.Load().pools[t.f.Upstream]
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
			if _, err := conn.Write(proxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
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
		se.ur = ftp.NewReader(bufio.NewReaderSize(conn, t.f.MaxCommandLine+2), t.f.MaxCommandLine)
		se.uw = bufio.NewWriter(conn)
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable endpoint")
	}
	return lastErr
}

func (se *ftpSession) upstreamTLS(ep *upstream.Endpoint) *tls.Config {
	tc := se.t.upTLS.Clone()
	if tc.ServerName == "" {
		host, _, err := net.SplitHostPort(ep.Address)
		if err == nil {
			tc.ServerName = host
		}
	}
	return tc
}

func (se *ftpSession) toClient(b []byte) error {
	if _, err := se.cw.Write(b); err != nil {
		return err
	}
	return se.cw.Flush()
}

func (se *ftpSession) toUpstream(c ftp.Command) error {
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
func (se *ftpSession) refuse(code int, text, what, detail string) bool {
	se.errors++
	se.t.s.stats.FTPRefused.Add(1)
	se.t.deny(se.ip, what, detail)
	if err := se.toClient(ftp.Line(code, text)); err != nil {
		return false
	}
	return se.errors < se.t.f.MaxErrors
}

// loop reads commands until one of the two connections ends. It returns
// the reason for the access log.
func (se *ftpSession) loop() string {
	t := se.t
	for {
		if t.f.IdleTimeout > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(t.f.IdleTimeout.D()))
		}
		line, err := se.cr.ReadLine()
		if err != nil {
			switch {
			case errors.Is(err, ftp.ErrLineTooLong):
				se.t.s.stats.FTPRefused.Add(1)
				t.deny(se.ip, "line_too_long", "")
				_ = se.toClient(ftp.Line(500, "command line too long"))
				return "line_too_long"
			case errors.Is(err, ftp.ErrBareNewline), errors.Is(err, ftp.ErrBareCR), errors.Is(err, ftp.ErrTelnet):
				// Each of these is a way for the proxy and the target
				// to disagree about where a command ends, which is how
				// one command becomes two.
				se.t.s.stats.FTPRefused.Add(1)
				t.deny(se.ip, "malformed_line", err.Error())
				_ = se.toClient(ftp.Line(500, "malformed command"))
				return "malformed_line"
			}
			return "client_closed"
		}
		cmd, err := ftp.ParseCommand(line)
		if err != nil {
			if !se.refuse(500, "unrecognised command", "malformed_command", "") {
				return "too_many_errors"
			}
			continue
		}
		done, reason := se.command(cmd)
		if done {
			return reason
		}
	}
}

// command decides one command and relays what it allows.
func (se *ftpSession) command(c ftp.Command) (bool, string) {
	t := se.t
	switch {
	case !ftp.Known[c.Verb]:
		// A verb this proxy cannot name the effect of is a verb it
		// cannot hold to a policy.
		if !se.refuse(502, "command not implemented", "unknown_command", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	case !t.verbs[c.Verb]:
		if !se.refuse(502, "command not allowed", "command_refused", c.Verb) {
			return true, "too_many_errors"
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
	if t.f.ReadOnly && ftp.Writes[c.Verb] {
		if !se.refuse(532, "the server is read only through this proxy", "read_only", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
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
	if ftp.Paths[c.Verb] && c.Arg != "" {
		if reason := se.pathAllowed(c); reason != "" {
			if !se.refuse(550, "refused by policy", "path_refused", reason+" "+sftpClip(c.Arg)) {
				return true, "too_many_errors"
			}
			return false, ""
		}
	}
	if ftp.Transfers[c.Verb] {
		return se.transfer(c)
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
func (se *ftpSession) relay(c ftp.Command) (bool, string) {
	if err := se.toUpstream(c); err != nil {
		_ = se.toClient(ftp.Line(421, "the server connection ended"))
		return true, "upstream_write"
	}
	rep, err := ftp.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(ftp.Line(421, "the server connection ended"))
		return true, "upstream_read"
	}
	se.follow(c, rep)
	if err := se.toClient(rep.Format()); err != nil {
		return true, "write"
	}
	if c.Verb == "QUIT" {
		return true, "quit"
	}
	return false, ""
}

// follow updates what the proxy knows from a reply it is passing on.
func (se *ftpSession) follow(c ftp.Command, rep ftp.Reply) {
	switch c.Verb {
	case "USER":
		se.user = c.Arg
	case "PASS", "ACCT":
		if rep.Code >= 200 && rep.Code < 300 {
			se.authed = true
			se.resolvePolicy()
			se.t.s.logs.SecurityEvent(context.Background(), "allow", "ftp_login",
				"listener", se.t.cfg.Name, "client_ip", se.ip.String(),
				"user", trimUser(se.user), "target", se.target, "tls", se.secure)
		} else if rep.Code >= 400 {
			se.t.s.stats.FTPAuthFailed.Add(1)
			se.t.deny(se.ip, "auth_failed", trimUser(se.user))
		}
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
func (se *ftpSession) resolvePolicy() {
	p := se.t.policy
	if !p.templated {
		return
	}
	if !sftpNameSafe(se.user) {
		se.t.deny(se.ip, "identity_refused", sftpClip(se.user))
		_ = se.toClient(ftp.Line(421, "this login cannot be used with the path policy here"))
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
func (se *ftpSession) resolve(arg string) string {
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
func (se *ftpSession) pathAllowed(c ftp.Command) string {
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

// ftpData is one arrangement for a data connection: what the proxy
// listens on for one side, and what it will dial for the other.
type ftpData struct {
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

func (se *ftpSession) closeData() {
	if se.data != nil {
		if se.data.ln != nil {
			_ = se.data.ln.Close()
		}
		se.data = nil
	}
}

// listenData opens the proxy's side of a data connection, inside the
// configured port range.
func (se *ftpSession) listenData() (net.Listener, error) {
	t := se.t
	host := se.localAddr()
	if t.loPort == 0 && t.hiPort == 0 {
		return net.Listen("tcp", net.JoinHostPort(host, "0"))
	}
	for p := t.loPort; p <= t.hiPort; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			return ln, nil
		}
	}
	return nil, errors.New("no free port in data_ports")
}

// localAddr is the address the proxy advertises and listens on: the one
// the configuration names, or the one this control connection arrived
// on, which is right unless the proxy is itself behind a NAT.
func (se *ftpSession) localAddr() string {
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
func (se *ftpSession) passive(c ftp.Command) (bool, string) {
	se.closeData()
	if err := se.toUpstream(c); err != nil {
		_ = se.toClient(ftp.Line(421, "the server connection ended"))
		return true, "upstream_write"
	}
	rep, err := ftp.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(ftp.Line(421, "the server connection ended"))
		return true, "upstream_read"
	}
	var port int
	switch {
	case c.Verb == "PASV" && rep.Code == 227:
		ap, err := ftp.ParsePASV(rep.Text())
		if err != nil {
			se.t.deny(se.ip, "upstream_address", sftpClip(rep.Text()))
			_ = se.toClient(ftp.Line(425, "the server's passive reply could not be read"))
			return false, ""
		}
		port = int(ap.Port())
	case c.Verb == "EPSV" && rep.Code == 229:
		port, err = ftp.ParseEPSV(rep.Text())
		if err != nil {
			se.t.deny(se.ip, "upstream_address", sftpClip(rep.Text()))
			_ = se.toClient(ftp.Line(425, "the server's passive reply could not be read"))
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
		_ = se.toClient(ftp.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	ln, err := se.listenData()
	if err != nil {
		se.t.s.logs.Error.Warn("ftp data listener", "listener", se.t.cfg.Name, "err", err.Error())
		_ = se.toClient(ftp.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	mine, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		_ = se.toClient(ftp.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	se.data = &ftpData{ln: ln,
		dial:     netip.AddrPortFrom(upAddr.Addr(), uint16(port)), //nolint:gosec // bounded by the parser
		deadline: time.Now().Add(se.t.f.DataTimeout.D())}

	var out ftp.Reply
	if c.Verb == "PASV" {
		nums, ok := ftp.FormatPASV(mine)
		if !ok {
			// PASV cannot spell an IPv6 address; a client on IPv6
			// has to use EPSV, and saying so is better than sending
			// six numbers that mean nothing.
			_ = ln.Close()
			se.data = nil
			_ = se.toClient(ftp.Line(522, "use EPSV; this address cannot be written as six octets"))
			return false, ""
		}
		out = ftp.Reply{Code: 227, Lines: []string{"Entering Passive Mode (" + nums + ")"}}
	} else {
		out = ftp.Reply{Code: 229, Lines: []string{"Entering Extended Passive Mode " + ftp.FormatEPSV(int(mine.Port()))}}
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
func (se *ftpSession) active(c ftp.Command) (bool, string) {
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
		ap, err = ftp.ParsePORT(c.Arg)
	} else {
		ap, err = ftp.ParseEPRT(c.Arg)
	}
	if err != nil {
		if !se.refuse(501, "malformed address", "malformed_address", sftpClip(c.Arg)) {
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
		_ = se.toClient(ftp.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	mine, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		_ = se.toClient(ftp.Line(425, "cannot arrange a data connection"))
		return false, ""
	}
	se.data = &ftpData{ln: ln, dial: ap, active: true,
		deadline: time.Now().Add(se.t.f.DataTimeout.D())}

	// The target is told the proxy's address, not the client's.
	var out ftp.Command
	if c.Verb == "PORT" {
		nums, ok := ftp.FormatPORT(mine)
		if !ok {
			_ = ln.Close()
			se.data = nil
			_ = se.toClient(ftp.Line(522, "use EPRT; this address cannot be written as six octets"))
			return false, ""
		}
		out = ftp.Command{Verb: "PORT", Arg: nums}
	} else {
		out = ftp.Command{Verb: "EPRT", Arg: ftp.FormatEPRT(mine)}
	}
	return se.relay(out)
}

// auth handles AUTH TLS on the client side. The reply is written before
// the handshake, and anything the client sent ahead of it is refused:
// bytes pipelined across the upgrade are read as plaintext by one side
// and as ciphertext by the other, which is the injection of
// CVE-2011-0411 in its FTP form.
func (se *ftpSession) auth(c ftp.Command) (bool, string) {
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
			_ = se.toClient(ftp.Line(431, "the server would not protect the connection"))
			return true, "upstream_auth"
		}
	}
	if n := se.cr.Buffered(); n > 0 {
		se.t.s.stats.FTPRefused.Add(1)
		t.deny(se.ip, "tls_pipelined", strconv.Itoa(n))
		_ = se.toClient(ftp.Line(500, "data pipelined across AUTH"))
		return true, "tls_pipelined"
	}
	if err := se.toClient(ftp.Line(234, "proceeding with TLS")); err != nil {
		return true, "write"
	}
	tc := tls.Server(se.client, t.tlsCfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return true, "tls_handshake"
	}
	se.client = tc
	se.secure = true
	se.cr = ftp.NewReader(bufio.NewReaderSize(tc, t.f.MaxCommandLine+2), t.f.MaxCommandLine)
	se.cw = bufio.NewWriter(tc)
	// RFC 4217 section 4: the login starts again on the protected
	// connection, so nothing learned before it is carried over.
	se.user, se.authed = "", false
	return false, ""
}

// upstreamAUTH upgrades the target's leg.
func (se *ftpSession) upstreamAUTH() error {
	if err := se.toUpstream(ftp.Command{Verb: "AUTH", Arg: "TLS"}); err != nil {
		return err
	}
	rep, err := ftp.ReadReply(se.ur)
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
	se.ur = ftp.NewReader(bufio.NewReaderSize(tc, se.t.f.MaxCommandLine+2), se.t.f.MaxCommandLine)
	se.uw = bufio.NewWriter(tc)
	return nil
}

// transfer relays a command that opens a data connection, and mediates
// that connection. The arrangement has to exist first: a transfer with
// no PASV, EPSV, PORT or EPRT in front of it is one the proxy has no
// way to be part of.
func (se *ftpSession) transfer(c ftp.Command) (bool, string) {
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
		_ = se.toClient(ftp.Line(421, "the server connection ended"))
		return true, "upstream_write"
	}
	rep, err := ftp.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(ftp.Line(421, "the server connection ended"))
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
	se.t.s.stats.FTPTransfers.Add(1)
	upload := ftp.Uploads[c.Verb]
	n, cut := se.moveData(data, c, upload)
	se.t.s.logs.Access.Info("ftp_transfer", "listener", se.t.cfg.Name, "client_ip", se.ip.String(),
		"user", trimUser(se.user), "target", se.target, "command", c.Verb,
		"path", sftpClip(se.resolve(c.Arg)), "bytes", n, "cut", cut)

	// The target's own completion reply follows the transfer.
	fin, err := ftp.ReadReply(se.ur)
	if err != nil {
		se.upFailed = true
		_ = se.toClient(ftp.Line(426, "the transfer ended"))
		return true, "upstream_read"
	}
	if cut != "" {
		// The proxy stopped the transfer, so the target's "complete"
		// would be a lie to the client.
		if err := se.toClient(ftp.Line(426, "transfer refused: "+cut)); err != nil {
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
func (se *ftpSession) moveData(d *ftpData, c ftp.Command, upload bool) (int64, string) {
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
	var scan *yaraStream
	if upload && se.policy.yara != nil {
		scan = se.policy.yara.stream("client")
	}
	n, reason := se.copyData(dst, src, scan)
	if reason != "" {
		se.t.s.stats.FTPRefused.Add(1)
		se.t.deny(se.ip, "transfer_cut", reason+" "+sftpClip(se.resolve(c.Arg)))
	}
	return n, reason
}

// copyData copies one direction, holding it to the size bound and,
// where there are rules, reading what goes past. A transfer cannot be
// un-sent, so both act by ending the connection rather than by
// reporting afterwards.
func (se *ftpSession) copyData(dst io.Writer, src io.Reader, scan *yaraStream) (int64, string) {
	buf := make([]byte, 32<<10)
	var total int64
	max := se.policy.maxFile
	for {
		n, err := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if max > 0 && total > max {
				return total, "max_file_bytes"
			}
			if scan != nil && scan.feed(buf[:n]) {
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
func (se *ftpSession) ftpYARAReport(scan *yaraStream) {
	ms := scan.matches()
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		names = append(names, m.Rule)
	}
	se.t.s.stats.YARAMatches.Add(1)
	se.t.s.logs.SecurityEvent(context.Background(), scan.g.cfg.Action, "yara_match",
		"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "proto", "ftp",
		"user", trimUser(se.user), "target", se.target, "rules", strings.Join(names, ","))
	if bl := se.t.s.bans.Load(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "yara")
	}
}
