package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// sshServer serves a kind: ssh listener: an SSH bastion that terminates
// the client's session and opens its own to the target.
//
// A jump host that forwards the stream cannot see which channel is a
// shell and which is a port forward, so the only policy it can hold is
// "may connect". Here every channel and every request inside the
// session is a decision, and the target never sees the client's key:
// the client authenticates to the proxy, the proxy authenticates to the
// target with a credential the client never holds.
type sshServer struct {
	s    *Server
	cfg  config.Listener
	h    *config.SSHListener
	ln   net.Listener
	scfg *ssh.ServerConfig

	upstreamAuth ssh.AuthMethod
	hostKeyCheck ssh.HostKeyCallback
	allow        []netip.Prefix
	channels     map[string]bool
	requests     map[string]bool
	subsystems   map[string]bool
	commands     []*regexp.Regexp
	forwards     []sshForward
	sftp         *sftpPolicy

	// mfaGuard is the second factor, when one is configured. It is
	// shared with every other listener reading the same enrolment file
	// only in the sense that the file is the same: the replay memory
	// and the lockout are per listener, per process.
	mfaGuard *mfa.Guard

	// keys and users are the credentials this listener accepts. They
	// are read at build time, so a reload rebuilds the listener rather
	// than changing the answer mid-connection.
	keys  map[string]bool
	users map[string]string

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
}

// sshForward is one allowed direct-tcpip destination.
type sshForward struct {
	name     string
	wildcard bool
	prefix   netip.Prefix
	isPrefix bool
	port     int // 0 is any
}

func newSSHServer(s *Server, cfg config.Listener, ln net.Listener) (*sshServer, error) {
	h := cfg.SSH
	t := &sshServer{s: s, cfg: cfg, h: h, ln: ln,
		channels: map[string]bool{}, requests: map[string]bool{}, subsystems: map[string]bool{},
		keys: map[string]bool{}, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	for _, c := range h.AllowChannels {
		t.channels[c] = true
	}
	for _, r := range h.AllowRequests {
		t.requests[r] = true
	}
	for _, sub := range h.AllowSubsystems {
		t.subsystems[sub] = true
	}
	for _, re := range h.AllowCommands {
		c, err := regexp.Compile(re)
		if err != nil {
			return nil, fmt.Errorf("ssh allow_commands: %w", err)
		}
		t.commands = append(t.commands, c)
	}
	for _, d := range h.Forward {
		f, err := parseSSHForward(d)
		if err != nil {
			return nil, fmt.Errorf("ssh forward %q: %w", d, err)
		}
		t.forwards = append(t.forwards, f)
	}
	for _, c := range h.AllowClients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ssh allow_clients: %w", err)
		}
		t.allow = append(t.allow, p)
	}
	if h.SFTP != nil {
		p, err := newSFTPPolicy(h.SFTP)
		if err != nil {
			return nil, err
		}
		t.sftp = p
	}
	if err := t.loadCredentials(); err != nil {
		return nil, err
	}
	if h.MFA != nil {
		store, err := mfa.Load(h.MFA.File)
		if err != nil {
			return nil, fmt.Errorf("ssh mfa: %w", err)
		}
		t.mfaGuard = mfa.NewGuard(store, h.MFA.Skew, mfa.Lockout{
			MaxFailures: h.MFA.MaxFailures,
			Window:      h.MFA.Window.D(),
			Duration:    h.MFA.Duration.D(),
			MaxUsers:    h.MFA.MaxUsers,
		})
	}
	if err := t.buildServerConfig(); err != nil {
		return nil, err
	}
	return t, nil
}

// loadCredentials reads the keys the listener accepts and the key it
// presents onwards.
func (t *sshServer) loadCredentials() error {
	h := t.h
	if h.AuthorizedKeys != "" {
		raw, err := os.ReadFile(h.AuthorizedKeys) //nolint:gosec // a path from the configuration
		if err != nil {
			return fmt.Errorf("ssh authorized_keys: %w", err)
		}
		for len(raw) > 0 {
			key, _, _, rest, err := ssh.ParseAuthorizedKey(raw)
			if err != nil {
				// One unreadable line must not silently shorten the
				// list: a key that was meant to be accepted and is not
				// is an outage, and one that was meant to be removed
				// and is not is worse.
				return fmt.Errorf("ssh authorized_keys: %w", err)
			}
			t.keys[string(key.Marshal())] = true
			raw = rest
		}
		if len(t.keys) == 0 {
			return errors.New("ssh authorized_keys: no keys in the file")
		}
	}
	if h.UsersFile != "" {
		users, err := passwd.LoadUsers(h.UsersFile)
		if err != nil {
			return fmt.Errorf("ssh users_file: %w", err)
		}
		t.users = users
	}
	raw, err := os.ReadFile(h.UpstreamKeyFile) //nolint:gosec // a path from the configuration
	if err != nil {
		return fmt.Errorf("ssh upstream_key_file: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return fmt.Errorf("ssh upstream_key_file: %w", err)
	}
	t.upstreamAuth = ssh.PublicKeys(signer)
	if h.UpstreamKnownHosts != "" {
		cb, err := knownHostsCallback(h.UpstreamKnownHosts)
		if err != nil {
			return fmt.Errorf("ssh upstream_known_hosts: %w", err)
		}
		t.hostKeyCheck = cb
	} else {
		t.hostKeyCheck = ssh.InsecureIgnoreHostKey() //nolint:gosec // refused by validation unless allow_insecure
	}
	return nil
}

func (t *sshServer) buildServerConfig() error {
	h := t.h
	cfg := &ssh.ServerConfig{
		ServerVersion: h.ServerVersion,
		MaxAuthTries:  h.MaxAuthTries,
	}
	if h.Banner != "" {
		banner := h.Banner
		if !strings.HasSuffix(banner, "\n") {
			banner += "\n"
		}
		cfg.BannerCallback = func(ssh.ConnMetadata) string { return banner }
	}
	if len(t.keys) > 0 {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !t.keys[string(key.Marshal())] {
				return nil, fmt.Errorf("unknown public key for %q", c.User())
			}
			if t.mfaGuard != nil {
				// The key is right and the session is not authorised
				// yet: RFC 4252 partial success, and the client is
				// told which method comes next.
				return nil, t.secondFactor("publickey")
			}
			return &ssh.Permissions{Extensions: map[string]string{
				"auth":        "publickey",
				"fingerprint": ssh.FingerprintSHA256(key),
			}}, nil
		}
	}
	if len(t.users) > 0 {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			hash, ok := t.users[c.User()]
			if !ok {
				// The same work is done for an unknown user as for a
				// known one, so the timing does not say which it was.
				passwd.VerifyDummy(string(pass))
				return nil, errors.New("authentication failed")
			}
			if !passwd.Verify(hash, string(pass)) {
				return nil, errors.New("authentication failed")
			}
			if t.mfaGuard != nil {
				return nil, t.secondFactor("password")
			}
			return &ssh.Permissions{Extensions: map[string]string{"auth": "password"}}, nil
		}
	}
	cfg.AuthLogCallback = func(c ssh.ConnMetadata, method string, err error) {
		if err == nil || method == "none" {
			return
		}
		t.s.stats.SSHAuthFailed.Add(1)
		ip := addrOf(c.RemoteAddr().String())
		t.deny(ip, "auth_failed", method+" for "+trimUser(c.User()))
	}
	for i, path := range h.HostKeys {
		raw, err := os.ReadFile(path) //nolint:gosec // a path from the configuration
		if err != nil {
			return fmt.Errorf("ssh host_keys[%d]: %w", i, err)
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return fmt.Errorf("ssh host_keys[%d]: %w", i, err)
		}
		cfg.AddHostKey(signer)
	}
	t.scfg = cfg
	return nil
}

// trimUser bounds what a name contributes to a log line, and keeps
// control characters out of it.
func trimUser(u string) string {
	u = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, u)
	if len(u) > 64 {
		return u[:64] + "..."
	}
	return u
}

func (t *sshServer) serve() {
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
		if t.open.Add(1) > int64(t.h.MaxSessions) {
			t.open.Add(-1)
			t.s.stats.SSHRejected.Add(1)
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
			defer safe.Guard("ssh session")
			t.handle(c)
		}()
	}
}

func (t *sshServer) admit(c net.Conn) bool {
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

func (t *sshServer) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

func (t *sshServer) shutdown(ctx context.Context) {
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

func (t *sshServer) allowed(ip netip.Addr) bool {
	if len(t.allow) == 0 {
		return true
	}
	if !ip.IsValid() {
		return false
	}
	for _, p := range t.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *sshServer) deny(ip netip.Addr, what, detail string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "ssh"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.s.logs.SecurityEvent(context.Background(), "deny", "ssh_"+what, attrs...)
	if bl := t.s.bans.Load(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "ssh_denied")
	}
}

// sshSession is one client connection and the target connection behind
// it.
type sshSession struct {
	t      *sshServer
	sconn  *ssh.ServerConn
	client *ssh.Client
	ip     netip.Addr
	user   string
	auth   string
	target string

	channels atomic.Int64
	opened   atomic.Uint64
	refused  atomic.Uint64
	wg       sync.WaitGroup
}

func (t *sshServer) handle(raw net.Conn) {
	s := t.s
	start := time.Now()
	s.stats.SSHSessions.Add(1)
	s.stats.SSHSessionsOpen.Add(1)
	defer s.stats.SSHSessionsOpen.Add(-1)
	ip := addrOf(raw.RemoteAddr().String())
	se := &sshSession{t: t, ip: ip}
	defer func() { _ = raw.Close() }()

	if !t.allowed(ip) {
		s.stats.SSHRejected.Add(1)
		t.deny(ip, "client_not_allowed", "")
		t.log(se, start, "client_not_allowed")
		return
	}
	// The handshake and authentication share one deadline. Once the
	// session is up the idle timeout takes over, applied by the
	// connection wrapper below.
	_ = raw.SetDeadline(time.Now().Add(t.h.HandshakeTimeout.D()))
	sconn, chans, reqs, err := ssh.NewServerConn(raw, t.scfg)
	if err != nil {
		t.log(se, start, "handshake")
		return
	}
	defer func() { _ = sconn.Close() }()
	_ = raw.SetDeadline(time.Time{})
	se.sconn = sconn
	se.user = sconn.User()
	if sconn.Permissions != nil {
		se.auth = sconn.Permissions.Extensions["auth"]
	}
	if t.h.SessionTimeout > 0 {
		timer := time.AfterFunc(t.h.SessionTimeout.D(), func() { _ = sconn.Close() })
		defer timer.Stop()
	}

	if err := se.connect(); err != nil {
		s.logs.Error.Warn("ssh target unavailable", "listener", t.cfg.Name, "user", trimUser(se.user), "err", err.Error())
		t.log(se, start, "upstream_unavailable")
		return
	}
	defer func() { _ = se.client.Close() }()

	go se.globalRequests(reqs)
	for nc := range chans {
		if se.channels.Load() >= int64(t.h.MaxChannels) {
			_ = nc.Reject(ssh.ResourceShortage, "too many channels")
			se.refused.Add(1)
			continue
		}
		se.channels.Add(1)
		se.wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer se.wg.Done()
			defer se.channels.Add(-1)
			defer safe.Guard("ssh channel")
			se.channel(nc)
		}(nc)
	}
	se.wg.Wait()
	t.log(se, start, "")
}

func (t *sshServer) log(se *sshSession, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", trimUser(se.user), "auth", se.auth, "target", se.target,
		"channels", se.opened.Load(), "refused", se.refused.Load(),
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.s.logs.Access.Info("ssh", attrs...)
}

// connect opens the target session. The user the proxy authenticates as
// is the configured one, or the name the client authenticated with when
// none is configured.
func (se *sshSession) connect() error {
	t := se.t
	pool := t.s.rt.Load().pools[t.h.Upstream]
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", t.h.Upstream)
	}
	user := t.h.UpstreamUser
	if user == "" {
		user = se.user
	}
	tried := map[*upstream.Endpoint]bool{}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		conn, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			lastErr = err
			continue
		}
		if t.h.ProxyProtocol {
			if _, err := conn.Write(proxyV2Header(se.sconn.RemoteAddr(), se.sconn.LocalAddr())); err != nil {
				pool.End(e, true, 0)
				_ = conn.Close()
				lastErr = err
				continue
			}
		}
		_ = conn.SetDeadline(time.Now().Add(t.h.HandshakeTimeout.D()))
		cc := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{t.upstreamAuth},
			HostKeyCallback: t.hostKeyCheck,
			Timeout:         t.h.HandshakeTimeout.D(),
		}
		nc, nchans, nreqs, err := ssh.NewClientConn(conn, e.Address, cc)
		if err != nil {
			pool.End(e, true, 0)
			_ = conn.Close()
			lastErr = err
			t.s.logs.Error.Warn("ssh target handshake failed", "listener", t.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		_ = conn.SetDeadline(time.Time{})
		pool.End(e, false, 0)
		se.client = ssh.NewClient(nc, nchans, nreqs)
		se.target = e.Address
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable endpoint")
	}
	return lastErr
}

// globalRequests answers the connection-wide requests. tcpip-forward is
// the one that matters: it asks the target to listen on the client's
// behalf, which turns an outbound session into an inbound path.
func (se *sshSession) globalRequests(reqs <-chan *ssh.Request) {
	defer safe.Guard("ssh global requests")
	for r := range reqs {
		switch {
		case r.Type == "keepalive@openssh.com":
			_ = r.Reply(true, nil)
		case (r.Type == "tcpip-forward" || r.Type == "cancel-tcpip-forward") && se.t.h.RemoteForward:
			ok, payload, err := se.client.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				_ = r.Reply(false, nil)
				return
			}
			_ = r.Reply(ok, payload)
		default:
			if r.Type == "tcpip-forward" {
				se.refused.Add(1)
				se.t.s.stats.SSHRefused.Add(1)
				se.t.deny(se.ip, "remote_forward_refused", "")
			}
			_ = r.Reply(false, nil)
		}
	}
}

// channel decides on one channel the client asked to open, and relays
// it when the policy allows.
func (se *sshSession) channel(nc ssh.NewChannel) {
	t := se.t
	kind := nc.ChannelType()
	if !t.channels[kind] {
		se.refuse(nc, "channel_refused", kind, ssh.Prohibited, "channel type not allowed")
		return
	}
	extra := nc.ExtraData()
	if kind == "direct-tcpip" {
		host, port, err := parseDirectTCPIP(extra)
		if err != nil {
			se.refuse(nc, "malformed_channel", kind, ssh.ConnectionFailed, "malformed channel request")
			return
		}
		if !t.forwardAllowed(host, port) {
			se.refuse(nc, "forward_refused", net.JoinHostPort(host, strconv.Itoa(port)), ssh.Prohibited, "destination not allowed")
			return
		}
	}
	// The channel is opened on the target first: a client that is told
	// its channel is open and then finds it is not has to guess why,
	// and the target's own refusal is the truthful answer.
	upCh, upReqs, err := se.client.OpenChannel(kind, extra)
	if err != nil {
		var oce *ssh.OpenChannelError
		if errors.As(err, &oce) {
			_ = nc.Reject(oce.Reason, oce.Message)
		} else {
			_ = nc.Reject(ssh.ConnectionFailed, "target refused the channel")
		}
		return
	}
	clientCh, clientReqs, err := nc.Accept()
	if err != nil {
		_ = upCh.Close()
		return
	}
	se.opened.Add(1)
	t.s.stats.SSHChannels.Add(1)

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientCh.Close()
			_ = upCh.Close()
		})
	}
	// serverDone closes once every request the target sent has been
	// relayed. exit-status is one of those, so nothing may close the
	// client's channel before this: a command whose status is lost
	// looks to the client like a command that crashed.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer safe.Guard("ssh target requests")
		for r := range upReqs {
			ok, err := clientCh.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				return
			}
			_ = r.Reply(ok, nil)
		}
	}()

	// The data pump exists from the start but waits to be told whether
	// this channel is copied at all: an sftp channel under inspection
	// is relayed packet by packet instead, and two readers on one
	// channel would each get half of it. The goroutine is registered
	// before anything can finish, so waiting for it is never a wait for
	// something that has not started.
	mode := make(chan bool, 1)
	var modeOnce sync.Once
	setMode := func(copyData bool) {
		modeOnce.Do(func() {
			mode <- copyData
			close(mode)
		})
	}
	var pumps sync.WaitGroup
	pumps.Add(1)
	go func() {
		defer pumps.Done()
		defer safe.Guard("ssh channel data")
		if !<-mode {
			return
		}
		se.pipe(clientCh, upCh)
		// The target's side is drained. Its last requests are relayed
		// first, and then anything the client still holds open ends
		// with the channel.
		<-serverDone
		closeBoth()
	}()
	startPump := func() { setMode(true) }
	if kind != "session" {
		// A forward carries bytes from the first octet: there is no
		// request that starts it.
		startPump()
	}

	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		defer setMode(false)
		defer safe.Guard("ssh channel requests")
		// Requests from the client are the policy's other half: the
		// channel type says "a session", and these say what is done
		// with it.
		se.clientRequests(clientCh, upCh, clientReqs, startPump)
	}()
	// Either side finishing ends the channel: the target closed it, or
	// the client did.
	select {
	case <-serverDone:
		// Let the pump drain what the target sent before closing; the
		// pump closes once it has, and this is the fallback for a
		// channel that never carried data.
		setMode(false)
		pumps.Wait()
		closeBoth()
	case <-reqDone:
		closeBoth()
		pumps.Wait()
	}
	<-serverDone
	<-reqDone
}

func (se *sshSession) refuse(nc ssh.NewChannel, what, detail string, reason ssh.RejectionReason, msg string) {
	se.refused.Add(1)
	se.t.s.stats.SSHRefused.Add(1)
	se.t.deny(se.ip, what, detail)
	_ = nc.Reject(reason, msg)
}

// clientRequests applies the request policy and relays what it allows.
// startPump is called once the request that begins the data flow has
// been forwarded, so an inspected sftp channel is never also copied
// blindly.
func (se *sshSession) clientRequests(clientCh, upCh ssh.Channel, reqs <-chan *ssh.Request, startPump func()) {
	t := se.t
	for r := range reqs {
		if !t.requests[r.Type] {
			se.refuseRequest(r, "request_refused", r.Type)
			continue
		}
		switch r.Type {
		case "subsystem":
			name := sshStringPayload(r.Payload)
			if !t.subsystems[name] {
				se.refuseRequest(r, "subsystem_refused", name)
				continue
			}
			if name == "sftp" && t.sftp != nil {
				// From here the channel carries SFTP, which is a
				// protocol of its own and gets its own decisions.
				ok, err := upCh.SendRequest(r.Type, r.WantReply, r.Payload)
				if err != nil || !ok {
					_ = r.Reply(false, nil)
					return
				}
				_ = r.Reply(true, nil)
				se.relaySFTP(clientCh, upCh)
				return
			}
		case "exec":
			cmd := sshStringPayload(r.Payload)
			if !se.commandAllowed(cmd) {
				se.refuseRequest(r, "command_refused", sftpClip(cmd))
				continue
			}
			t.s.logs.SecurityEvent(context.Background(), "allow", "ssh_exec",
				"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", trimUser(se.user),
				"target", se.target, "command", sftpClip(cmd))
		}
		// The mode is chosen before the request is forwarded. The
		// other way round, a fast command could finish and close the
		// channel before the copier existed, and its output would be
		// lost to a race rather than to anything the policy decided.
		switch r.Type {
		case "shell", "exec", "subsystem":
			startPump()
		}
		ok, err := upCh.SendRequest(r.Type, r.WantReply, r.Payload)
		if err != nil {
			_ = r.Reply(false, nil)
			return
		}
		_ = r.Reply(ok, nil)
	}
}

func (se *sshSession) refuseRequest(r *ssh.Request, what, detail string) {
	se.refused.Add(1)
	se.t.s.stats.SSHRefused.Add(1)
	se.t.deny(se.ip, what, detail)
	_ = r.Reply(false, nil)
}

func (se *sshSession) commandAllowed(cmd string) bool {
	if len(se.t.commands) == 0 {
		return true
	}
	for _, re := range se.t.commands {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// pipe copies a channel's data and its extended (stderr) data both
// ways, and half-closes so the far side sees the end of input.
func (se *sshSession) pipe(clientCh, upCh ssh.Channel) {
	// The client to target direction is not waited for. A client that
	// runs a command without closing its input never sends EOF, so
	// waiting for it would mean waiting for the client rather than for
	// the command; it ends when the channel is closed.
	go func() {
		defer safe.Guard("ssh data to target")
		n, _ := copyBounded(upCh, clientCh)
		se.t.s.stats.SSHBytesIn.Add(uint64(n)) //nolint:gosec // non-negative
		_ = upCh.CloseWrite()
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("ssh data to client")
		n, _ := copyBounded(clientCh, upCh)
		se.t.s.stats.SSHBytesOut.Add(uint64(n)) //nolint:gosec // non-negative
		_ = clientCh.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("ssh stderr to client")
		_, _ = copyBounded(clientCh.Stderr(), upCh.Stderr())
	}()
	wg.Wait()
}

// forwardAllowed applies the direct-tcpip destination policy.
func (t *sshServer) forwardAllowed(host string, port int) bool {
	addr, isAddr := netip.ParseAddr(host)
	if isAddr == nil {
		addr = addr.Unmap()
	}
	for _, f := range t.forwards {
		if f.port != 0 && f.port != port {
			continue
		}
		switch {
		case f.isPrefix:
			if isAddr == nil && f.prefix.Contains(addr) {
				return true
			}
		case f.wildcard:
			suffix := f.name[1:] // ".example.com"
			h := strings.ToLower(host)
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
		default:
			if strings.EqualFold(f.name, host) {
				return true
			}
		}
	}
	return false
}

func parseSSHForward(d string) (sshForward, error) {
	host, port, err := net.SplitHostPort(d)
	if err != nil {
		return sshForward{}, errors.New("must be host:port")
	}
	f := sshForward{name: strings.ToLower(host)}
	if port != "*" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return sshForward{}, errors.New("port must be a number or *")
		}
		f.port = n
	}
	switch {
	case strings.Contains(host, "/"):
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return sshForward{}, err
		}
		f.prefix, f.isPrefix = p, true
	case strings.HasPrefix(host, "*."):
		f.wildcard = true
	}
	return f, nil
}

// parseDirectTCPIP reads the channel payload of RFC 4254 section 7.2:
// the destination the client wants reached, then the origin it claims.
func parseDirectTCPIP(b []byte) (string, int, error) {
	host, rest, ok := sshString(b)
	if !ok || len(rest) < 4 {
		return "", 0, errors.New("malformed direct-tcpip payload")
	}
	port := binary.BigEndian.Uint32(rest)
	if port == 0 || port > 65535 {
		return "", 0, errors.New("port out of range")
	}
	if host == "" || strings.ContainsAny(host, " \r\n\x00") {
		return "", 0, errors.New("malformed host")
	}
	return host, int(port), nil
}

// sshString reads one SSH string (RFC 4251 section 5).
func sshString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := int64(binary.BigEndian.Uint32(b))
	if n > int64(len(b))-4 {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// sshStringPayload reads the single string a request payload carries,
// which is how exec and subsystem name what they want.
func sshStringPayload(b []byte) string {
	s, _, ok := sshString(b)
	if !ok {
		return ""
	}
	return s
}

// secondFactor builds the partial success that asks for a one-time
// code. The first factor has already been verified; nothing about the
// session is authorised until the code is too.
func (t *sshServer) secondFactor(first string) error {
	return &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return t.verifyCode(c, challenge, first)
		},
	}}
}

// verifyCode runs the keyboard-interactive round and checks the answer.
// What the client is told is the same whatever went wrong: a user who
// never enrolled, a wrong code, a replayed one and a locked account are
// one answer, because telling them apart is how an attacker learns
// which accounts are worth attacking.
func (t *sshServer) verifyCode(c ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge, first string) (*ssh.Permissions, error) {
	ip := addrOf(c.RemoteAddr().String())
	user := c.User()
	m := t.h.MFA
	if !t.mfaGuard.Enrolled(user) && (m.RequireEnrolment == nil || *m.RequireEnrolment) {
		// The prompt is still shown. A client that is refused before
		// being asked has learned that this name is not enrolled.
		_, _ = challenge(user, "", []string{m.Prompt}, []bool{true})
		t.s.stats.MFAFailed.Add(1)
		t.deny(ip, "mfa_not_enrolled", trimUser(user))
		return nil, errors.New("authentication failed")
	}
	answers, err := challenge(user, "", []string{m.Prompt}, []bool{true})
	if err != nil {
		return nil, err
	}
	if len(answers) != 1 {
		return nil, errors.New("authentication failed")
	}
	if err := t.mfaGuard.Verify(user, strings.TrimSpace(answers[0]), time.Now()); err != nil {
		t.s.stats.MFAFailed.Add(1)
		t.deny(ip, "mfa_failed", err.Error())
		return nil, errors.New("authentication failed")
	}
	t.s.stats.MFAVerified.Add(1)
	return &ssh.Permissions{Extensions: map[string]string{"auth": first + "+mfa"}}, nil
}
