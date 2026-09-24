package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/upstream"
)

// server serves a kind: ssh listener: an SSH bastion that terminates
// the client's session and opens its own to the target.
//
// A jump host that forwards the stream cannot see which channel is a
// shell and which is a port forward, so the only policy it can hold is
// "may connect". Here every channel and every request inside the
// session is a decision, and the target never sees the client's key:
// the client authenticates to the proxy, the proxy authenticates to the
// target with a credential the client never holds.
type server struct {
	engine proxy.Host
	cfg    config.Listener
	h      *config.SSHListener
	ln     net.Listener
	scfg   *cssh.ServerConfig

	upstreamAuth cssh.AuthMethod
	hostKeyCheck cssh.HostKeyCallback
	allow        []netip.Prefix
	// base is the listener's own policy, used by a session that no
	// principal entry refined.
	base       *sshPolicy
	principals []*sshPrincipal
	// caKeys are the user certificate authorities, when one is
	// configured.
	caKeys map[string]bool

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

func newServer(engine proxy.Host, cfg config.Listener, ln net.Listener) (*server, error) {
	h := cfg.SSH
	t := &server{engine: engine, cfg: cfg, h: h, ln: ln,
		keys: map[string]bool{}, caKeys: map[string]bool{},
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	base, err := compileSSHPolicy(&config.SSHPolicy{
		Recording:       h.Recording,
		UpstreamUser:    h.UpstreamUser,
		AllowChannels:   h.AllowChannels,
		AllowRequests:   h.AllowRequests,
		AllowSubsystems: h.AllowSubsystems,
		AllowCommands:   h.AllowCommands,
		AllowEnv:        h.AllowEnv,
		Forward:         h.Forward,
		RemoteForward:   &h.RemoteForward,
		SFTP:            h.SFTP,
	}, nil)
	if err != nil {
		return nil, err
	}
	if h.AllowFileTransferCommands != nil {
		base.transfers = *h.AllowFileTransferCommands
	}
	t.base = base
	for i := range h.Principals {
		e := &h.Principals[i]
		pr := &sshPrincipal{name: e.Name, users: map[string]bool{}, certs: map[string]bool{},
			fingerprints: map[string]bool{}, policy: base}
		for _, f := range e.Fingerprints {
			pr.fingerprints[f] = true
		}
		for _, c := range e.CertPrincipals {
			pr.certs[c] = true
		}
		for _, u := range e.Users {
			pr.users[u] = true
		}
		pr.isDefault = len(pr.fingerprints) == 0 && len(pr.certs) == 0
		if e.Policy != nil {
			pr.deny = e.Policy.Deny
			p, err := compileSSHPolicy(e.Policy, base)
			if err != nil {
				return nil, fmt.Errorf("ssh principal %q: %w", e.Name, err)
			}
			pr.policy = p
		}
		t.principals = append(t.principals, pr)
	}
	for _, c := range h.AllowClients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ssh allow_clients: %w", err)
		}
		t.allow = append(t.allow, p)
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
func (t *server) loadCredentials() error {
	h := t.h
	if h.AuthorizedKeys != "" {
		raw, err := os.ReadFile(h.AuthorizedKeys) //nolint:gosec // a path from the configuration
		if err != nil {
			return fmt.Errorf("ssh authorized_keys: %w", err)
		}
		for len(raw) > 0 {
			key, _, _, rest, err := cssh.ParseAuthorizedKey(raw)
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
	if h.TrustedUserCAKeys != "" {
		raw, err := os.ReadFile(h.TrustedUserCAKeys) //nolint:gosec // a path from the configuration
		if err != nil {
			return fmt.Errorf("ssh trusted_user_ca_keys: %w", err)
		}
		for len(raw) > 0 {
			key, _, _, rest, err := cssh.ParseAuthorizedKey(raw)
			if err != nil {
				return fmt.Errorf("ssh trusted_user_ca_keys: %w", err)
			}
			t.caKeys[string(key.Marshal())] = true
			raw = rest
		}
		if len(t.caKeys) == 0 {
			return errors.New("ssh trusted_user_ca_keys: no keys in the file")
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
	signer, err := cssh.ParsePrivateKey(raw)
	if err != nil {
		return fmt.Errorf("ssh upstream_key_file: %w", err)
	}
	t.upstreamAuth = cssh.PublicKeys(signer)
	if h.UpstreamKnownHosts != "" {
		cb, err := knownHostsCallback(h.UpstreamKnownHosts)
		if err != nil {
			return fmt.Errorf("ssh upstream_known_hosts: %w", err)
		}
		t.hostKeyCheck = cb
	} else {
		t.hostKeyCheck = cssh.InsecureIgnoreHostKey() //nolint:gosec // refused by validation unless allow_insecure
	}
	return nil
}

func (t *server) buildServerConfig() error {
	h := t.h
	cfg := &cssh.ServerConfig{
		ServerVersion: h.ServerVersion,
		MaxAuthTries:  h.MaxAuthTries,
	}
	if h.Banner != "" {
		banner := h.Banner
		if !strings.HasSuffix(banner, "\n") {
			banner += "\n"
		}
		cfg.BannerCallback = func(cssh.ConnMetadata) string { return banner }
	}
	if len(t.keys) > 0 || len(t.caKeys) > 0 {
		cfg.PublicKeyCallback = func(c cssh.ConnMetadata, key cssh.PublicKey) (*cssh.Permissions, error) {
			kind, err := t.acceptKey(c, key)
			if err != nil {
				return nil, err
			}
			// The key is accepted; which principal it is decides the
			// policy, and a key nobody claims is refused here rather
			// than served under the listener's default.
			pr, ok := t.principalFor(c.User(), key)
			if !ok {
				return nil, fmt.Errorf("no principal covers this key for %q", c.User())
			}
			if pr != nil && pr.deny {
				return nil, fmt.Errorf("principal %q is denied", pr.name)
			}
			ext := map[string]string{
				"auth":        kind,
				"fingerprint": cssh.FingerprintSHA256(key),
			}
			if pr != nil {
				ext["principal"] = pr.name
			}
			if t.mfaGuard != nil {
				// The key is right and the session is not authorised
				// yet: RFC 4252 partial success, and the client is
				// told which method comes next.
				return nil, t.secondFactor(kind, ext)
			}
			return &cssh.Permissions{Extensions: ext}, nil
		}
	}
	if len(t.users) > 0 {
		cfg.PasswordCallback = func(c cssh.ConnMetadata, pass []byte) (*cssh.Permissions, error) {
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
				return nil, t.secondFactor("password", map[string]string{"auth": "password"})
			}
			return &cssh.Permissions{Extensions: map[string]string{"auth": "password"}}, nil
		}
	}
	cfg.AuthLogCallback = func(c cssh.ConnMetadata, method string, err error) {
		if err == nil || method == "none" {
			return
		}
		t.engine.Counters().SSHAuthFailed.Add(1)
		ip := netutil.AddrOf(c.RemoteAddr().String())
		t.deny(ip, "auth_failed", method+" for "+textsafe.Clip64(c.User()))
	}
	for i, path := range h.HostKeys {
		raw, err := os.ReadFile(path) //nolint:gosec // a path from the configuration
		if err != nil {
			return fmt.Errorf("ssh host_keys[%d]: %w", i, err)
		}
		signer, err := cssh.ParsePrivateKey(raw)
		if err != nil {
			return fmt.Errorf("ssh host_keys[%d]: %w", i, err)
		}
		cfg.AddHostKey(signer)
	}
	t.scfg = cfg
	return nil
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
		if t.open.Add(1) > int64(t.h.MaxSessions) {
			t.open.Add(-1)
			t.engine.Counters().SSHRejected.Add(1)
			t.engine.Counters().Refuse("ssh", "max_sessions")
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

func (t *server) allowed(ip netip.Addr) bool {
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

func (t *server) deny(ip netip.Addr, what, detail string) {
	t.engine.Counters().Refuse("ssh", what)
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "ssh"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "ssh_"+what, attrs...)
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "ssh_denied")
	}
}

// session is one client connection and the target connection behind
// it.
type session struct {
	t      *server
	sconn  *cssh.ServerConn
	client *cssh.Client
	ip     netip.Addr
	user   string
	auth   string
	target string
	// policy is the listener's, or the one the matched principal
	// refined it to. principal names that entry for the log.
	policy    *sshPolicy
	principal string

	channels atomic.Int64
	opened   atomic.Uint64
	refused  atomic.Uint64
	wg       sync.WaitGroup
}

func (t *server) handle(raw net.Conn) {
	s := t.engine
	start := time.Now()
	s.Counters().SSHSessions.Add(1)
	s.Counters().SSHSessionsOpen.Add(1)
	defer s.Counters().SSHSessionsOpen.Add(-1)
	ip := netutil.AddrOf(raw.RemoteAddr().String())
	se := &session{t: t, ip: ip}
	defer func() { _ = raw.Close() }()

	if !t.allowed(ip) {
		s.Counters().SSHRejected.Add(1)
		t.deny(ip, "client_not_allowed", "")
		t.log(se, start, "client_not_allowed")
		return
	}
	// The handshake and authentication share one deadline. Once the
	// session is up the idle timeout takes over, applied by the
	// connection wrapper below.
	_ = raw.SetDeadline(time.Now().Add(t.h.HandshakeTimeout.D()))
	sconn, chans, reqs, err := cssh.NewServerConn(raw, t.scfg)
	if err != nil {
		t.log(se, start, "handshake")
		return
	}
	defer func() { _ = sconn.Close() }()
	_ = raw.SetDeadline(time.Time{})
	se.sconn = sconn
	se.user = sconn.User()
	se.policy = t.base
	if sconn.Permissions != nil {
		se.auth = sconn.Permissions.Extensions["auth"]
		se.principal = sconn.Permissions.Extensions["principal"]
	}
	if se.principal != "" {
		for _, pr := range t.principals {
			if pr.name == se.principal {
				se.policy = pr.policy
				break
			}
		}
	}
	if t.h.SessionTimeout > 0 {
		timer := time.AfterFunc(t.h.SessionTimeout.D(), func() { _ = sconn.Close() })
		defer timer.Stop()
	}

	if err := se.connect(); err != nil {
		s.Logs().Error.Warn("ssh target unavailable", "listener", t.cfg.Name, "user", textsafe.Clip64(se.user), "err", err.Error())
		t.log(se, start, "upstream_unavailable")
		return
	}
	defer func() { _ = se.client.Close() }()

	go se.globalRequests(reqs)
	for nc := range chans {
		if se.channels.Load() >= int64(t.h.MaxChannels) {
			_ = nc.Reject(cssh.ResourceShortage, "too many channels")
			se.refused.Add(1)
			continue
		}
		se.channels.Add(1)
		se.wg.Add(1)
		go func(nc cssh.NewChannel) {
			defer se.wg.Done()
			defer se.channels.Add(-1)
			defer safe.Guard("ssh channel")
			se.channel(nc)
		}(nc)
	}
	se.wg.Wait()
	t.log(se, start, "")
}

func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "auth", se.auth, "principal", se.principal, "target", se.target,
		"channels", se.opened.Load(), "refused", se.refused.Load(),
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.engine.Logs().Access.Info("ssh", attrs...)
}

// connect opens the target session. The user the proxy authenticates as
// is the configured one, or the name the client authenticated with when
// none is configured.
func (se *session) connect() error {
	t := se.t
	pool := t.engine.Pool(t.h.Upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", t.h.Upstream)
	}
	user := se.policy.upstreamUser
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
			if _, err := conn.Write(netutil.ProxyV2Header(se.sconn.RemoteAddr(), se.sconn.LocalAddr())); err != nil {
				pool.End(e, true, 0)
				_ = conn.Close()
				lastErr = err
				continue
			}
		}
		_ = conn.SetDeadline(time.Now().Add(t.h.HandshakeTimeout.D()))
		cc := &cssh.ClientConfig{
			User:            user,
			Auth:            []cssh.AuthMethod{t.upstreamAuth},
			HostKeyCallback: t.hostKeyCheck,
			Timeout:         t.h.HandshakeTimeout.D(),
		}
		nc, nchans, nreqs, err := cssh.NewClientConn(conn, e.Address, cc)
		if err != nil {
			pool.End(e, true, 0)
			_ = conn.Close()
			lastErr = err
			t.engine.Logs().Error.Warn("ssh target handshake failed", "listener", t.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		_ = conn.SetDeadline(time.Time{})
		pool.End(e, false, 0)
		se.client = cssh.NewClient(nc, nchans, nreqs)
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
func (se *session) globalRequests(reqs <-chan *cssh.Request) {
	defer safe.Guard("ssh global requests")
	for r := range reqs {
		switch {
		case r.Type == "keepalive@openssh.com":
			_ = r.Reply(true, nil)
		case (r.Type == "tcpip-forward" || r.Type == "cancel-tcpip-forward") && se.policy.remoteForward:
			ok, payload, err := se.client.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				_ = r.Reply(false, nil)
				return
			}
			_ = r.Reply(ok, payload)
		default:
			if r.Type == "tcpip-forward" {
				se.refused.Add(1)
				se.t.engine.Counters().SSHRefused.Add(1)
				se.t.deny(se.ip, "remote_forward_refused", "")
			}
			_ = r.Reply(false, nil)
		}
	}
}

// channel decides on one channel the client asked to open, and relays
// it when the policy allows.
func (se *session) channel(nc cssh.NewChannel) {
	t := se.t
	kind := nc.ChannelType()
	if !se.policy.channels[kind] {
		se.refuse(nc, "channel_refused", kind, cssh.Prohibited, "channel type not allowed")
		return
	}
	extra := nc.ExtraData()
	if kind == "direct-tcpip" {
		host, port, err := parseDirectTCPIP(extra)
		if err != nil {
			se.refuse(nc, "malformed_channel", kind, cssh.ConnectionFailed, "malformed channel request")
			return
		}
		if !se.policy.forwardAllowed(host, port) {
			se.refuse(nc, "forward_refused", net.JoinHostPort(host, strconv.Itoa(port)), cssh.Prohibited, "destination not allowed")
			return
		}
	}
	// The channel is opened on the target first: a client that is told
	// its channel is open and then finds it is not has to guess why,
	// and the target's own refusal is the truthful answer.
	upCh, upReqs, err := se.client.OpenChannel(kind, extra)
	if err != nil {
		var oce *cssh.OpenChannelError
		if errors.As(err, &oce) {
			_ = nc.Reject(oce.Reason, oce.Message)
		} else {
			_ = nc.Reject(cssh.ConnectionFailed, "target refused the channel")
		}
		return
	}
	clientCh, clientReqs, err := nc.Accept()
	if err != nil {
		_ = upCh.Close()
		return
	}
	se.opened.Add(1)
	t.engine.Counters().SSHChannels.Add(1)

	// answering is held while a client request is being decided, from
	// the moment it is read to the moment its answer has been written.
	// Closing inside that window loses the answer, and a client waiting
	// for one is told the channel ended instead: an exec that ran, and
	// whose exit status was relayed, reported to the client as EOF.
	// The window is real because the target can finish a command and
	// close its channel while the reply to the request that started it
	// is still on its way back.
	var answering sync.Mutex
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			answering.Lock()
			answering.Unlock() //nolint:staticcheck // waiting for the answer, not guarding anything here
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

	// st carries what the requests on this channel settle and the data
	// pump then needs: the terminal they asked for, and the recording
	// they opened. It is written by the request goroutine before it
	// starts the pump and read by the pump after, so the channel that
	// starts the pump is what orders the two.
	st := &sshChannel{}

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
		se.pipe(clientCh, upCh, st.rec)
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
		se.clientRequests(clientCh, upCh, clientReqs, startPump, &answering, st)
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
	closeSSHRecording(st.rec, se)
}

// sshChannel is what one channel's requests settle: the terminal the
// client asked for, and the recording that was opened for it.
type sshChannel struct {
	term       string
	cols, rows int
	rec        *sessionrec.Recording
}

func (se *session) refuse(nc cssh.NewChannel, what, detail string, reason cssh.RejectionReason, msg string) {
	se.refused.Add(1)
	se.t.engine.Counters().SSHRefused.Add(1)
	se.t.deny(se.ip, what, detail)
	_ = nc.Reject(reason, msg)
}

// clientRequests applies the request policy and relays what it allows.
// startPump is called once the request that begins the data flow has
// been forwarded, so an inspected sftp channel is never also copied
// blindly.
func (se *session) clientRequests(clientCh, upCh cssh.Channel, reqs <-chan *cssh.Request, startPump func(), answering *sync.Mutex, st *sshChannel) {
	for r := range reqs {
		if !se.answerRequest(clientCh, upCh, r, startPump, answering, st) {
			return
		}
	}
}

// answerRequest decides one request and answers it, holding answering
// for as long as the client is owed a reply. It reports whether the
// loop goes on.
func (se *session) answerRequest(clientCh, upCh cssh.Channel, r *cssh.Request, startPump func(), answering *sync.Mutex, st *sshChannel) bool {
	t := se.t
	answering.Lock()
	defer answering.Unlock()
	if !se.policy.requests[r.Type] {
		se.refuseRequest(r, "request_refused", r.Type)
		return true
	}
	switch r.Type {
	case "env":
		name, ok := sshEnvRequest(r.Payload)
		if !ok {
			se.refuseRequest(r, "malformed_request", "env")
			return true
		}
		if !se.policy.envAllowed(name) {
			// A variable the target would read before it runs the
			// command the policy approved.
			se.refuseRequest(r, "env_refused", name)
			return true
		}
	case "subsystem":
		name := sshStringPayload(r.Payload)
		if !se.policy.subsystems[name] {
			se.refuseRequest(r, "subsystem_refused", name)
			return true
		}
		if name == "sftp" && se.policy.sftp != nil {
			// The path lists may name this session's own user, so
			// they are resolved here, once, where a name that
			// cannot stand in a pattern refuses the subsystem
			// rather than quietly widening it.
			sp, err := se.policy.sftp.forSession(se.user, se.principal)
			if err != nil {
				se.refuseRequest(r, "sftp_identity_refused", err.Error())
				return true
			}
			// From here the channel carries SFTP, which is a
			// protocol of its own and gets its own decisions.
			ok, err := upCh.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil || !ok {
				_ = r.Reply(false, nil)
				return false
			}
			_ = r.Reply(true, nil)
			se.relaySFTP(clientCh, upCh, sp)
			return false
		}
	case "exec":
		cmd := sshStringPayload(r.Payload)
		if !se.policy.transfers && fileTransferCommand(cmd) {
			// scp and rsync move files without ever opening the
			// sftp subsystem, so every path and operation rule
			// there is simply not on their path. Refusing them is
			// what makes an sftp policy mean anything.
			se.refuseRequest(r, "file_transfer_refused", textsafe.Clip256(cmd))
			return true
		}
		if !se.commandAllowed(cmd) {
			se.refuseRequest(r, "command_refused", textsafe.Clip256(cmd))
			return true
		}
		t.engine.Logs().SecurityEvent(context.Background(), "allow", "ssh_exec",
			"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
			"target", se.target, "command", textsafe.Clip256(cmd))
	}
	switch r.Type {
	case "pty-req":
		// The size the session is drawn at, which a recording needs in
		// its header: a player that guesses the geometry wraps every
		// line somewhere the session did not.
		if term, cols, rows, ok := sshPTYRequest(r.Payload); ok {
			st.term, st.cols, st.rows = term, cols, rows
		}
	case "window-change":
		if cols, rows, ok := sshWindowChange(r.Payload); ok {
			st.cols, st.rows = cols, rows
			st.rec.Resize(cols, rows)
		}
	}
	// The mode is chosen before the request is forwarded. The
	// other way round, a fast command could finish and close the
	// channel before the copier existed, and its output would be
	// lost to a race rather than to anything the policy decided.
	switch r.Type {
	case "shell", "exec", "subsystem":
		se.startRecording(st, r)
		startPump()
	}
	ok, err := upCh.SendRequest(r.Type, r.WantReply, r.Payload)
	if err != nil {
		_ = r.Reply(false, nil)
		return false
	}
	_ = r.Reply(ok, nil)
	return true
}

func (se *session) refuseRequest(r *cssh.Request, what, detail string) {
	se.refused.Add(1)
	se.t.engine.Counters().SSHRefused.Add(1)
	se.t.deny(se.ip, what, detail)
	_ = r.Reply(false, nil)
}

func (se *session) commandAllowed(cmd string) bool {
	if len(se.policy.commands) == 0 {
		return true
	}
	for _, re := range se.policy.commands {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// startRecording opens this channel's recording, if the policy asks for
// one. It runs before the pump, because the pump is what feeds it.
func (se *session) startRecording(st *sshChannel, r *cssh.Request) {
	rec := se.policy.recorder
	if rec == nil || st.rec != nil {
		return
	}
	// An sftp channel is not a terminal. Its own log line says what
	// each request did, which is the readable record; a cast file of
	// the packet stream would be neither watchable nor useful.
	if r.Type == "subsystem" {
		return
	}
	command := ""
	if r.Type == "exec" {
		command = textsafe.Clip256(sshStringPayload(r.Payload))
	}
	if !records(rec, r.Type == "exec") {
		return
	}
	f, err := openSSHRecording(rec, se, st.cols, st.rows, st.term, command)
	if err != nil {
		se.sshRecordFailed(err)
		return
	}
	st.rec = f
}

// pipe copies a channel's data and its extended (stderr) data both
// ways, and half-closes so the far side sees the end of input.
func (se *session) pipe(clientCh, upCh cssh.Channel, rec *sessionrec.Recording) {
	// The client to target direction is not waited for. A client that
	// runs a command without closing its input never sends EOF, so
	// waiting for it would mean waiting for the client rather than for
	// the command; it ends when the channel is closed.
	var toTarget io.Writer = upCh
	if rec != nil && se.policy.recorder.Config().Input {
		toTarget = sessionrec.Writer{Dst: upCh, Rec: rec, Input: true}
	}
	go func() {
		defer safe.Guard("ssh data to target")
		n, _ := copyBounded(toTarget, clientCh)
		se.t.engine.Counters().SSHBytesIn.Add(uint64(n)) //nolint:gosec // non-negative
		_ = upCh.CloseWrite()
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	// Both of the target's streams are what the session showed, and a
	// terminal does not keep them apart either: a recording that left
	// out stderr would be missing exactly the errors.
	var toClient, toClientErr io.Writer = clientCh, clientCh.Stderr()
	if rec != nil {
		toClient = sessionrec.Writer{Dst: clientCh, Rec: rec}
		toClientErr = sessionrec.Writer{Dst: clientCh.Stderr(), Rec: rec}
	}
	go func() {
		defer wg.Done()
		defer safe.Guard("ssh data to client")
		n, _ := copyBounded(toClient, upCh)
		se.t.engine.Counters().SSHBytesOut.Add(uint64(n)) //nolint:gosec // non-negative
		_ = clientCh.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("ssh stderr to client")
		_, _ = copyBounded(toClientErr, upCh.Stderr())
	}()
	wg.Wait()
}

// forwardAllowed applies the direct-tcpip destination policy.
func (p *sshPolicy) forwardAllowed(host string, port int) bool {
	addr, isAddr := netip.ParseAddr(host)
	if isAddr == nil {
		addr = addr.Unmap()
	}
	for _, f := range p.forwards {
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
func (t *server) secondFactor(first string, ext map[string]string) error {
	return &cssh.PartialSuccessError{Next: cssh.ServerAuthCallbacks{
		KeyboardInteractiveCallback: func(c cssh.ConnMetadata, challenge cssh.KeyboardInteractiveChallenge) (*cssh.Permissions, error) {
			return t.verifyCode(c, challenge, first, ext)
		},
	}}
}

// verifyCode runs the keyboard-interactive round and checks the answer.
// What the client is told is the same whatever went wrong: a user who
// never enrolled, a wrong code, a replayed one and a locked account are
// one answer, because telling them apart is how an attacker learns
// which accounts are worth attacking.
func (t *server) verifyCode(c cssh.ConnMetadata, challenge cssh.KeyboardInteractiveChallenge, first string, ext map[string]string) (*cssh.Permissions, error) {
	ip := netutil.AddrOf(c.RemoteAddr().String())
	user := c.User()
	m := t.h.MFA
	if !t.mfaGuard.Enrolled(user) && (m.RequireEnrolment == nil || *m.RequireEnrolment) {
		// The prompt is still shown. A client that is refused before
		// being asked has learned that this name is not enrolled.
		_, _ = challenge(user, "", []string{m.Prompt}, []bool{true})
		t.engine.Counters().MFAFailed.Add(1)
		t.deny(ip, "mfa_not_enrolled", textsafe.Clip64(user))
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
		t.engine.Counters().MFAFailed.Add(1)
		t.deny(ip, "mfa_failed", err.Error())
		return nil, errors.New("authentication failed")
	}
	t.engine.Counters().MFAVerified.Add(1)
	out := map[string]string{}
	for k, v := range ext {
		out[k] = v
	}
	out["auth"] = first + "+mfa"
	return &cssh.Permissions{Extensions: out}, nil
}
