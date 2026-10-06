package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	wire "github.com/rom/xproxy/internal/smtp"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server serves a kind: smtp listener. It speaks one SMTP session to
// the client and a second one to the upstream, and decides for itself
// where every command and every message ends, so the two ends can never
// disagree about it.
type server struct {
	engine proxy.Host
	cfg    config.Listener
	m      *config.SMTPListener
	ln     net.Listener
	tlsCfg *tls.Config // for the client side (starttls or implicit)
	upTLS  *tls.Config // for the upstream side
	allow  []netip.Prefix
	verbs  map[string]bool
	hidden map[string]bool
	host   string

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
}

// newServer builds the listener's static policy. The TLS
// configuration is the listener's own, so certificates reload with
// everything else.
func newServer(engine proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	m := cfg.SMTP
	t := &server{engine: engine, cfg: cfg, m: m, ln: ln, tlsCfg: tc,
		verbs: map[string]bool{}, hidden: map[string]bool{},
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	for _, c := range m.Commands {
		t.verbs[strings.ToUpper(c)] = true
	}
	for _, k := range config.SMTPAlwaysHidden {
		t.hidden[k] = true
	}
	for _, k := range m.HideCapabilities {
		t.hidden[strings.ToUpper(strings.TrimSpace(k))] = true
	}
	for _, c := range m.AllowClients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("smtp allow_clients: %w", err)
		}
		t.allow = append(t.allow, p)
	}
	if m.UpstreamTLSMode != "none" {
		uc, _, err := tlsconf.Client(m.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("smtp upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	t.host = m.Hostname
	if t.host == "" {
		if m.Banner != "" {
			t.host, _, _ = strings.Cut(m.Banner, " ")
		} else {
			t.host = "xproxy"
		}
	}
	return t, nil
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
		if t.open.Add(1) > int64(t.m.MaxConnections) {
			t.open.Add(-1)
			t.engine.Counters().SMTPRejected.Add(1)
			t.engine.Counters().Refuse("smtp", "max_connections")
			// 421 is the one refusal a mail client retries later
			// instead of bouncing the message.
			_, _ = c.Write([]byte("421 4.3.2 too many connections, try again later\r\n"))
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
			defer safe.Guard("smtp session")
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

// session is one client connection and the upstream connection that
// serves it.
type session struct {
	t      *server
	client net.Conn
	// tap records the session for a pcapng capture, and is nil -- usable, and
	// doing nothing -- whenever no rule wants this one, which is the usual case.
	tap  *capture.Tap
	cr   *wire.Reader
	up   net.Conn
	ur   *wire.Reader
	pool *upstream.Pool
	ep   *upstream.Endpoint

	ip        netip.Addr
	secure    bool // the client side is encrypted
	greeted   bool // EHLO or HELO has been accepted since the last reset
	authed    bool
	inMail    bool
	rcpts     int
	messages  int
	errors    int
	bytesIn   int64
	deadline  time.Time
	upFailed  bool // the upstream leg failed, which the pool should hear about
	closeSess bool // end the session after the current reply
}

func (t *server) handle(client net.Conn) {
	s := t.engine
	start := time.Now()
	s.Counters().SMTPSessions.Add(1)
	s.Counters().SMTPSessionsOpen.Add(1)
	defer s.Counters().SMTPSessionsOpen.Add(-1)
	ip := netutil.AddrOf(client.RemoteAddr().String())
	se := &session{t: t, client: client, ip: ip, deadline: start.Add(t.m.SessionTimeout.D())}
	// Opened before anything can refuse the session, because a refused session is
	// the one an operator most often wants and it never dials: after that point
	// there is nothing left to record. A nil tap wraps nothing and writes nothing.
	se.tap = t.engine.Capture().Open("smtp", t.cfg.Name, "", client.RemoteAddr())
	defer se.tap.Close()
	se.client = se.tap.Client(client)
	defer func() {
		if se.up != nil {
			_ = se.up.Close()
			if se.ep != nil && se.pool != nil {
				se.pool.End(se.ep, se.upFailed, 0)
			}
		}
		_ = se.client.Close()
	}()

	if !t.allowed(ip) {
		s.Counters().SMTPRejected.Add(1)
		_, _ = client.Write([]byte("554 5.7.1 access denied\r\n"))
		t.deny(se, "client_not_allowed", "")
		t.log(se, start, "client_not_allowed")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own allow list -- that is local policy about local clients, and
	// a feed must not overrule an allow rule an operator wrote -- and before a
	// greeting is exchanged with anybody.
	if reason := t.admitClient(se); reason != "" {
		s.Counters().SMTPRejected.Add(1)
		_, _ = client.Write([]byte("554 5.7.1 access denied\r\n"))
		t.log(se, start, reason)
		return
	}
	if t.m.TLSMode == "implicit" {
		tc := tls.Server(client, t.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(t.m.ReadTimeout.D()))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.log(se, start, "tls_handshake")
			return
		}
		_ = tc.SetDeadline(time.Time{})
		// The tap follows the protocol rather than the TLS records carrying it:
		// tls.Server reads the socket directly, so nothing recorded the handshake,
		// and from here the tap sees the plaintext inside it.
		se.client = se.tap.Client(tc)
		se.secure = true
	}
	se.cr = wire.NewReader(se.client, t.m.MaxCommandLine)
	se.cr.AllowBareLF = t.m.BareNewlines == "convert"

	greeting, err := se.connect()
	if err != nil {
		s.Counters().SMTPRefused.Add(1)
		_, _ = se.client.Write([]byte("421 4.4.1 upstream unavailable\r\n"))
		s.Logs().Error.Warn("smtp upstream unavailable", "listener", t.cfg.Name, "err", err.Error())
		t.log(se, start, "upstream_unavailable")
		return
	}
	if t.m.Banner != "" {
		greeting = wire.Reply{Code: 220, Lines: []string{t.m.Banner}}
	}
	if err := se.toClient(greeting); err != nil {
		t.log(se, start, "write_error")
		return
	}
	reason := se.loop()
	s.Counters().SMTPBytesIn.Add(uint64(se.bytesIn)) //nolint:gosec // non-negative
	t.log(se, start, reason)
}

// allowed applies allow_clients. An empty list allows everything, which
// is what an inbound mail listener wants and what a submission listener
// should not have.
// admitClient is the two questions this relay asks about a client before it
// carries anything for it: do the imported lists know this address, and does the
// estate's authorisation policy allow it here.
//
// It asks about the address and nothing else, and that is the whole of what this
// kind can offer. SMTP does have an identity -- the SASL exchange has one -- and
// this relay deliberately does not parse it, because those lines carry the
// password. So it never learns who authenticated, only that the server said 235,
// and a name it invented would be worse than no name. A rule about users matches
// nobody on this kind; a rule here is written with `networks`, `targets` and
// `schedule`, which on a mail relay is a real policy: which networks may submit,
// to which pool, in which hours.
//
// What the envelope says is this listener's own business. `MAIL FROM` is an
// address rather than an identity, and the verb list and the recipient rules above
// are where a decision about it belongs.
func (t *server) admitClient(se *session) string {
	ip := se.ip
	e := t.engine
	return admit.Client(admit.Deps{
		Lists: e.ThreatIntel(),
		// A behaviour pack holding this address out, where one is.
		Quarantined: e.Packs().Quarantined,
		Policy:      e.Authorization(),
		Logs:        e.Logs(),
		Matched:     func() { e.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { e.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.cfg.Name,
		Kind:     "smtp",
		Client:   ip,
		Target:   t.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: t.cfg.Shadowing,
		Record: func(reason, rule, detail string) {
			e.Counters().WouldRefuse("smtp", reason)
			e.Shadow().Record("smtp", t.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(se, reason, detail) },
	})
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

// deny records a refusal, and tells the capture the session was one.
//
// The capture asks about the refusal rather than how the session ended, which is
// why it is recorded here and not from the access log: a session that ran and then
// closed on a timeout did not get turned away, and a `denied: true` rule that
// matched it would select most of the traffic on the listener.
func (t *server) deny(se *session, what, detail string) {
	ip := se.ip
	se.tap.Deny(what)
	t.engine.Counters().Refuse("smtp", what)
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "smtp"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "smtp_"+what, attrs...)
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "smtp_denied")
	}
}

// shadowed records a policy refusal a listener in shadow mode does not
// enforce, and says whether it was recorded rather than refused.
//
// Only the verb list reaches it. The protocol-state refusals ("send EHLO
// first", "a transaction is already open"), the encryption and
// authentication requirements, the size bound and a malformed command are
// refused in shadow mode too: none of them is a question about what this
// estate carries, and answering out of order would leave the client and
// the server with different ideas of the session.
func (t *server) shadowed(ip netip.Addr, what, detail string) bool {
	if !t.cfg.Shadowing() {
		return false
	}
	t.engine.Counters().WouldRefuse("smtp", what)
	t.engine.Shadow().Record("smtp", t.cfg.Name, what, "", detail)
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "smtp"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.engine.Logs().SecurityEvent(context.Background(), "would_deny", "smtp_"+what, attrs...)
	return true
}

func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "tls", se.secure,
		"messages", se.messages, "bytes_in", se.bytesIn, "refused", se.errors,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if se.ep != nil {
		attrs = append(attrs, "endpoint", se.ep.Address)
	}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.engine.Logs().Access.Info("smtp", attrs...)
}

// connect opens the upstream session and returns its greeting.
func (se *session) connect() (wire.Reply, error) {
	t := se.t
	pool := t.engine.Pool(t.m.Upstream)
	if pool == nil {
		return wire.Reply{}, fmt.Errorf("upstream %q has no pool", t.m.Upstream)
	}
	se.pool = pool
	tried := map[*upstream.Endpoint]bool{}
	var conn net.Conn
	var ep *upstream.Endpoint
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			t.engine.Logs().Error.Warn("smtp upstream dial failed", "listener", t.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		conn, ep = c, e
		break
	}
	if conn == nil {
		return wire.Reply{}, errors.New("no reachable endpoint")
	}
	se.up, se.ep = se.tap.Upstream(conn), ep
	// Anything that goes wrong from here until the upstream session is
	// up is the endpoint's to answer for.
	se.upFailed = true
	if t.m.ProxyProtocol {
		if _, err := se.up.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
			return wire.Reply{}, err
		}
	}
	if t.m.UpstreamTLSMode == "implicit" {
		tc := tls.Client(se.up, se.upstreamTLS(ep))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return wire.Reply{}, err
		}
		se.up = tc
	}
	se.ur = wire.NewReader(se.up, t.m.MaxCommandLine)
	greeting, err := se.readUp()
	if err != nil {
		return wire.Reply{}, err
	}
	if greeting.Code != 220 {
		return wire.Reply{}, fmt.Errorf("upstream greeting was %d", greeting.Code)
	}
	caps, err := se.upEHLO()
	if err != nil {
		return wire.Reply{}, err
	}
	if t.m.UpstreamTLSMode == "starttls" {
		if _, ok := wire.Capability(caps, "STARTTLS"); !ok {
			return wire.Reply{}, errors.New("upstream does not offer STARTTLS and upstream_tls_mode is starttls")
		}
		if err := se.upstreamSTARTTLS(ep); err != nil {
			return wire.Reply{}, err
		}
		if caps, err = se.upEHLO(); err != nil {
			return wire.Reply{}, err
		}
	}
	if t.m.XClient {
		if _, ok := wire.Capability(caps, "XCLIENT"); ok {
			if err := se.sendXClient(); err != nil {
				return wire.Reply{}, err
			}
		}
	}
	se.upFailed = false
	return greeting, nil
}

// upstreamTLS fills in the server name from the endpoint when the
// configuration does not pin one, so verification has something to
// check against.
func (se *session) upstreamTLS(ep *upstream.Endpoint) *tls.Config {
	c := se.t.upTLS.Clone()
	if c.ServerName == "" && !c.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(ep.Address)
		if err != nil {
			host = ep.Address
		}
		c.ServerName = host
	}
	return c
}

// upstreamSTARTTLS upgrades the upstream leg. The reply is read before
// the handshake, and anything the upstream had already sent after it is
// a violation: those octets were written before it could know the
// handshake was coming, and treating them as part of the TLS stream is
// how a plaintext command gets smuggled into an encrypted session
// (the STARTTLS injection of CVE-2011-0411).
func (se *session) upstreamSTARTTLS(ep *upstream.Endpoint) error {
	if err := se.writeUp("STARTTLS"); err != nil {
		return err
	}
	rep, err := se.readUp()
	if err != nil {
		return err
	}
	if rep.Code != 220 {
		return fmt.Errorf("upstream refused STARTTLS with %d", rep.Code)
	}
	if n := se.ur.Buffered(); n > 0 {
		return fmt.Errorf("upstream sent %d octets after its STARTTLS reply", n)
	}
	tc := tls.Client(se.up, se.upstreamTLS(ep))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return err
	}
	se.up = tc
	se.ur = wire.NewReader(se.up, se.t.m.MaxCommandLine)
	return nil
}

// sendXClient tells the upstream which client this session is for, so
// its own logs and policies see the real address instead of the proxy's.
func (se *session) sendXClient() error {
	port := 0
	if a, ok := se.client.RemoteAddr().(*net.TCPAddr); ok {
		port = a.Port
	}
	addr := "[UNAVAILABLE]"
	if se.ip.IsValid() {
		addr = se.ip.String()
		if se.ip.Is6() {
			addr = "IPV6:" + addr
		}
	}
	if err := se.writeUp("XCLIENT ADDR=" + addr + " PORT=" + strconv.Itoa(port)); err != nil {
		return err
	}
	rep, err := se.readUp()
	if err != nil {
		return err
	}
	if rep.Code != 220 && rep.Code != 250 {
		return fmt.Errorf("upstream refused XCLIENT with %d", rep.Code)
	}
	return nil
}

func (se *session) upEHLO() (wire.Reply, error) {
	if err := se.writeUp("EHLO " + se.t.host); err != nil {
		return wire.Reply{}, err
	}
	rep, err := se.readUp()
	if err != nil {
		return wire.Reply{}, err
	}
	if rep.Code != 250 {
		return wire.Reply{}, fmt.Errorf("upstream refused EHLO with %d", rep.Code)
	}
	return rep, nil
}

func (se *session) writeUp(line string) error {
	_ = se.up.SetWriteDeadline(time.Now().Add(se.t.m.ReadTimeout.D()))
	_, err := se.up.Write([]byte(line + "\r\n"))
	return err
}

func (se *session) readUp() (wire.Reply, error) {
	_ = se.up.SetReadDeadline(se.readBy())
	return wire.ReadReply(se.ur)
}

// readBy is the earlier of the per-command timeout and what is left of
// the session timeout, so a client that sends one legal command every
// few minutes still ends.
func (se *session) readBy() time.Time {
	d := time.Now().Add(se.t.m.ReadTimeout.D())
	if d.After(se.deadline) {
		return se.deadline
	}
	return d
}

func (se *session) toClient(rep wire.Reply) error {
	_ = se.client.SetWriteDeadline(time.Now().Add(se.t.m.ReadTimeout.D()))
	_, err := se.client.Write(rep.Format())
	return err
}

// refuse answers the client without asking the upstream, and counts
// towards max_errors. reason is the counter's label: the reply text is
// what the client is told, which is deliberately vaguer than what an
// operator needs to see.
func (se *session) refuse(code int, text, reason string) error {
	se.errors++
	se.t.engine.Counters().SMTPRefused.Add(1)
	se.t.engine.Counters().Refuse("smtp", reason)
	if se.errors >= se.t.m.MaxErrors {
		se.closeSess = true
		_ = se.toClient(wire.Reply{Code: code, Lines: []string{text}})
		return se.toClient(wire.Reply{Code: 421, Lines: []string{"4.7.0 too many errors, closing connection"}})
	}
	return se.toClient(wire.Reply{Code: code, Lines: []string{text}})
}

// loop reads client commands until the session ends, and returns the
// reason for the access log.
func (se *session) loop() string {
	t := se.t
	for {
		if time.Now().After(se.deadline) {
			_ = se.toClient(wire.Reply{Code: 421, Lines: []string{"4.4.2 session timed out"}})
			return "session_timeout"
		}
		_ = se.client.SetReadDeadline(se.readBy())
		line, err := se.cr.ReadLine()
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrLineTooLong):
				t.engine.Counters().SMTPProtocolErrors.Add(1)
				_ = se.toClient(wire.Reply{Code: 500, Lines: []string{"5.5.6 line too long"}})
				t.deny(se, "line_too_long", "")
				return "line_too_long"
			case errors.Is(err, wire.ErrBareNewline), errors.Is(err, wire.ErrBareCR):
				// A line that ends differently for the proxy than for
				// the next hop is the whole of SMTP smuggling. The
				// session ends rather than guessing which reading the
				// sender meant.
				t.engine.Counters().SMTPProtocolErrors.Add(1)
				_ = se.toClient(wire.Reply{Code: 500, Lines: []string{"5.5.2 line must end with CRLF"}})
				t.deny(se, "bare_newline", err.Error())
				return "bare_newline"
			default:
				return "client_closed"
			}
		}
		cmd, perr := wire.ParseCommand(line)
		if perr != nil {
			if err := se.refuse(500, "5.5.2 command not recognised", "unknown_command"); err != nil {
				return "write_error"
			}
			if se.closeSess {
				return "too_many_errors"
			}
			continue
		}
		reason, err := se.command(cmd)
		if err != nil {
			return "write_error"
		}
		if reason != "" {
			return reason
		}
		if se.closeSess {
			return "too_many_errors"
		}
	}
}

// command handles one client command. A non-empty reason ends the
// session; an error means the client or upstream connection broke.
func (se *session) command(cmd wire.Command) (string, error) {
	t := se.t
	if !t.verbs[cmd.Verb] && !t.shadowed(se.ip, "command_refused", cmd.Verb) {
		return "", se.refuse(502, "5.5.1 command not available here", "command_refused")
	}
	switch cmd.Verb {
	case "QUIT":
		// Answered by the proxy: the upstream is told separately so it
		// ends its own session cleanly.
		_ = se.writeUp("QUIT")
		_ = se.toClient(wire.Reply{Code: 221, Lines: []string{"2.0.0 closing connection"}})
		return "quit", nil
	case "STARTTLS":
		return se.startTLS(cmd)
	case "EHLO", "HELO":
		return se.hello(cmd)
	case "AUTH":
		return se.auth(cmd)
	case "MAIL":
		return se.mail(cmd)
	case "RCPT":
		return se.rcpt(cmd)
	case "DATA":
		return se.data()
	case "RSET":
		se.inMail, se.rcpts = false, 0
		return se.relay(cmd)
	default:
		return se.relay(cmd)
	}
}

// relay passes a command to the upstream and its reply back, unchanged.
func (se *session) relay(cmd wire.Command) (string, error) {
	if err := se.writeUp(cmd.Raw); err != nil {
		return "upstream_write", nil
	}
	rep, err := se.readUp()
	if err != nil {
		return se.upstreamFailure(err)
	}
	return "", se.toClient(rep)
}

// upstreamFailure turns a broken or unparseable upstream reply into a
// temporary failure for the client. A reply the proxy cannot parse is
// never passed through: it is exactly the case where the client would
// read something the proxy did not.
func (se *session) upstreamFailure(err error) (string, error) {
	reason := "upstream_closed"
	if errors.Is(err, wire.ErrBadReply) || errors.Is(err, wire.ErrTooManyReplyLines) ||
		errors.Is(err, wire.ErrLineTooLong) || errors.Is(err, wire.ErrBareNewline) || errors.Is(err, wire.ErrBareCR) {
		se.t.engine.Counters().SMTPProtocolErrors.Add(1)
		se.t.engine.Logs().Error.Warn("smtp upstream reply refused", "listener", se.t.cfg.Name, "err", err.Error())
		reason = "upstream_protocol"
	}
	se.upFailed = true
	_ = se.toClient(wire.Reply{Code: 421, Lines: []string{"4.3.0 upstream failure"}})
	return reason, nil
}

// hello relays the greeting and rewrites the capability list: what the
// client is told is what this proxy will actually do, not what the
// upstream would do for somebody talking to it directly.
func (se *session) hello(cmd wire.Command) (string, error) {
	t := se.t
	if err := se.writeUp(cmd.Raw); err != nil {
		return "upstream_write", nil
	}
	rep, err := se.readUp()
	if err != nil {
		return se.upstreamFailure(err)
	}
	if rep.Code != 250 || cmd.Verb == "HELO" {
		if rep.Code == 250 {
			se.greeted = true
			se.inMail, se.rcpts = false, 0
		}
		return "", se.toClient(rep)
	}
	var add []string
	if t.m.TLSMode == "starttls" && !se.secure && t.verbs["STARTTLS"] {
		add = append(add, "STARTTLS")
	}
	if t.m.MaxMessageSize > 0 {
		add = append(add, "SIZE "+strconv.FormatInt(t.m.MaxMessageSize, 10))
	}
	out := wire.FilterEHLO(rep, func(kw string) bool {
		if t.hidden[kw] {
			return false
		}
		// The proxy's own SIZE replaces the upstream's when one is set,
		// so a client is never told a limit this proxy will not honour.
		return kw != "SIZE" || t.m.MaxMessageSize == 0
	}, add)
	se.greeted = true
	se.inMail, se.rcpts = false, 0
	return "", se.toClient(out)
}

// startTLS upgrades the client leg. Everything the session learned
// before the handshake is discarded (RFC 3207 section 4.2): the
// plaintext greeting and any authentication carry no weight inside the
// encrypted session that follows.
func (se *session) startTLS(wire.Command) (string, error) {
	t := se.t
	if se.secure {
		return "", se.refuse(503, "5.5.1 TLS is already active", "tls_already_active")
	}
	if t.tlsCfg == nil || t.m.TLSMode != "starttls" {
		return "", se.refuse(454, "4.7.0 TLS not available", "tls_unavailable")
	}
	// Anything already buffered was written before the client could have
	// seen the 220, so it was meant to be read as plaintext by one side
	// and as ciphertext by the other. That is the STARTTLS injection,
	// and the session ends on it.
	if n := se.cr.Buffered(); n > 0 {
		t.engine.Counters().SMTPProtocolErrors.Add(1)
		_ = se.toClient(wire.Reply{Code: 554, Lines: []string{"5.7.0 data pipelined across STARTTLS"}})
		t.deny(se, "starttls_injection", strconv.Itoa(n)+" octets")
		return "starttls_injection", nil
	}
	if err := se.toClient(wire.Reply{Code: 220, Lines: []string{"2.0.0 ready to start TLS"}}); err != nil {
		return "", err
	}
	// STARTTLS is an in-band upgrade, so the capture pauses over the handshake and
	// picks the plaintext up again on the far side: the file then holds one
	// readable stream of the protocol rather than cleartext and then ciphertext.
	se.tap.Pause()
	tc := tls.Server(se.client, t.tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(t.m.ReadTimeout.D()))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return "tls_handshake", nil
	}
	_ = tc.SetDeadline(time.Time{})
	se.client = se.tap.Client(tc)
	se.secure = true
	se.greeted, se.authed, se.inMail, se.rcpts = false, false, false, 0
	se.cr = wire.NewReader(se.client, t.m.MaxCommandLine)
	se.cr.AllowBareLF = t.m.BareNewlines == "convert"
	t.engine.Counters().SMTPTLSUpgrades.Add(1)
	// The upstream session is reset too, so its state cannot outlive the
	// client state that was just discarded.
	if err := se.writeUp("RSET"); err != nil {
		return "upstream_write", nil
	}
	if _, err := se.readUp(); err != nil {
		return se.upstreamFailure(err)
	}
	return "", nil
}

// auth relays an authentication exchange, including its challenge and
// response lines. Nothing from those lines is logged: they carry the
// password.
func (se *session) auth(cmd wire.Command) (string, error) {
	t := se.t
	if !se.greeted {
		return "", se.refuse(503, "5.5.1 send EHLO first", "ehlo_required")
	}
	if t.m.RequireTLS && !se.secure {
		return "", se.refuse(538, "5.7.11 encryption required for authentication", "encryption_required_for_auth")
	}
	if se.authed {
		return "", se.refuse(503, "5.5.1 already authenticated", "already_authenticated")
	}
	if err := se.writeUp(cmd.Raw); err != nil {
		return "upstream_write", nil
	}
	for round := 0; round < 16; round++ {
		rep, err := se.readUp()
		if err != nil {
			return se.upstreamFailure(err)
		}
		if rep.Code != 334 {
			if rep.Code == 235 {
				se.authed = true
			}
			return "", se.toClient(rep)
		}
		if err := se.toClient(rep); err != nil {
			return "", err
		}
		_ = se.client.SetReadDeadline(se.readBy())
		line, err := se.cr.ReadLine()
		if err != nil {
			return "client_closed", nil
		}
		if err := se.writeUp(string(line)); err != nil {
			return "upstream_write", nil
		}
	}
	// A server that keeps challenging is not going to stop.
	_ = se.toClient(wire.Reply{Code: 454, Lines: []string{"4.7.0 authentication exchange too long"}})
	return "auth_loop", nil
}

func (se *session) mail(cmd wire.Command) (string, error) {
	t := se.t
	if !se.greeted {
		return "", se.refuse(503, "5.5.1 send EHLO first", "ehlo_required")
	}
	if t.m.RequireTLS && !se.secure {
		return "", se.refuse(530, "5.7.0 encryption required", "encryption_required")
	}
	if t.m.RequireAuth && !se.authed {
		return "", se.refuse(530, "5.7.0 authentication required", "authentication_required")
	}
	if se.inMail {
		return "", se.refuse(503, "5.5.1 a transaction is already open", "transaction_open")
	}
	if se.messages >= t.m.MaxMessages {
		_ = se.toClient(wire.Reply{Code: 421, Lines: []string{"4.7.0 too many messages on one connection"}})
		return "max_messages", nil
	}
	if size, ok := smtpSizeParam(cmd.Arg); ok && t.m.MaxMessageSize > 0 && size > t.m.MaxMessageSize {
		// Refusing the declared size here is the only refusal that
		// costs nobody the message body.
		return "", se.refuse(552, "5.3.4 message size exceeds "+strconv.FormatInt(t.m.MaxMessageSize, 10), "message_too_large")
	}
	reason, err := se.relay(cmd)
	if reason == "" && err == nil {
		se.inMail, se.rcpts = true, 0
	}
	return reason, err
}

func (se *session) rcpt(cmd wire.Command) (string, error) {
	if !se.inMail {
		return "", se.refuse(503, "5.5.1 send MAIL first", "mail_required")
	}
	if se.rcpts >= se.t.m.MaxRecipients {
		return "", se.refuse(452, "4.5.3 too many recipients", "too_many_recipients")
	}
	reason, err := se.relay(cmd)
	if reason == "" && err == nil {
		se.rcpts++
	}
	return reason, err
}

// data relays one message. The proxy reads the body itself and writes
// every line out again, so the terminator it acted on is the terminator
// the upstream sees.
func (se *session) data() (string, error) {
	t := se.t
	if !se.inMail || se.rcpts == 0 {
		return "", se.refuse(503, "5.5.1 send MAIL and RCPT first", "mail_and_rcpt_required")
	}
	if err := se.writeUp("DATA"); err != nil {
		return "upstream_write", nil
	}
	rep, err := se.readUp()
	if err != nil {
		return se.upstreamFailure(err)
	}
	if rep.Code != 354 {
		se.inMail, se.rcpts = false, 0
		return "", se.toClient(rep)
	}
	if err := se.toClient(rep); err != nil {
		return "", err
	}
	_ = se.client.SetReadDeadline(se.deadline)
	_ = se.up.SetWriteDeadline(se.deadline)
	n, cerr := wire.CopyData(se.up, se.cr, t.m.MaxTextLine, t.m.MaxMessageSize)
	se.bytesIn += n
	se.inMail, se.rcpts = false, 0
	if cerr != nil {
		return se.dataFailed(cerr)
	}
	final, err := se.readUp()
	if err != nil {
		return se.upstreamFailure(err)
	}
	if final.Code >= 200 && final.Code < 300 {
		se.messages++
		t.engine.Counters().SMTPMessages.Add(1)
	}
	return "", se.toClient(final)
}

// dataFailed ends a message the proxy refused or could not read. The
// upstream connection is dropped without its terminator, so a partial
// message is never delivered as a whole one: there is no way to take
// back the lines already written, and a truncated message accepted by
// the next hop would be worse than a refused one.
func (se *session) dataFailed(cerr error) (string, error) {
	t := se.t
	_ = se.up.Close()
	switch {
	case errors.Is(cerr, wire.ErrMessageTooLarge):
		t.engine.Counters().SMTPRefused.Add(1)
		_ = se.toClient(wire.Reply{Code: 552, Lines: []string{"5.3.4 message size exceeds " + strconv.FormatInt(t.m.MaxMessageSize, 10)}})
		return "message_too_large", nil
	case errors.Is(cerr, wire.ErrLineTooLong):
		t.engine.Counters().SMTPProtocolErrors.Add(1)
		_ = se.toClient(wire.Reply{Code: 500, Lines: []string{"5.5.6 message line too long"}})
		t.deny(se, "line_too_long", "in DATA")
		return "line_too_long", nil
	case errors.Is(cerr, wire.ErrBareNewline), errors.Is(cerr, wire.ErrBareCR):
		t.engine.Counters().SMTPProtocolErrors.Add(1)
		_ = se.toClient(wire.Reply{Code: 500, Lines: []string{"5.5.2 message line must end with CRLF"}})
		t.deny(se, "smuggling", cerr.Error())
		return "smuggling", nil
	default:
		return "data_failed", nil
	}
}

// smtpSizeParam reads the SIZE= parameter of MAIL FROM (RFC 1870).
func smtpSizeParam(arg string) (int64, bool) {
	for _, f := range strings.Fields(arg) {
		k, v, ok := strings.Cut(f, "=")
		if !ok || !strings.EqualFold(k, "SIZE") {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
