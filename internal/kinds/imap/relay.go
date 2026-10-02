package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	wire "github.com/rom/xproxy/internal/imap"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

var errNoUpstream = errors.New("imap: no reachable server endpoint")

// handle serves one connection: the client's leg, the server's leg, and the
// greeting that has to cross before either goroutine starts.
func (t *server) handle(client net.Conn) {
	defer func() { _ = client.Close() }()
	ip := netutil.AddrOf(client.RemoteAddr().String())
	if !t.policy.Client(ip) {
		t.deny(ip, "client_not_allowed", "")
		return
	}
	if t.admitClient(ip) != "" {
		return
	}
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		t.host.Counters().Refuse("imap", "rate_limited")
		return
	}
	if ok, reason := t.gate.Enter(ip); !ok {
		t.host.Counters().Refuse("imap", reason)
		return
	}
	defer t.gate.Leave(ip)

	_, isTLS := client.(*tls.Conn)
	up, err := t.dial(ip)
	if err != nil {
		t.host.Counters().Refuse("imap", "upstream_failed")
		t.host.Logs().Error.Warn("imap upstream dial failed", "listener", t.name,
			"client_ip", ip.String(), "error", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	t.host.Counters().IMAPConnections.Add(1)

	c := newConn(t, ip, client, up, isTLS)
	if !t.greeting(c) {
		return
	}
	deadline := time.Now().Add(t.lifetime)
	done := make(chan struct{})
	go func() {
		defer safe.Guard("imap response reader")
		defer close(done)
		t.fromServer(c, deadline)
	}()
	t.fromClient(c, deadline)
	// Closing the upstream ends the response goroutine's read, which is what
	// makes this wait finite: a server that never says anything again must
	// not hold a goroutine for the life of the process.
	_ = up.Close()
	<-done
}

// greeting carries the server's first line, which is the one line of this
// protocol the client reads before it has asked anything.
//
// Two decisions are made on it. A PREAUTH greeting is refused, because it
// says the connection is authenticated and no identity was claimed. And the
// capability list it advertises is narrowed, which is the only chance to
// narrow it before the client chooses a mechanism.
func (t *server) greeting(c *conn) bool {
	_ = c.up.SetReadDeadline(time.Now().Add(or(t.c.IdleTimeout.D(), 30*time.Second)))
	line, err := c.sr.ReadLine()
	_ = c.up.SetReadDeadline(time.Time{})
	if err != nil {
		t.host.Counters().Refuse("imap", "upstream_failed")
		return false
	}
	r, err := wire.ParseResponse(line)
	if err != nil {
		t.deny(c.ip, "malformed_greeting", err.Error())
		return false
	}
	if d := t.policy.Answer(r, t.preauthNo); !d.Allow {
		t.host.Counters().IMAPPreauthRefused.Add(1)
		t.refusedAnswer(c, r, d)
		_ = c.line("* BYE " + reasonText(d))
		return false
	}
	_, encrypted := c.client.(*tls.Conn)
	out, stripped := c.rewriteCaps(r, encrypted)
	if stripped > 0 {
		t.host.Counters().IMAPCapabilitiesStripped.Add(uint64(stripped))
	}
	return c.writeClient(append(out, '\r', '\n')) == nil
}

// fromClient reads commands, decides about them, and forwards what it
// allows.
func (t *server) fromClient(c *conn, deadline time.Time) {
	for {
		if !t.setClientDeadline(c, deadline) {
			return
		}
		line, err := c.reader().ReadLine()
		switch {
		case errors.Is(err, wire.ErrLineTooLong):
			t.denyConn(c, "line_too_long", "")
			_ = c.line("* BAD line too long")
			return
		case err != nil:
			return
		}
		if stop := t.handleLine(c, line); stop {
			return
		}
	}
}

// setClientDeadline bounds how long the client may say nothing. An idling
// connection gets the IDLE bound instead, which is the whole point of IDLE:
// it says nothing for a long time on purpose.
func (t *server) setClientDeadline(c *conn, deadline time.Time) bool {
	now := time.Now()
	if now.After(deadline) {
		t.host.Counters().Refuse("imap", "session_timeout")
		return false
	}
	until := now.Add(t.idle)
	if idling, since := c.isIdling(); idling {
		until = since.Add(t.maxIdle)
		if now.After(until) {
			t.denyConn(c, "idle_too_long", "")
			return false
		}
	}
	if until.After(deadline) {
		until = deadline
	}
	return c.client.SetReadDeadline(until) == nil
}

// handleLine is one line from the client. It reports whether the connection
// is finished.
func (t *server) handleLine(c *conn, line []byte) bool {
	// Inside a SASL exchange the lines are credential material: base64, or
	// `*` to cancel. They are bounded and forwarded, never parsed as
	// commands and never logged.
	if c.inAuth() {
		return c.writeServer(append(line, '\r', '\n')) != nil
	}
	// Between IDLE and DONE the only line the protocol allows is DONE.
	// Anything else is a client that has lost track of its own state, or
	// somebody pipelining a command into a connection that is parked.
	if idling, _ := c.isIdling(); idling {
		if !strings.EqualFold(strings.TrimSpace(string(line)), "DONE") {
			t.denyConn(c, "not_done", "")
			return true
		}
		c.setIdling(false)
		return c.writeServer(append(line, '\r', '\n')) != nil
	}
	cmd, err := wire.ParseCommand(line)
	if err != nil {
		t.denyConn(c, "malformed_command", err.Error())
		_ = c.line("* BAD " + err.Error())
		return !t.enforcing()
	}
	if t.maxCmds > 0 {
		c.mu.Lock()
		c.commands++
		over := c.commands > t.maxCmds
		c.mu.Unlock()
		if over {
			t.denyConn(c, "too_many_commands", "")
			return true
		}
	}
	req, d := t.decide(c, cmd)
	t.logCommand(c, req, d)
	if !d.Allow {
		t.refused(c, &req, d)
		if t.enforcing() || d.Hard {
			if cmd.Literal != nil {
				// The client announced octets and will send them whatever
				// it is told, so they are read and dropped.
				_ = c.reader().Discard(cmd.Literal.Size)
			}
			return c.refuse(cmd.Tag, d) != nil
		}
	}
	return t.forward(c, cmd, req)
}

// decide builds the request the policy decides about and asks it.
func (t *server) decide(c *conn, cmd *wire.Command) (Request, Decision) {
	state, user, encrypted := c.snapshot()
	req := Request{
		Client: c.ip, User: user, State: state, Encrypted: encrypted, Command: cmd,
	}
	if cmd.Literal != nil {
		req.Literal = cmd.Literal.Size
	}
	names, err := wire.Mailboxes(cmd)
	if err != nil {
		return req, Decision{Reason: "malformed_mailbox", Detail: err.Error(), Hard: true}
	}
	req.Mailboxes = names
	if set, ok := sequenceSet(cmd); ok {
		s, err := wire.ParseSeqSet(set, wire.MaxSeqTerms)
		if err != nil {
			return req, Decision{Reason: "malformed_sequence_set", Detail: err.Error(), Hard: true}
		}
		req.Messages, req.Open = s.Count, s.Open
	}
	// The credential questions come before the command lists: a LOGIN on a
	// connection in the clear is refused whatever any rule says.
	switch cmd.Effective() {
	case "LOGIN":
		if d := t.policy.Mechanism("login", encrypted); !d.Allow {
			return req, d
		}
		if u, ok := wire.Login(cmd); ok {
			req.User = u
			if d := t.policy.User(u); !d.Allow {
				return req, d
			}
			if reason := t.admitUser(c, u); reason != "" {
				return req, Decision{Reason: reason, Hard: true}
			}
		}
	case "AUTHENTICATE":
		mech, _ := wire.Mechanism(cmd)
		if d := t.policy.Mechanism(mech, encrypted); !d.Allow {
			return req, d
		}
	}
	return req, t.policy.Decide(req)
}

// sequenceSet is the argument that is one, for the commands that take one.
// A UID form puts the sub-command first, so everything after it has moved
// along by one.
func sequenceSet(cmd *wire.Command) (string, bool) {
	i := 0
	if cmd.Name == "UID" {
		i = 1
	}
	switch cmd.Effective() {
	case "FETCH", "STORE", "COPY", "MOVE":
		if len(cmd.Args) > i {
			return cmd.Args[i], true
		}
	}
	return "", false
}

// forward sends an allowed command on, and takes the three decisions that
// follow from what it was: a STARTTLS this relay answers itself, an IDLE
// that parks the connection, an AUTHENTICATE that turns the next lines into
// credential material.
func (t *server) forward(c *conn, cmd *wire.Command, req Request) bool {
	name := cmd.Effective()
	if name == "STARTTLS" {
		return t.starttls(c, cmd)
	}
	if !c.remember(cmd.Tag, name) {
		t.denyConn(c, "too_many_pending", "")
		return true
	}
	switch name {
	case "LOGIN":
		if u, ok := wire.Login(cmd); ok {
			c.setUser(u)
			if !req.Encrypted {
				t.host.Counters().IMAPPlaintextLogins.Add(1)
			}
		}
	case "AUTHENTICATE":
		mech, initial := wire.Mechanism(cmd)
		if !initial {
			// Without an initial response the exchange continues on the
			// lines after this one, and those lines are a credential.
			c.startAuth(cmd.Tag, mech)
		}
		if !req.Encrypted && wire.Plaintext(mech) {
			t.host.Counters().IMAPPlaintextLogins.Add(1)
		}
	case "IDLE":
		c.setIdling(true)
	case "APPEND":
		if cmd.Literal != nil && cmd.Literal.Size > 0 {
			t.host.Counters().IMAPAppendBytes.Add(uint64(cmd.Literal.Size)) //nolint:gosec // positive by the line above
		}
	}
	if wire.Collects(cmd) && req.Messages > 0 {
		t.host.Counters().IMAPFetchedMessages.Add(req.Messages)
		c.mu.Lock()
		c.fetched += req.Messages
		c.mu.Unlock()
	}
	t.host.Counters().IMAPCommands.Add(1)
	if reason := t.decideAnomaly(c, req); reason != "" && t.enforcing() {
		_ = c.refuse(cmd.Tag, Decision{Reason: reason})
		return false
	}
	if err := c.writeServer(append(cmd.Raw, '\r', '\n')); err != nil {
		return true
	}
	if cmd.Literal != nil {
		if err := c.forwardLiteralChain(cmd, req); err != nil {
			return true
		}
	}
	return false
}

// starttls answers the upgrade itself rather than forwarding it.
//
// The two legs are separate decisions: this relay terminates the client's
// TLS and reaches the server however `upstream_tls_mode` says. Forwarding
// the command would mean the client's session key was negotiated with the
// server, and this relay would be reading nothing from then on.
func (t *server) starttls(c *conn, cmd *wire.Command) bool {
	_, already := c.client.(*tls.Conn)
	if t.tlsMode != "starttls" || t.tlsCfg == nil || already {
		d := Decision{Reason: "starttls_not_offered", Hard: true}
		t.refused(c, nil, d)
		return c.refuse(cmd.Tag, d) != nil
	}
	// Anything already buffered was sent before the client could have seen
	// the answer, which is the injection this protocol shares with SMTP's
	// STARTTLS: a command pipelined behind the upgrade would be read as
	// plaintext by one end and as ciphertext by the other.
	if c.reader().Buffered() > 0 {
		t.denyConn(c, "starttls_injection", "")
		return true
	}
	if err := c.line(cmd.Tag + " OK begin TLS negotiation"); err != nil {
		return true
	}
	if err := c.upgrade(t.tlsCfg, 10*time.Second); err != nil {
		t.denyConn(c, "starttls_failed", err.Error())
		return true
	}
	return false
}

// fromServer reads responses, decides about the ones that are decisions, and
// forwards them.
func (t *server) fromServer(c *conn, deadline time.Time) {
	for {
		until := time.Now().Add(t.lifetime)
		if idling, since := c.isIdling(); idling {
			until = since.Add(t.maxIdle)
		}
		if until.After(deadline) {
			until = deadline
		}
		if c.up.SetReadDeadline(until) != nil {
			return
		}
		line, err := c.sr.ReadLine()
		switch {
		case errors.Is(err, wire.ErrLineTooLong):
			t.denyConn(c, "response_too_long", "")
			return
		case err != nil:
			return
		}
		r, perr := wire.ParseResponse(line)
		if perr != nil {
			// A response this relay cannot read is one the client would read
			// differently, which is the whole reason a relay parses at all.
			t.denyConn(c, "malformed_response", perr.Error())
			return
		}
		if d := t.policy.Answer(r, t.preauthNo); !d.Allow {
			t.host.Counters().IMAPPreauthRefused.Add(1)
			t.refusedAnswer(c, r, d)
			_ = c.line("* BYE " + reasonText(d))
			return
		}
		if r.Tag != "" {
			name, failed := c.advance(r)
			if failed {
				t.authFailed(c, name)
			}
			// A tagged answer ends a SASL exchange whichever way it went,
			// so the lines after it are commands again.
			c.endAuth(r.Tag)
			t.logAnswer(c, r, name)
		}
		_, encrypted := c.client.(*tls.Conn)
		out, stripped := c.rewriteCaps(r, encrypted)
		if stripped > 0 {
			t.host.Counters().IMAPCapabilitiesStripped.Add(uint64(stripped))
		}
		if c.writeClient(append(out, '\r', '\n')) != nil {
			return
		}
	}
}

// dial opens the connection to a mailbox server, with TLS where the
// listener asks for it.
func (t *server) dial(client netip.Addr) (net.Conn, error) {
	pool := t.host.Pool(t.c.Upstream)
	if pool == nil {
		return nil, errNoUpstream
	}
	e, _ := pool.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil, errNoUpstream
	}
	const dialTimeout = 10 * time.Second
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.Dial("tcp", e.Address)
	if err != nil {
		return nil, err
	}
	if t.upTLSMode == "disable" || t.upTLSCfg == nil {
		return c, nil
	}
	cfg := t.upTLSCfg.Clone()
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		host, _, splitErr := net.SplitHostPort(e.Address)
		if splitErr != nil {
			host = e.Address
		}
		cfg.ServerName = host
	}
	if t.upTLSMode == "starttls" {
		if err := startTLSUpstream(c, t.maxResp, dialTimeout); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	tc := tls.Client(c, cfg)
	ctx, cancel := contextWithTimeout(dialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return tc, nil
}

// startTLSUpstream performs the upgrade towards the server on this relay's
// own behalf: the greeting, the STARTTLS, and the OK that has to come back
// before the handshake starts.
func startTLSUpstream(up net.Conn, max int, timeout time.Duration) error {
	_ = up.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = up.SetDeadline(time.Time{}) }()
	rd := wire.NewReader(up, max)
	if _, err := rd.ReadLine(); err != nil { // the greeting
		return err
	}
	if _, err := up.Write([]byte("x1 STARTTLS\r\n")); err != nil {
		return err
	}
	for {
		line, err := rd.ReadLine()
		if err != nil {
			return err
		}
		r, perr := wire.ParseResponse(line)
		if perr != nil {
			return perr
		}
		if r.Tag != "x1" {
			continue // untagged data before the answer, which is ordinary
		}
		if !r.OK() {
			return errors.New("imap: the server refused STARTTLS: " + r.Text)
		}
		return nil
	}
}

// contextWithTimeout is a context with a deadline, kept here so the
// handshake paths read the same way.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// admitClient is what this relay asks about an address before it carries
// anything for it: the threat-intelligence lists, the quarantine, and the
// estate's own authorisation policy.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists:       h.ThreatIntel(),
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "imap",
		Client:   ip,
		Target:   t.c.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("imap", reason)
			h.Shadow().Record("imap", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// admitUser asks the estate's policy about the identity a LOGIN claimed.
//
// It is a claim rather than a proven identity -- the server checks the
// password -- so the action is `connect`: this is a filter on who may
// attempt a login on this listener, which is worth having and worth not
// overstating.
func (t *server) admitUser(c *conn, user string) string {
	h := t.host
	return h.Authorization().Ask(authorization.Subject{
		Listener: t.name,
		Kind:     "imap",
		Client:   c.ip,
		User:     user,
		Target:   t.c.Upstream,
		Action:   authorization.ActionConnect,
	}, user, authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("imap", reason)
			h.Shadow().Record("imap", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(c.ip, reason, detail) },
	})
}

// errorsAsTimeout is errors.As against net.Error plus the timeout test.
func errorsAsTimeout(err error, ne *net.Error) bool {
	return errors.As(err, ne) && (*ne).Timeout()
}
