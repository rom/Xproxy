package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/netutil"
	wire "github.com/rom/xproxy/internal/pop3"
	"github.com/rom/xproxy/internal/upstream"
)

var errNoUpstream = errors.New("pop3: no reachable server endpoint")

// The relay.
//
// One goroutine, because POP3 is lock-step: a command, then its reply, and
// nothing from the server in between. That is the whole difference from the
// imap kind next door, and it is what makes the copying bound enforceable
// mid-transfer -- this loop is holding the reply while it counts it.

// conn is one client connection and its upstream.
type conn struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	// tap records the session for a pcapng capture, and is nil -- usable, and
	// doing nothing -- whenever no rule wants this one, which is the usual case.
	tap *capture.Tap
	cr  *wire.Reader
	sr  *wire.Reader

	state     wire.State
	user      string
	encrypted bool
	// retrieved and messages are the running totals the bounds measure.
	retrieved int64
	messages  int
	// greeting is the server's own greeting line, kept because an APOP
	// digest is computed over the timestamp in it -- so a listener that
	// rewrote the greeting could not carry APOP, and this one does not
	// rewrite it.
	greeting string
}

// handle serves one connection.
func (t *server) handle(client net.Conn) {
	defer func() { _ = client.Close() }()
	ip := netutil.AddrOf(client.RemoteAddr().String())
	// Opened before anything can refuse the session, because a refused session is
	// the one an operator most often wants and it never dials: after that point
	// there is nothing left to record. A nil tap wraps nothing and writes nothing.
	tap := t.host.Capture().Open("pop3", t.name, "", client.RemoteAddr())
	defer tap.Close()
	client = tap.Client(client)
	if !t.policy.Client(ip) {
		tap.Deny("client_not_allowed")
		t.deny(ip, "client_not_allowed", "")
		return
	}
	if reason := t.admitClient(ip); reason != "" {
		tap.Deny(reason)
		return
	}
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		tap.Deny("rate_limited")
		t.host.Counters().Refuse("pop3", "rate_limited")
		return
	}
	if ok, reason := t.gate.Enter(ip); !ok {
		tap.Deny(reason)
		t.host.Counters().Refuse("pop3", reason)
		return
	}
	defer t.gate.Leave(ip)

	_, isTLS := netutil.TLSConn(client)
	up, greeted, err := t.dial(ip)
	if err != nil {
		tap.Deny("upstream_failed")
		t.host.Counters().Refuse("pop3", "upstream_failed")
		t.host.Logs().Error.Warn("pop3 upstream dial failed", "listener", t.name,
			"client_ip", ip.String(), "error", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	up = tap.Upstream(up)
	t.host.Counters().POP3Connections.Add(1)

	c := &conn{
		t: t, ip: ip, client: client, up: up, tap: tap,
		cr:        wire.NewReader(client, t.maxLine),
		sr:        wire.NewReader(up, t.maxResp),
		encrypted: isTLS,
	}
	if !t.greeting(c, greeted) {
		return
	}
	t.loop(c)
}

// greeting carries the server's first line unchanged.
//
// Unchanged is the point: the `<...>` in it is the challenge an APOP digest
// is computed over, so a relay that invented its own greeting would have to
// refuse APOP outright. This one keeps the server's, which means a digest
// the client computes verifies at the server that issued the challenge.
// line is the greeting dial already read, which is how a leg this relay
// upgraded itself still has one: RFC 2595 leaves the server in the
// AUTHORIZATION state it was already in and does not have it greet again, so
// the only +OK that connection will ever send arrived before the handshake.
func (t *server) greeting(c *conn, line []byte) bool {
	if line == nil {
		_ = c.up.SetReadDeadline(time.Now().Add(t.idle))
		var err error
		line, err = c.sr.ReadLine()
		_ = c.up.SetReadDeadline(time.Time{})
		if err != nil {
			t.host.Counters().Refuse("pop3", "upstream_failed")
			return false
		}
	}
	r, perr := wire.ParseReply(line)
	if perr != nil || !r.OK {
		t.deny(c.ip, "malformed_greeting", reasonOf(perr))
		return false
	}
	c.greeting = r.Text
	return c.write(append(line, '\r', '\n')) == nil
}

func reasonOf(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// loop is the command and reply cycle.
func (t *server) loop(c *conn) {
	deadline := time.Now().Add(t.lifetime)
	for {
		if time.Now().After(deadline) {
			t.host.Counters().Refuse("pop3", "session_timeout")
			return
		}
		until := time.Now().Add(t.idle)
		if until.After(deadline) {
			until = deadline
		}
		if c.client.SetReadDeadline(until) != nil {
			return
		}
		line, err := c.cr.ReadLine()
		switch {
		case errors.Is(err, wire.ErrLineTooLong):
			t.denyConn(c, "line_too_long", "")
			_ = c.reply("-ERR line too long")
			return
		case err != nil:
			return
		}
		if stop := t.command(c, line, deadline); stop {
			return
		}
	}
}

// command handles one client command. It reports whether the connection is
// finished.
func (t *server) command(c *conn, line []byte, deadline time.Time) bool {
	cmd, err := wire.ParseCommand(line)
	if err != nil {
		t.denyConn(c, "malformed_command", err.Error())
		return c.reply("-ERR "+err.Error()) != nil
	}
	req := Request{
		Client: c.ip, User: c.user, State: c.state, Encrypted: c.encrypted,
		Command: cmd, Retrieved: c.retrieved, Messages: c.messages,
	}
	d := t.decide(c, req)
	t.logCommand(c, req, d)
	if !d.Allow {
		t.refused(c, &req, d)
		if t.enforcing() || d.Hard {
			return t.answerRefusal(c, d)
		}
	}
	t.host.Counters().POP3Commands.Add(1)
	if cmd.Name == "STLS" {
		return t.stls(c, cmd)
	}
	if reason := t.decideAnomaly(c, req); reason != "" && t.enforcing() {
		return t.answerRefusal(c, Decision{Reason: reason})
	}
	if c.writeServer(append(line, '\r', '\n')) != nil {
		return true
	}
	switch cmd.Name {
	case "AUTH":
		return t.authExchange(c, cmd, deadline)
	case "QUIT":
		// The reply to QUIT is the last thing on the connection, so it is
		// carried and then the loop ends rather than waiting for a line
		// nobody is going to send.
		_ = t.reply(c, cmd)
		return true
	}
	return t.reply(c, cmd) != nil
}

// decide asks the policy, with the credential questions first.
func (t *server) decide(c *conn, req Request) Decision {
	cmd := req.Command
	switch cmd.Name {
	case "USER", "PASS":
		if d := t.policy.Mechanism("user", c.encrypted); !d.Allow {
			return d
		}
		if u, ok := cmd.User(); ok {
			if d := t.policy.User(u); !d.Allow {
				return d
			}
			if reason := t.admitUser(c, u); reason != "" {
				return Decision{Reason: reason, Hard: true}
			}
			c.user = u
			c.tap.User(u)
			req.User = u
			if !c.encrypted {
				t.host.Counters().POP3PlaintextLogins.Add(1)
			}
		}
	case "APOP":
		if d := t.policy.Mechanism("apop", c.encrypted); !d.Allow {
			return d
		}
		if u, ok := cmd.APOPUser(); ok {
			if d := t.policy.User(u); !d.Allow {
				return d
			}
			c.user = u
			c.tap.User(u)
			req.User = u
		}
	case "AUTH":
		mech, _, ok := cmd.Mechanism()
		if !ok {
			// `AUTH` with no mechanism names nothing, so neither require_tls
			// nor the mechanism list has anything to decide about -- and the
			// exchange that follows it used to move this relay's state to
			// transaction on the server's `+OK`, with no credential behind it
			// and no user name to attribute anything to. It is refused rather
			// than guessed at: a client that wants the mechanism list has CAPA
			// (RFC 2449), which this relay reads and narrows.
			return Decision{Reason: "auth_no_mechanism", Hard: true}
		}
		if d := t.policy.Mechanism(mech, c.encrypted); !d.Allow {
			return d
		}
		if !c.encrypted && wire.Plaintext(mech) {
			t.host.Counters().POP3PlaintextLogins.Add(1)
		}
	}
	return t.policy.Decide(req)
}

// answerRefusal tells the client no, in the protocol's own terms.
func (t *server) answerRefusal(c *conn, d Decision) bool {
	switch strings.ToLower(t.c.DenyResponse) {
	case "drop":
		return false
	case "close":
		return true
	default:
		return c.reply("-ERR refused by xproxy: "+reasonText(d)) != nil
	}
}

func reasonText(d Decision) string {
	if d.Detail == "" {
		return d.Reason
	}
	return d.Reason + " (" + d.Detail + ")"
}

// reply carries the server's answer, which is one line or many depending on
// the command -- and on this protocol that distinction is the difference
// between a working relay and two ends that disagree about where a message
// ended.
func (t *server) reply(c *conn, cmd *wire.Command) error {
	line, err := c.sr.ReadLine()
	if err != nil {
		return err
	}
	r, perr := wire.ParseReply(line)
	if perr != nil {
		t.denyConn(c, "malformed_reply", perr.Error())
		return perr
	}
	switch cmd.Name {
	case "CAPA":
		if r.OK {
			return t.capa(c, line)
		}
	case "DELE":
		// Counted here, on the reply, because the mailbox changed only if
		// the server said it did -- and counted here rather than in body(),
		// where it was: body carries a multi-line reply, and DELE's is one
		// line (RFC 1939 section 5), so the count could never happen. A
		// deletion is the one thing a mail client does through this relay
		// that an operator cannot undo, and `pop3_deletes` read zero however
		// many of them crossed.
		if r.OK {
			t.host.Counters().POP3Deletes.Add(1)
		}
	case "USER", "PASS", "APOP":
		if !r.OK {
			t.authFailed(c, cmd.Name)
		} else if cmd.Name != "USER" {
			// USER is only half a credential; the state moves on the reply
			// that accepted the whole of one.
			c.state = wire.StateTransaction
		}
	}
	if err := c.write(append(line, '\r', '\n')); err != nil {
		return err
	}
	if !r.OK || !cmd.Multiline() {
		return nil
	}
	return t.body(c, cmd)
}

// body carries a multi-line reply, counting it as it passes.
//
// The count is the bound: a client that has taken its allowance is cut off
// here rather than at its next command, because one RETR of a very large
// message is a copy of a mailbox all by itself.
func (t *server) body(c *conn, cmd *wire.Command) error {
	req := Request{Client: c.ip, User: c.user, State: c.state, Command: cmd}
	_, maxBytes := t.policy.Bounds(req)
	var carried int64
	for {
		line, err := c.sr.ReadLine()
		if err != nil {
			return err
		}
		if wire.Terminator(line) {
			break
		}
		// The count is of the message as its author wrote it, so the
		// stuffing dot the protocol adds is not charged to the client --
		// and the line is forwarded exactly as it arrived, because it is
		// already stuffed correctly and stuffing it again would add a dot
		// the recipient would have to remove.
		carried += int64(len(wire.Unstuff(line))) + 2
		if maxBytes > 0 && c.retrieved+carried > maxBytes {
			t.refused(c, &req, Decision{Reason: "retrieval_too_large",
				Detail: "the bound was reached mid-message"})
			return errors.New("pop3: retrieval bound reached")
		}
		if err := c.write(append(line, '\r', '\n')); err != nil {
			return err
		}
	}
	if cmd.Collects() {
		c.retrieved += carried
		c.messages++
		if carried > 0 {
			t.host.Counters().POP3RetrievedBytes.Add(uint64(carried))
		}
		t.logRetrieval(c, cmd, carried)
	}
	return c.write([]byte(".\r\n"))
}

// capa carries a CAPA reply with the list narrowed: a mechanism the policy
// will refuse is removed, and STLS goes where the connection is already TLS.
func (t *server) capa(c *conn, first []byte) error {
	if err := c.write(append(first, '\r', '\n')); err != nil {
		return err
	}
	stripped := 0
	for {
		line, err := c.sr.ReadLine()
		if err != nil {
			return err
		}
		if wire.Terminator(line) {
			break
		}
		out, drop := t.narrow(c, string(wire.Unstuff(line)))
		if drop {
			stripped++
			continue
		}
		if err := c.write(append([]byte(out), '\r', '\n')); err != nil {
			return err
		}
	}
	if stripped > 0 {
		t.host.Counters().POP3CapabilitiesStripped.Add(uint64(stripped))
	}
	return c.write([]byte(".\r\n"))
}

// narrow decides what to do with one capability line, and returns the line
// to send in its place.
func (t *server) narrow(c *conn, line string) (string, bool) {
	name, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
	switch strings.ToUpper(name) {
	case "STLS":
		return line, c.encrypted
	case "SASL":
		kept := make([]string, 0, 4)
		for _, m := range strings.Fields(rest) {
			d := t.policy.Mechanism(m, c.encrypted)
			if d.Allow {
				kept = append(kept, m)
			}
		}
		if len(kept) == 0 {
			// A SASL line with nothing on it would advertise a mechanism
			// list the client cannot choose from, which is worse than not
			// advertising SASL at all.
			return "", true
		}
		return "SASL " + strings.Join(kept, " "), false
	case "USER":
		d := t.policy.Mechanism("user", c.encrypted)
		return line, !d.Allow
	}
	return line, false
}

// authExchange carries the lines of a SASL exchange, which are credential
// material: forwarded, bounded, never parsed and never logged.
func (t *server) authExchange(c *conn, cmd *wire.Command, deadline time.Time) bool {
	c.cr.SetMax(wire.MaxAuthLine)
	defer c.cr.SetMax(t.maxLine)
	for {
		line, err := c.sr.ReadLine()
		if err != nil {
			return true
		}
		r, perr := wire.ParseReply(line)
		if perr != nil {
			t.denyConn(c, "malformed_reply", perr.Error())
			return true
		}
		if c.write(append(line, '\r', '\n')) != nil {
			return true
		}
		if !r.Continuation() {
			if r.OK {
				// The exchange named a mechanism -- a bare AUTH is refused
				// before it gets here -- so an +OK that ends it is a
				// credential the server accepted.
				c.state = wire.StateTransaction
			} else {
				t.authFailed(c, cmd.Name)
			}
			return false
		}
		until := time.Now().Add(t.idle)
		if until.After(deadline) {
			until = deadline
		}
		if c.client.SetReadDeadline(until) != nil {
			return true
		}
		answer, err := c.cr.ReadLine()
		if err != nil {
			return true
		}
		if c.writeServer(append(answer, '\r', '\n')) != nil {
			return true
		}
	}
}

// stls answers the upgrade itself rather than forwarding it, for the reason
// every other kind in this project does: the two legs are two decisions.
func (t *server) stls(c *conn, _ *wire.Command) bool {
	if t.tlsMode != "starttls" || t.tlsCfg == nil || c.encrypted {
		d := Decision{Reason: "stls_not_offered", Hard: true}
		t.refused(c, nil, d)
		return t.answerRefusal(c, d)
	}
	// Anything already buffered was sent before the client could have seen
	// the answer: a command pipelined behind the upgrade is plaintext to one
	// end and ciphertext to the other.
	if c.cr.Buffered() > 0 {
		t.denyConn(c, "stls_injection", "")
		return true
	}
	if c.reply("+OK begin TLS negotiation") != nil {
		return true
	}
	// STLS is an in-band upgrade, so the capture pauses over the handshake and
	// picks the plaintext up again on the far side: the file then holds one
	// readable stream of the protocol rather than cleartext and then ciphertext.
	c.tap.Pause()
	tc := tls.Server(c.client, t.tlsCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		t.denyConn(c, "stls_failed", err.Error())
		return true
	}
	c.client = c.tap.Client(tc)
	c.cr = wire.NewReader(c.client, t.maxLine)
	c.encrypted = true
	return false
}

// write and writeServer are the two writes, kept as methods so the relay
// reads the same way in both directions.
func (c *conn) write(b []byte) error {
	_, err := c.client.Write(b)
	return err
}

func (c *conn) writeServer(b []byte) error {
	_, err := c.up.Write(b)
	return err
}

func (c *conn) reply(s string) error { return c.write([]byte(s + "\r\n")) }

// dial opens the connection to a mailbox server. The second result is the
// greeting, when the upgrade below had to read it to get there; nil means the
// caller reads it itself.
func (t *server) dial(client netip.Addr) (net.Conn, []byte, error) {
	pool := t.host.Pool(t.c.Upstream)
	if pool == nil {
		return nil, nil, errNoUpstream
	}
	e, _ := pool.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil, nil, errNoUpstream
	}
	const dialTimeout = 10 * time.Second
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.Dial("tcp", e.Address)
	if err != nil {
		return nil, nil, err
	}
	if t.upTLSMode == "disable" || t.upTLSCfg == nil {
		return c, nil, nil
	}
	cfg := t.upTLSCfg.Clone()
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		host, _, splitErr := net.SplitHostPort(e.Address)
		if splitErr != nil {
			host = e.Address
		}
		cfg.ServerName = host
	}
	var greeting []byte
	if t.upTLSMode == "starttls" {
		greeting, err = stlsUpstream(c, t.maxResp, dialTimeout)
		if err != nil {
			_ = c.Close()
			return nil, nil, err
		}
	}
	tc := tls.Client(c, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	return tc, greeting, nil
}

// stlsUpstream performs the upgrade towards the server on this relay's own
// behalf: read the greeting, ask, and require the +OK before handshaking.
//
// The greeting comes back rather than being discarded, because it is the only
// one this connection sends -- RFC 2595 leaves the server in AUTHORIZATION and
// does not have it greet again -- and on POP3 it is also the APOP challenge.
func stlsUpstream(up net.Conn, max int, timeout time.Duration) ([]byte, error) {
	_ = up.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = up.SetDeadline(time.Time{}) }()
	rd := wire.NewReader(up, max)
	greeting, err := rd.ReadLine()
	if err != nil {
		return nil, err
	}
	if _, err := up.Write([]byte("STLS\r\n")); err != nil {
		return nil, err
	}
	line, err := rd.ReadLine()
	if err != nil {
		return nil, err
	}
	r, perr := wire.ParseReply(line)
	if perr != nil {
		return nil, perr
	}
	if !r.OK {
		return nil, errors.New("pop3: the server refused STLS: " + r.Text)
	}
	// Anything behind the +OK was sent in clear and would be read as though
	// it had arrived inside the session: the client leg's injection check,
	// pointed the other way. Nothing legitimate is there to lose, because the
	// server has nothing more to say until this relay speaks.
	if n := rd.Buffered(); n > 0 {
		return nil, errors.New("pop3: the server pipelined " + strconv.Itoa(n) + " octets behind its STLS answer")
	}
	return greeting, nil
}

// admitClient is what this relay asks about an address before it carries
// anything for it.
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
		Kind:     "pop3",
		Client:   ip,
		Target:   t.c.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("pop3", reason)
			h.Shadow().Record("pop3", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// admitUser asks the estate's policy about the identity a USER or APOP
// claimed, which is a claim rather than a proven identity.
func (t *server) admitUser(c *conn, user string) string {
	h := t.host
	return h.Authorization().Ask(authorization.Subject{
		Listener: t.name,
		Kind:     "pop3",
		Client:   c.ip,
		User:     user,
		Target:   t.c.Upstream,
		Action:   authorization.ActionConnect,
	}, user, authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("pop3", reason)
			h.Shadow().Record("pop3", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(c.ip, reason, detail) },
	})
}
