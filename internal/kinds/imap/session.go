package imap

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/imap"
)

// One connection's state, and the two writers that share it.
//
// IMAP is not lock-step. A server sends untagged data whenever it likes --
// that is what IDLE is -- so this relay runs a goroutine each way, and both
// of them write to the client: one forwarding the server's responses, the
// other answering a command the policy refused. So every write to either
// peer goes through one mutex, which is also what makes the STARTTLS
// upgrade safe: the writer is replaced while that lock is held.
//
// The state the policy decides with -- which IMAP state the connection is
// in, which identity it claimed -- is written by the goroutine reading the
// server, because that is where the answer arrives, and read by the one
// reading the client. It lives under the same mutex.

// maxPending bounds the commands in flight on one connection. A client may
// pipeline, and a tag is chosen by the client, so without a bound the table
// that pairs an answer to its question is a table the client sizes.
const maxPending = 64

// conn is one client connection and its upstream.
type conn struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cr *wire.Reader // the client's commands
	sr *wire.Reader // the server's responses

	mu        sync.Mutex
	cw        io.Writer // the client, replaced by the STARTTLS upgrade
	sw        io.Writer // the server
	state     wire.State
	user      string
	encrypted bool
	// pending pairs a tag with the command it named, so a tagged response
	// can move the state machine. It is bounded and a command past the
	// bound is refused rather than forgotten: forgetting would make the
	// state unreliable, which is worse than refusing one command.
	pending map[string]string
	// idling is set between an accepted IDLE and the DONE that ends it.
	// While it is set the only line the client may send is DONE.
	idling   bool
	idleFrom time.Time
	// authing is set between an accepted AUTHENTICATE and its tagged
	// answer. The lines in between are credential material and are
	// forwarded without being parsed as commands.
	authing  bool
	authTag  string
	authMech string
	// authCont says the server has asked for the next step of that exchange
	// and this relay has not carried an answer to it yet. It is the turn
	// token that keeps the exchange lock-step: see takeAuthTurn.
	authCont bool
	commands int
	// fetched counts the messages this connection's requests have named,
	// which is the number the access log reports and the anomaly models
	// read.
	fetched uint64
}

func newConn(t *server, ip netip.Addr, client, up net.Conn, encrypted bool) *conn {
	return &conn{
		t: t, ip: ip, client: client, up: up,
		cr:        wire.NewReader(client, t.maxLine),
		sr:        wire.NewReader(up, t.maxResp),
		cw:        client,
		sw:        up,
		encrypted: encrypted,
		pending:   make(map[string]string, 8),
	}
}

// writeClient and writeServer serialise every write.
func (c *conn) writeClient(b []byte) error {
	c.mu.Lock()
	w := c.cw
	c.mu.Unlock()
	_, err := w.Write(b)
	return err
}

func (c *conn) writeServer(b []byte) error {
	c.mu.Lock()
	w := c.sw
	c.mu.Unlock()
	_, err := w.Write(b)
	return err
}

// line writes one CRLF-terminated line to the client.
func (c *conn) line(s string) error { return c.writeClient([]byte(s + "\r\n")) }

// snapshot is what the policy needs to know about the connection, read
// under the lock in one go rather than field by field -- a decision made
// half before and half after a tagged OK would be a decision about a state
// that never existed.
func (c *conn) snapshot() (wire.State, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.user, c.encrypted
}

func (c *conn) setState(s wire.State) {
	c.mu.Lock()
	c.state = s
	c.mu.Unlock()
}

func (c *conn) setUser(u string) {
	c.mu.Lock()
	c.user = u
	c.mu.Unlock()
}

// remember records a tag and the command it named.
func (c *conn) remember(tag, name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) >= maxPending {
		return false
	}
	c.pending[tag] = name
	return true
}

// take returns and forgets the command a tag named.
func (c *conn) take(tag string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name, ok := c.pending[tag]
	delete(c.pending, tag)
	return name, ok
}

func (c *conn) setIdling(on bool) {
	c.mu.Lock()
	c.idling, c.idleFrom = on, time.Now()
	c.mu.Unlock()
}

func (c *conn) isIdling() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.idling, c.idleFrom
}

func (c *conn) startAuth(tag, mech string) {
	c.mu.Lock()
	c.authing, c.authTag, c.authMech, c.authCont = true, tag, mech, false
	c.mu.Unlock()
}

// serverAsked records the server's continuation request, which is the one
// thing that makes the next client line credential material.
func (c *conn) serverAsked() {
	c.mu.Lock()
	if c.authing {
		c.authCont = true
	}
	c.mu.Unlock()
}

// takeAuthTurn reports whether a client line is the answer to a continuation
// request this relay has seen, and consumes it.
//
// One request, one answer: that is the whole of the lock-step, and it is what
// keeps the auth path from being a hole in everything else. While a SASL
// exchange is open the lines are credential material -- base64, or `*` to
// cancel -- and they are forwarded without being parsed as commands, which is
// right and is also an invitation: a client that sent `a1 AUTHENTICATE
// XNOTAMECH` and then a second line would have had that line forwarded
// unparsed, past the command lists, the mailbox lists, the user list and the
// log. The server, having answered the mechanism it does not implement with a
// tagged NO, reads that line as a command. So a line arrives in auth mode only
// when the server has asked for one.
func (c *conn) takeAuthTurn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.authCont {
		return false
	}
	c.authCont = false
	return true
}

// endAuth clears the exchange when the tag is the one that opened it. A
// tagged answer for another command cannot end it, which matters because a
// client may pipeline: the lines of a SASL exchange are credential material
// until *its* answer arrives, not until any answer does.
func (c *conn) endAuth(tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authing && c.authTag == tag {
		c.authing, c.authTag, c.authMech, c.authCont = false, "", "", false
	}
}

func (c *conn) inAuth() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authing
}

// upgrade replaces the client's reader and writer with a TLS session this
// relay terminates, which is what `tls_mode: starttls` means.
func (c *conn) upgrade(cfg *tls.Config, timeout time.Duration) error {
	tc := tls.Server(c.client, cfg)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.client, c.cw = tc, tc
	c.cr = wire.NewReader(tc, c.t.maxLine)
	c.encrypted = true
	c.mu.Unlock()
	return nil
}

// reader returns the client reader, which the upgrade replaces.
func (c *conn) reader() *wire.Reader {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cr
}

// refuse answers a command the policy refused, in the protocol's own terms.
//
// The default is a tagged NO, which every mail client displays to the person
// using it. BAD says "your client is wrong", which is a worse lie than
// saying no. drop and close exist for a listener that would rather tell an
// attacker nothing, at the cost of a client that hangs.
func (c *conn) refuse(tag string, d Decision) error {
	switch strings.ToLower(c.t.c.DenyResponse) {
	case "drop":
		return nil
	case "close":
		return errClose
	case "bad":
		return c.line(tag + " BAD " + reasonText(d))
	default:
		return c.line(tag + " NO " + reasonText(d))
	}
}

// reasonText is what the client is told: the reason, and the proxy that
// refused it, because a person reading "NO mailbox_not_allowed" in a mail
// client should be able to tell it came from a policy rather than from their
// mail server being broken.
func reasonText(d Decision) string {
	s := "[CANNOT] refused by xproxy: " + d.Reason
	if d.Detail != "" {
		s += " (" + d.Detail + ")"
	}
	return s
}

// errClose asks the caller to end the connection.
var errClose = errors.New("imap: close the connection")

// forwardLiteralChain copies the octets of a literal the policy allowed,
// then the line that continues the command, for as many literals as the
// command chains.
//
// A command does not end at a literal: `LOGIN {4}` is followed by four
// octets and then the rest of the line, which may itself end in another
// literal. Each hop is bounded, and the number of hops is bounded, because
// without that one command is an unbounded conversation.
func (c *conn) forwardLiteralChain(cmd *wire.Command, req Request) error {
	lits := 0
	// The chain's declared octets, added up. The bound is about the command
	// rather than about one hop of it: ten literals of a megabyte each are a
	// ten-megabyte APPEND however the client chose to spell it, and a bound
	// applied per hop is a bound a client divides its way past.
	total := req.Literal
	// The rule that decided the command decides its continuations too. Passing
	// an empty rule here was a bound bypass: the first literal was checked
	// against the rule's own max_append_bytes and every chained one against the
	// listener's, so a rule tightening the bound for one user applied to the
	// mailbox name and not to the message.
	rl, found := c.t.policy.ruleFor(req)
	for cmd.Literal != nil {
		if lits++; lits > c.t.maxLits {
			c.t.denyConn(c, "too_many_literals", strconv.Itoa(lits))
			return errClose
		}
		if err := c.reader().CopyLiteral(c.serverWriter(), int64(cmd.Literal.Size)); err != nil {
			return err
		}
		line, err := c.reader().ReadLine()
		if err != nil {
			return err
		}
		// The continuation is part of the same command, so it is decided
		// about as such: its own literal gets the same bound, under the
		// command's own name and the command's own rule.
		next, perr := wire.ParseCommand([]byte(cmd.Tag + " " + cmd.Name + " " + string(line)))
		if perr == nil && next.Literal != nil {
			total += next.Literal.Size
			req.Literal = total
			req.Command = cmd
			if d := c.t.policy.boundsCheck(req, cmd.Effective(), rl, found); !d.Allow {
				c.t.refused(c, &req, d)
				if c.t.enforcing() || d.Hard {
					// The command's first octets are already upstream, so
					// there is no answering this with a tagged refusal and a
					// live connection: the server is mid-line and whatever
					// the client sends next would be read as the rest of that
					// command. The refusal goes out and the connection ends.
					_ = c.refuse(cmd.Tag, d)
					return errClose
				}
			}
			cmd.Literal = next.Literal
		} else {
			cmd.Literal = nil
		}
		if err := c.writeServer(append(line, '\r', '\n')); err != nil {
			return err
		}
	}
	return nil
}

// serverWriter is the upstream writer as an io.Writer that takes the lock
// per write, which is what CopyLiteral needs.
func (c *conn) serverWriter() io.Writer { return writerFunc(c.writeServer) }

type writerFunc func([]byte) error

func (f writerFunc) Write(b []byte) (int, error) {
	if err := f(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// narrow rewrites a capability list on its way to the client.
//
// Three groups go. A mechanism the policy will refuse, because a client that
// never offers it never has a password refused halfway through an exchange.
// Compression, always, because a deflated stream cannot be inspected.
// STARTTLS, where this listener is already TLS -- an upgrade inside an
// upgrade is a command the client will send and the server will refuse.
//
// One is added: LOGINDISABLED, where LOGIN would be refused on this
// connection. RFC 3501 §6.2.3 makes that the way a server says so.
func (c *conn) narrow(caps wire.Caps, encrypted bool) (wire.Caps, int) {
	p := c.t.policy
	before := len(caps)
	out := caps.Without(func(name string) bool {
		switch {
		case p.noCompress && wire.Compressed(name):
			return true
		case name == "STARTTLS" && encrypted:
			return true
		}
		mech, isAuth := strings.CutPrefix(name, "AUTH=")
		if !isAuth {
			return false
		}
		if p.requireTLS && !encrypted && wire.Plaintext(mech) {
			return true
		}
		return len(p.mechanisms) > 0 && !p.mechanisms[strings.ToLower(mech)]
	})
	loginRefused := (p.requireTLS && !encrypted) ||
		(len(p.mechanisms) > 0 && !p.mechanisms["login"])
	if loginRefused {
		out = out.With("LOGINDISABLED")
	}
	stripped := before - len(out)
	if loginRefused {
		stripped++
	}
	return out, stripped
}

// rewriteCaps rewrites the capability list inside a response, where it
// carries one, and reports how many capabilities it removed.
//
// Two shapes carry it: the untagged CAPABILITY response and the CAPABILITY
// response code of an OK -- the second of which is how a greeting
// advertises, so a relay that handled only the first would narrow nothing
// on the one line every client reads.
func (c *conn) rewriteCaps(r *wire.Response, encrypted bool) ([]byte, int) {
	switch {
	case r.Item == "CAPABILITY":
		caps, n := c.narrow(wire.ParseCaps(r.Text), encrypted)
		return []byte("* CAPABILITY " + caps.String()), n
	case r.Code == "CAPABILITY":
		caps, n := c.narrow(wire.ParseCaps(r.CodeArgs), encrypted)
		tag := "*"
		if r.Tag != "" {
			tag = r.Tag
		}
		line := tag + " " + r.Status + " [CAPABILITY " + caps.String() + "]"
		if r.Text != "" {
			line += " " + r.Text
		}
		return []byte(line), n
	}
	return r.Raw, 0
}

// advance moves the state machine on a tagged response, and reports whether
// the answer was an authentication failure -- which is the one thing on this
// protocol worth counting per attempt rather than per connection.
func (c *conn) advance(r *wire.Response) (name string, authFailed bool) {
	name, ok := c.take(r.Tag)
	if !ok {
		return "", false
	}
	switch name {
	case "LOGIN", "AUTHENTICATE":
		if r.OK() {
			c.setState(wire.StateAuth)
		} else if r.Failed() {
			authFailed = true
		}
	case "SELECT", "EXAMINE":
		if r.OK() {
			c.setState(wire.StateSelected)
		}
	case "CLOSE", "UNSELECT":
		if r.OK() {
			c.setState(wire.StateAuth)
		}
	case "LOGOUT":
		c.setState(wire.StateLogout)
	}
	return name, authFailed
}
