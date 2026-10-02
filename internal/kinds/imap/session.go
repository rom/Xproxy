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
	c.authing, c.authTag, c.authMech = true, tag, mech
	c.mu.Unlock()
}

// endAuth clears the exchange when the tag is the one that opened it. A
// tagged answer for another command cannot end it, which matters because a
// client may pipeline: the lines of a SASL exchange are credential material
// until *its* answer arrives, not until any answer does.
func (c *conn) endAuth(tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authing && c.authTag == tag {
		c.authing, c.authTag, c.authMech = false, "", ""
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
		// command's own name.
		next, perr := wire.ParseCommand([]byte(cmd.Tag + " " + cmd.Name + " " + string(line)))
		if perr == nil && next.Literal != nil {
			req.Literal = next.Literal.Size
			req.Command = cmd
			if d := c.t.policy.boundsCheck(req, cmd.Effective(), rule{}, false); !d.Allow {
				c.t.refused(c, &req, d)
				if c.t.enforcing() || d.Hard {
					// The client is going to send the octets it announced
					// whatever it is told, so they are read and dropped:
					// the alternative is a connection that desynchronises.
					_ = c.reader().Discard(next.Literal.Size)
					return c.refuse(cmd.Tag, d)
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
