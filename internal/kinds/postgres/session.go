package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/pgwire"
)

// One connection, and the state a policy on this protocol needs it to have.
//
// The interesting thing about a PostgreSQL connection is that it has three
// phases and the relay's job is different in each.
//
// **Before encryption.** The client may send an SSLRequest, which is eight
// octets and is not a startup packet. The relay answers it itself rather than
// forwarding it, because the answer decides whether the rest of the connection
// is readable by anybody on the path -- and because forwarding it would mean the
// server's answer decided, and the server's answer is exactly what an attacker
// on the path rewrites. A relay configured to require TLS answers 'S' and
// completes the handshake; one that is not may answer 'N', and then the identity
// in the next packet crosses the network in the clear.
//
// **Before authentication.** The startup packet carries the user, the database
// and the application name: the only identity this protocol has before a
// credential is checked, and a claim rather than a credential. The relay decides
// about the claim, then forwards the packet *as the octets the client sent* --
// re-encoding it would mean deciding about one message and forwarding another.
// Then it watches the server's authentication request, because pg_hba.conf
// decides the method and this is where a relay notices that the line which
// matched says md5.
//
// **After authentication.** Statements, in two protocols: the simple one (Query)
// and the extended one (Parse/Bind/Execute) that every driver written this
// century actually uses.

// session is one client connection.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	secure   bool
	user     string
	database string
	app      string

	// authed says the server has answered AuthenticationOk. Until it does,
	// every statement is one the database has not agreed to run, and a client
	// that sent one anyway is a client the relay has nothing to say about --
	// so the relay does not need to guess: it refuses a statement before
	// authentication, because on this protocol there is no legitimate one.
	authed atomic.Bool

	// backendPID and backendSecret are what the server handed out for this
	// connection, kept so that a cancel request arriving on another connection
	// can be recognised as belonging to this one.
	backendPID, backendSecret atomic.Int32

	// cmu guards writing to the client, which both directions do: the server's
	// answers and the relay's own refusals.
	cmu sync.Mutex

	mu sync.Mutex
	// inCopy says a COPY is in progress in the given direction, because while
	// one is, the stream carries CopyData rather than messages a policy has
	// anything to say about.
	inCopy bool
	// prepared maps a prepared statement's name to what it was, so that an
	// Execute can be refused for the statement it runs rather than the
	// message it is. Bounded, because the names come off the network.
	prepared map[string]wire.Statement

	statements, denied int

	// startupRaw is the packet the client sent, kept so it can be forwarded as
	// the octets it was, and hs the handshake budget.
	startupRaw []byte
	hs         time.Duration
}

const maxPrepared = 256

// writeClient writes to the client, serialised against the other direction.
func (se *session) writeClient(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.cmu.Lock()
	defer se.cmu.Unlock()
	_, err := se.client.Write(b)
	return err
}

// refuse tells the client no in the protocol it is speaking.
//
// A relay that closed the connection instead would be indistinguishable from a
// network fault, and an application's operator would spend a day on the wrong
// problem. 42501 is insufficient_privilege, which is what the database itself
// would answer, so an application's existing error handling works -- and the
// message says the proxy refused it, so nobody goes looking for a GRANT that
// would not have helped.
func (se *session) refuse(d Decision, what string) error {
	if !se.t.policy.nak {
		return errDropped
	}
	msg := fmt.Sprintf("refused by xproxy: %s", d.Reason)
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	if what != "" {
		msg += " on " + what
	}
	if err := se.writeClient(wire.ErrorResponse("ERROR", "42501", msg)); err != nil {
		return err
	}
	// The client will not send another statement until it sees this.
	return se.writeClient(wire.ReadyForQuery('I'))
}

// fatal ends the connection with a reason the client's library will report.
func (se *session) fatal(d Decision) {
	if !se.t.policy.nak {
		return
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	// 28000 is invalid_authorization_specification, which is the class a
	// client expects for "you may not connect".
	_ = se.writeClient(wire.ErrorResponse("FATAL", "28000", msg))
}

var errDropped = errors.New("postgres: refused without an answer")

// remember records what a prepared statement is, bounded.
func (se *session) remember(name string, st wire.Statement) {
	if name == "" {
		// The unnamed statement, which every driver reuses. It is one slot.
		name = "\x00unnamed"
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	if se.prepared == nil {
		se.prepared = make(map[string]wire.Statement, 8)
	}
	if len(se.prepared) >= maxPrepared {
		if _, known := se.prepared[name]; !known {
			// The table is full of names a client chose. Forgetting one would
			// make a later Execute undecidable, so the relay refuses to learn
			// a new one instead and the Execute is refused for being unknown.
			return
		}
	}
	se.prepared[name] = st
}

// recall returns what a prepared statement was.
func (se *session) recall(name string) (wire.Statement, bool) {
	if name == "" {
		name = "\x00unnamed"
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	st, ok := se.prepared[name]
	return st, ok
}

func (se *session) setCopy(on bool) {
	se.mu.Lock()
	se.inCopy = on
	se.mu.Unlock()
}

func (se *session) copying() bool {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.inCopy
}

// observe records what this connection said about the machine at the other end.
//
// A database client is a device too, and on a segment where the proxy also
// relays DHCP the application name and the role are what tie a record to a
// host. The statement text is deliberately not recorded: it is the contents of
// somebody's database, and an inventory is not the place for it.
func (se *session) observe() {
	se.t.host.ObserveAsset(assets.Observation{
		Proto:     "postgres",
		Listener:  se.t.name,
		Addr:      se.ip,
		UserAgent: se.app,
		ClientID:  se.user,
	})
}

// upgrade completes a TLS handshake with the client after answering an
// SSLRequest.
func (se *session) upgrade(cfg *tls.Config, timeout time.Duration) error {
	if cfg == nil {
		return errors.New("postgres: tls is required but the listener has no certificate")
	}
	se.cmu.Lock()
	defer se.cmu.Unlock()
	if err := se.writeClient0([]byte{wire.AllowTLS}); err != nil {
		return err
	}
	tc := tls.Server(se.client, cfg)
	// A context rather than a deadline on the connection: a deadline would have
	// to be cleared afterwards, and a relay that forgot would kill a live
	// session at an hour that looked like a network fault.
	ctx, cancel := context.Background(), func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	se.client = tc
	se.secure = true
	return nil
}

// writeClient0 writes without taking the lock, for callers that hold it.
func (se *session) writeClient0(b []byte) error {
	_, err := se.client.Write(b)
	return err
}
