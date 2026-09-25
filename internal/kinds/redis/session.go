package redis

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/respwire"
)

// One connection, and the state a policy on this protocol needs it to have.
//
// Two things here are mutable and both matter. The identity changes: AUTH can be
// sent at any point on a live connection, and sent again as somebody else, so "the
// user on this connection" is a value that changes rather than one read at the
// start. And the selected database changes with SELECT, which is what an
// allow_databases policy is about.
//
// `authed` is taken from the *server's* answer rather than from the relay having
// seen an AUTH. A relay that trusted the attempt would treat a wrong password as a
// successful login, which is the whole of what require_auth exists to prevent.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cliReader *wire.Reader

	cmu sync.Mutex
	umu sync.Mutex

	// authed says the server has accepted a credential on this connection.
	authed atomic.Bool
	// pending is the identity of the AUTH or HELLO in flight, held until the
	// server answers: the relay must not record a user that the server refused.
	pending atomic.Pointer[string]

	mu       sync.Mutex
	secure   bool
	user     string
	database int

	commands, denied int
}

func (se *session) writeClient(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.cmu.Lock()
	defer se.cmu.Unlock()
	_, err := se.client.Write(b)
	return err
}

func (se *session) writeUp(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.umu.Lock()
	defer se.umu.Unlock()
	_, err := se.up.Write(b)
	return err
}

// sess builds the policy's view of this connection.
func (se *session) sess() *Session {
	se.mu.Lock()
	defer se.mu.Unlock()
	return &Session{IP: se.ip, User: se.user, Secure: se.secure,
		Authed: se.authed.Load(), Database: se.database, At: time.Now()}
}

// expectAuth records the identity an AUTH or HELLO asked for, to be confirmed or
// discarded when the server answers.
func (se *session) expectAuth(user string) {
	if user == "" {
		// The one-argument AUTH form names no user; Redis authenticates it as
		// `default`, so that is the name the policy and the log line use.
		user = "default"
	}
	u := user
	se.pending.Store(&u)
}

// authOK is called when the server accepts a credential.
func (se *session) authOK() {
	se.authed.Store(true)
	if u := se.pending.Swap(nil); u != nil {
		se.mu.Lock()
		se.user = *u
		se.mu.Unlock()
	}
}

// authFailed is called when the server refuses one. The identity is discarded
// rather than kept: recording a user the server rejected would have every later
// log line, and every later rule match, name somebody who never logged in.
func (se *session) authFailed() { se.pending.Store(nil) }

func (se *session) setDatabase(db int) {
	se.mu.Lock()
	se.database = db
	se.mu.Unlock()
}

// refuse tells the client no in the protocol it is speaking.
//
// NOPERM is the kind Redis's own ACL uses for "this user may not run this
// command", so a client library reports it the way it reports the server's
// refusals -- and the message says xproxy refused it, so nobody spends an
// afternoon on an ACL rule that would not have helped.
func (se *session) refuse(d Decision) error {
	if !se.t.policy.nak {
		return nil
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	return se.writeClient(wire.Error("NOPERM", msg))
}
