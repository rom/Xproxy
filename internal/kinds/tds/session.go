package tds

import (
	"net"
	"net/netip"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/tdswire"
)

// One connection, and the state a policy on this protocol needs it to have.
//
// The identity here is settled once, at the LOGIN7, and does not change: TDS has
// no equivalent of MySQL's COM_CHANGE_USER. What it does have is
// RESETCONNECTION -- a status bit on any message, which a connection pool sets
// when it hands a pooled connection to a different caller. The credential does
// not change, so the policy's view of who is connected is still right; what
// changes is which part of an application is using it. The relay notes it,
// because an operator reading a session's history needs to know the batches
// before and after a reset may have come from different code.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cliReader, srvReader *wire.Reader
	// spid is the server process identifier from the server's own packets,
	// echoed in anything the relay originates so a client library that tracks it
	// is not confused by a zero appearing mid-connection.
	spid uint16
	// size is the packet size the login settled on, for framing what the relay
	// writes itself.
	size int

	cmu sync.Mutex
	umu sync.Mutex

	mu         sync.Mutex
	secure     bool
	upSecure   bool
	user       string
	database   string
	app        string
	host       string
	library    string
	integrated bool
	resets     int

	statements, denied int
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
	return &Session{IP: se.ip, User: se.user, Database: se.database, App: se.app,
		Integrated: se.integrated, Secure: se.secure, At: time.Now()}
}

// refuse tells the client no in the protocol it is speaking.
//
// The error token carries 229, which is SQL Server's own number for "permission
// denied on an object", at severity 14. A client library reports it the way it
// reports the server's refusals, so an application's existing error handling
// works -- and the message says xproxy refused it, so nobody spends an afternoon
// looking for a GRANT that would not have helped.
func (se *session) refuse(d Decision) error {
	if !se.t.policy.nak {
		return nil
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	tok := wire.ErrorToken(wire.PermissionDenied, msg, "xproxy")
	return se.writeClient(wire.Frame(wire.TypeTabularResult, se.spid, tok, se.size))
}

// fatal refuses the login itself, with the number a client expects for "you may
// not connect" rather than "you may not do that".
func (se *session) fatal(d Decision) {
	if !se.t.policy.nak {
		return
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	tok := wire.ErrorToken(wire.LoginFailed, msg, "xproxy")
	_ = se.writeClient(wire.Frame(wire.TypeTabularResult, se.spid, tok, se.size))
}
