package mysql

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/mysqlwire"
)

// One connection, and the state a policy on this protocol needs it to have.
//
// The identity is mutable, which is the thing to notice. COM_CHANGE_USER
// re-authenticates a live connection as somebody else, so "the user on this
// connection" is not a value read once at the handshake -- it is a value that
// changes, and every decision after the change has to be made about the new one.
// A relay that read it once would have a user policy that applied to the first
// message of a connection and nothing after it.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cliReader, srvReader *wire.Reader

	secure bool
	// serverCaps and clientCaps are what each side offered and asked for, and
	// stripped is what the relay cleared from the greeting.
	serverCaps, clientCaps, stripped uint32

	// authed says the authentication exchange is over, so the client's packets
	// are commands rather than credential material.
	authed atomic.Bool

	cmu sync.Mutex
	umu sync.Mutex

	mu       sync.Mutex
	user     string
	database string
	program  string
	plugin   string

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

// setIdentity records who the connection is now, after a COM_CHANGE_USER.
func (se *session) setIdentity(user, db, plugin string) {
	se.mu.Lock()
	se.user, se.database = user, db
	if plugin != "" {
		se.plugin = plugin
	}
	se.mu.Unlock()
}

// sess builds the policy's view of this connection.
func (se *session) sess() *Session {
	se.mu.Lock()
	defer se.mu.Unlock()
	return &Session{IP: se.ip, User: se.user, Database: se.database,
		Program: se.program, Secure: se.secure, At: time.Now()}
}

// refuse tells the client no in the protocol it is speaking.
//
// 1142 is ER_TABLEACCESS_DENIED_ERROR with SQLSTATE 42000, which a client
// library reports the way it reports the server's own refusals -- so an
// application's existing error handling works, and the message says the proxy
// refused it so nobody goes looking for a GRANT that would not have helped.
func (se *session) refuse(d Decision, seq byte) error {
	if !se.t.policy.nak {
		return nil
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	return se.writeClient(wire.ErrPacket(seq, wire.StatementDenied, "42000", msg))
}

// fatal ends the connection with a reason the client's library will report.
// 1045 is ER_ACCESS_DENIED_ERROR with 28000, the class a client expects for
// "you may not connect".
func (se *session) fatal(d Decision, seq byte) {
	if !se.t.policy.nak {
		return
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	_ = se.writeClient(wire.ErrPacket(seq, wire.AccessDenied, "28000", msg))
}

// upgrade completes a TLS handshake with the client, and with the server on the
// other leg, after the short login form.
//
// Both legs are upgraded independently, which is the point: the relay reads the
// protocol in the middle, so it terminates the client's TLS and starts its own.
func (se *session) upgrade(cfg *tls.Config, short wire.Packet, hs time.Duration) error {
	if cfg == nil {
		return errors.New("mysql: tls is required but the listener has no certificate")
	}
	// The server has to know the client is upgrading, or it will read the TLS
	// ClientHello as a handshake response.
	if err := se.writeUp(wire.Frame(short.Seq, short.Payload)); err != nil {
		return err
	}
	if se.t.upTLSMode != "disable" {
		up := se.t.upTLSCfg.Clone()
		if up.ServerName == "" && !up.InsecureSkipVerify {
			host, _, err := net.SplitHostPort(se.up.RemoteAddr().String())
			if err != nil {
				host = se.up.RemoteAddr().String()
			}
			up.ServerName = host
		}
		tc := tls.Client(se.up, up)
		if hs > 0 {
			_ = tc.SetDeadline(time.Now().Add(hs))
		}
		if err := tc.Handshake(); err != nil {
			return err
		}
		if hs > 0 {
			_ = tc.SetDeadline(time.Time{})
		}
		se.up = tc
	}

	se.cmu.Lock()
	defer se.cmu.Unlock()
	tc := tls.Server(se.client, cfg)
	if hs > 0 {
		_ = tc.SetDeadline(time.Now().Add(hs))
	}
	if err := tc.Handshake(); err != nil {
		return err
	}
	if hs > 0 {
		_ = tc.SetDeadline(time.Time{})
	}
	se.client = tc
	se.mu.Lock()
	se.secure = true
	se.mu.Unlock()
	// The upstream reader is reading the old connection object, so it is
	// rebuilt around the upgraded one.
	se.srvReader = wire.NewReader(se.up, se.t.policy.MaxMessage())
	se.srvReader.Lax()
	return nil
}
