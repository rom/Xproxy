package ntske

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
)

// Terminating NTS key establishment rather than relaying it.
//
// The relaying listener beside this reads the one thing a TLS handshake shows in
// the clear and hands the connection on, which is all a relay that holds no keys
// can honestly do. Terminating is the other posture: this listener is the key
// establishment server. It presents the certificate, derives the two NTS keys
// from the TLS exporter, and hands the client cookies of its own -- cookies the
// kind: ntp listener beside it can open, which is what lets that listener
// verify a client's time requests and put NTS in front of a time server that
// cannot speak it.
//
// The keys inside a cookie are the client's session keys, sealed under a master
// key this relay holds. That master key is rotated, kept with an overlap so the
// cookies already issued keep working, and written down so a restart does not
// invalidate every cookie in the estate at once. None of that is optional: each
// of them is the difference between a rotation nobody notices and an estate
// whose clients all re-establish keys at the same moment.

// The bounds of one terminating exchange.
const (
	// termHandshake is the default deadline for the TLS handshake and the
	// exchange after it. Key establishment is a handshake and two short
	// messages; a client that needs longer is not one.
	termHandshake = 10 * time.Second
	// termRead bounds one read while the request is still arriving, so a
	// client that sends a record at a time cannot hold a handshake slot.
	termRead = 2 * time.Second
)

// terminator is the terminating side of one kind: ntske listener.
type terminator struct {
	host proxy.Host
	cfg  config.Listener
	t    *config.NTSKETerminate
	tc   *tls.Config
	keys *ke.CookieKeys
	// cookies is how many to issue per exchange.
	cookies int
	// rotate is the interval between cookie keys, and state the file they
	// are kept in.
	rotate time.Duration
	state  string
	// rotations counts the key rotations this listener has done, for the
	// test that has to wait for one.
	rotations atomic.Uint64
}

func newTerminator(host proxy.Host, cfg config.Listener, tc *tls.Config) (*terminator, error) {
	t := cfg.NTSKE.Terminate
	if tc == nil {
		// Validation refuses this configuration, so reaching it means the
		// engine handed a terminating listener no TLS -- which would otherwise
		// be a listener that accepted connections and could answer none.
		return nil, errors.New("ntske: terminating key establishment needs a tls section")
	}
	keys, err := ke.NewCookieKeys(t.History())
	if err != nil {
		return nil, err
	}
	term := &terminator{host: host, cfg: cfg, t: t, keys: keys,
		cookies: t.CookieCount(), rotate: t.Rotation(), state: t.State}
	if term.state != "" {
		if err := keys.Load(term.state); err != nil {
			if errors.Is(err, ke.ErrState) {
				// A state file that is there and wrong is worth refusing to
				// start over: carrying on with fresh keys would do the thing
				// the file exists to prevent, quietly, and an operator who
				// moved a file would never find out.
				return nil, fmt.Errorf("ntske: the cookie key state %s: %w", term.state, err)
			}
			// Not there is a first start. The fresh set is written at once
			// rather than at the first rotation: a restart before then would
			// otherwise lose keys that had already sealed cookies, which is
			// the failure this file exists to prevent and the one an operator
			// would meet during the first day.
			host.Logs().Error.Info("ntske starting with fresh cookie keys",
				"listener", cfg.Name, "state", term.state)
			term.save()
		}
	}
	// The ALPN is not negotiable on this port: a connection that does not offer
	// it is not an NTS client, and the handshake fails rather than succeeding
	// into a protocol neither side named.
	//
	// A client certificate, where an estate wants one, is the listener's own
	// tls.client_auth and tls.client_ca_file, as it is everywhere else: NTS-KE
	// authenticates the server to the client and says nothing about the client,
	// so a certificate is the only thing that can name who is calling -- and it
	// is configured where every other listener's is rather than a second time
	// here.
	term.tc = tc.Clone()
	term.tc.NextProtos = []string{wireALPN}
	return term, nil
}

// wireALPN is the application protocol of RFC 8915.
const wireALPN = "ntske/1"

// CookieKeys implements proxy.NTSKeyHolder, which is how the time listener
// beside this one opens the cookies this one issues.
func (s *server) NTSCookieKeys() *ke.CookieKeys {
	if s.term == nil {
		return nil
	}
	return s.term.keys
}

// rotateLoop makes a new cookie key on the interval and saves the set.
//
// It runs from the listener's own goroutine rather than a timer inside the key
// set, because rotating is also saving: a key that became current without being
// written down is a key a restart would lose, and the cookies sealed under it
// would be refused by the process that comes back.
func (t *terminator) rotateLoop(done <-chan struct{}) {
	defer safe.Guard("ntske cookie key rotation")
	tick := time.NewTicker(t.rotate)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			if err := t.keys.Rotate(); err != nil {
				t.host.Logs().Error.Warn("ntske could not rotate the cookie key",
					"listener", t.cfg.Name, "error", err.Error())
				continue
			}
			t.save()
			t.rotations.Add(1)
		}
	}
}

func (t *terminator) save() {
	if t.state == "" {
		return
	}
	if err := t.keys.Save(t.state); err != nil {
		// Worth an operator's attention: the keys are fine now and will be
		// gone at the next restart.
		t.host.Logs().Error.Warn("ntske could not write the cookie keys",
			"listener", t.cfg.Name, "state", t.state, "error", err.Error())
	}
}

// exchange answers one connection. It returns the reason it refused, or "".
func (t *terminator) exchange(client net.Conn) (name string, protos []string, reason string) {
	c := t.host.Counters()
	hard := time.Now().Add(termHandshake)
	if d := t.cfg.NTSKE.HandshakeTimeout.D(); d > 0 {
		hard = time.Now().Add(d)
	}
	conn := tls.Server(client, t.tc)
	defer t.host.Fingerprints().Delete(client.RemoteAddr().String())
	ctx, cancel := context.WithDeadline(context.Background(), hard)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		// Every reason a handshake fails here is the same kind of fact: this
		// was not a client that could have been served. The detail is the
		// error, and the reason is one counter, because a port that reported a
		// different refusal for every TLS fault would be a port an attacker
		// could enumerate the configuration through.
		return "", nil, "handshake_failed"
	}
	st := conn.ConnectionState()
	name, protos = st.ServerName, []string{}
	if st.NegotiatedProtocol != "" {
		protos = []string{st.NegotiatedProtocol}
	}
	if st.NegotiatedProtocol != wireALPN {
		// With RequireALPN the handshake would already have failed; without it
		// a client can get this far having named nothing, and it is still not
		// an NTS client.
		c.NTSKENotNTS.Add(1)
		return name, protos, "alpn_not_offered"
	}
	req, err := t.readRequest(conn, hard)
	if err != nil {
		if !errors.Is(err, errNoRequest) {
			// A client that said nothing gets no answer. There is nothing to
			// report a fault in, and an error record sent to a connection that
			// has already stopped talking is a reply to nobody.
			_ = t.write(conn, ke.ErrorMessage(errorCodeFor(err)), hard)
		}
		return name, protos, refusalFor(err)
	}
	proto, aead, ok := ke.Negotiate(req)
	if !ok {
		c.NTSKENoTerms.Add(1)
		_ = t.write(conn, ke.NoTermsMessage(), hard)
		return name, protos, "no_terms"
	}
	keys, err := ke.DeriveFromTLS(conn, proto, aead)
	if err != nil {
		// The exporter is the whole basis of NTS. A failure here is this
		// relay's, not the client's, so it is an internal error rather than a
		// bad request -- and it is logged, because it should never happen.
		t.host.Logs().Error.Warn("ntske could not derive the NTS keys",
			"listener", t.cfg.Name, "error", err.Error())
		_ = t.write(conn, ke.ErrorMessage(ke.ErrInternalServer), hard)
		return name, protos, "derivation_failed"
	}
	resp := &ke.Response{NextProtocol: proto, AEAD: aead}
	for i := 0; i < t.cookies; i++ {
		cookie, err := t.keys.Seal(aead, keys)
		if err != nil {
			t.host.Logs().Error.Warn("ntske could not seal a cookie",
				"listener", t.cfg.Name, "error", err.Error())
			_ = t.write(conn, ke.ErrorMessage(ke.ErrInternalServer), hard)
			return name, protos, "cookie_failed"
		}
		resp.Cookies = append(resp.Cookies, cookie)
	}
	// Where to spend them. Said only when it is somewhere other than here,
	// because a record repeating the address the client already used is a
	// record the client has to compare rather than ignore.
	resp.Server = t.t.Server
	if t.t.Port != 0 {
		resp.Port, resp.HasPort = uint16(t.t.Port), true //nolint:gosec // validated 1..65535
	}
	if err := t.write(conn, resp.AppendTo(nil), hard); err != nil {
		return name, protos, "write_failed"
	}
	c.NTSKETerminated.Add(1)
	c.NTSKECookies.Add(uint64(len(resp.Cookies))) //nolint:gosec // bounded by cookies
	// Closed rather than kept: an exchange is one request and one answer, and a
	// connection held open afterwards is a handshake slot nobody is using.
	_ = conn.Close()
	return name, protos, ""
}

// readRequest reads one whole key establishment message.
//
// A message with no End of Message record is not a short message to answer as
// far as it goes: the client may still be writing, and a server that answered
// half a negotiation would be agreeing to terms nobody finished proposing. So
// the loop reads until the message parses, the bound is reached, or the
// deadline passes.
func (t *terminator) readRequest(conn *tls.Conn, hard time.Time) (*ke.Request, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for {
		deadline := time.Now().Add(termRead)
		if deadline.After(hard) {
			deadline = hard
		}
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			q, perr := ke.ParseRequest(buf)
			switch {
			case perr == nil:
				_ = conn.SetReadDeadline(time.Time{})
				return q, nil
			case errors.Is(perr, ke.ErrTruncated), errors.Is(perr, ke.ErrNoEnd):
				// Still arriving.
			default:
				return nil, perr
			}
		}
		if err != nil {
			if len(buf) == 0 {
				return nil, errNoRequest
			}
			return nil, fmt.Errorf("%w: %w", ke.ErrTruncated, err)
		}
	}
}

// errNoRequest is a client that completed the handshake and said nothing. It is
// its own case because it is the shape of a scanner rather than of a client
// with a bug.
var errNoRequest = errors.New("ntske: no request")

// errorCodeFor is the error record a refusal deserves. The distinction is RFC
// 8915's own: code 0 for a critical record the server did not recognise, code 1
// for a request it recognised and will not act on.
func errorCodeFor(err error) uint16 {
	if errors.Is(err, ke.ErrCritical) {
		return ke.ErrUnrecognisedCritical
	}
	return ke.ErrBadRequest
}

// refusalFor names a refusal for the counters and the log.
func refusalFor(err error) string {
	switch {
	case errors.Is(err, errNoRequest):
		return "no_request"
	case errors.Is(err, ke.ErrCritical):
		return "unknown_critical_record"
	case errors.Is(err, ke.ErrTooLong):
		return "request_too_large"
	case errors.Is(err, ke.ErrTruncated), errors.Is(err, ke.ErrNoEnd):
		return "incomplete_request"
	}
	return "bad_request"
}

// write sends one message, whole, within the exchange's deadline.
func (t *terminator) write(conn *tls.Conn, msg []byte, hard time.Time) error {
	_ = conn.SetWriteDeadline(hard)
	_, err := conn.Write(msg)
	return err
}

// terminating says whether a name is one this listener will answer for, which
// is the same list the relaying side applies -- with one difference that
// matters: here the name was authenticated by the certificate the client
// verified, rather than read out of a ClientHello anybody could have written.
func (s *server) terminatingNameAllowed(name string) bool {
	return s.nameAllowed(strings.ToLower(name))
}
