package ntske

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Establishing keys as a client.
//
// This relay is a client as well as a server. Terminating a client's NTS means
// the time source can be a plain NTP server -- but where the source does speak
// NTS, the relay should be speaking it too, and that means holding an
// association of its own: its own key establishment, its own cookies, its own
// authenticator on every request, and verification of every answer.
//
// The alternative would be to forward the client's own NTS toward a source that
// shares no keys with it, which cannot work, or to ask the source in plain NTP
// and tell the client its time was authenticated end to end, which would be a
// lie. So the relay is a party to the security in both directions, and the
// configuration says so.

// ALPN is the application protocol RFC 8915 assigns to key establishment. A
// server that does not negotiate it is not a key establishment server, whatever
// else is listening on the port.
const ALPN = "ntske/1"

// DefaultPort is the key establishment port.
const DefaultPort = "4460"

// Client establishes keys with a key establishment server.
type Client struct {
	// Address is the server, host:port. A bare host takes DefaultPort.
	Address string
	// TLS is the client configuration: the roots that may have issued the
	// server's certificate, the name to verify, and a client certificate where
	// the server asks for one. The application protocol and the minimum
	// version are set here rather than taken from it, because both are the
	// standard's requirements rather than the caller's choice.
	TLS *tls.Config
	// Timeout bounds the whole exchange: the dial, the handshake and the two
	// messages. Zero takes DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout bounds a key establishment. It is a TLS handshake and two
// short messages; a server that needs longer is a server this relay should be
// reporting rather than waiting for.
const DefaultTimeout = 10 * time.Second

// Established is what an exchange produced.
type Established struct {
	Keys    *Keys
	AEAD    uint16
	Cookies [][]byte
	// Server and Port are what the server said about where to spend the
	// cookies, when it said anything. They are reported rather than acted on:
	// where a relay sends time traffic is the estate's decision, and a record
	// from a key establishment server is not a licence to move it.
	Server  string
	Port    uint16
	HasPort bool
	// At is when the exchange finished, so a caller can tell a set of cookies
	// that is merely old from one that is exhausted.
	At time.Time
}

// ErrALPN is a server that did not negotiate the key establishment protocol.
var ErrALPN = errors.New("ntske: the server did not negotiate ntske/1")

// Establish does one whole key establishment.
func (c *Client) Establish(ctx context.Context) (*Established, error) {
	if c.Address == "" {
		return nil, errors.New("ntske: no key establishment address")
	}
	addr := c.Address
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host, addr = addr, net.JoinHostPort(addr, DefaultPort)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cfg := &tls.Config{MinVersion: tls.VersionTLS13} //nolint:gosec // set from the caller's below
	if c.TLS != nil {
		cfg = c.TLS.Clone()
	}
	// RFC 8915 s3 requires TLS 1.3, and the application protocol is what
	// identifies the exchange. Neither is the caller's to lower.
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{ALPN}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}

	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ntske: establishing keys with %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("ntske: the dialer did not return a TLS connection")
	}
	if deadline, has := ctx.Deadline(); has {
		_ = tc.SetDeadline(deadline)
	}
	if tc.ConnectionState().NegotiatedProtocol != ALPN {
		return nil, ErrALPN
	}
	if _, err := tc.Write(ClientRequest().AppendTo(nil)); err != nil {
		return nil, fmt.Errorf("ntske: sending the request: %w", err)
	}
	resp, err := readResponse(tc)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveFromTLS(tc, resp.NextProtocol, resp.AEAD)
	if err != nil {
		return nil, err
	}
	return &Established{Keys: keys, AEAD: resp.AEAD, Cookies: resp.Cookies,
		Server: resp.Server, Port: resp.Port, HasPort: resp.HasPort, At: time.Now()}, nil
}

// readResponse reads one whole message.
//
// A message with no End of Message record is not a response to act on as far as
// it goes: the server may still be writing, and a client that took half a
// negotiation would be spending cookies under terms nobody finished agreeing.
func readResponse(conn *tls.Conn) (*Response, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for {
		n, rerr := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			resp, perr := ParseResponse(buf)
			switch {
			case perr == nil:
				return resp, nil
			case errors.Is(perr, ErrTruncated), errors.Is(perr, ErrNoEnd):
				// Still arriving.
			default:
				return nil, perr
			}
		}
		if rerr != nil {
			if len(buf) == 0 {
				return nil, errors.New("ntske: the server answered nothing")
			}
			return nil, fmt.Errorf("%w: %w", ErrTruncated, rerr)
		}
	}
}
