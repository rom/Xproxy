// Package ldap is a minimal LDAP v3 client for authenticating users against
// a directory (OpenLDAP, Active Directory): connect, simple bind and search.
// It implements only the subset of RFC 4511 the ldap_auth filter needs and
// hand-rolls the BER encoding (see ber.go) rather than pulling in a
// dependency. It is not a general-purpose LDAP library.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// Search scopes (RFC 4511 §4.5.1.2).
const (
	ScopeBase = 0
	ScopeOne  = 1
	ScopeSub  = 2
)

// Application tags for the operations this client uses.
const (
	appBindRequest       = 0
	appBindResponse      = 1
	appSearchRequest     = 3
	appSearchResultEntry = 4
	appSearchResultDone  = 5
	appExtendedRequest   = 23
	appExtendedResponse  = 24
)

const startTLSOID = "1.3.6.1.4.1.1466.20037"

// resultSuccess is the LDAP result code for a successful operation.
const resultSuccess = 0

// ErrInvalidCredentials is returned by Bind when the directory rejects the
// DN and password (result code 49).
var ErrInvalidCredentials = errors.New("ldap: invalid credentials")

// Options configure a dial.
type Options struct {
	// URL is ldap://host:port or ldaps://host:port.
	URL string
	// StartTLS upgrades an ldap:// connection to TLS before binding.
	StartTLS bool
	// TLS is the client TLS configuration for ldaps:// and StartTLS.
	TLS *tls.Config
	// Timeout bounds the dial and each request. Default 5s.
	Timeout time.Duration
}

// Conn is a single LDAP connection. It is not safe for concurrent use; the
// filter dials one connection per authentication.
type Conn struct {
	c       net.Conn
	msgID   int
	timeout time.Duration
}

// Entry is one search result.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Dial connects and, for ldaps or StartTLS, completes the TLS handshake.
func Dial(o Options) (*Conn, error) {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	host := u.Host
	tlsCfg := o.TLS
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tlsCfg.ServerName == "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = h
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := &net.Dialer{Timeout: timeout}
	switch u.Scheme {
	case "ldaps":
		raw, err := d.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return &Conn{c: tc, timeout: timeout}, nil
	case "ldap":
		raw, err := d.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		conn := &Conn{c: raw, timeout: timeout}
		if o.StartTLS {
			if err := conn.startTLS(ctx, tlsCfg); err != nil {
				_ = raw.Close()
				return nil, err
			}
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("ldap: unsupported scheme %q", u.Scheme)
	}
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

func (c *Conn) nextID() int { c.msgID++; return c.msgID }

// message wraps a protocol op in an LDAPMessage with the next message ID.
func (c *Conn) message(op *packet) *packet {
	return node(classUniversal, tagSequence, integer(c.nextID()), op)
}

// roundTrip writes an LDAPMessage and reads the reply message, returning the
// protocol op (the second child of the reply).
func (c *Conn) roundTrip(op *packet) (*packet, error) {
	msg := c.message(op)
	_ = c.c.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.c.Write(msg.encode(nil)); err != nil {
		return nil, err
	}
	_ = c.c.SetReadDeadline(time.Now().Add(c.timeout))
	reply, err := readTLV(c.c)
	if err != nil {
		return nil, err
	}
	pkt, _, err := parse(reply)
	if err != nil {
		return nil, err
	}
	if len(pkt.kids) < 2 {
		return nil, errors.New("ldap: malformed reply")
	}
	return pkt.kids[1], nil
}

// Bind performs a simple bind. An empty password is rejected up front so an
// unauthenticated bind can never pass as a valid login (RFC 4513 §5.1.2).
func (c *Conn) Bind(dn, password string) error {
	if password == "" {
		return ErrInvalidCredentials
	}
	op := node(classApplication, appBindRequest,
		integer(3), // LDAP version
		str(dn),
		leaf(classContext, 0, []byte(password)), // simple authentication
	)
	resp, err := c.roundTrip(op)
	if err != nil {
		return err
	}
	if resp.class != classApplication || resp.tag != appBindResponse {
		return errors.New("ldap: unexpected bind response")
	}
	code, err := resultCode(resp)
	if err != nil {
		return err
	}
	switch code {
	case resultSuccess:
		return nil
	case 49:
		return ErrInvalidCredentials
	default:
		return fmt.Errorf("ldap: bind failed, result code %d", code)
	}
}

// Search runs a search and returns the entries. filter is a parsed filter
// (see ParseFilter). attrs limits the attributes returned; empty returns
// all user attributes.
func (c *Conn) Search(baseDN string, scope int, filter *packet, attrs []string, sizeLimit int) ([]Entry, error) {
	attrSeq := node(classUniversal, tagSequence)
	for _, a := range attrs {
		attrSeq.add(str(a))
	}
	op := node(classApplication, appSearchRequest,
		str(baseDN),
		enumerated(scope),
		enumerated(0), // derefAliases: never
		integer(sizeLimit),
		integer(int(c.timeout/time.Second)),
		boolean(false), // typesOnly
		filter,
		attrSeq,
	)
	msg := c.message(op)
	_ = c.c.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.c.Write(msg.encode(nil)); err != nil {
		return nil, err
	}
	var entries []Entry
	for {
		_ = c.c.SetReadDeadline(time.Now().Add(c.timeout))
		raw, err := readTLV(c.c)
		if err != nil {
			return nil, err
		}
		pkt, _, err := parse(raw)
		if err != nil {
			return nil, err
		}
		if len(pkt.kids) < 2 {
			return nil, errors.New("ldap: malformed search reply")
		}
		body := pkt.kids[1]
		switch {
		case body.class == classApplication && body.tag == appSearchResultEntry:
			e, err := parseEntry(body)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
			if sizeLimit > 0 && len(entries) > sizeLimit {
				// Abandoning a search mid-stream leaves the server's remaining
				// messages unread; close the connection so it cannot be
				// reused out of step.
				_ = c.c.Close()
				return nil, errors.New("ldap: server exceeded size limit")
			}
		case body.class == classApplication && body.tag == appSearchResultDone:
			code, err := resultCode(body)
			if err != nil {
				return nil, err
			}
			if code != resultSuccess && code != 4 { // 4 = sizeLimitExceeded, entries still valid
				return nil, fmt.Errorf("ldap: search failed, result code %d", code)
			}
			return entries, nil
		default:
			// Ignore other messages (e.g. search result references).
		}
	}
}

// startTLS sends the StartTLS extended operation and, on success, upgrades
// the connection to TLS.
func (c *Conn) startTLS(ctx context.Context, tlsCfg *tls.Config) error {
	op := node(classApplication, appExtendedRequest,
		leaf(classContext, 0, []byte(startTLSOID)),
	)
	resp, err := c.roundTrip(op)
	if err != nil {
		return err
	}
	if resp.class != classApplication || resp.tag != appExtendedResponse {
		return errors.New("ldap: unexpected StartTLS response")
	}
	code, err := resultCode(resp)
	if err != nil {
		return err
	}
	if code != resultSuccess {
		return fmt.Errorf("ldap: StartTLS refused, result code %d", code)
	}
	tc := tls.Client(c.c, tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	c.c = tc
	return nil
}

// resultCode reads the resultCode (first child) of an LDAPResult op.
func resultCode(op *packet) (int, error) {
	if len(op.kids) == 0 {
		return 0, errors.New("ldap: result without a code")
	}
	return op.kids[0].intValue()
}

// parseEntry reads a SearchResultEntry into an Entry.
func parseEntry(op *packet) (Entry, error) {
	if len(op.kids) < 2 {
		return Entry{}, errors.New("ldap: malformed entry")
	}
	e := Entry{DN: string(op.kids[0].data), Attrs: map[string][]string{}}
	for _, attr := range op.kids[1].kids {
		if len(attr.kids) < 2 {
			continue
		}
		name := string(attr.kids[0].data)
		for _, v := range attr.kids[1].kids {
			e.Attrs[name] = append(e.Attrs[name], string(v.data))
		}
	}
	return e, nil
}

// readTLV reads exactly one BER TLV from r and returns its raw bytes.
func readTLV(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	out := hdr
	first := hdr[1]
	var length int
	if first < 0x80 {
		length = int(first)
	} else {
		count := int(first & 0x7f)
		if count == 0 || count > 4 {
			return nil, errors.New("ldap: bad length prefix")
		}
		lb := make([]byte, count)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		for _, b := range lb {
			length = length<<8 | int(b)
		}
		out = append(out, lb...)
	}
	if length < 0 || length > 8<<20 {
		return nil, fmt.Errorf("ldap: message length %d out of range", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(out, body...), nil
}
