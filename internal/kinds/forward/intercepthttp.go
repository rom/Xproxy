package forward

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/relay"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/textsafe"
)

// HTTP inside an intercepted tunnel.
//
// The egress rules can name a method, a path, a content type and a body size.
// Inside a CONNECT tunnel none of those were visible, so those rules decided
// nothing there -- and on an estate whose egress is almost entirely HTTPS, that
// meant they decided nothing at all. The listener said so, in validation and in
// its own documentation, which is better than pretending otherwise and still not
// a policy.
//
// This is the other half. Where the tunnel is already being decrypted, the
// requests in it are ordinary HTTP messages: they are read, each one is decided
// about, and each one is relayed. The same rules, the same phases, the same
// counters and events as a plain request through the proxy -- because it is the
// same policy, and an operator should not have to learn that a rule means one
// thing on port 80 and another on port 443.
//
// # What is read, and what is not
//
// HTTP/1.1, which is what `intercept.alpn` offers by default. Three things are
// relayed as bytes instead, and each is counted so that "nothing was read" is
// never a silent answer:
//
//   - a tunnel that negotiated h2, because this reads HTTP/1 and a proxy that
//     guessed at HTTP/2 framing would corrupt the stream;
//   - a tunnel whose first bytes are not a request line, because a database or
//     an SSH session inside TLS is a thing that happens and answering it with a
//     400 would break it for no reason;
//   - everything after a 101, because the connection has stopped being
//     request-and-response. What those messages carry is the WebSocket guard's
//     question rather than this one.
//
// # What a refusal looks like from inside
//
// The client believes it has an end-to-end connection to the destination, so a
// refusal is an HTTP response on that connection: 403 with the reason, and then
// the connection closes. It closes rather than carrying on because keeping it
// alive would mean reading the rest of a request body nobody is allowed to send,
// which is a bound an attacker chooses.
//
// The requests are relayed as they arrived. Nothing is added -- no Via, no
// forwarded headers -- because the point of this listener's interception is that
// the destination sees what the client sent, and a header the client did not
// write is a change to the message it is being judged on. What the parse does
// normalise is framing: a request with both a length and a chunked encoding is
// refused by the reader rather than passed on, which is the request-smuggling
// shape, and reading it here is the only place this listener could ever have
// caught it.

// firstLineWait bounds how long a tunnel with no ALPN is given to say whether
// firstLineWait bounds how long a tunnel with no ALPN is given to say whether
// it is HTTP. It is short because the cost is paid by the other case: a service
// that speaks before its client -- SMTP, a database greeting -- sends nothing
// until this gives up, so this is added latency on those connections and nothing
// else. A destination that negotiated http/1.1 is never waited on at all.
const firstLineWait = time.Second

// maxRequestLine bounds the line this reads before deciding. A request line
// longer than this is not one worth reading.
const maxRequestLine = 8 << 10

// alpnOf is what a TLS connection negotiated, or "" for anything else.
func alpnOf(c net.Conn) string {
	if tc, ok := netutil.TLSConn(c); ok {
		return tc.ConnectionState().NegotiatedProtocol
	}
	return ""
}

// looksLikeHTTP1 reports whether the first line the client sends is an HTTP/1
// request line, without consuming it.
//
// The check is the version at the end of the line rather than a list of known
// methods: WebDAV, CalDAV and half a dozen other extensions have methods of
// their own, and a proxy that answered 400 to PROPFIND because it had never
// heard of it would be breaking a site to no purpose. What is not an HTTP/1
// request line is relayed as bytes, which is what a database or an SSH session
// inside TLS needs.
//
// What is already buffered is examined before anything more is asked for. A
// client sends its first line in one write, so the whole line arrives in one
// record and asking for a byte past it waits out the deadline for a byte that
// is not coming until this has answered -- a second of latency on every
// intercepted connection, which is the sort of cost that is only ever found by
// looking at how long a test took.
func looksLikeHTTP1(cr *bufio.Reader, client net.Conn, wait time.Duration) bool {
	_ = client.SetReadDeadline(time.Now().Add(wait))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	seen := 0
	for {
		b, err := cr.Peek(max(cr.Buffered(), seen+1))
		if i := bytes.IndexByte(b[min(seen, len(b)):], '\n'); i >= 0 {
			return isRequestLine(b[:min(seen, len(b))+i])
		}
		seen = len(b)
		if err != nil || seen >= maxRequestLine {
			return false
		}
	}
}

// isRequestLine is the shape of an HTTP/1 request line: whatever method and
// target, and then the version this reads.
func isRequestLine(line []byte) bool {
	s := strings.TrimSuffix(string(line), "\r")
	return strings.HasSuffix(s, " HTTP/1.1") || strings.HasSuffix(s, " HTTP/1.0")
}

// maxTunnelHead bounds one request or response head inside a tunnel. The reader
// is sized to it, so a head that will not fit fails to parse rather than growing
// until something else does.
const maxTunnelHead = 64 << 10

// maxTunnelRequests bounds how many requests one tunnel may carry. A keep-alive
// connection is meant to carry many, and "many" still has to be a number: this
// is the one bound that a client both controls and does not pay for, because a
// request can be a hundred bytes.
const maxTunnelRequests = 10000

// errYARAMatch ends a read when a stream rule asks for the connection to close.
var errYARAMatch = errors.New("forward: a stream rule matched")

// wantsHTTP decides whether a tunnel's plaintext is read as HTTP.
//
// auto is the default and means "when there is something to decide": a listener
// whose rules all name destinations gains nothing from parsing, and an existing
// deployment should not change behaviour because a version did.
func (f *forwardServer) wantsHTTP(p *forwardPolicy, alpn string) bool {
	if f.mitm == nil {
		return false
	}
	switch f.mitm.cfg.HTTP {
	case "off":
		return false
	case "on":
	default: // auto
		if p.egress == nil || p.egress.requestOnly == 0 {
			return false
		}
	}
	// h2 is read by nothing here. The default alpn offers only http/1.1, so
	// this is the case where an operator asked for h2 as well.
	return alpn == "" || alpn == "http/1.1"
}

// httpTunnel is one intercepted connection read as HTTP: both of its sides,
// the policy that decides about it, and who opened it to where.
type httpTunnel struct {
	f                *forwardServer
	client, upstream net.Conn
	cr, ur           *bufio.Reader
	p                *forwardPolicy
	in               *interceptor
	ip               netip.Addr
	user, host       string
	port             int
	idle             time.Duration
	// hit says a stream rule asked for this connection to end. It is a flag and
	// not only the error the read returns, because that error does not reliably
	// arrive: a bufio.Reader hands a stored read error to whoever asks next, and
	// the header parser asks past the end of what it needs and ignores what it
	// gets. The flag is checked before anything is relayed, so a match in a head
	// stops the request there -- which is what the same rule did when this
	// tunnel was bytes.
	hit atomic.Bool
}

// serveInterceptedHTTP reads the requests inside one intercepted tunnel.
//
// client and upstream are both already TLS. It returns the bytes each way and a
// reason where the tunnel ended in one.
func (f *forwardServer) serveInterceptedHTTP(client, upstream net.Conn, p *forwardPolicy,
	in *interceptor, ip netip.Addr, user, host string, port int) (int64, int64, string) {
	// A tunnel that has ended is closed here. The byte relay closed both sides
	// itself, so nothing above this did: without it a connection the policy cut
	// stayed open until its deadline, which is a client waiting for an answer
	// that is never coming.
	defer func() {
		_ = client.Close()
		_ = upstream.Close()
	}()
	t := &httpTunnel{f: f, client: client, upstream: upstream, p: p, in: in,
		ip: ip, user: user, host: host, port: port, idle: p.cfg.IdleTimeout.D()}
	var scanned, back *streamscan.Stream
	if in.yara != nil {
		scanned = in.yara.Stream("client")
		back = in.yara.Stream("upstream")
	}
	// The scanning sits on the reads, so a stream rule sees exactly the bytes
	// it saw when this relayed them without reading: the heads as well as the
	// bodies, in both directions.
	t.cr = bufio.NewReaderSize(&scanConn{Conn: client, s: scanned, t: t}, maxTunnelHead)
	t.ur = bufio.NewReaderSize(&scanConn{Conn: upstream, s: back, t: t}, maxTunnelHead)
	return t.run()
}

// run reads one tunnel's requests until it ends.
func (t *httpTunnel) run() (int64, int64, string) {
	// Whether this really is HTTP. The destination's ALPN is the answer where
	// there is one -- a site that negotiated http/1.1 has said so -- and where
	// there is none the client's first line is read instead, bounded, because
	// a service that speaks first would otherwise be waited on for nothing.
	if alpn := alpnOf(t.client); alpn != "http/1.1" && !looksLikeHTTP1(t.cr, t.client, firstLineWait) {
		t.f.host.Counters().InterceptBytesOnly.Add(1)
		i, o := t.spliceBoth()
		return i, o, t.endReason("")
	}
	var inBytes, outBytes int64
	for n := 0; ; n++ {
		if n >= maxTunnelRequests {
			return inBytes, outBytes, "tunnel_requests"
		}
		_ = t.client.SetDeadline(time.Now().Add(t.idle))
		req, err := http.ReadRequest(t.cr)
		if t.hit.Load() {
			return inBytes, outBytes, "yara"
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return inBytes, outBytes, ""
			}
			// A head this could not read is not relayed. It is the smuggling
			// shape as often as it is a broken client, and either way the
			// destination should not be the one to decide.
			t.f.host.Counters().Refuse("forward", "bad_request")
			if t.f.alerts() {
				t.f.host.Logs().SecurityEvent(context.Background(), "deny", "forward_tunnel_bad_request",
					"listener", t.f.name, "client_ip", t.ip.String(), "dest", t.host,
					"err", textsafe.Clip256(err.Error()))
			}
			_ = writeTunnelStatus(t.client, http.StatusBadRequest, "bad_request")
			return inBytes, outBytes, "bad_request"
		}
		res := t.one(req)
		inBytes += res.in
		outBytes += res.out
		if res.upgraded {
			// Past a 101 this is not HTTP any more. What is left is relayed,
			// with whatever either reader has already buffered going first.
			i, o := t.spliceBoth()
			return inBytes + i, outBytes + o, t.endReason(res.reason)
		}
		if !res.keepAlive {
			return inBytes, outBytes, t.endReason(res.reason)
		}
	}
}

// endReason is why a tunnel ended, with a stream match taking precedence: a
// relay that stopped because a rule matched ended in that rule and not in the
// quiet end of a connection.
func (t *httpTunnel) endReason(reason string) string {
	if reason == "" && t.hit.Load() {
		return "yara"
	}
	return reason
}

// exchange is what one request and its response did.
type exchange struct {
	in, out   int64
	keepAlive bool
	upgraded  bool
	reason    string
}

// one decides about one request, relays it, decides about the response, and
// relays that.
func (t *httpTunnel) one(req *http.Request) exchange {
	defer func() { _ = req.Body.Close() }()
	f := t.f
	f.host.Counters().InterceptRequests.Add(1)

	// The Host a request names has to be the host the tunnel was opened to.
	// Otherwise a client permitted to reach one name uses the connection to
	// that name's address to ask for another, which is the SNI check's question
	// one layer up and gets the same answer.
	if reason := f.tunnelHostGuard(t.p.cfg.SNI, req, t.ip, t.host); reason != "" {
		_ = writeTunnelStatus(t.client, http.StatusForbidden, reason)
		return exchange{reason: reason}
	}

	rf := &requestFacts{method: req.Method, path: req.URL.Path,
		contentType: req.Header.Get("Content-Type"), bytes: req.ContentLength}
	host := hostOnly(t.host)
	if t.p.egress != nil {
		sub := egressSubject{client: t.ip, user: t.user, host: host, port: t.port,
			at: time.Now(), phase: phaseRequest, method: rf.method, path: rf.path,
			reqType: rf.contentType, reqBytes: rf.bytes}
		d := t.p.egress.Decide(sub)
		f.recordEgress(t.ip, t.user, host, t.port, d)
		if !d.Allowed && !f.shadowed(d.Reason, egressDetail(d, host, t.port)) {
			f.host.Counters().Refuse("forward", d.Reason)
			t.deny(req, d.Reason)
			return exchange{reason: d.Reason}
		}
		// A body nobody declared the length of is counted as it goes past.
		if req.ContentLength < 0 && req.Body != nil {
			if bound, _, _ := t.p.egress.BodyBound(sub); bound > 0 {
				req.Body = &boundedBody{ReadCloser: req.Body, left: bound}
			}
		}
	}

	_ = t.upstream.SetDeadline(time.Now().Add(t.idle))
	if err := req.Write(t.upstream); err != nil {
		switch {
		case t.hit.Load():
			return exchange{reason: "yara"}
		case errors.Is(err, errBodyTooLarge):
			f.host.Counters().Refuse("forward", "rule_deny")
			if f.alerts() {
				f.host.Logs().SecurityEvent(context.Background(), "deny", "forward_egress_denied",
					"listener", f.name, "client_ip", t.ip.String(), "user", textsafe.Clip64(t.user),
					"destination", t.host, "detail", "undeclared body over the bound")
			}
			_ = writeTunnelStatus(t.client, http.StatusForbidden, "rule_deny")
			return exchange{reason: "rule_deny"}
		}
		return exchange{reason: "upstream"}
	}

	resp, ex := t.response(req)
	if resp == nil {
		return ex
	}
	defer func() { _ = resp.Body.Close() }()

	if t.p.egress != nil {
		sub := egressSubject{client: t.ip, user: t.user, host: host, port: t.port,
			at: time.Now(), phase: phaseResponse, method: rf.method, path: rf.path,
			reqType: rf.contentType, reqBytes: rf.bytes,
			respType: resp.Header.Get("Content-Type"), respBytes: resp.ContentLength}
		d := t.p.egress.Decide(sub)
		f.recordEgress(t.ip, t.user, host, t.port, d)
		if !d.Allowed && !f.shadowed(d.Reason, egressDetail(d, host, t.port)) {
			// Nothing of the response has been written yet, so the client gets
			// the refusal instead of the body. The destination was contacted --
			// that cannot be undone and the documentation says so.
			f.host.Counters().Refuse("forward", d.Reason)
			t.deny(req, d.Reason)
			return exchange{reason: d.Reason}
		}
		if resp.ContentLength < 0 && resp.Body != nil {
			if bound, rule, comment := t.p.egress.BodyBound(sub); bound > 0 {
				resp.Body = &countedBody{ReadCloser: resp.Body, left: bound,
					onOver: func() {
						f.host.Counters().Refuse("forward", "rule_deny")
						if !f.alerts() {
							return
						}
						f.host.Logs().SecurityEvent(context.Background(), "deny",
							"forward_egress_denied", "listener", f.name,
							"client_ip", t.ip.String(), "user", textsafe.Clip64(t.user),
							"destination", t.host, "rule", textsafe.Clip64(rule),
							"comment", textsafe.Clip256(comment),
							"detail", "undeclared response body over the bound")
					}}
			}
		}
	}

	_ = t.client.SetDeadline(time.Now().Add(t.idle))
	if err := resp.Write(t.client); err != nil {
		return exchange{reason: "client"}
	}
	f.logTunnelRequest(req, resp, t.ip, t.user, t.host)
	ex = exchange{in: req.ContentLength, out: resp.ContentLength}
	if ex.in < 0 {
		ex.in = 0
	}
	if ex.out < 0 {
		ex.out = 0
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		ex.upgraded = true
		return ex
	}
	ex.keepAlive = !req.Close && !resp.Close && req.ProtoAtLeast(1, 1)
	return ex
}

// response reads the destination's answer, relaying everything before the final
// response straight back: a 100 Continue is between the client and the
// destination, and holding it would stall an upload that was waiting for it.
//
// A nil response means the exchange is over and the reason says why.
func (t *httpTunnel) response(req *http.Request) (*http.Response, exchange) {
	for {
		_ = t.upstream.SetDeadline(time.Now().Add(t.idle))
		resp, err := http.ReadResponse(t.ur, req)
		if t.hit.Load() {
			return nil, exchange{reason: "yara"}
		}
		if err != nil {
			t.f.host.Counters().ForwardErrors.Add(1)
			_ = writeTunnelStatus(t.client, http.StatusBadGateway, "upstream")
			return nil, exchange{reason: "upstream"}
		}
		// 101 is below 200 and is not one of these. It is the end of the
		// conversation rather than a step in it: relaying it and reading again
		// waits for a response the connection has stopped being able to carry,
		// which is a hang rather than a slow site.
		if resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, exchange{}
		}
		if err := resp.Write(t.client); err != nil {
			return nil, exchange{reason: "client"}
		}
	}
}

// tunnelHostGuard answers the same question as sniGuard, about the Host header
// rather than the server name, and under the same setting: a tunnel opened to
// one name carrying a request for another is one name's permission being spent
// on a different host.
func (f *forwardServer) tunnelHostGuard(mode string, req *http.Request, ip netip.Addr, host string) string {
	if mode == "off" || req.Host == "" {
		return ""
	}
	if strings.EqualFold(hostOnly(req.Host), hostOnly(host)) {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(hostOnly(host), "[]")); err == nil {
		// The tunnel named an address, so the policy checked an address and the
		// bytes go there whatever the request says; the name only picks a
		// virtual host once they arrive.
		return ""
	}
	// actionFor makes this a refusal only where the mode enforces; observed, it
	// is an alert and the shadow ledger's, which alert_on_deny does not speak for.
	if mode != "enforce" || f.alerts() {
		f.host.Logs().SecurityEvent(context.Background(), actionFor(mode), "forward_tunnel_host_mismatch",
			"listener", f.name, "client_ip", ip.String(), "connect", textsafe.Clip256(host),
			"host", textsafe.Clip256(req.Host), "mode", mode)
	}
	if mode != "enforce" {
		f.host.Counters().WouldRefuse("forward", "host_mismatch")
		f.host.Shadow().Record("forward", f.name, "host_mismatch", "host", req.Host+" through "+host)
		return ""
	}
	f.host.Counters().Refuse("forward", "host_mismatch")
	if bl := f.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "forward_host_mismatch")
	}
	return "host_mismatch"
}

// deny answers one request with a refusal and counts it where every other
// refusal on this listener is counted.
func (t *httpTunnel) deny(req *http.Request, reason string) {
	f := t.f
	f.host.Counters().ForwardDenied.Add(1)
	if bl := f.host.Bans(); bl != nil {
		bl.Observe(t.ip, "forward_denied")
	}
	f.host.Logs().Access.Info("forward_intercept_request", "listener", f.name,
		"client_ip", t.ip.String(), "user", textsafe.Clip64(t.user), "method", req.Method,
		"destination", t.host, "status", http.StatusForbidden, "reason", reason)
	_ = writeTunnelStatus(t.client, http.StatusForbidden, reason)
}

// logTunnelRequest writes the access line for one request inside a tunnel.
//
// The method, the destination and the status, which is what the plain path logs
// as well. Not the path: this listener logs a destination rather than a URL
// everywhere else, and an intercepted connection is the last place to start
// writing down more of what somebody asked for than the rest of the proxy does.
func (f *forwardServer) logTunnelRequest(req *http.Request, resp *http.Response,
	ip netip.Addr, user, host string) {
	f.host.Logs().Access.Info("forward_intercept_request", "listener", f.name,
		"client_ip", ip.String(), "user", textsafe.Clip64(user), "method", req.Method,
		"destination", host, "status", resp.StatusCode)
}

// writeTunnelStatus answers inside the tunnel, in the one shape a client that
// believes it is talking to the destination can read.
func writeTunnelStatus(w io.Writer, status int, reason string) error {
	body := fmt.Sprintf("%d %s: %s\n", status, http.StatusText(status), reason)
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	return err
}

// spliceBoth relays what is left of a tunnel after it stopped being HTTP,
// sending each reader's buffered bytes on first.
func (t *httpTunnel) spliceBoth() (int64, int64) {
	var early, back int64
	if n := t.cr.Buffered(); n > 0 {
		b, _ := t.cr.Peek(n)
		if _, err := t.upstream.Write(b); err != nil {
			return 0, 0
		}
		_, _ = t.cr.Discard(n)
		early = int64(n)
	}
	if n := t.ur.Buffered(); n > 0 {
		b, _ := t.ur.Peek(n)
		if _, err := t.client.Write(b); err != nil {
			return early, 0
		}
		_, _ = t.ur.Discard(n)
		back = int64(n)
	}
	_ = t.client.SetDeadline(time.Time{})
	_ = t.upstream.SetDeadline(time.Time{})
	i, o := relay.Splice(t.client, t.upstream, t.idle)
	return i + early, o + back
}

// hostOnly drops a port from a host:port, leaving a bare name or address.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// portOf reads the port of a host:port, or returns the default.
func portOf(h string, def int) int {
	if _, port, err := net.SplitHostPort(h); err == nil {
		n := 0
		for _, r := range port {
			if r < '0' || r > '9' {
				return def
			}
			n = n*10 + int(r-'0')
		}
		if n > 0 && n <= 65535 {
			return n
		}
	}
	return def
}

// scanConn feeds what it reads to a stream rule set.
//
// It sits on the connection rather than on the bodies so that a rule sees the
// heads too, which is what it saw when this tunnel was relayed without being
// read -- turning on HTTP awareness must not quietly narrow what YARA covers.
type scanConn struct {
	net.Conn
	s *streamscan.Stream
	t *httpTunnel
}

func (c *scanConn) Read(p []byte) (int, error) {
	if c.t.hit.Load() {
		return 0, errYARAMatch
	}
	n, err := c.Conn.Read(p)
	if n > 0 && c.s != nil && c.s.Feed(p[:n]) &&
		c.t.f.yaraMatched(c.s, c.t.in, c.t.ip, c.t.host) {
		c.t.hit.Store(true)
		return n, errYARAMatch
	}
	return n, err
}

// countedBody counts a response body and says so once it passes a bound. The
// read then ends, so the rest of the body does not reach the client.
type countedBody struct {
	io.ReadCloser
	left   int64
	onOver func()
	over   bool
}

func (b *countedBody) Read(p []byte) (int, error) {
	if b.over {
		return 0, io.EOF
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		b.over = true
		if b.onOver != nil {
			b.onOver()
		}
		// The bytes already read have been written; what is cut is the rest.
		return n, io.EOF
	}
	return n, err
}
