package forward

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mitm"
	"github.com/rom/xproxy/internal/relay"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/tlsconf"
)

const (
	// recordHandshake is the TLS record type of a handshake message.
	recordHandshake = 22
	// maxHelloRecord is the largest TLS record, plus its header: what a
	// ClientHello can occupy, and therefore what has to be readable
	// before the handshake is answered.
	maxHelloRecord = 5 + 16384
)

// interceptor is the compiled intercept section of a forward listener.
type interceptor struct {
	ca      *mitm.CA
	cfg     *config.ForwardIntercept
	hosts   []destRule
	bypass  []destRule
	roots   *x509.CertPool
	minTLS  uint16
	alpn    []string
	verify  bool
	yara    *streamscan.Guard
	timeout time.Duration
}

func newInterceptor(c *config.ForwardIntercept, connectTimeout time.Duration) (*interceptor, error) {
	ca, err := mitm.Load(mitm.Options{
		CertFile: c.CACertFile, KeyFile: c.CAKeyFile,
		LeafTTL: c.LeafTTL.D(), MaxCache: c.MaxCache,
	})
	if err != nil {
		return nil, err
	}
	in := &interceptor{ca: ca, cfg: c, verify: c.VerifyUpstream == nil || *c.VerifyUpstream,
		alpn: c.ALPN, timeout: connectTimeout}
	if len(in.alpn) == 0 {
		in.alpn = []string{"http/1.1"}
	}
	if in.hosts, err = compileDestRules(c.Hosts); err != nil {
		return nil, fmt.Errorf("intercept hosts: %w", err)
	}
	if in.bypass, err = compileDestRules(c.BypassHosts); err != nil {
		return nil, fmt.Errorf("intercept bypass_hosts: %w", err)
	}
	in.minTLS = tls.VersionTLS12
	if c.MinVersion == "1.3" {
		in.minTLS = tls.VersionTLS13
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile) //nolint:gosec // a path from the configuration
		if err != nil {
			return nil, fmt.Errorf("intercept ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("intercept ca_file: no certificates")
		}
		in.roots = pool
	}
	if c.YARA != nil {
		g, err := streamscan.New(c.YARA)
		if err != nil {
			return nil, err
		}
		in.yara = g
	}
	return in, nil
}

// wants reports whether a destination is intercepted. The bypass list
// is checked first and wins: it is where the traffic an estate must not
// read is written, and a rule that can be overtaken by another rule is
// not that.
func (in *interceptor) wants(host string, ips []netip.Addr) bool {
	if in == nil {
		return false
	}
	if anyRule(in.bypass, host, ips) {
		return false
	}
	if len(in.hosts) == 0 {
		return true
	}
	return anyRule(in.hosts, host, ips)
}

// intercept terminates the client's TLS, opens its own to the
// destination, and relays what passes between them.
//
// The order is the security property: the destination is dialled and
// verified first, and only then is a certificate forged for it. A
// client therefore never sees a forged certificate for a server whose
// own certificate did not verify — it sees the handshake fail, which is
// what it would have seen without a proxy in the way.
func (f *forwardServer) intercept(client, dst net.Conn, host string, port int,
	p *forwardPolicy, ip netip.Addr, user string) (int64, int64, string) {
	in := f.mitm
	br, ok := readerOf(client)
	if !ok {
		br = bufio.NewReaderSize(client, maxHelloRecord)
	} else if br.Size() < maxHelloRecord {
		// The reader the CONNECT left behind is sized for a request
		// head. A ClientHello is bigger than that, and the name is in
		// its tail: reading only the first few bytes would leave the
		// name unread and the check that uses it dead.
		br = bufio.NewReaderSize(br, maxHelloRecord)
	}
	// The peek waits for bytes a client controls, so it is bounded: a
	// connection that opens a tunnel and then says nothing must not hold
	// a goroutine open for as long as it likes.
	_ = client.SetReadDeadline(time.Now().Add(in.timeout))
	peek, err := br.Peek(5)
	if err != nil && len(peek) == 0 {
		_ = client.SetReadDeadline(time.Time{})
		return 0, 0, "client_closed"
	}
	if len(peek) == 5 && peek[0] == recordHandshake {
		// Take the whole record, so the extensions are there to read.
		// A short read is not fatal: what arrived is parsed, and a hello
		// whose name could not be read is treated as one without a name.
		if full, perr := br.Peek(5 + int(binary.BigEndian.Uint16(peek[3:5]))); perr == nil || len(full) > len(peek) {
			peek = full
		}
	}
	_ = client.SetReadDeadline(time.Time{})
	name, isTLS := mitm.ClientHelloName(peek)
	if !isTLS {
		// A CONNECT tunnel does not have to carry TLS. Answering a
		// handshake to something that was speaking SSH or a database
		// protocol breaks it for no reason, so what cannot be read is
		// passed through as it is.
		f.host.Counters().InterceptPassed.Add(1)
		return f.spliceBuffered(br, client, dst, in.timeout)
	}
	if name == "" {
		name = host
	}
	// The name the client asked for has to be the destination it asked
	// for. A tunnel opened to one host and a handshake for another is
	// somebody using the proxy to reach a name the policy checked
	// against a different one.
	//
	// A tunnel opened to an address is the exception, and not a hole:
	// there the policy checked the address, the bytes go to that
	// address whatever the handshake says, and the name only picks a
	// virtual host once they arrive.
	_, addrErr := netip.ParseAddr(host)
	if addrErr != nil && !strings.EqualFold(name, host) {
		f.host.Counters().InterceptRefused.Add(1)
		f.host.Counters().Refuse("forward", "sni_mismatch")
		// The ban ladder hears about this before alert_on_deny can silence
		// the record: turning the log down is not a decision to stop
		// responding.
		if bl := f.host.Bans(); bl != nil && ip.IsValid() {
			bl.Observe(ip, "forward_sni_mismatch")
		}
		if f.alerts() {
			f.host.Logs().SecurityEvent(context.Background(), "deny", "forward_sni_mismatch",
				"listener", f.name, "client_ip", ip.String(), "connect", host, "sni", textsafe.Clip256(name))
		}
		return 0, 0, "sni_mismatch"
	}

	upstream, err := in.dialUpstream(dst, name)
	if err != nil {
		// The destination did not verify. The client is not given a
		// forged certificate for it: the tunnel ends here, which is
		// what would have happened without a proxy in the way.
		f.host.Counters().InterceptRefused.Add(1)
		f.host.Counters().Refuse("forward", "upstream_tls")
		if f.alerts() {
			f.host.Logs().SecurityEvent(context.Background(), "deny", "forward_upstream_tls",
				"listener", f.name, "client_ip", ip.String(), "dest", host, "err", err.Error())
		}
		return 0, 0, "upstream_tls"
	}
	defer func() { _ = upstream.Close() }()

	state := upstream.ConnectionState()
	var real *x509.Certificate
	if len(state.PeerCertificates) > 0 {
		real = state.PeerCertificates[0]
	}
	leaf, err := in.ca.Leaf(name, real)
	if err != nil {
		f.host.Logs().Error.Warn("intercept: could not issue a certificate",
			"listener", f.name, "host", name, "err", err.Error())
		return 0, 0, "issue"
	}
	srv := tls.Server(&prefixConn{Conn: client, r: br}, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   negotiated(in.alpn, state.NegotiatedProtocol),
	})
	ctx, cancel := context.WithTimeout(context.Background(), in.timeout)
	defer cancel()
	if err := srv.HandshakeContext(ctx); err != nil {
		// Usually the client does not trust the CA, which is the
		// client behaving correctly.
		f.host.Counters().InterceptRefused.Add(1)
		f.host.Counters().Refuse("forward", "client_tls")
		return 0, 0, "client_tls"
	}
	f.host.Counters().Intercepted.Add(1)
	alpn := srv.ConnectionState().NegotiatedProtocol
	f.host.Logs().Access.Info("forward_intercept", "listener", f.name, "client_ip", ip.String(),
		"user", textsafe.Clip64(user), "dest", host, "sni", name,
		"alpn", alpn, "upstream_tls", tlsconf.VersionName(state.Version))
	// Read the plaintext as HTTP where there is something to decide about it,
	// and relay it as bytes otherwise: see intercepthttp.go.
	if p != nil && f.wantsHTTP(p, alpn) {
		return f.serveInterceptedHTTP(srv, upstream, p, in, ip, user, host, port)
	}
	f.host.Counters().InterceptBytesOnly.Add(1)
	return f.relayDecrypted(srv, upstream, in, ip, host)
}

// negotiated keeps the client's choice and the destination's agreeing:
// a proxy that tells a client "h2" and then speaks http/1.1 onwards is
// a proxy that breaks the site.
func negotiated(offered []string, upstream string) []string {
	if upstream == "" {
		return nil
	}
	for _, p := range offered {
		if p == upstream {
			return []string{upstream}
		}
	}
	return nil
}

// dialUpstream completes TLS to the destination over the already
// dialled connection, verifying it unless the configuration explicitly
// said not to.
func (in *interceptor) dialUpstream(dst net.Conn, name string) (*tls.Conn, error) {
	cfg := &tls.Config{
		ServerName:         name,
		MinVersion:         in.minTLS,
		RootCAs:            in.roots,
		NextProtos:         in.alpn,
		InsecureSkipVerify: !in.verify, //nolint:gosec // opt-in, warned about at load, and the point of the key
	}
	tc := tls.Client(dst, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), in.timeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}

// relayDecrypted copies the two plaintext directions, scanning each one
// the rules asked for. Both directions are worth reading and they are
// worth reading for different things: what the client sends is what
// leaves the estate, and what the destination returns is what arrives
// in it.
func (f *forwardServer) relayDecrypted(client, upstream net.Conn, in *interceptor,
	ip netip.Addr, host string) (int64, int64, string) {
	var out, back *streamscan.Stream
	if in.yara != nil {
		out = in.yara.Stream("client")
		back = in.yara.Stream("upstream")
	}
	type result struct {
		n      int64
		reason string
	}
	done := make(chan result, 2)
	go func() {
		defer safe.Guard("intercept to upstream")
		n, reason := f.copyScanned(upstream, client, out, in, ip, host)
		_ = closeWrite(upstream)
		done <- result{n, reason}
	}()
	go func() {
		defer safe.Guard("intercept to client")
		n, reason := f.copyScanned(client, upstream, back, in, ip, host)
		_ = closeWrite(client)
		done <- result{n, reason}
	}()
	first := <-done
	second := <-done
	_ = client.Close()
	_ = upstream.Close()
	reason := first.reason
	if reason == "" {
		reason = second.reason
	}
	f.host.Counters().InterceptBytes.Add(uint64(first.n + second.n)) //nolint:gosec // non-negative
	return first.n, second.n, reason
}

// copyScanned copies one direction, reading what goes past when there
// are rules. A match ends the connection: the bytes cannot be unsent,
// so the only thing left to decide is whether the rest follows them.
func (f *forwardServer) copyScanned(dst io.Writer, src io.Reader, scan *streamscan.Stream,
	in *interceptor, ip netip.Addr, host string) (int64, string) {
	if scan == nil {
		n, _ := io.Copy(dst, src)
		return n, ""
	}
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if scan.Feed(buf[:n]) && f.yaraMatched(scan, in, ip, host) {
				return total, "yara"
			}
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, ""
			}
		}
		if err != nil {
			return total, ""
		}
	}
}

// yaraMatched records one stream match and reports whether the connection ends.
//
// It is one function because there are now two readers of the decrypted stream
// -- the byte relay and the HTTP reader -- and a match has to be counted, logged
// and banned on identically whichever of them saw it. The alternative was the
// same twenty lines twice, which is how two code paths come to disagree about
// what a match means.
func (f *forwardServer) yaraMatched(scan *streamscan.Stream, in *interceptor,
	ip netip.Addr, host string) bool {
	f.host.Counters().YARAMatches.Add(1)
	names := make([]string, 0, 4)
	for _, m := range scan.Matches() {
		names = append(names, m.Rule)
	}
	f.host.Logs().SecurityEvent(context.Background(), in.yara.Cfg.Action, "yara_match",
		"listener", f.name, "client_ip", ip.String(), "proto", "forward_intercept",
		"dest", host, "rules", strings.Join(names, ","))
	if bl := f.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "yara")
	}
	return in.yara.Cfg.Action == "close"
}

// spliceBuffered relays a tunnel whose first bytes were already read.
func (f *forwardServer) spliceBuffered(br *bufio.Reader, client, dst net.Conn, idle time.Duration) (int64, int64, string) {
	var early int64
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := dst.Write(b); err != nil {
			return 0, 0, "write"
		}
		if _, err := br.Discard(n); err != nil {
			return 0, 0, "read"
		}
		early = int64(n)
	}
	in, out := relay.Splice(client, dst, idle)
	return in + early, out, ""
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// prefixConn is a connection whose first bytes have already been read
// into a buffer.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// bufferedConn keeps whatever the client already sent in front of the
// connection, so the handshake the interceptor reads starts where the
// client started it.
func bufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	return &prefixConn{Conn: c, r: br}
}

// readerOf returns the buffer already in front of a connection, when
// there is one, so the bytes a caller peeked are not read twice.
func readerOf(c net.Conn) (*bufio.Reader, bool) {
	if p, ok := c.(*prefixConn); ok {
		return p.r, true
	}
	return nil, false
}

// peekClientHello reads enough of a tunnel's first bytes to find the server
// name in a TLS ClientHello, without consuming them.
//
// It is the half of interception that is worth having on its own. Pulled out of
// intercept so a tunnel nobody is decrypting can be asked the same question,
// which is the one question a name-based egress policy depends on.
func peekClientHello(client net.Conn, br *bufio.Reader, wait time.Duration) (*bufio.Reader, string, bool) {
	if br == nil {
		br = bufio.NewReaderSize(client, maxHelloRecord)
	} else if br.Size() < maxHelloRecord {
		// The reader the CONNECT left behind is sized for a request head, and
		// the name is in the hello's tail.
		br = bufio.NewReaderSize(br, maxHelloRecord)
	}
	_ = client.SetReadDeadline(time.Now().Add(wait))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	peek, err := br.Peek(5)
	if err != nil && len(peek) == 0 {
		return br, "", false
	}
	if len(peek) == 5 && peek[0] == recordHandshake {
		if full, perr := br.Peek(5 + int(binary.BigEndian.Uint16(peek[3:5]))); perr == nil || len(full) > len(peek) {
			peek = full
		}
	}
	name, isTLS := mitm.ClientHelloName(peek)
	return br, name, isTLS
}

// sniGuard is the destination check a tunnel still needs when nothing is
// decrypting it.
//
// A client allowed to reach cdn.example.com can open a tunnel there and then
// handshake for anything else that address serves, which on a shared CDN is a
// great many things. The destination policy then decided about a name nobody
// used. The check costs a peek at bytes the client was going to send anyway, and
// it is the difference between an allow list of names and an allow list of
// addresses that happen to have names.
//
// A handshake with no server name is not a mismatch: that is what Encrypted
// Client Hello looks like from here, and refusing it would be refusing a client
// for using a privacy feature. A tunnel opened to an address is not a mismatch
// either -- there the policy checked the address, and the bytes go to that
// address whatever the handshake says.
//
// It returns the reader to carry on with, and the refusal reason where the mode
// is enforce.
func (f *forwardServer) sniGuard(mode string, client net.Conn, br *bufio.Reader, host string,
	ip netip.Addr, wait time.Duration) (*bufio.Reader, string) {
	if mode == "off" {
		return br, ""
	}
	br, name, isTLS := peekClientHello(client, br, wait)
	if !isTLS || name == "" || strings.EqualFold(name, host) {
		return br, ""
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return br, ""
	}
	// actionFor makes this a refusal only where the mode enforces; observed, it
	// is an alert and the shadow ledger's, which alert_on_deny does not speak for.
	if mode != "enforce" || f.alerts() {
		f.host.Logs().SecurityEvent(context.Background(), actionFor(mode), "forward_sni_mismatch",
			"listener", f.name, "client_ip", ip.String(), "connect", textsafe.Clip256(host),
			"sni", textsafe.Clip256(name), "mode", mode)
	}
	if mode != "enforce" {
		f.host.Counters().WouldRefuse("forward", "sni_mismatch")
		f.host.Shadow().Record("forward", f.name, "sni_mismatch", "sni", name+" through "+host)
		return br, ""
	}
	f.host.Counters().Refuse("forward", "sni_mismatch")
	if bl := f.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "forward_sni_mismatch")
	}
	return br, "sni_mismatch"
}

// actionFor is the event action one of the sni modes writes under: a refusal is
// a deny, and a recorded mismatch is an alert, which is the spelling every other
// observe-only decision here uses.
func actionFor(mode string) string {
	if mode == "enforce" {
		return "deny"
	}
	return "alert"
}
