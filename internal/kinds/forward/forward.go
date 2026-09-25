package forward

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/httpx"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/relay"
)

// forwardServer serves a kind: forward listener: an explicit proxy that
// tunnels CONNECT requests and relays absolute-URI http requests to
// destinations the policy allows. TLS between the client and the
// destination is never terminated. The policy is compiled from the
// listener configuration and replaced on reload.
type forwardServer struct {
	host proxy.Host
	name string
	// shadow says this listener evaluates its destination policy without
	// enforcing it.
	shadow bool
	policy atomic.Pointer[forwardPolicy]
	tr     *http.Transport
	// masque is the compiled MASQUE section, nil without one. It is
	// built once: turning UDP or IP proxying on or off is a listener
	// change, not a policy swap.
	masque *masquePolicy
	// mitm is the compiled intercept section, nil without one. Like
	// masque it is built once: turning interception on or off is a
	// listener change, not a policy swap, because it holds a signing
	// key and a certificate cache.
	mitm *interceptor

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	cons map[net.Conn]struct{}
	once sync.Once
	done chan struct{}

	authMu    sync.Mutex
	authCache map[[32]byte]time.Time
	authSem   chan struct{}
	// authWaiting counts callers queued on authSem (bounded by Acquire).
	authWaiting atomic.Int32
}

type forwardPolicy struct {
	cfg   config.ForwardListener
	ports map[int]bool
	allow []destRule
	deny  []destRule
	users map[string]string
}

// destRule matches a destination by name (exact or *.suffix) or by
// resolved address (prefix).
type destRule struct {
	name     string
	wildcard bool
	prefix   netip.Prefix
	isPrefix bool
}

const (
	forwardAuthTTL        = 5 * time.Minute
	forwardResponseHeader = 60 * time.Second
)

type forwardDialKey struct{}

func newForwardServer(host proxy.Host, lc config.Listener) (*forwardServer, error) {
	f := &forwardServer{host: host, name: lc.Name, shadow: lc.Shadowing(),
		cons: map[net.Conn]struct{}{}, done: make(chan struct{}),
		authCache: map[[32]byte]time.Time{}, authSem: make(chan struct{}, 4)}
	if err := f.apply(lc.Forward); err != nil {
		return nil, err
	}
	f.masque = newMasquePolicy(lc.Forward.Masque)
	if lc.Forward.Intercept != nil {
		mi, err := newInterceptor(lc.Forward.Intercept, lc.Forward.ConnectTimeout.D())
		if err != nil {
			return nil, fmt.Errorf("forward intercept: %w", err)
		}
		f.mitm = mi
		host.Logs().Error.Warn("TLS interception is on: clients on this listener see certificates this proxy signs",
			"listener", lc.Name, "ca", mi.ca.Subject(), "ca_expires", mi.ca.NotAfter().Format(time.RFC3339))
	}
	f.tr = &http.Transport{
		Proxy:                 nil,
		DialContext:           f.dialChecked,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: forwardResponseHeader,
		ForceAttemptHTTP2:     false,
	}
	return f, nil
}

// apply compiles a listener configuration (start and reload).
func (f *forwardServer) apply(fc *config.ForwardListener) error {
	p := &forwardPolicy{cfg: *fc, ports: map[int]bool{}}
	for _, port := range fc.Ports {
		p.ports[port] = true
	}
	var err error
	if p.allow, err = compileDestRules(fc.Allow); err != nil {
		return fmt.Errorf("forward allow: %w", err)
	}
	if p.deny, err = compileDestRules(fc.Deny); err != nil {
		return fmt.Errorf("forward deny: %w", err)
	}
	if fc.Auth != nil {
		users, err := passwd.LoadUsers(fc.Auth.UsersFile)
		if err != nil {
			return fmt.Errorf("forward auth: %w", err)
		}
		p.users = users
	}
	f.policy.Store(p)
	f.authMu.Lock()
	f.authCache = map[[32]byte]time.Time{}
	f.authMu.Unlock()
	return nil
}

func compileDestRules(list []string) ([]destRule, error) {
	rules := make([]destRule, 0, len(list))
	for _, d := range list {
		if pfx, err := netip.ParsePrefix(d); err == nil {
			rules = append(rules, destRule{prefix: pfx.Masked(), isPrefix: true})
			continue
		}
		if a, err := netip.ParseAddr(d); err == nil {
			a = a.Unmap()
			rules = append(rules, destRule{prefix: netip.PrefixFrom(a, a.BitLen()), isPrefix: true})
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(d, "."))
		switch {
		case strings.HasPrefix(name, "*."):
			rules = append(rules, destRule{name: name[1:], wildcard: true})
		case name != "":
			rules = append(rules, destRule{name: name})
		default:
			return nil, errors.New("empty destination")
		}
	}
	return rules, nil
}

func (r destRule) matches(host string, ips []netip.Addr) bool {
	if r.isPrefix {
		for _, ip := range ips {
			if r.prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if r.wildcard {
		return strings.HasSuffix(host, r.name) && len(host) > len(r.name)
	}
	return host == r.name
}

func anyRule(rules []destRule, host string, ips []netip.Addr) bool {
	for _, r := range rules {
		if r.matches(host, ips) {
			return true
		}
	}
	return false
}

// notPublic lists the address blocks beyond the stdlib predicates that a
// forward proxy must not reach unless allow_private is set: CGNAT, "this
// network", IETF protocol assignments, benchmarking, reserved, and the
// IPv6 transition prefixes that embed an internal IPv4 address (NAT64,
// 6to4, Teredo).
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// privateAddr reports addresses a forward proxy must not reach unless
// allow_private is set: loopback, link local, RFC 1918, unique local,
// multicast, unspecified and the notPublic blocks.
func privateAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range notPublic {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// shadowed records a destination policy refusal a listener in shadow mode
// does not enforce, and says whether it was recorded rather than applied.
//
// Two of this policy's refusals are never shadowed, and the difference is
// the direction they protect. The operator's own destination lists -- the
// ports, the deny list, the allow list -- say where this estate's clients
// may go, and shadowing those tells an operator what a new egress policy
// would have stopped. "private" says the client may not use this proxy to
// reach the network the proxy is on, which protects the estate *from* the
// client: shadowing it would turn a trial into a server-side request
// forgery. A destination that does not resolve is not a policy question
// at all.
func (f *forwardServer) shadowed(reason, dest string) bool {
	if !f.shadow {
		return false
	}
	f.host.Counters().WouldRefuse("forward", reason)
	f.host.Shadow().Record("forward", f.name, reason, "", dest)
	return true
}

// check applies the destination policy and returns the addresses to
// dial, or the deny reason.
func (f *forwardServer) check(ctx context.Context, p *forwardPolicy, host string, port int) ([]netip.Addr, string) {
	if !p.ports[port] && !f.shadowed("port", net.JoinHostPort(host, strconv.Itoa(port))) {
		return nil, "port"
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, "host"
	}
	var ips []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		ips = []netip.Addr{a.Unmap()}
	} else {
		rctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout.D())
		defer cancel()
		found, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
		if err != nil || len(found) == 0 {
			return nil, "resolve"
		}
		ips = make([]netip.Addr, 0, len(found))
		for _, a := range found {
			ips = append(ips, a.Unmap())
		}
	}
	if !p.cfg.AllowPrivate {
		for _, ip := range ips {
			if privateAddr(ip) {
				return nil, "private"
			}
		}
	}
	if anyRule(p.deny, host, ips) && !f.shadowed("deny", host) {
		return nil, "deny"
	}
	if len(p.allow) > 0 && !anyRule(p.allow, host, ips) && !f.shadowed("not_allowed", host) {
		return nil, "not_allowed"
	}
	return ips, ""
}

// dialChecked dials the addresses that check approved (carried in ctx)
// rather than the name, so a rebinding between check and dial cannot
// redirect the connection.
func (f *forwardServer) dialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	ips, _ := ctx.Value(forwardDialKey{}).([]netip.Addr)
	if len(ips) == 0 {
		return nil, errors.New("forward: destination not checked")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p := f.policy.Load()
	d := net.Dialer{Timeout: p.cfg.ConnectTimeout.D()}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// authenticate checks Proxy-Authorization Basic against the users file.
func (f *forwardServer) authenticate(p *forwardPolicy, r *http.Request) (string, bool) {
	h := r.Header.Get("Proxy-Authorization")
	scheme, cred, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return "", false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" {
		return "", false
	}
	hash, known := p.users[user]
	key := sha256.Sum256([]byte(user + "\x00" + pass))
	now := time.Now()
	if known {
		f.authMu.Lock()
		exp, hit := f.authCache[key]
		f.authMu.Unlock()
		if hit && now.Before(exp) {
			return user, true
		}
	}
	// The hash runs behind a small semaphore; a client that leaves while
	// queued, or a queue already deep, gets a refusal instead of a slot
	// held for the whole wait.
	if !passwd.Acquire(r.Context(), f.authSem, &f.authWaiting) {
		return "", false
	}
	if known {
		ok = passwd.Verify(hash, pass)
	} else {
		// Same cost as a wrong password for a known user: no timing oracle
		// on which names exist.
		passwd.VerifyDummy(pass)
		ok = false
	}
	<-f.authSem
	if !ok {
		return "", false
	}
	f.authMu.Lock()
	if len(f.authCache) >= 4096 {
		f.authCache = map[[32]byte]time.Time{}
	}
	f.authCache[key] = now.Add(forwardAuthTTL)
	f.authMu.Unlock()
	return user, true
}

func (f *forwardServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := f.host
	p := f.policy.Load()
	start := time.Now()
	ip := netutil.RemoteAddr(r)
	h.Counters().ForwardRequests.Add(1)
	user := ""
	if p.cfg.Auth != nil {
		u, ok := f.authenticate(p, r)
		if !ok {
			h.Counters().ForwardAuthFailed.Add(1)
			w.Header().Set("Proxy-Authenticate", `Basic realm="`+p.cfg.Auth.Realm+`", charset="UTF-8"`)
			f.deny(w, r, ip, "", http.StatusProxyAuthRequired, "auth", start)
			return
		}
		user = u
		r.Header.Del("Proxy-Authorization")
	}
	// An extended CONNECT carries a :protocol pseudo-header: it is
	// asking for UDP or IP proxying rather than a TCP tunnel.
	if f.serveMasque(w, r, p, ip, user, start) {
		return
	}
	if r.Method == http.MethodConnect {
		f.connect(w, r, p, ip, user, start)
		return
	}
	if !r.URL.IsAbs() {
		f.deny(w, r, ip, user, http.StatusBadRequest, "not_absolute", start)
		return
	}
	if r.URL.Scheme != "http" {
		f.deny(w, r, ip, user, http.StatusBadRequest, "scheme", start)
		return
	}
	f.plain(w, r, p, ip, user, start)
}

// deny answers a refused request and records it. Policy refusals are
// security events and count toward the forward_denied ban reason.
func (f *forwardServer) deny(w http.ResponseWriter, r *http.Request, ip netip.Addr, user string, status int, reason string, start time.Time) {
	h := f.host
	dest := r.URL.Host
	if r.Method == http.MethodConnect {
		dest = r.Host
	}
	// Every refusal is counted by its reason, whatever it was answered
	// with: 403 for a destination the policy refuses, 407 for a missing
	// credential, 400 for a request that is not a proxy request, 503
	// for a bound. The 500 and 502 paths are errors rather than
	// refusals — a failed dial, a hijack the server would not allow —
	// and they belong to the error counters instead.
	if status < 500 || status == http.StatusServiceUnavailable {
		h.Counters().Refuse("forward", reason)
	}
	switch status {
	case http.StatusForbidden:
		h.Counters().ForwardDenied.Add(1)
		h.Logs().SecurityEvent(r.Context(), "deny", "forward_"+reason, "listener", f.name, "client_ip", ip.String(), "user", user, "method", r.Method, "destination", dest)
		if bl := h.Bans(); bl != nil {
			bl.Observe(ip, "forward_denied")
		}
	case http.StatusProxyAuthRequired:
		if bl := h.Bans(); bl != nil {
			bl.Observe(ip, "forward_auth")
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%d %s: %s\n", status, http.StatusText(status), reason)
	f.log(r, ip, user, dest, status, 0, 0, start, reason)
}

func (f *forwardServer) log(r *http.Request, ip netip.Addr, user, dest string, status int, in, out int64, start time.Time, reason string) {
	attrs := []any{"listener", f.name, "client_ip", ip.String(), "user", user, "method", r.Method, "destination", dest,
		"status", status, "bytes_in", in, "bytes_out", out, "duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	f.host.Logs().Access.Info("forward", attrs...)
}

// connect opens a tunnel: policy check, dial the checked address, then
// splice the hijacked client connection with an idle timeout.
func (f *forwardServer) connect(w http.ResponseWriter, r *http.Request, p *forwardPolicy, ip netip.Addr, user string, start time.Time) {
	h := f.host
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		f.deny(w, r, ip, user, http.StatusBadRequest, "authority", start)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		f.deny(w, r, ip, user, http.StatusBadRequest, "authority", start)
		return
	}
	ips, reason := f.check(r.Context(), p, host, port)
	if reason != "" {
		f.deny(w, r, ip, user, http.StatusForbidden, reason, start)
		return
	}
	select {
	case <-f.done:
		f.deny(w, r, ip, user, http.StatusServiceUnavailable, "shutting_down", start)
		return
	default:
	}
	if f.open.Add(1) > int64(p.cfg.MaxTunnels) {
		f.open.Add(-1)
		h.Counters().ForwardRejected.Add(1)
		f.deny(w, r, ip, user, http.StatusServiceUnavailable, "tunnel_limit", start)
		return
	}
	defer f.open.Add(-1)
	ctx := context.WithValue(r.Context(), forwardDialKey{}, ips)
	dst, err := f.dialChecked(ctx, "tcp", r.Host)
	if err != nil {
		h.Counters().ForwardErrors.Add(1)
		f.deny(w, r, ip, user, http.StatusBadGateway, "dial", start)
		return
	}
	if r.ProtoMajor == 2 {
		f.connectH2(w, r, p, dst, host, ips, ip, user, start)
		return
	}
	rc := http.NewResponseController(w)
	client, bufrw, err := rc.Hijack()
	if err != nil {
		_ = dst.Close()
		h.Counters().ForwardErrors.Add(1)
		f.deny(w, r, ip, user, http.StatusInternalServerError, "hijack", start)
		return
	}
	h.Counters().ForwardTunnels.Add(1)
	h.Counters().ForwardTunnelsOpen.Add(1)
	defer h.Counters().ForwardTunnelsOpen.Add(-1)
	f.track(client, true)
	f.wg.Add(1)
	defer f.wg.Done()
	defer f.track(client, false)
	_ = client.SetDeadline(time.Time{})
	_, err = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err == nil {
		err = bufrw.Flush()
	}
	if err != nil {
		_ = client.Close()
		_ = dst.Close()
		return
	}
	if f.mitm != nil && f.mitm.wants(host, ips) {
		// Whatever the client sent before our reply is the start of the
		// handshake this is about to terminate, so it stays on the
		// client's side rather than being sent on to the destination.
		in, out, reason := f.intercept(bufferedConn(client, bufrw.Reader), dst, host, ip, user)
		h.Counters().ForwardBytesIn.Add(uint64(in))   //nolint:gosec // non-negative
		h.Counters().ForwardBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
		f.log(r, ip, user, r.Host, http.StatusOK, in, out, start, reason)
		return
	}
	var early int64
	if n := bufrw.Reader.Buffered(); n > 0 { // bytes the client sent before our reply
		b, _ := bufrw.Peek(n)
		if _, err := dst.Write(b); err != nil {
			_ = client.Close()
			_ = dst.Close()
			return
		}
		early = int64(n)
		_, _ = bufrw.Discard(n)
	}
	in, out := relay.Splice(client, dst, p.cfg.IdleTimeout.D())
	in += early
	h.Counters().ForwardBytesIn.Add(uint64(in))   //nolint:gosec // non-negative
	h.Counters().ForwardBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
	f.log(r, ip, user, r.Host, http.StatusOK, in, out, start, "")
}

// connectH2 tunnels a CONNECT request that arrived on an HTTP/2 stream:
// the request body is the client to destination direction and the
// response body the other, flushed per write. The stream is bounded by
// the idle timeout on the destination side and by the client closing
// its half.
func (f *forwardServer) connectH2(w http.ResponseWriter, r *http.Request, p *forwardPolicy, dst net.Conn,
	host string, ips []netip.Addr, ip netip.Addr, user string, start time.Time) {
	h := f.host
	rc := http.NewResponseController(w)
	h.Counters().ForwardTunnels.Add(1)
	h.Counters().ForwardTunnelsOpen.Add(1)
	defer h.Counters().ForwardTunnelsOpen.Add(-1)
	f.track(dst, true)
	f.wg.Add(1)
	defer f.wg.Done()
	defer f.track(dst, false)
	defer func() { _ = dst.Close() }()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}
	if f.mitm != nil && f.mitm.wants(host, ips) {
		// An HTTP/2 CONNECT stream is a full-duplex byte stream just like a
		// hijacked HTTP/1 connection. Adapt it to net.Conn so interception
		// cannot be bypassed by selecting h2 on the outer proxy connection.
		client := &h2StreamConn{body: r.Body, w: w, rc: rc}
		in, out, reason := f.intercept(client, dst, host, ip, user)
		h.Counters().ForwardBytesIn.Add(uint64(in))   //nolint:gosec // non-negative
		h.Counters().ForwardBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
		f.log(r, ip, user, r.Host, http.StatusOK, in, out, start, reason)
		return
	}
	idle := p.cfg.IdleTimeout.D()
	var in atomic.Int64
	var out int64
	go func() {
		// Ends when the client closes its half or, after the handler
		// returns, when the server closes the request body.
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
				wn, werr := dst.Write(buf[:n])
				in.Add(int64(wn))
				if werr != nil {
					return
				}
			}
			if err != nil {
				if tc, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = tc.CloseWrite()
				}
				return
			}
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		_ = dst.SetReadDeadline(time.Now().Add(idle))
		n, err := dst.Read(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			out += int64(wn)
			if werr != nil {
				break
			}
			if err := rc.Flush(); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	_ = dst.Close() // the destination is done: end the stream without waiting for the client's half
	n := in.Load()
	h.Counters().ForwardBytesIn.Add(uint64(n))    //nolint:gosec // non-negative
	h.Counters().ForwardBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
	f.log(r, ip, user, r.Host, http.StatusOK, n, out, start, "")
}

// h2StreamConn presents an HTTP/2 CONNECT request and response body as the
// net.Conn expected by the TLS interceptor. Response writes are flushed so
// handshake records are not retained by net/http's response buffering.
type h2StreamConn struct {
	body io.ReadCloser
	w    http.ResponseWriter
	rc   *http.ResponseController
}

func (c *h2StreamConn) Read(p []byte) (int, error) { return c.body.Read(p) }
func (c *h2StreamConn) Close() error               { return c.body.Close() }
func (c *h2StreamConn) LocalAddr() net.Addr        { return h2StreamAddr("proxy") }
func (c *h2StreamConn) RemoteAddr() net.Addr       { return h2StreamAddr("client") }
func (c *h2StreamConn) SetDeadline(t time.Time) error {
	if err := c.rc.SetReadDeadline(t); err != nil {
		return err
	}
	return c.rc.SetWriteDeadline(t)
}
func (c *h2StreamConn) SetReadDeadline(t time.Time) error  { return c.rc.SetReadDeadline(t) }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error { return c.rc.SetWriteDeadline(t) }
func (c *h2StreamConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil {
		err = c.rc.Flush()
	}
	return n, err
}

type h2StreamAddr string

func (a h2StreamAddr) Network() string { return "h2" }
func (a h2StreamAddr) String() string  { return string(a) }

// plain relays an absolute-URI http request through the checked dialer
// and copies the response back, bounded by max_response_bytes.
func (f *forwardServer) plain(w http.ResponseWriter, r *http.Request, p *forwardPolicy, ip netip.Addr, user string, start time.Time) {
	h := f.host
	host := r.URL.Hostname()
	port := 80
	if ps := r.URL.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil {
			f.deny(w, r, ip, user, http.StatusBadRequest, "port", start)
			return
		}
		port = n
	}
	ips, reason := f.check(r.Context(), p, host, port)
	if reason != "" {
		f.deny(w, r, ip, user, http.StatusForbidden, reason, start)
		return
	}
	ctx := context.WithValue(r.Context(), forwardDialKey{}, ips)
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.Host = r.URL.Host
	httpx.StripHopByHop(out.Header)
	out.Header.Add("Via", "1.1 xproxy")
	if out.Header.Get("X-Forwarded-For") != "" {
		out.Header.Del("X-Forwarded-For") // never relay a client supplied chain
	}
	resp, err := f.tr.RoundTrip(out)
	if err != nil {
		h.Counters().ForwardErrors.Add(1)
		f.deny(w, r, ip, user, http.StatusBadGateway, "upstream", start)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	httpx.StripHopByHop(resp.Header)
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Add("Via", "1.1 xproxy")
	w.WriteHeader(resp.StatusCode)
	var body io.Reader = resp.Body
	if p.cfg.MaxResponseBytes > 0 {
		body = io.LimitReader(resp.Body, p.cfg.MaxResponseBytes+1)
	}
	n, _ := io.Copy(w, body)
	if p.cfg.MaxResponseBytes > 0 && n > p.cfg.MaxResponseBytes {
		h.Counters().ForwardErrors.Add(1)
		// Cut the connection so the client sees a truncated response
		// rather than a complete looking one.
		if c, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = c.Close()
		}
	}
	h.Counters().ForwardBytesOut.Add(uint64(n)) //nolint:gosec // non-negative
	f.log(r, ip, user, r.URL.Host, resp.StatusCode, r.ContentLength, n, start, "")
}

func (f *forwardServer) track(c net.Conn, add bool) {
	f.mu.Lock()
	if add {
		f.cons[c] = struct{}{}
	} else {
		delete(f.cons, c)
	}
	f.mu.Unlock()
}

// shutdown waits for tunnels up to ctx, then closes the rest. The HTTP
// server's own Shutdown has already stopped accepting.
func (f *forwardServer) shutdown(ctx context.Context) {
	f.once.Do(func() { close(f.done) })
	f.tr.CloseIdleConnections()
	finished := make(chan struct{})
	go func() { f.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		f.mu.Lock()
		for c := range f.cons {
			_ = c.Close()
		}
		f.mu.Unlock()
		<-finished
	}
}
