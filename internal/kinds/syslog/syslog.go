package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	wire "github.com/rom/xproxy/internal/syslog"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server serves a kind: syslog listener: a relay that reads what
// it forwards.
//
// Reading it is the point. Almost every field is written by the sender
// and believed by the collector, so the relay is the one place that can
// say what a record actually came from — and the one place that can
// stop a message whose text carries a newline from becoming two records
// downstream.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	l      *config.SyslogListener
	ln     net.Listener
	pc     net.PacketConn
	tlsCfg *tls.Config
	upTLS  *tls.Config

	framing   wire.Framing
	upFraming wire.Framing
	allow     []netip.Prefix
	facOK     map[int]bool
	facDeny   map[int]bool
	minSev    int
	deny      []*regexp.Regexp
	redact    []redaction
	limiter   *limiter

	queue chan *record
	open  atomic.Int64
	// running is what a shutdown waits for: the accepted sessions and the
	// two goroutines serve starts. It is acceptgroup rather than a bare
	// WaitGroup because the engine can call Shutdown before serve has run
	// its first Add, and before an accepted connection has reached its
	// own -- and a WaitGroup's Add must not race its Wait.
	running acceptgroup.Group
	mu      sync.Mutex
	once    sync.Once
	cons    map[net.Conn]struct{}
	done    chan struct{}
}

type redaction struct {
	name string
	re   *regexp.Regexp
	with string
}

// record is a parsed message and where it came from.
type record struct {
	msg  wire.Message
	from netip.Addr
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, pc net.PacketConn, tc *tls.Config) (*server, error) {
	l := cfg.Syslog
	t := &server{host: host, cfg: cfg, l: l, ln: ln, pc: pc, tlsCfg: tc,
		facOK: map[int]bool{}, facDeny: map[int]bool{}, minSev: 7,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{}),
		queue: make(chan *record, l.Queue)}
	var err error
	if t.framing, err = framingOf(l.Framing); err != nil {
		return nil, err
	}
	if t.upFraming, err = framingOf(l.UpstreamFraming); err != nil {
		return nil, err
	}
	for _, f := range l.AllowFacilities {
		n, ok := wire.FacilityNumber(f)
		if !ok {
			return nil, fmt.Errorf("syslog allow_facilities: %q", f)
		}
		t.facOK[n] = true
	}
	for _, f := range l.DenyFacilities {
		n, ok := wire.FacilityNumber(f)
		if !ok {
			return nil, fmt.Errorf("syslog deny_facilities: %q", f)
		}
		t.facDeny[n] = true
	}
	if l.MinSeverity != "" {
		n, ok := wire.SeverityNumber(l.MinSeverity)
		if !ok {
			return nil, fmt.Errorf("syslog min_severity: %q", l.MinSeverity)
		}
		t.minSev = n
	}
	for _, c := range l.AllowSenders {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("syslog allow_senders: %w", err)
		}
		t.allow = append(t.allow, p)
	}
	for _, pat := range l.DenyPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("syslog deny_patterns: %w", err)
		}
		t.deny = append(t.deny, re)
	}
	for _, r := range l.Redact {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("syslog redact %q: %w", r.Name, err)
		}
		with := r.With
		if with == "" {
			with = "[redacted]"
		}
		t.redact = append(t.redact, redaction{name: r.Name, re: re, with: with})
	}
	if l.RateLimit > 0 {
		t.limiter = newSyslogLimiter(l.RateLimit, l.RateBurst, l.MaxSenders)
	}
	if l.UpstreamTLSMode != "none" {
		uc, _, err := tlsconf.Client(l.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("syslog upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	return t, nil
}

func framingOf(s string) (wire.Framing, error) {
	switch s {
	case "octet_counting":
		return wire.OctetCounting, nil
	case "non_transparent":
		return wire.NonTransparent, nil
	case "auto":
		return wire.Auto, nil
	}
	return 0, fmt.Errorf("syslog framing: %q", s)
}

func (t *server) serve() {
	if !t.running.Enter() {
		// Shut down before it started, which a reload can do.
		return
	}
	defer t.running.Leave()
	go func() {
		if !t.running.Enter() {
			return
		}
		defer t.running.Leave()
		defer safe.Guard("syslog forwarder")
		t.forward()
	}()
	if t.pc != nil {
		go func() {
			if !t.running.Enter() {
				return
			}
			defer t.running.Leave()
			defer safe.Guard("syslog udp")
			t.serveUDP()
		}()
	}
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			var opErr *net.OpError
			if errors.As(err, &opErr) && strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if t.open.Add(1) > int64(t.l.MaxConnections) {
			t.open.Add(-1)
			t.host.Counters().SyslogRejected.Add(1)
			t.host.Counters().Refuse("syslog", "max_connections")
			_ = c.Close()
			continue
		}
		if !t.admit(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.running.Leave()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("syslog stream")
			t.handleStream(c)
		}()
	}
}

func (t *server) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running.Enter() {
		return false
	}
	t.cons[c] = struct{}{}
	return true
}

func (t *server) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

func (t *server) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		_ = t.ln.Close()
		if t.pc != nil {
			_ = t.pc.Close()
		}
	})
	t.running.Close()
	t.running.Wait(ctx)
	if ctx.Err() != nil {
		t.mu.Lock()
		for c := range t.cons {
			_ = c.Close()
		}
		t.mu.Unlock()
		// And this returns rather than waiting again, which is what it did
		// before the group replaced the WaitGroup: a shutdown that hangs on
		// one session is worse than one that stops asking.
	}
}

// serveUDP reads datagrams. On UDP the sender's address is the only
// thing about a message that is not simply asserted, and even that is
// forgeable; allow_senders is the whole of the authentication there is.
func (t *server) serveUDP() {
	buf := make([]byte, t.l.MaxMessageBytes+16)
	for {
		n, addr, err := t.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		ap, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			continue
		}
		if n > t.l.MaxMessageBytes {
			t.refuse(ap.Addr(), "too_large", "")
			continue
		}
		// One datagram is one message (RFC 5426 section 3.1), so there
		// is no framing to read and nothing to resync.
		t.take(append([]byte(nil), buf[:n]...), ap.Addr())
	}
}

// handleStream reads framed messages from one connection.
func (t *server) handleStream(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	if !t.senderAllowed(ip) {
		t.refuse(ip, "sender_refused", "")
		return
	}
	if t.l.TLSMode == "implicit" {
		tc := tls.Server(c, t.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return
		}
		c = tc
	}
	t.host.Counters().SyslogConnections.Add(1)
	r := wire.NewReader(c, t.l.MaxMessageBytes, t.framing)
	for {
		if t.l.IdleTimeout > 0 {
			_ = c.SetReadDeadline(time.Now().Add(t.l.IdleTimeout.D()))
		}
		raw, err := r.ReadMessage()
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrOversizeSkipped):
				// The reader skipped to the next line ending and is at
				// a boundary again. One sender writing one long line
				// should not cost every record behind it.
				t.refuse(ip, "too_large", "")
				continue
			case errors.Is(err, wire.ErrTooLarge), errors.Is(err, wire.ErrMalformed):
				// A counted frame that cannot be read leaves the stream
				// at an offset nobody knows; there is nothing honest to
				// do but end it.
				t.refuse(ip, "framing", err.Error())
			}
			return
		}
		t.take(raw, ip)
	}
}

func (t *server) senderAllowed(ip netip.Addr) bool {
	if len(t.allow) == 0 {
		return true
	}
	for _, p := range t.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// take parses one message and applies the policy to it.
func (t *server) take(raw []byte, from netip.Addr) {
	t.host.Counters().SyslogReceived.Add(1)
	if !t.senderAllowed(from) && !t.shadowed("sender_refused", from.String()) {
		t.refuse(from, "sender_refused", "")
		return
	}
	if t.limiter != nil && !t.limiter.allow(from) {
		t.host.Counters().SyslogRateLimited.Add(1)
		t.host.Counters().Refuse("syslog", "rate_limit")
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		// A message the relay could not read is a message whose
		// facility, severity and host are unknown, which is every field
		// a rule here decides on.
		t.refuse(from, "malformed", err.Error())
		return
	}
	if reason := t.filter(m); reason != "" && !t.shadowed(reason, textsafe.Clip64(m.Message)) {
		t.host.Counters().SyslogDropped.Add(1)
		// The reason the message was dropped was until now thrown away
		// with it: a relay dropping half its traffic could not say
		// whether that was the facility list, the severity floor or a
		// pattern. It is not a security event — a sender saying
		// something this relay does not carry is ordinary — so it is
		// counted rather than logged.
		t.host.Counters().Refuse("syslog", reason)
		return
	}
	t.rewrite(&m, from)
	select {
	case t.queue <- &record{msg: m, from: from}:
	default:
		// The collector is behind. Dropping here keeps one slow
		// collector from blocking every sender, and it is counted so
		// the gap is visible rather than guessed at.
		t.host.Counters().SyslogQueueDropped.Add(1)
		t.host.Counters().Refuse("syslog", "queue_full")
	}
}

// shadowed records a policy drop a listener in shadow mode does not
// enforce, and says whether it was recorded rather than dropped. Only
// policy reaches it: a malformed message, the rate limit and a full queue
// are refused in shadow mode too, because none of them is a question
// about what this estate carries.
func (t *server) shadowed(what, detail string) bool {
	if !t.cfg.Shadowing() {
		return false
	}
	t.host.Counters().WouldRefuse("syslog", what)
	t.host.Shadow().Record("syslog", t.cfg.Name, what, "", detail)
	return true
}

// filter applies what a message claims to be. It returns the reason it
// was dropped, or empty.
func (t *server) filter(m wire.Message) string {
	if len(t.facOK) > 0 && !t.facOK[m.Facility] {
		return "facility"
	}
	if t.facDeny[m.Facility] {
		return "facility"
	}
	if m.Severity > t.minSev {
		return "severity"
	}
	for _, re := range t.deny {
		if re.MatchString(m.Message) {
			return "pattern"
		}
	}
	return ""
}

// rewrite applies what the relay knows that the sender did not say.
func (t *server) rewrite(m *wire.Message, from netip.Addr) {
	for _, r := range t.redact {
		if r.re.MatchString(m.Message) {
			m.Message = r.re.ReplaceAllString(m.Message, r.with)
			m.Structured = append(m.Structured, wire.SDElement{
				ID:     "xproxyRedaction@0",
				Params: []wire.SDParam{{Name: "rule", Value: r.name}},
			})
			t.host.Counters().SyslogRedacted.Add(1)
		}
	}
	switch t.l.Hostname {
	case "observed":
		m.Hostname = from.String()
	case "annotate":
		// The sender's name is often the useful one and is never the
		// true one, so both are kept and which is which is stated.
		m.Structured = append(m.Structured, wire.SDElement{
			ID: "xproxyOrigin@0",
			Params: []wire.SDParam{
				{Name: "ip", Value: from.String()},
				{Name: "listener", Value: t.cfg.Name},
				{Name: "claimed", Value: m.Hostname},
			},
		})
		if m.Hostname == "" {
			m.Hostname = from.String()
		}
	}
	if !m.HasTimestamp {
		// A record with no time is a record nobody can order. The relay
		// saw it now, and says so rather than leaving the collector to
		// invent one.
		m.Timestamp, m.HasTimestamp = time.Now().UTC(), true
	}
}

func (t *server) refuse(ip netip.Addr, what, detail string) {
	t.host.Counters().SyslogRefused.Add(1)
	t.host.Counters().Refuse("syslog", what)
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "syslog"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "syslog_"+what, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "syslog_denied")
	}
}

// forward writes queued records to the collector, keeping one
// connection open and rebuilding it when it fails. Everything it sends
// is RFC 5424 in one framing, whatever arrived: one dialect out is what
// makes the record the collector stores the record this relay decided
// about.
func (t *server) forward() {
	var conn net.Conn
	var ep *upstream.Endpoint
	var pool *upstream.Pool
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
		if ep != nil && pool != nil {
			pool.End(ep, false, 0)
		}
	}()
	for {
		var rec *record
		select {
		case <-t.done:
			return
		case rec = <-t.queue:
		}
		out := wire.Frame(rec.msg.Format(), t.upFraming)
		for attempt := 0; attempt < 2; attempt++ {
			if conn == nil {
				c, e, p, err := t.dialCollector()
				if err != nil {
					t.host.Counters().SyslogSendFailed.Add(1)
					t.host.Logs().Error.Warn("syslog collector unavailable",
						"listener", t.cfg.Name, "err", err.Error())
					break
				}
				conn, ep, pool = c, e, p
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(out); err != nil {
				_ = conn.Close()
				if ep != nil && pool != nil {
					pool.End(ep, true, 0)
				}
				conn, ep, pool = nil, nil, nil
				continue
			}
			t.host.Counters().SyslogForwarded.Add(1)
			break
		}
	}
}

func (t *server) dialCollector() (net.Conn, *upstream.Endpoint, *upstream.Pool, error) {
	pool := t.host.Pool(t.l.Upstream)
	if pool == nil {
		return nil, nil, nil, fmt.Errorf("upstream %q has no pool", t.l.Upstream)
	}
	tried := map[*upstream.Endpoint]bool{}
	var lastErr error
	for i := 0; i < 3; i++ {
		ep, _ := pool.Pick("", "", tried, upstream.CanaryAny)
		if ep == nil {
			break
		}
		tried[ep] = true
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		c, err := d.DialContext(context.Background(), "tcp", ep.Address)
		pool.Begin(ep)
		if err != nil {
			pool.End(ep, true, 0)
			lastErr = err
			continue
		}
		if t.l.UpstreamTLSMode == "implicit" {
			tc := tls.Client(c, t.collectorTLS(ep))
			if err := tc.HandshakeContext(context.Background()); err != nil {
				pool.End(ep, true, 0)
				_ = c.Close()
				lastErr = err
				continue
			}
			c = tc
		}
		return c, ep, pool, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable collector")
	}
	return nil, nil, nil, lastErr
}

func (t *server) collectorTLS(ep *upstream.Endpoint) *tls.Config {
	tc := t.upTLS.Clone()
	if tc.ServerName == "" {
		if host, _, err := net.SplitHostPort(ep.Address); err == nil {
			tc.ServerName = host
		}
	}
	return tc
}

// limiter bounds what one sender may send. A log flood is a
// denial of service on the collector and a way to push older records
// out of whatever window it keeps, so the bound is per sender rather
// than per listener.
type limiter struct {
	rate  float64
	burst float64
	max   int

	mu      sync.Mutex
	buckets map[netip.Addr]*syslogBucket
}

type syslogBucket struct {
	tokens float64
	last   time.Time
}

func newSyslogLimiter(rate, burst, max int) *limiter {
	if burst <= 0 {
		burst = rate
	}
	if max <= 0 {
		max = 65536
	}
	return &limiter{rate: float64(rate), burst: float64(burst), max: max,
		buckets: map[netip.Addr]*syslogBucket{}}
}

func (l *limiter) allow(ip netip.Addr) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= l.max {
			// The table is full of senders. Dropping the new one holds
			// the bound without letting an attacker with many addresses
			// evict the entries that are doing the limiting.
			return false
		}
		b = &syslogBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
