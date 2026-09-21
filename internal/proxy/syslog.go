package proxy

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

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/syslog"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// syslogServer serves a kind: syslog listener: a relay that reads what
// it forwards.
//
// Reading it is the point. Almost every field is written by the sender
// and believed by the collector, so the relay is the one place that can
// say what a record actually came from — and the one place that can
// stop a message whose text carries a newline from becoming two records
// downstream.
type syslogServer struct {
	s      *Server
	cfg    config.Listener
	l      *config.SyslogListener
	ln     net.Listener
	pc     net.PacketConn
	tlsCfg *tls.Config
	upTLS  *tls.Config

	framing   syslog.Framing
	upFraming syslog.Framing
	allow     []netip.Prefix
	facOK     map[int]bool
	facDeny   map[int]bool
	minSev    int
	deny      []*regexp.Regexp
	redact    []syslogRedaction
	limiter   *syslogLimiter

	queue chan *syslogRecord
	open  atomic.Int64
	wg    sync.WaitGroup
	mu    sync.Mutex
	once  sync.Once
	cons  map[net.Conn]struct{}
	done  chan struct{}
}

type syslogRedaction struct {
	name string
	re   *regexp.Regexp
	with string
}

// syslogRecord is a parsed message and where it came from.
type syslogRecord struct {
	msg  syslog.Message
	from netip.Addr
}

func newSyslogServer(s *Server, cfg config.Listener, ln net.Listener, pc net.PacketConn, tc *tls.Config) (*syslogServer, error) {
	l := cfg.Syslog
	t := &syslogServer{s: s, cfg: cfg, l: l, ln: ln, pc: pc, tlsCfg: tc,
		facOK: map[int]bool{}, facDeny: map[int]bool{}, minSev: 7,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{}),
		queue: make(chan *syslogRecord, l.Queue)}
	var err error
	if t.framing, err = syslogFraming(l.Framing); err != nil {
		return nil, err
	}
	if t.upFraming, err = syslogFraming(l.UpstreamFraming); err != nil {
		return nil, err
	}
	for _, f := range l.AllowFacilities {
		n, ok := syslog.FacilityNumber(f)
		if !ok {
			return nil, fmt.Errorf("syslog allow_facilities: %q", f)
		}
		t.facOK[n] = true
	}
	for _, f := range l.DenyFacilities {
		n, ok := syslog.FacilityNumber(f)
		if !ok {
			return nil, fmt.Errorf("syslog deny_facilities: %q", f)
		}
		t.facDeny[n] = true
	}
	if l.MinSeverity != "" {
		n, ok := syslog.SeverityNumber(l.MinSeverity)
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
		t.redact = append(t.redact, syslogRedaction{name: r.Name, re: re, with: with})
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

func syslogFraming(s string) (syslog.Framing, error) {
	switch s {
	case "octet_counting":
		return syslog.OctetCounting, nil
	case "non_transparent":
		return syslog.NonTransparent, nil
	case "auto":
		return syslog.Auto, nil
	}
	return 0, fmt.Errorf("syslog framing: %q", s)
}

func (t *syslogServer) serve() {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		defer safe.Guard("syslog forwarder")
		t.forward()
	}()
	if t.pc != nil {
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
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
			t.s.stats.SyslogRejected.Add(1)
			_ = c.Close()
			continue
		}
		if !t.admit(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.wg.Done()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("syslog stream")
			t.handleStream(c)
		}()
	}
}

func (t *syslogServer) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
	t.cons[c] = struct{}{}
	t.wg.Add(1)
	return true
}

func (t *syslogServer) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

func (t *syslogServer) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		_ = t.ln.Close()
		if t.pc != nil {
			_ = t.pc.Close()
		}
	})
	finished := make(chan struct{})
	go func() { t.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		t.mu.Lock()
		for c := range t.cons {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-finished
	}
}

// serveUDP reads datagrams. On UDP the sender's address is the only
// thing about a message that is not simply asserted, and even that is
// forgeable; allow_senders is the whole of the authentication there is.
func (t *syslogServer) serveUDP() {
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
func (t *syslogServer) handleStream(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := addrOf(c.RemoteAddr().String())
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
	t.s.stats.SyslogConnections.Add(1)
	r := syslog.NewReader(c, t.l.MaxMessageBytes, t.framing)
	for {
		if t.l.IdleTimeout > 0 {
			_ = c.SetReadDeadline(time.Now().Add(t.l.IdleTimeout.D()))
		}
		raw, err := r.ReadMessage()
		if err != nil {
			switch {
			case errors.Is(err, syslog.ErrOversizeSkipped):
				// The reader skipped to the next line ending and is at
				// a boundary again. One sender writing one long line
				// should not cost every record behind it.
				t.refuse(ip, "too_large", "")
				continue
			case errors.Is(err, syslog.ErrTooLarge), errors.Is(err, syslog.ErrMalformed):
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

func (t *syslogServer) senderAllowed(ip netip.Addr) bool {
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
func (t *syslogServer) take(raw []byte, from netip.Addr) {
	t.s.stats.SyslogReceived.Add(1)
	if !t.senderAllowed(from) {
		t.refuse(from, "sender_refused", "")
		return
	}
	if t.limiter != nil && !t.limiter.allow(from) {
		t.s.stats.SyslogRateLimited.Add(1)
		return
	}
	m, err := syslog.Parse(raw)
	if err != nil {
		// A message the relay could not read is a message whose
		// facility, severity and host are unknown, which is every field
		// a rule here decides on.
		t.refuse(from, "malformed", err.Error())
		return
	}
	if reason := t.filter(m); reason != "" {
		t.s.stats.SyslogDropped.Add(1)
		return
	}
	t.rewrite(&m, from)
	select {
	case t.queue <- &syslogRecord{msg: m, from: from}:
	default:
		// The collector is behind. Dropping here keeps one slow
		// collector from blocking every sender, and it is counted so
		// the gap is visible rather than guessed at.
		t.s.stats.SyslogQueueDropped.Add(1)
	}
}

// filter applies what a message claims to be. It returns the reason it
// was dropped, or empty.
func (t *syslogServer) filter(m syslog.Message) string {
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
func (t *syslogServer) rewrite(m *syslog.Message, from netip.Addr) {
	for _, r := range t.redact {
		if r.re.MatchString(m.Message) {
			m.Message = r.re.ReplaceAllString(m.Message, r.with)
			m.Structured = append(m.Structured, syslog.SDElement{
				ID:     "xproxyRedaction@0",
				Params: []syslog.SDParam{{Name: "rule", Value: r.name}},
			})
			t.s.stats.SyslogRedacted.Add(1)
		}
	}
	switch t.l.Hostname {
	case "observed":
		m.Hostname = from.String()
	case "annotate":
		// The sender's name is often the useful one and is never the
		// true one, so both are kept and which is which is stated.
		m.Structured = append(m.Structured, syslog.SDElement{
			ID: "xproxyOrigin@0",
			Params: []syslog.SDParam{
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

func (t *syslogServer) refuse(ip netip.Addr, what, detail string) {
	t.s.stats.SyslogRefused.Add(1)
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "syslog"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.s.logs.SecurityEvent(context.Background(), "deny", "syslog_"+what, attrs...)
	if bl := t.s.bans.Load(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "syslog_denied")
	}
}

// forward writes queued records to the collector, keeping one
// connection open and rebuilding it when it fails. Everything it sends
// is RFC 5424 in one framing, whatever arrived: one dialect out is what
// makes the record the collector stores the record this relay decided
// about.
func (t *syslogServer) forward() {
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
		var rec *syslogRecord
		select {
		case <-t.done:
			return
		case rec = <-t.queue:
		}
		out := syslog.Frame(rec.msg.Format(), t.upFraming)
		for attempt := 0; attempt < 2; attempt++ {
			if conn == nil {
				c, e, p, err := t.dialCollector()
				if err != nil {
					t.s.stats.SyslogSendFailed.Add(1)
					t.s.logs.Error.Warn("syslog collector unavailable",
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
			t.s.stats.SyslogForwarded.Add(1)
			break
		}
	}
}

func (t *syslogServer) dialCollector() (net.Conn, *upstream.Endpoint, *upstream.Pool, error) {
	pool := t.s.rt.Load().pools[t.l.Upstream]
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

func (t *syslogServer) collectorTLS(ep *upstream.Endpoint) *tls.Config {
	tc := t.upTLS.Clone()
	if tc.ServerName == "" {
		if host, _, err := net.SplitHostPort(ep.Address); err == nil {
			tc.ServerName = host
		}
	}
	return tc
}

// syslogLimiter bounds what one sender may send. A log flood is a
// denial of service on the collector and a way to push older records
// out of whatever window it keeps, so the bound is per sender rather
// than per listener.
type syslogLimiter struct {
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

func newSyslogLimiter(rate, burst, max int) *syslogLimiter {
	if burst <= 0 {
		burst = rate
	}
	if max <= 0 {
		max = 65536
	}
	return &syslogLimiter{rate: float64(rate), burst: float64(burst), max: max,
		buckets: map[netip.Addr]*syslogBucket{}}
}

func (l *syslogLimiter) allow(ip netip.Addr) bool {
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
