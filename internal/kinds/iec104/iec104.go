// Package iec104 serves a kind: iec104 listener: an IEC 60870-5-104 relay
// for electricity transmission and distribution.
//
// IEC 104 is the protocol that operates the grid, and it has no security
// properties: a TCP connection on port 2404, no authentication, no
// integrity, no session. Anyone who can reach a substation gateway can
// trip a breaker on it. IEC 62351-3 wraps it in TLS and is almost nowhere
// deployed, because the controlled stations are substation equipment with
// twenty-year service lives and no upgrade path.
//
// So the relay is the only place a policy can live, and this is that
// place. It works in both directions:
//
//   - reverse: a control centre connects here and the relay dials the
//     substation. This is how an RTU that cannot be patched gets an allow
//     list, a command policy, enforced select-before-operate and an audit
//     trail of everything that was commanded.
//   - forward: the control centre uses this as the controlled egress to
//     reach stations elsewhere, and the routes say which stations it may
//     reach at all.
//
// Four things are deliberate in the data path.
//
// Every APDU is parsed whole. A relay that forwarded what it could not
// read would be forwarding what it could not decide about, and the
// substation behind it will read those octets somehow.
//
// Both directions are read. Most of this protocol's traffic is telemetry
// travelling up, and the policy is about commands travelling down -- but
// the sequence numbering is in both directions and only makes sense read
// as a pair, and a station sending an *activation* to its own control
// centre is a station behaving as a controlling station, which is worth
// refusing.
//
// The forwarding is full duplex and unserialised. Unlike Modbus, where a
// slave has one scan and a relay that pipelined into it would be a load
// generator, IEC 104 is designed for both ends to send when they have
// something to say. Serialising it would break the protocol's own flow
// control.
//
// And the metric payloads are never decoded. A measurement's scaled value,
// quality descriptor and timestamp are forwarded untouched: decoding every
// one of the hundred-odd types would be a second implementation of the
// standard, and a relay that got one wrong would corrupt a reading nobody
// could trace. What is read is the ASDU header, the object addresses and a
// command's qualifier -- which is what a policy is written about.
package iec104

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: iec104 listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	m      *config.IEC104Listener
	ln     net.Listener
	tlsCfg *tls.Config
	upTLS  *tls.Config

	policy  *Policy
	selects *selects
	limiter *limits.KeyedLimiter
	cmdRate *limits.KeyedLimiter

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
	// nextSession numbers connections, so that a selection belongs to the
	// connection that made it and to no other.
	nextSession atomic.Uint64
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	m := cfg.IEC104
	t := &server{host: host, cfg: cfg, m: m, ln: ln, tlsCfg: tc,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	var err error
	if t.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	t.selects = newSelects(m.MaxSelections, m.SelectTimeout.D(), time.Now)
	if m.UpstreamTLSMode == "implicit" {
		uc, _, err := tlsconf.Client(m.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("iec104 upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	if m.RateLimit > 0 {
		burst := m.RateBurst
		if burst <= 0 {
			burst = m.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burst, 65536)
	}
	if m.CommandRateLimit > 0 {
		burst := m.CommandRateBurst
		if burst <= 0 {
			burst = m.CommandRateLimit
		}
		// A separate limiter, because a control centre that sends a
		// thousand breaker commands a second is not a busy control
		// centre, and a frame limit loose enough for telemetry says
		// nothing about that.
		t.cmdRate = limits.NewKeyedLimiter(float64(m.CommandRateLimit), burst, 65536)
	}
	return t, nil
}

func (t *server) serve() {
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
		max := t.m.MaxConnections
		if max <= 0 {
			max = 32
		}
		if t.open.Add(1) > int64(max) {
			t.open.Add(-1)
			t.host.Counters().IEC104Rejected.Add(1)
			t.host.Counters().Refuse("iec104", "max_connections")
			_ = c.Close()
			continue
		}
		if !t.track(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.wg.Done()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("iec104 session")
			t.handle(c)
		}()
	}
}

func (t *server) track(c net.Conn) bool {
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
	})
	finished := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(finished)
	}()
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

// enforcing says whether this listener refuses for policy or only records
// what it would have refused.
func (t *server) enforcing() bool { return !t.cfg.Shadowing() }

// session is one controlling station's connection and the station
// connection it is relayed to.
type session struct {
	t      *server
	id     uint64
	client net.Conn
	up     net.Conn
	ip     netip.Addr
	secure bool
	live   *sessions.Session
	pool   *upstream.Pool
	ep     *upstream.Endpoint

	// upstreamName is the pool this session is relayed to, for the log.
	upstreamName string
	// down and upSeq follow the two directions' sequence numbers: down is
	// what the controlling station sends, upSeq what the station sends.
	down, upSeq seqState

	closed   atomic.Bool
	commands atomic.Uint64
	denied   atomic.Uint64
}

func (t *server) handle(client net.Conn) {
	s := t.host
	start := time.Now()
	s.Counters().IEC104Sessions.Add(1)
	s.Counters().IEC104SessionsOpen.Add(1)
	defer s.Counters().IEC104SessionsOpen.Add(-1)
	ip := netutil.AddrOf(client.RemoteAddr().String())
	se := &session{t: t, id: t.nextSession.Add(1), client: client, ip: ip}
	defer func() {
		// Every selection this connection held goes with it. A selection
		// that outlived its connection would let a later client execute
		// on an earlier one's intention, which is exactly the injection
		// the check exists to stop.
		t.selects.Close(se.id)
		if se.up != nil {
			_ = se.up.Close()
		}
		_ = client.Close()
	}()
	if !t.policy.Client(ip) {
		s.Counters().IEC104Rejected.Add(1)
		t.deny(ip, "client_not_allowed", "")
		t.log(se, start, "client_not_allowed")
		return
	}
	se.live = s.Sessions().Register(sessions.Info{
		Kind: "iec104", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer se.live.Done()
	if t.m.TLSMode == "implicit" || (t.tlsCfg != nil && t.m.TLSMode == "") {
		tc := tls.Server(client, t.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.deny(ip, "tls_handshake", err.Error())
			t.log(se, start, "tls_handshake")
			return
		}
		_ = tc.SetDeadline(time.Time{})
		se.client, se.secure = tc, true
	}
	if err := se.dial(); err != nil {
		s.Counters().IEC104UpstreamFail.Add(1)
		s.Logs().Error.Warn("iec104 station dial failed", "listener", t.cfg.Name,
			"client", ip.String(), "error", err.Error())
		t.log(se, start, "upstream_unavailable")
		return
	}
	reason := se.run()
	t.log(se, start, reason)
}

// dial opens the station connection, once, before either direction is
// pumped.
//
// Unlike the Modbus relay, which dials a device per unit identifier as
// frames arrive, this dials one station per session, and there is no
// per-address routing at all. The reason is the protocol's own shape: the
// first frame a control centre sends is STARTDT_act, a U-format frame with
// no common address in it, so a relay that chose a pool from the common
// address could not choose one until the first I frame -- by which time the
// association is up and the handshake answered. One listener per
// association is the honest shape, and common_addresses is what bounds
// which stations may be addressed through it.
func (se *session) dial() error {
	t := se.t
	name := t.m.Upstream
	if name == "" {
		return errors.New("no upstream for this listener")
	}
	se.upstreamName = name
	pool := t.host.Pool(name)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", name)
	}
	se.pool = pool
	timeout := t.m.ConnectTimeout.D()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			t.host.Logs().Error.Warn("iec104 station dial failed", "listener", t.cfg.Name,
				"endpoint", e.Address, "error", err.Error())
			continue
		}
		se.up, se.ep = c, e
		break
	}
	if se.up == nil {
		return errors.New("no reachable station endpoint")
	}
	if t.m.ProxyProtocol {
		if _, err := se.up.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
			return err
		}
	}
	if t.upTLS != nil {
		c := t.upTLS.Clone()
		if c.ServerName == "" && !c.InsecureSkipVerify {
			host, _, err := net.SplitHostPort(se.ep.Address)
			if err != nil {
				host = se.ep.Address
			}
			c.ServerName = host
		}
		tc := tls.Client(se.up, c)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return err
		}
		se.up = tc
	}
	if se.ep != nil {
		se.live.Annotate("", se.ep.Address, "")
	}
	return nil
}

// run relays in both directions until one end stops.
func (se *session) run() string {
	var wg sync.WaitGroup
	reasons := make(chan string, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("iec104 downstream")
		reasons <- se.pump(true)
		se.closed.Store(true)
		_ = se.up.Close()
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("iec104 upstream")
		reasons <- se.pump(false)
		se.closed.Store(true)
		_ = se.client.Close()
		_ = se.up.Close()
	}()
	wg.Wait()
	close(reasons)
	// The first reason that is not a plain close is the one worth
	// recording: "the station went away" says less than "a command was
	// refused and the centre gave up".
	first := ""
	for r := range reasons {
		if r != "" && (first == "" || first == "closed") {
			first = r
		}
	}
	if se.ep != nil && se.pool != nil {
		se.pool.End(se.ep, false, 0)
	}
	return first
}

// pump reads frames from one side, decides about them, and writes what is
// allowed to the other. fromClient says which side.
func (se *session) pump(fromClient bool) string {
	t := se.t
	src, dst := se.client, se.up
	if !fromClient {
		src, dst = se.up, se.client
	}
	// max_frame_bytes is a *policy* bound below the protocol's own, which
	// is already small: the length field is one octet, so no APDU can
	// exceed 257 octets whatever a station claims. The check is therefore
	// after the read rather than around it -- there is nothing to protect
	// memory from, and a listener whose stations only speak short frames
	// still gets to say so.
	max := t.m.MaxFrameBytes
	rd := wire.NewReader(src)
	idle := t.m.IdleTimeout.D()
	if idle <= 0 {
		idle = 120 * time.Second
	}
	for {
		if se.closed.Load() {
			return "closed"
		}
		_ = src.SetReadDeadline(time.Now().Add(idle))
		frame, err := rd.ReadFrame()
		if err != nil {
			if reason := se.readError(err, fromClient); reason != "" {
				return reason
			}
			return "closed"
		}
		t.host.Counters().IEC104Frames.Add(1)
		if max > 0 && len(frame.Raw) > max {
			t.host.Counters().IEC104Malformed.Add(1)
			t.host.Counters().Refuse("iec104", "frame_too_long")
			t.deny(se.ip, "iec104_frame_too_long", itoa(len(frame.Raw)))
			return "iec104_frame_too_long"
		}
		reason, allow := se.decide(frame, fromClient)
		if !allow {
			// How a refusal is answered is the listener's choice. The
			// default tells the truth in the protocol's own words: the same
			// ASDU back with the negative-confirm bit set and cause
			// actcon, which is what a station does when it will not carry
			// out a command, and what a control centre's alarm list
			// already understands.
			switch se.t.m.DenyResponse {
			case "", "negative":
				se.answerNegative(frame, fromClient)
			case "drop":
				// Nothing, which the centre reads as a timeout.
			case "close":
				return reason
			}
			continue
		}
		// Forward the octets that arrived rather than re-encoding them:
		// re-encoding is how a relay and a station come to disagree about
		// what was said.
		if _, err := dst.Write(frame.Raw); err != nil {
			return "closed"
		}
	}
}

// readError turns a reader failure into a reason, or the empty string for
// an ordinary end of connection.
func (se *session) readError(err error, fromClient bool) string {
	t := se.t
	switch {
	case errors.Is(err, wire.ErrStart), errors.Is(err, wire.ErrLength),
		errors.Is(err, wire.ErrShortASDU), errors.Is(err, wire.ErrObjects):
		// Malformed is not policy: a frame this could not read is a frame
		// it cannot decide about, and it is refused whether or not the
		// listener is enforcing (docs/CONFIG.md, the shadow table).
		t.host.Counters().IEC104Malformed.Add(1)
		t.host.Counters().Refuse("iec104", "malformed")
		from := "client"
		if !fromClient {
			from = "station"
		}
		t.deny(se.ip, "iec104_malformed", from+": "+err.Error())
		return "iec104_malformed"
	}
	return ""
}
