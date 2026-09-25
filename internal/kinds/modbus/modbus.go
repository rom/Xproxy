// Package modbus serves a kind: modbus listener: a Modbus relay that
// reads every frame and decides about it.
//
// Modbus is the protocol that runs the plant floor and has no security
// properties at all: no authentication, no integrity, no session. A frame
// says which device it is for, what to do and where, and the device does
// it. The devices cannot be fixed -- they are a decade old, the vendor is
// gone, and the process they run does not stop -- so the only place a
// policy can exist is in the path.
//
// This listener is that place. It works in both directions:
//
//   - reverse: masters connect here and it dials the devices. This is how
//     a PLC that cannot be patched gets an allow list, a read-only
//     historian, a value bound on a setpoint and an audit trail.
//   - forward: the plant's masters use it as the controlled egress to
//     reach devices elsewhere, and the routes say which destination each
//     unit identifier may reach at all.
//
// Two things are deliberate in the data path. Every frame is parsed
// whole, because a relay that forwarded what it could not read would be
// forwarding what it could not decide about -- and the device behind it
// will read those bytes somehow. And requests are serialised towards each
// device, because a Modbus slave has one scan: a relay that pipelined
// into it would be turning a policy engine into a load generator.
package modbus

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: modbus listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	m      *config.ModbusListener
	ln     net.Listener
	tlsCfg *tls.Config
	upTLS  *tls.Config

	policy    *Policy
	framing   wire.Framing
	upFraming wire.Framing
	routes    []*route
	learner   *Learner
	tracer    *Tracer
	limiter   *limits.KeyedLimiter

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
	// txn numbers the frames this relay originates towards a device
	// whose framing has no transaction identifier of its own.
	txn atomic.Uint32
}

// route is a compiled unit-identifier route.
type route struct {
	name     string
	units    ranges
	upstream string
	framing  wire.Framing
	override int // -1 for none
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	m := cfg.Modbus
	t := &server{host: host, cfg: cfg, m: m, ln: ln, tlsCfg: tc,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	var err error
	if t.framing, err = wire.FramingOf(m.Framing); err != nil {
		return nil, err
	}
	up := m.UpstreamFraming
	if up == "" {
		up = m.Framing
	}
	if t.upFraming, err = wire.FramingOf(up); err != nil {
		return nil, fmt.Errorf("upstream_%w", err)
	}
	if t.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	for i := range m.Routes {
		r := &m.Routes[i]
		cr := &route{name: r.Name, upstream: r.Upstream, framing: t.upFraming, override: -1}
		if cr.units, err = parseRanges("routes."+r.Name+".units", r.Units, 255); err != nil {
			return nil, err
		}
		if r.Framing != "" {
			if cr.framing, err = wire.FramingOf(r.Framing); err != nil {
				return nil, fmt.Errorf("routes.%s: %w", r.Name, err)
			}
		}
		if r.UnitOverride != nil {
			cr.override = *r.UnitOverride
		}
		t.routes = append(t.routes, cr)
	}
	if m.UpstreamTLSMode == "implicit" {
		uc, _, err := tlsconf.Client(m.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("modbus upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	if l := m.Learn; l != nil && l.Enabled {
		t.learner = NewLearner(cfg.Name, l.File, l.Interval.D(), l.MaxSubjects)
	}
	if tr := m.Trace; tr != nil {
		req := tr.Requests == nil || *tr.Requests
		resp := tr.Responses == nil || *tr.Responses
		tracer, err := NewTracer(cfg.Name, tr.File, tr.MaxBytes, tr.IncludeData, req, resp)
		if err != nil {
			return nil, err
		}
		t.tracer = tracer
	}
	if m.RateLimit > 0 {
		burst := m.RateBurst
		if burst <= 0 {
			burst = m.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burst, 65536)
	}
	return t, nil
}

func (t *server) serve() {
	if t.learner != nil {
		t.learner.Start(func(err error) {
			t.host.Logs().Error.Warn("modbus learning report could not be written",
				"listener", t.cfg.Name, "error", err.Error())
		})
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
		max := t.m.MaxConnections
		if max <= 0 {
			max = 64
		}
		if t.open.Add(1) > int64(max) {
			t.open.Add(-1)
			t.host.Counters().ModbusRejected.Add(1)
			t.host.Counters().Refuse("modbus", "max_connections")
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
			defer safe.Guard("modbus session")
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
	if err := t.learner.Stop(); err != nil {
		t.host.Logs().Error.Warn("modbus learning report could not be written at shutdown",
			"listener", t.cfg.Name, "error", err.Error())
	}
	_ = t.tracer.Close()
}

// session is one master's connection and the device connections it uses.
type session struct {
	t      *server
	client net.Conn
	ip     netip.Addr
	role   string
	secure bool
	live   *sessions.Session

	// workers are the per-route device connections, opened on demand:
	// one session may reach several devices when the routes send
	// different unit identifiers to different pools.
	workers map[string]*worker
	// writes serialises the frames written back to the master.
	writes chan []byte
	// pending bounds the requests in flight.
	pending chan struct{}

	requests, denied, exceptions atomic.Uint64
	closed                       atomic.Bool
	wg                           sync.WaitGroup
}

// worker serialises requests towards one device pool. A Modbus slave has
// one scan; a relay that pipelined into it would be a load generator
// wearing a policy engine's clothes.
type worker struct {
	route *route
	jobs  chan *job
	// conn is the device connection, rebuilt when it fails.
	conn net.Conn
	rd   *wire.Reader
	pool *upstream.Pool
	ep   *upstream.Endpoint
	once sync.Once
	done chan struct{}
}

// job is one request waiting for its device.
type job struct {
	req   request
	raw   []byte
	frame *wire.Frame
	// txn is the transaction identifier the master used, which the
	// answer has to carry whatever the device's framing does.
	txn uint16
}

func (t *server) handle(client net.Conn) {
	s := t.host
	start := time.Now()
	s.Counters().ModbusSessions.Add(1)
	s.Counters().ModbusSessionsOpen.Add(1)
	defer s.Counters().ModbusSessionsOpen.Add(-1)
	ip := netutil.AddrOf(client.RemoteAddr().String())
	se := &session{t: t, client: client, ip: ip,
		workers: map[string]*worker{}, writes: make(chan []byte, 16),
		pending: make(chan struct{}, t.m.Pending())}
	defer func() {
		se.stop()
		_ = client.Close()
	}()
	if !t.policy.ClientAllowed(ip) {
		t.host.Counters().ModbusRejected.Add(1)
		t.deny(ip, "client_not_allowed", "")
		t.log(se, start, "client_not_allowed")
		return
	}
	// Listed from here: a Modbus session is a device's connection that
	// lives for as long as the plant runs, so "who is connected and can
	// you get them off" is the question an operator has during an
	// incident. Closing the master's socket ends it; the per-device
	// workers are stopped by the deferred work above.
	se.live = s.Sessions().Register(sessions.Info{
		Kind: "modbus", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
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
		if reason := se.readRole(tc.ConnectionState()); reason != "" {
			t.host.Counters().ModbusRejected.Add(1)
			t.deny(ip, reason, "")
			t.log(se, start, reason)
			return
		}
	} else if t.policy.RoleRequired() {
		// A role can only come from a certificate, and a certificate can
		// only come from TLS. Saying so here rather than refusing every
		// frame is the difference between a misconfiguration and a
		// mystery.
		t.deny(ip, "security_requires_tls", "")
		t.log(se, start, "security_requires_tls")
		return
	}
	reason := se.run()
	t.log(se, start, reason)
}

// readRole reads the Modbus/TCP Security role out of the client
// certificate and applies the role policy.
func (se *session) readRole(st tls.ConnectionState) string {
	p := se.t.policy
	if p.RoleMode() == "off" {
		return ""
	}
	var cert *x509.Certificate
	if len(st.PeerCertificates) > 0 {
		cert = st.PeerCertificates[0]
	}
	if cert == nil {
		if p.RoleRequired() {
			return "no_client_certificate"
		}
		return ""
	}
	var role string
	var err error
	switch p.RoleSource() {
	case "cn", "ou":
		role, err = wire.RoleFromSubject(cert, p.RoleSource())
	default:
		role, err = wire.RoleFromCert(cert)
	}
	if err != nil {
		if p.RoleRequired() {
			return "no_role"
		}
		return ""
	}
	if !p.RoleAllowed(role) {
		return "role_not_allowed"
	}
	se.role = role
	se.live.Annotate(role, "", "")
	return ""
}

// run reads frames from the master until the connection ends.
func (se *session) run() string {
	t := se.t
	se.wg.Add(1)
	go func() {
		defer se.wg.Done()
		defer safe.Guard("modbus writer")
		for b := range se.writes {
			if _, err := se.client.Write(b); err != nil {
				se.closed.Store(true)
				return
			}
		}
	}()
	max := t.m.MaxFrameBytes
	if max <= 0 {
		max = wire.MaxADU
	}
	rd := wire.NewReader(&limitedReader{r: se.client, max: max}, t.framing, true)
	idle := t.m.IdleTimeout.D()
	if idle <= 0 {
		idle = 120 * time.Second
	}
	for {
		_ = se.client.SetReadDeadline(time.Now().Add(idle))
		frame, raw, err := rd.ReadFrame()
		if err != nil {
			if errors.Is(err, wire.ErrChecksum) || errors.Is(err, wire.ErrProtocol) ||
				errors.Is(err, wire.ErrLength) || errors.Is(err, wire.ErrFormat) ||
				errors.Is(err, wire.ErrUnknownFunction) {
				t.host.Counters().ModbusMalformed.Add(1)
				t.deny(se.ip, "framing", err.Error())
				return "framing"
			}
			return ""
		}
		if len(raw) > max {
			t.host.Counters().ModbusMalformed.Add(1)
			t.deny(se.ip, "frame_too_large", "")
			return "frame_too_large"
		}
		if t.limiter != nil && !t.limiter.Allow(se.ip.String()) {
			t.host.Counters().ModbusRateLimited.Add(1)
			t.host.Counters().Refuse("modbus", "rate_limit")
			continue
		}
		pdu, err := wire.ParseRequest(frame.PDU)
		if err != nil {
			// A frame the relay cannot read is a frame it cannot decide
			// about, and the device would read those bytes somehow.
			t.host.Counters().ModbusMalformed.Add(1)
			t.deny(se.ip, "malformed", err.Error())
			se.answerException(frame, wire.FCReadHoldingRegisters, wire.ExIllegalFunction, frame.PDU)
			return "malformed"
		}
		t.host.Counters().ModbusRequests.Add(1)
		se.requests.Add(1)
		req := request{client: se.ip, role: se.role, unit: frame.Unit, pdu: pdu}
		decision := t.policy.Decide(req)
		enforcing := t.enforcing()
		observed := t.policy.Observed(req)
		t.learner.Observe(req, decision.Allow, time.Now())
		t.traceRequest(se, frame, raw, pdu, decision, observed)
		if !decision.Allow && enforcing {
			se.denied.Add(1)
			t.host.Counters().ModbusDenied.Add(1)
			t.refuse(se, frame, pdu, decision)
			switch t.m.DenyResponse {
			case "drop":
				continue
			case "close":
				return "denied"
			default:
				se.answerException(frame, pdu.Function, exceptionFor(decision), nil)
				continue
			}
		}
		if !decision.Allow {
			// Shadow mode, or learning without enforcement: the refusal
			// is recorded and the frame goes on, which is the only honest
			// way to find out what a policy would have broken.
			t.host.Counters().ModbusWouldDeny.Add(1)
			t.host.Counters().WouldRefuse("modbus", decision.Reason)
			t.audit(se, frame, pdu, decision, "would_deny")
			t.host.Shadow().Record("modbus", t.cfg.Name, decision.Reason, decision.Rule,
				fmt.Sprintf("unit %d %s %s", frame.Unit, wire.FunctionName(pdu.Function), pdu.Access))
		}
		if t.m.LogFrames {
			t.logFrame(se, frame, pdu, decision)
		}
		w, reason := se.workerFor(frame.Unit)
		if reason != "" {
			t.host.Counters().ModbusDenied.Add(1)
			se.denied.Add(1)
			t.deny(se.ip, reason, fmt.Sprintf("unit %d", frame.Unit))
			se.answerException(frame, pdu.Function, wire.ExGatewayPathUnavail, nil)
			continue
		}
		select {
		case se.pending <- struct{}{}:
		case <-time.After(t.requestTimeout()):
			// Every slot is taken by a request the device has not
			// answered: the device is the bottleneck, and saying so as
			// a gateway exception is what a master understands.
			t.host.Counters().ModbusQueueFull.Add(1)
			t.host.Counters().Refuse("modbus", "queue_full")
			se.answerException(frame, pdu.Function, wire.ExServerBusy, nil)
			continue
		}
		// The values this write carries become what the relay knows about
		// those addresses: the next write's delta, transition and rate are
		// measured against them. Recorded here, where the frame has been
		// allowed and is about to reach the device.
		t.policy.observeWrite(req, time.Now())
		// The value table's own numbers, so an operator can see how many
		// addresses the policy knows a value for and how often a check
		// ran without one.
		points, unknown, _ := t.policy.ValueState()
		t.host.Counters().ModbusValuePoints.Store(int64(points))
		t.host.Counters().ModbusValueUnknown.Store(unknown)
		j := &job{req: req, raw: raw, frame: frame, txn: frame.Transaction}
		select {
		case w.jobs <- j:
		case <-w.done:
			<-se.pending
			se.answerException(frame, pdu.Function, wire.ExGatewayNoResponse, nil)
		}
	}
}

// enforcing says whether the policy decides or only records. A learning
// run is observe-only unless it says otherwise, which is what stops one
// being left on by accident, and a listener in shadow mode records
// without deciding whether or not it is learning.
func (t *server) enforcing() bool {
	if t.cfg.Shadowing() {
		return false
	}
	l := t.m.Learn
	if l == nil || !l.Enabled {
		return true
	}
	return l.Enforce
}

func (t *server) requestTimeout() time.Duration {
	if d := t.m.RequestTimeout.D(); d > 0 {
		return d
	}
	return 5 * time.Second
}

// workerFor finds or starts the worker for a unit identifier.
func (se *session) workerFor(unit byte) (*worker, string) {
	t := se.t
	var chosen *route
	for _, r := range t.routes {
		if r.units.has(int(unit)) {
			chosen = r
			break
		}
	}
	if chosen == nil {
		if t.m.Upstream == "" {
			// A forward listener with no route for a unit has nowhere to
			// send it, and inventing a destination is the one thing an
			// egress gateway must not do.
			return nil, "no_route_for_unit"
		}
		chosen = &route{name: "default", upstream: t.m.Upstream, framing: t.upFraming, override: -1}
	}
	if w := se.workers[chosen.name]; w != nil {
		return w, ""
	}
	w := &worker{route: chosen, jobs: make(chan *job, t.m.Pending()), done: make(chan struct{})}
	se.workers[chosen.name] = w
	se.wg.Add(1)
	go func() {
		defer se.wg.Done()
		defer safe.Guard("modbus device worker")
		se.serveWorker(w)
	}()
	return w, ""
}

// serveWorker runs one device connection: write a request, read its
// answer, hand it back. In order, because the device has one scan.
func (se *session) serveWorker(w *worker) {
	t := se.t
	defer func() {
		w.once.Do(func() { close(w.done) })
		if w.conn != nil {
			_ = w.conn.Close()
		}
		if w.ep != nil && w.pool != nil {
			w.pool.End(w.ep, false, 0)
		}
	}()
	for {
		var j *job
		select {
		case <-t.done:
			return
		case j = <-w.jobs:
		}
		if j == nil {
			return
		}
		resp, pdu, err := se.exchange(w, j)
		<-se.pending
		if err != nil {
			t.host.Counters().ModbusUpstreamFailed.Add(1)
			t.host.Logs().Error.Warn("modbus device exchange failed", "listener", t.cfg.Name,
				"unit", j.frame.Unit, "route", w.route.name, "error", err.Error())
			se.answerException(j.frame, j.req.pdu.Function, wire.ExGatewayNoResponse, nil)
			continue
		}
		t.host.Counters().ModbusResponses.Add(1)
		if pdu != nil && pdu.IsException {
			t.host.Counters().ModbusExceptions.Add(1)
			se.exceptions.Add(1)
			t.learner.ObserveException(j.req, time.Now())
		}
		// A read's answer is the other half of what the relay knows: a
		// master polling a register tells this policy what the register
		// holds, which is what a delta or a transition is measured
		// against. An exception says nothing about a value.
		if pdu != nil && !pdu.IsException {
			t.policy.observeRead(j.req, pdu, time.Now())
		}
		t.traceResponse(se, w, j, resp, pdu)
		se.send(resp)
	}
}

// exchange writes one request to the device and reads its answer,
// dialling or redialling as needed.
func (se *session) exchange(w *worker, j *job) ([]byte, *wire.PDU, error) {
	t := se.t
	for attempt := 0; attempt < 2; attempt++ {
		if w.conn == nil {
			if err := se.dial(w); err != nil {
				return nil, nil, err
			}
		}
		unit := j.frame.Unit
		if w.route.override >= 0 {
			unit = byte(w.route.override)
		}
		out := j.raw
		if w.route.framing != t.framing || unit != j.frame.Unit {
			// The framings differ or the unit is rewritten, so the frame
			// is built rather than forwarded. Everywhere else the bytes
			// that arrived are the bytes that go on: re-encoding a frame
			// is how a relay and a device come to disagree about what
			// was said.
			out = wire.Encode(w.route.framing, &wire.Frame{
				Transaction: uint16(t.txn.Add(1)), //nolint:gosec // a wrapping counter is what the field is
				Unit:        unit, PDU: j.frame.PDU})
		}
		deadline := time.Now().Add(t.requestTimeout())
		_ = w.conn.SetDeadline(deadline)
		if _, err := w.conn.Write(out); err != nil {
			se.dropConn(w)
			if attempt == 0 {
				continue
			}
			return nil, nil, err
		}
		w.rd.Expect(j.req.pdu.Function)
		frame, raw, err := w.rd.ReadFrame()
		if err != nil {
			se.dropConn(w)
			if attempt == 0 && isTemporary(err) {
				continue
			}
			return nil, nil, err
		}
		pdu, perr := wire.ParseResponse(frame.PDU, j.req.pdu)
		if perr != nil {
			// The device answered something this relay cannot read. The
			// master must not be handed it: the two would read the same
			// bytes differently, which is the whole class of bug this
			// relay exists to prevent.
			t.host.Counters().ModbusMalformed.Add(1)
			t.deny(se.ip, "malformed_response", perr.Error())
			return wire.Encode(t.framing, &wire.Frame{Transaction: j.txn, Unit: j.frame.Unit,
				PDU: wire.ExceptionPDU(j.req.pdu.Function, wire.ExServerFailure)}), nil, nil
		}
		if frame.Unit != unit && t.framing == wire.FramingTCP {
			// A device answering for another unit identifier is either a
			// gateway with a bug or an answer to somebody else's
			// request. Either way it is not this exchange's answer.
			t.host.Counters().ModbusMalformed.Add(1)
			t.deny(se.ip, "response_unit_mismatch",
				fmt.Sprintf("asked %d, answered %d", unit, frame.Unit))
			return wire.Encode(t.framing, &wire.Frame{Transaction: j.txn, Unit: j.frame.Unit,
				PDU: wire.ExceptionPDU(j.req.pdu.Function, wire.ExServerFailure)}), nil, nil
		}
		out = raw
		if w.route.framing != t.framing || unit != j.frame.Unit {
			out = wire.Encode(t.framing, &wire.Frame{Transaction: j.txn, Unit: j.frame.Unit, PDU: frame.PDU})
		} else if t.framing == wire.FramingTCP {
			// The transaction identifier the master used is the one the
			// master matches on, and a gateway that renumbered it would
			// break every master that has more than one request in
			// flight.
			out = wire.Encode(wire.FramingTCP, &wire.Frame{Transaction: j.txn, Unit: frame.Unit, PDU: frame.PDU})
		}
		return out, pdu, nil
	}
	return nil, nil, errors.New("modbus: no answer from the device")
}

func isTemporary(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, net.ErrClosed)
}

func (se *session) dropConn(w *worker) {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
	if w.ep != nil && w.pool != nil {
		w.pool.End(w.ep, true, 0)
		w.ep = nil
	}
}

// dial opens the device connection for a route.
func (se *session) dial(w *worker) error {
	t := se.t
	pool := t.host.Pool(w.route.upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", w.route.upstream)
	}
	w.pool = pool
	tried := map[*upstream.Endpoint]bool{}
	timeout := t.m.ConnectTimeout.D()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
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
			t.host.Logs().Error.Warn("modbus device dial failed", "listener", t.cfg.Name,
				"route", w.route.name, "endpoint", e.Address, "error", err.Error())
			continue
		}
		w.conn, w.ep = c, e
		break
	}
	if w.conn == nil {
		return errors.New("no reachable device endpoint")
	}
	if t.m.ProxyProtocol {
		if _, err := w.conn.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
			se.dropConn(w)
			return err
		}
	}
	if t.upTLS != nil {
		c := t.upTLS.Clone()
		if c.ServerName == "" && !c.InsecureSkipVerify {
			host, _, err := net.SplitHostPort(w.ep.Address)
			if err != nil {
				host = w.ep.Address
			}
			c.ServerName = host
		}
		tc := tls.Client(w.conn, c)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			se.dropConn(w)
			return err
		}
		w.conn = tc
	}
	max := t.m.MaxFrameBytes
	if max <= 0 {
		max = wire.MaxADU
	}
	w.rd = wire.NewReader(&limitedReader{r: w.conn, max: max}, w.route.framing, false)
	return nil
}

// send queues a frame for the master.
func (se *session) send(b []byte) {
	if se.closed.Load() {
		return
	}
	select {
	case se.writes <- b:
	case <-time.After(se.t.requestTimeout()):
		se.closed.Store(true)
	}
}

// answerException answers a request with an exception, which is how this
// relay refuses without ending the session: the master reads it as the
// device's own refusal and carries on.
func (se *session) answerException(frame *wire.Frame, fc, code byte, _ []byte) {
	se.send(wire.Encode(se.t.framing, &wire.Frame{
		Transaction: frame.Transaction, Unit: frame.Unit, PDU: wire.ExceptionPDU(fc, code)}))
}

// exceptionFor maps a refusal to the exception a master will read. An
// illegal function for a code the policy does not permit, an illegal data
// address for a range it does not permit: a master's diagnostics then say
// something true about what was refused.
func exceptionFor(d Decision) byte {
	switch d.Reason {
	case "read_only", "read_only_unknown_function", "rule_deny", "no_rule":
		return wire.ExIllegalFunction
	case "value_out_of_range", "coil_set_not_allowed", "coil_clear_not_allowed", "value_masked_write",
		"value_delta", "value_transition", "value_no_select", "value_unknown":
		// Every one of these is a statement about the value asked for,
		// which is what an illegal data value means to a master's own
		// diagnostics.
		return wire.ExIllegalValue
	case "value_rate":
		// Not an illegal value: the same write would be accepted later.
		// Server busy is the nearest true thing the protocol has, and a
		// master reads it as "ask again".
		return wire.ExServerBusy
	case "unit_not_allowed":
		return wire.ExGatewayPathUnavail
	}
	return wire.ExIllegalAddress
}

func (se *session) stop() {
	close(se.writes)
	for _, w := range se.workers {
		w.once.Do(func() { close(w.done) })
	}
	se.wg.Wait()
}

// limitedReader bounds what one frame may read, so a length field that
// lies costs a bounded read rather than the process's memory.
type limitedReader struct {
	r   net.Conn
	max int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if len(p) > l.max {
		p = p[:l.max]
	}
	return l.r.Read(p)
}

// deny writes a security event and counts a refusal.
func (t *server) deny(ip netip.Addr, what, detail string) {
	t.host.Counters().ModbusRefused.Add(1)
	t.host.Counters().Refuse("modbus", what)
	if !t.m.Alerts() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "modbus"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "modbus_"+what, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "modbus_denied")
	}
}

// refuse records a frame the policy refused: the event carries what was
// asked for, because "a write was refused" is not an audit trail and
// "unit 3, write_single_register at 40010, value 900, rule setpoints" is.
func (t *server) refuse(se *session, frame *wire.Frame, pdu *wire.PDU, d Decision) {
	t.host.Counters().Refuse("modbus", d.Reason)
	if !t.m.Alerts() {
		return
	}
	t.audit(se, frame, pdu, d, "deny")
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "modbus_denied")
	}
}

// audit writes the security event for one decision.
func (t *server) audit(se *session, frame *wire.Frame, pdu *wire.PDU, d Decision, kind string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "proto", "modbus",
		"unit", frame.Unit, "function", wire.FunctionName(pdu.Function),
		"access", string(pdu.Access), "reason", d.Reason}
	if se.role != "" {
		attrs = append(attrs, "role", se.role)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Comment != "" {
		attrs = append(attrs, "comment", d.Comment)
	}
	if pdu.HasRange {
		attrs = append(attrs, "address", pdu.Address, "quantity", pdu.Quantity)
	}
	if len(pdu.Registers) > 0 {
		attrs = append(attrs, "value", pdu.Registers[0])
	}
	t.host.Logs().SecurityEvent(context.Background(), kind, "modbus_"+d.Reason, attrs...)
}

// logFrame writes the per-frame access line: the audit trail a plant is
// asked for.
func (t *server) logFrame(se *session, frame *wire.Frame, pdu *wire.PDU, d Decision) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "tls", se.secure,
		"unit", frame.Unit, "transaction", frame.Transaction,
		"function", wire.FunctionName(pdu.Function), "access", string(pdu.Access),
		"decision", decisionName(d)}
	if se.role != "" {
		attrs = append(attrs, "role", se.role)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if pdu.HasRange {
		attrs = append(attrs, "address", pdu.Address, "quantity", pdu.Quantity)
	}
	t.host.Logs().Access.Info("modbus", attrs...)
}

func decisionName(d Decision) string {
	if d.Allow {
		return "allow"
	}
	return "deny"
}

func (t *server) traceRequest(se *session, frame *wire.Frame, raw []byte, pdu *wire.PDU, d Decision, observed []string) {
	if t.tracer == nil {
		return
	}
	e := TraceEntry{Client: se.ip.String(), Role: se.role, Transaction: frame.Transaction,
		Unit: frame.Unit, Decision: decisionName(d), Rule: d.Rule}
	if len(observed) > 0 {
		e.Rule = strings.Join(append([]string{d.Rule}, observed...), ",")
	}
	t.tracer.Request(e, pdu, raw)
}

func (t *server) traceResponse(se *session, w *worker, j *job, raw []byte, pdu *wire.PDU) {
	if t.tracer == nil {
		return
	}
	e := TraceEntry{Client: se.ip.String(), Role: se.role, Transaction: j.txn,
		Unit: j.frame.Unit, Upstream: w.route.upstream}
	t.tracer.Response(e, pdu, raw)
}

// log writes the session's access line.
func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "tls", se.secure,
		"framing", t.framing.String(), "mode", t.mode(),
		"requests", se.requests.Load(), "denied", se.denied.Load(),
		"exceptions", se.exceptions.Load(),
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if se.role != "" {
		attrs = append(attrs, "role", se.role)
	}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.host.Logs().Access.Info("modbus", attrs...)
}

func (t *server) mode() string {
	if t.m.Mode == "forward" {
		return "forward"
	}
	return "reverse"
}
