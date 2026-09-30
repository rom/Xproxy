package s7

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/s7"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: s7 listener.
type server struct {
	host    proxy.Host
	cfg     config.Listener
	name    string
	sc      *config.S7Listener
	policy  *policy
	decoy   *decoy
	learner *learner
	ln      net.Listener

	// limiter bounds requests per second per client address.
	limiter *limits.KeyedLimiter

	// anomaly is the behavioural models, nil when the block is off.
	anomaly *anomaly.Detector

	// engineering recognises the plant's own tooling and ties it to an
	// approved work order.
	engineering *engineering.Guard

	// gate bounds the sessions held, altogether and per client address.
	gate *sesslimit.Gate

	// sessions tracks what has been accepted, so shutdown waits for it. A
	// bare WaitGroup would not do: its Add must not race its Wait, and an
	// accept loop Adds at exactly the moment a shutdown Waits.
	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener) (*server, error) {
	p, err := compile(cfg.S7)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, sc: cfg.S7, policy: p, ln: ln,
		gate: sesslimit.New(cfg.S7.MaxSessions, cfg.S7.MaxSessionsPerClient)}
	if t.decoy, err = newDecoy(cfg.S7.Deception, cfg.Name); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	if l := cfg.S7.Learn; l != nil && l.Enabled {
		t.learner = newLearner(&learnConfig{
			enabled: true, listener: cfg.Name, file: l.File,
			interval: l.Interval.D(), maxSubjects: l.MaxSubjects,
		})
	}
	if n := cfg.S7.RateLimit; n > 0 {
		burst := cfg.S7.RateBurst
		if burst <= 0 {
			burst = n
		}
		t.limiter = limits.NewKeyedLimiter(float64(n), burst, 0)
	}
	if t.anomaly, err = anomaly.FromConfig(cfg.S7.Anomaly, time.Now()); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	if t.engineering, err = engineering.FromConfig(cfg.S7.Engineering, "s7", cfg.Name,
		host.Access(), host.Logs().Error); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	return t, nil
}

// enforcing says whether the policy decides or only records.
//
// A learning run is observe-only unless it says otherwise, which is what stops
// one being left on by accident: the point of learning is to find out what the
// traffic is, and a run that refused half of it has changed the thing it was
// measuring.
func (t *server) enforcing() bool {
	if t.sc.MonitorOnly || t.cfg.Shadowing() {
		return false
	}
	l := t.sc.Learn
	if l == nil || !l.Enabled {
		return true
	}
	return l.Enforce
}

func (t *server) maxFrame() int {
	if n := t.sc.MaxFrameBytes; n > 0 {
		return n
	}
	return wire.DefaultMaxFrame
}

func (t *server) serve() {
	if t.learner != nil {
		t.learner.Start(func(err error) {
			t.host.Logs().Error.Warn("s7 learning report could not be written",
				"listener", t.name, "error", err.Error())
		})
	}
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if t.sessions.Closing() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if !t.sessions.Enter() {
			// Accepted as the listener was shutting down. Serving it would
			// start a session nothing waits for, so it is closed instead.
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer safe.Guard("s7 session")
			t.handle(c)
		}()
	}
}

func (t *server) shutdown(ctx context.Context) {
	if !t.sessions.Close() {
		return
	}
	_ = t.ln.Close()
	t.sessions.Wait(ctx)
	if err := t.learner.Stop(); err != nil {
		t.host.Logs().Error.Warn("s7 learning report could not be written at shutdown",
			"listener", t.name, "error", err.Error())
	}
}

// session is one connection and the state the policy needs it to have.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cliReader *wire.Reader
	upReader  *wire.Reader

	cmu sync.Mutex
	umu sync.Mutex

	mu         sync.Mutex
	rack, slot int
	resource   uint8
	addressed  bool
	pduLength  int
	requests   int
	denied     int
	// learnSubjects are the subjects the last request belonged to, so that an
	// access fault coming back can be attributed to them. A response says
	// which function failed and never which block, so the request is the only
	// place the block was known. Guarded by mu because the two directions are
	// separate goroutines.
	learnSubjects []learnKey
}

func (se *session) sess() *Session {
	se.mu.Lock()
	defer se.mu.Unlock()
	return &Session{IP: se.ip, Rack: se.rack, Slot: se.slot, Resource: se.resource,
		Addressed: se.addressed, PDULength: se.pduLength, At: time.Now()}
}

func (se *session) addressedAs(s *Session) {
	se.mu.Lock()
	se.rack, se.slot, se.resource, se.addressed = s.Rack, s.Slot, s.Resource, s.Addressed
	se.mu.Unlock()
}

func (se *session) negotiated(n int) {
	se.mu.Lock()
	se.pduLength = n
	se.mu.Unlock()
}

func (se *session) count() int {
	se.mu.Lock()
	defer se.mu.Unlock()
	se.requests++
	return se.requests
}

func (se *session) refusal() {
	se.mu.Lock()
	se.denied++
	se.mu.Unlock()
}

func (se *session) writeClient(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.cmu.Lock()
	defer se.cmu.Unlock()
	_, err := se.client.Write(b)
	return err
}

func (se *session) writeUp(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.umu.Lock()
	defer se.umu.Unlock()
	_, err := se.up.Write(b)
	return err
}

// handle runs one connection.
//
// The first frame decides where it goes: a COTP connection request carries the
// rack and the slot of the CPU, so a client that may not reach that controller
// is refused **before the PLC is dialled**. That ordering is the point rather
// than an optimisation: a CPU has very few connection resources -- an S7-300
// has sixteen altogether -- and a client that may not reach it should not take
// one of them.
// admitClient is the two questions this relay asks about a client that has no
// identity: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// S7comm names nobody -- a client is an address and a rack and slot -- so the
// policy decides on the address, the listener, the pool and the hour. Which
// functions and which data blocks that client may touch is the `s7` policy's own
// business, because it is the thing that can say what a write to DB1 means.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists:   h.ThreatIntel(),
		Policy:  h.Authorization(),
		Logs:    h.Logs(),
		Matched: func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked: func() { h.Counters().ThreatIntelBlocked.Add(1) },
		// One fact per connection, to the cross-listener window: this
		// address was on this listener. It is what the questions no
		// listener can answer by itself are built from -- one host on
		// three control protocols is three of these facts and one actor.
		Observe: func(f correlate.Fact) { h.ObserveFact(ip, f) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "s7",
		Client:   ip,
		Target:   t.sc.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("s7", reason)
			h.Shadow().Record("s7", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

func (t *server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	se := &session{t: t, ip: ip, client: c}

	if d := t.policy.Connect(se.sess()); !d.Allow {
		t.refused(se, d, "connect")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own address lists -- those are local policy about local
	// clients -- and before the PLC is dialled.
	if t.admitClient(ip) != "" {
		return
	}
	if !t.admit(se) {
		return
	}
	defer t.release(se)

	// The connection request, under the handshake timeout: a client that
	// opens a socket and says nothing is a client holding a slot.
	_ = se.client.SetReadDeadline(time.Now().Add(t.handshakeTimeout()))
	se.cliReader = wire.NewReader(se.client, t.maxFrame())
	first, err := se.cliReader.Next()
	if err != nil {
		t.deny(ip, "no_connection_request", err.Error())
		return
	}
	_ = se.client.SetReadDeadline(time.Time{})
	cr, err := wire.ParseCOTP(first.Payload)
	if err != nil {
		t.deny(ip, "unreadable_frame", err.Error())
		return
	}
	s := se.sess()
	if d := t.policy.Connection(s, cr); !d.Allow {
		se.addressedAs(s)
		t.refused(se, d, cr.TypeName())
		if t.policy.respond != "drop" {
			_ = se.writeClient(disconnect(cr.SrcRef, cr.DstRef))
		}
		return
	}
	se.addressedAs(s)
	t.observe(se, cr)

	// A listener that is nothing but a fabricated controller answers here,
	// and nothing is dialled: there is no CPU behind it to reach. The
	// client has already passed this listener's own address lists, the
	// imported feeds and the rack and slot policy above.
	if d := t.decoy; d != nil && d.whole && d.admits(ip) {
		reason := se.serveDecoy(cr)
		s := se.sess()
		t.host.Logs().Access.Info("s7 decoy session", "listener", t.name,
			"client_ip", ip.String(), "proto", "s7", "rack", s.Rack, "slot", s.Slot,
			"requests", se.count()-1, "reason", reason)
		return
	}
	up, err := t.dial(se)
	if err != nil {
		t.deny(ip, "upstream_unavailable", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	se.up = up
	se.upReader = wire.NewReader(up, t.maxFrame())
	if err := se.writeUp(first.Raw); err != nil {
		t.deny(ip, "upstream_unavailable", err.Error())
		return
	}
	t.relay(se)
}

// admit and release bound the sessions this listener holds, and the counting
// is internal/sesslimit's rather than this file's. Six kinds had their own copy
// and all six read a counter and then incremented it, so concurrent accepts
// could pass the bound; the shared gate takes the count under the lock that
// checked it.
func (t *server) admit(se *session) bool {
	ok, reason := t.gate.Enter(se.ip)
	if !ok {
		t.deny(se.ip, reason, "")
	}
	return ok
}

func (t *server) release(se *session) { t.gate.Leave(se.ip) }

func (t *server) handshakeTimeout() time.Duration {
	if d := t.sc.HandshakeTimeout.D(); d > 0 {
		return d
	}
	return 30 * time.Second
}

// dial opens the connection to the PLC.
func (t *server) dial(se *session) (net.Conn, error) {
	pool := t.host.Pool(t.sc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.sc.Upstream)
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: 10 * time.Second}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			continue
		}
		return c, nil
	}
	return nil, errors.New("no reachable s7 endpoint")
}

// relay runs both directions.
func (t *server) relay(se *session) {
	if d := t.sc.SessionDuration.D(); d > 0 {
		_ = se.client.SetDeadline(time.Now().Add(d))
		_ = se.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("s7 plc reader")
		t.fromPLC(se)
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("s7 client reader")
		t.fromClient(se)
		_ = se.up.Close()
	}()
	wg.Wait()
}

// fromClient reads the client's frames and applies the policy.
func (t *server) fromClient(se *session) {
	max := t.sc.MaxRequests
	for {
		if idle := t.sc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		f, err := se.cliReader.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.deny(se.ip, "unreadable_frame", err.Error())
			}
			return
		}
		c, err := wire.ParseCOTP(f.Payload)
		if err != nil {
			t.deny(se.ip, "unreadable_frame", err.Error())
			return
		}
		if !c.Known() {
			// A transport PDU type nobody here understands. Forwarding it
			// would be forwarding something to a controller with no policy
			// applied to it at all.
			t.refuse(se, hard("cotp_type_unknown", c.TypeName()), c.TypeName())
			return
		}
		switch c.Type {
		case wire.COTPData, wire.COTPExpeditedData:
		default:
			// A disconnect, an acknowledgement or a reject: transport
			// housekeeping with no S7 inside it.
			if err := se.writeUp(f.Raw); err != nil {
				return
			}
			continue
		}
		if t.limiter != nil && !t.limiter.Allow(se.ip.String()) {
			t.refused(se, hard("rate_limited", ""), "")
			// A rate limit is not a reason to end a plant connection: the
			// request is refused and the session carries on, which is what
			// the modbus kind does for the same reason.
			continue
		}
		if n := se.count(); max > 0 && n > max {
			t.refuse(se, hard("too_many_requests", fmt.Sprint(max)), "")
			return
		}
		ok, fatal := t.decide(se, c)
		if fatal {
			return
		}
		if !ok {
			continue
		}
		if err := se.writeUp(f.Raw); err != nil {
			return
		}
	}
}

// decide applies the policy to one COTP data PDU.
func (t *server) decide(se *session, c *wire.COTP) (forward, fatal bool) {
	// Which of the two protocols this is, which is one octet's worth of
	// question. An S7-1200 or S7-1500 driven by TIA Portal speaks
	// S7comm-plus, and a relay that read only classic S7comm ended the
	// connection on its first PDU -- so the controllers an estate has
	// actually bought since about 2012 could not be put behind it at all.
	if wire.IsPlus(c.Data) {
		return t.decidePlus(se, c)
	}
	pdu, err := wire.ParseS7(c.Data)
	if err != nil {
		// Not an S7 PDU. It is a data PDU on an ISO-on-TCP connection to a
		// PLC, and this relay has no policy for whatever else it might be.
		t.refuse(se, hard("unreadable_pdu", err.Error()), "")
		return false, true
	}
	s := se.sess()
	d := t.policy.Request(s, pdu)
	// Learning records the request and what the policy made of it, whether or
	// not the refusal is enforced: a run wants to know that the policy and the
	// traffic disagree, and which way.
	t.observeLearn(se, pdu, d.Allow, time.Now())
	if !d.Allow {
		return t.refusal(se, pdu, d)
	}
	// What the request changes about this connection, recorded once the
	// policy has allowed it.
	if calling, called, length, ok := pdu.Setup(); ok {
		_ = calling
		_ = called
		if sd := t.policy.Setup(length); !sd.Allow {
			return t.refusal(se, pdu, sd)
		}
		se.negotiated(int(length))
	}
	// Behavioural detection, after the policy and on the requests that are
	// going on to the controller: the models learn from what reached the CPU,
	// and a request the policy refused never got there.
	if reason := t.decideAnomaly(se, pdu); reason != "" {
		return t.respond(se, pdu, reason)
	}
	// And engineering: the operations that change what the machine is rather
	// than what it is doing. Reported whatever the policy said, and refused
	// where this listener requires an approved work order for them.
	if reason := t.decideEngineering(se, pdu); reason != "" {
		return t.respond(se, pdu, reason)
	}
	if t.sc.LogRequests {
		t.logRequest(se, pdu)
	}
	return true, false
}

// decidePlus applies the S7comm-plus policy to one PDU.
func (t *server) decidePlus(se *session, c *wire.COTP) (forward, fatal bool) {
	pdu, err := wire.ParsePlus(c.Data)
	if err != nil {
		// The declared length did not agree with the frame, or a request
		// carried no function code where the opcode said it would. Either way
		// this is a PDU the relay could not read, and forwarding one to a
		// controller is forwarding what it cannot decide about.
		t.refuse(se, hard("unreadable_pdu", err.Error()), "")
		return false, true
	}
	if pdu.IsAnswer() {
		// A response or a notification arriving from the client's side. The
		// controller answers; a client that answers is not a client. Only what
		// is positively an answer is refused here -- a connect PDU and a
		// keepalive are neither requests nor answers, and a session cannot
		// start without the first of them.
		t.refuse(se, hard("unexpected_message", plusDetail(pdu)), "")
		return false, true
	}
	d := t.policy.plus.Plus(pdu)
	if !d.Allow {
		return t.plusRefusal(se, pdu, d)
	}
	if t.sc.LogRequests {
		t.logPlus(se, pdu)
	}
	return true, false
}

// plusRefusal is what the relay does about a refused S7comm-plus PDU.
//
// **There is no refusal to write in this protocol.** Classic S7comm has one --
// an acknowledgement carrying an access fault, which is what a password-
// protected CPU answers -- so a refused classic request is answered and the
// poll loop carries on. S7comm-plus has no response this relay can build: the
// response format is not something public reverse engineering pins down well
// enough to render, and inventing one would put octets on the wire that no
// controller would send, which is worse for the engineering station than
// silence. So `deny_response: error` degrades to `drop` here -- the request is
// swallowed and the client reads a timeout for it -- and `close` is available
// for an estate that would rather the session end loudly. The load warns about
// the degradation, because an operator should hear it from the reference
// rather than from the field.
func (t *server) plusRefusal(se *session, pdu *wire.PlusPDU, d Decision) (forward, fatal bool) {
	se.refusal()
	t.refused(se, d, plusDetail(pdu))
	if !t.enforcing() && !d.Hard {
		return true, false
	}
	if t.policy.respond == "close" {
		return false, true
	}
	return false, false
}

// refusal turns a refused decision into what the relay does about it.
//
// A refused request is answered and the connection carries on, which is the
// modbus kind's choice and for the same reason: a plant connection is a poll
// loop, and dropping it because one request was refused turns a refusal into
// an outage. The exceptions are the frames the relay could not read, where
// there is nothing left to be sure of.
func (t *server) refusal(se *session, pdu *wire.PDU, d Decision) (forward, fatal bool) {
	se.refusal()
	t.refused(se, d, describe(pdu))
	if !t.enforcing() && !d.Hard {
		return true, false
	}
	return t.respond(se, pdu, d.Reason)
}

// respond is what the client is told about a request that was kept from the
// controller. It is separate from refusal because the behavioural models have
// already done their own recording by the time they refuse one, and doing it
// twice would count the refusal twice.
func (t *server) respond(se *session, pdu *wire.PDU, reason string) (forward, fatal bool) {
	// The fabrication answers instead, for the clients it covers, and only
	// here: this is the path where the request has already been kept from
	// the controller.
	if se.deceive(pdu, reason) {
		return false, false
	}
	switch t.policy.respond {
	case "drop":
	case "close":
		return false, true
	default:
		if u, ok := pdu.UserData(); ok {
			_ = se.writeClient(errorUserData(pdu, u))
		} else {
			_ = se.writeClient(errorAck(pdu))
		}
	}
	return false, false
}

// refuse is the refusal for the cases that end the connection.
func (t *server) refuse(se *session, d Decision, what string) {
	se.refusal()
	t.refused(se, d, what)
}

// fromPLC forwards the controller's answers, and reads one thing out of
// them: what the PLC itself refused.
func (t *server) fromPLC(se *session) {
	for {
		f, err := se.upReader.Next()
		if err != nil {
			return
		}
		t.readPLC(se, f)
		if err := se.writeClient(f.Raw); err != nil {
			return
		}
	}
}

// readPLC reads the controller's side without deciding anything the client
// asked for.
//
// Two things are worth reading. An error class of *access fault* is the PLC
// refusing something this relay allowed, which is the case where the two
// policies disagree -- and on this protocol it usually means the CPU is
// password-protected and the client has not supplied one. And the negotiated
// PDU length is confirmed here, because the length in force is the smaller of
// what the two sides asked for.
func (t *server) readPLC(se *session, f *wire.Frame) {
	c, err := wire.ParseCOTP(f.Payload)
	if err != nil || (c.Type != wire.COTPData && c.Type != wire.COTPExpeditedData) {
		return
	}
	pdu, err := wire.ParseS7(c.Data)
	if err != nil {
		return
	}
	if _, _, length, ok := pdu.Setup(); ok {
		se.negotiated(int(length))
	}
	if pdu.HasError && pdu.ErrClass != 0 {
		t.plcRefused(se, pdu)
	}
}

// observe records what this connection said about the controller at the other
// end.
func (t *server) observe(se *session, c *wire.COTP) {
	o := assets.Observation{
		Proto:    "s7",
		Listener: t.name,
		Addr:     se.ip,
	}
	if resource, rack, slot, ok := c.Destination(); ok {
		// The rack and slot are the strongest thing this protocol says about
		// what is at the other end, and the connection resource says what
		// the client is: an engineering station opens `pg`, a panel opens
		// `op`.
		o.Description = fmt.Sprintf("s7 %s rack %d slot %d", wire.ResourceName(resource), rack, slot)
	}
	t.host.ObserveAsset(o)
}
