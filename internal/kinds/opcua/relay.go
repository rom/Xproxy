package opcua

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: opcua listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	oc     *config.OPCUAListener
	policy *policy
	ln     net.Listener

	learner  *learner
	limiter  *limits.KeyedLimiter
	gate     *sesslimit.Gate
	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener) (*server, error) {
	p, err := compile(cfg.OPCUA, time.Now)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, oc: cfg.OPCUA, policy: p, ln: ln,
		gate: sesslimit.New(cfg.OPCUA.MaxSessions, cfg.OPCUA.MaxSessionsPerClient)}
	if l := cfg.OPCUA.Learn; l != nil && l.Enabled {
		t.learner = newLearner(&learnConfig{
			enabled: true, listener: cfg.Name, file: l.File,
			interval: l.Interval.D(), maxSubjects: l.MaxSubjects,
		})
	}
	if n := cfg.OPCUA.RateLimit; n > 0 {
		burst := cfg.OPCUA.RateBurst
		if burst <= 0 {
			burst = n
		}
		t.limiter = limits.NewKeyedLimiter(float64(n), burst, 0)
	}
	return t, nil
}

// enforcing says whether the policy decides or only records.
//
// A learning run is observe-only unless it says otherwise, which is what stops one
// being left on by accident: the point of learning is to find out what the traffic
// is, and a run that refused half of it has changed the thing it was measuring.
func (t *server) enforcing() bool {
	if t.oc.MonitorOnly || t.cfg.Shadowing() {
		return false
	}
	l := t.oc.Learn
	if l == nil || !l.Enabled {
		return true
	}
	return l.Enforce
}

// The bounds, each falling back to the wire package's own.
func (t *server) maxChunk() int {
	if n := t.oc.MaxChunkSize; n > 0 {
		return n
	}
	return wire.MaxMessageSize
}

func (t *server) handshakeTimeout() time.Duration {
	if d := t.oc.HandshakeTimeout.D(); d > 0 {
		return d
	}
	return 30 * time.Second
}

func (t *server) serve() {
	if t.learner != nil {
		t.learner.Start(func(err error) {
			t.host.Logs().Error.Warn("opcua learning report could not be written",
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
			// Accepted as the listener was shutting down. Serving it would start
			// a session nothing waits for.
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer safe.Guard("opcua session")
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
		t.host.Logs().Error.Warn("opcua learning report could not be written at shutdown",
			"listener", t.name, "error", err.Error())
	}
}

// conn is one connection and the state the policy needs it to have.
type conn struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cliReader *wire.Reader
	upReader  *wire.Reader
	// Two assemblers, one per direction: the chunks of one direction arrive in
	// one order on one socket, and a request's chunks are nothing to do with a
	// response's.
	fromCli *wire.Assembler
	fromSrv *wire.Assembler

	cmu sync.Mutex
	umu sync.Mutex

	mu sync.Mutex
	s  Session
	// requests counts what the client has sent, and denied what was refused.
	requests int
	denied   int
	// pending maps a request identifier to the service it carried, so a response
	// can be attributed. A response names no service of its own beyond its own
	// TypeId, and a ServiceFault names none at all.
	pending map[uint32]wire.Service
	// handles maps a request identifier to the client's own request handle, which
	// is what a fault this relay composes has to echo for the client's library to
	// match it to the call it made.
	handles map[uint32]uint32
	// subjects maps a request identifier to the learning subjects the request was
	// recorded under, so a fault the server answers it with is counted against
	// those same rows. A fault names no nodes of its own, so a fault attributed by
	// identity and service alone would land on a row with no node in it and leave
	// the rows the request made reading as traffic the server accepted -- which is
	// how a learning run proposes a rule for something that cannot happen.
	subjects map[uint32][]learnKey
}

// MaxPendingRequests bounds the table above. A client with more than this many
// services in flight is not a client any plant has, and the table is one a peer
// would otherwise fill by opening request identifiers it never finishes.
const MaxPendingRequests = 64

func (c *conn) sess() Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.s
	s.At = time.Now()
	return s
}

// update applies a change to the session under the lock.
func (c *conn) update(f func(*Session)) {
	c.mu.Lock()
	f(&c.s)
	c.mu.Unlock()
}

func (c *conn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	return c.requests
}

func (c *conn) refusal() {
	c.mu.Lock()
	c.denied++
	c.mu.Unlock()
}

// remember records which service a request identifier carried.
func (c *conn) remember(id uint32, svc wire.Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = make(map[uint32]wire.Service, 8)
	}
	if len(c.pending) >= MaxPendingRequests {
		// Past the bound the association is dropped rather than the table grown:
		// what is lost is the ability to name the service a response belongs to,
		// which costs a log line its detail and costs the decision nothing.
		return
	}
	c.pending[id] = svc
}

// took returns and forgets the service a request identifier carried.
func (c *conn) took(id uint32) (wire.Service, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	svc, ok := c.pending[id]
	delete(c.pending, id)
	return svc, ok
}

// recordSubjects remembers which learning subjects a request was recorded under.
func (c *conn) recordSubjects(id uint32, keys []learnKey) {
	if len(keys) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.subjects == nil {
		c.subjects = make(map[uint32][]learnKey, 8)
	}
	if len(c.subjects) >= MaxPendingRequests {
		// The same bound as the table above, and the same trade: what is lost is
		// the ability to say which rows a fault belongs to, not a decision.
		return
	}
	c.subjects[id] = keys
}

// tookSubjects returns and forgets them.
func (c *conn) tookSubjects(id uint32) []learnKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := c.subjects[id]
	delete(c.subjects, id)
	return keys
}

func (c *conn) writeClient(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	c.cmu.Lock()
	defer c.cmu.Unlock()
	_, err := c.client.Write(b)
	return err
}

func (c *conn) writeUp(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	c.umu.Lock()
	defer c.umu.Unlock()
	_, err := c.up.Write(b)
	return err
}

// admitClient is the two questions this relay asks about a client that has not yet
// named itself: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// It runs on the address alone, before the handshake, because that is all there is
// at this point — the application and the user arrive several messages later, and a
// client the lists refuse should not get to send them.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists:   h.ThreatIntel(),
		Policy:  h.Authorization(),
		Logs:    h.Logs(),
		Matched: func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked: func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "opcua",
		Client:   ip,
		Target:   t.oc.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("opcua", reason)
			h.Shadow().Record("opcua", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// handle runs one connection.
//
// The Hello is read before the server is dialled, and that ordering is the point
// rather than an optimisation: the Hello names the endpoint and proposes the buffer
// sizes, so a client asking for something this listener will not carry is refused
// while refusing is still free — no socket to the plant, no channel, no session.
func (t *server) handle(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	ip := netutil.AddrOf(nc.RemoteAddr().String())
	c := &conn{t: t, ip: ip, client: nc,
		fromCli: wire.NewAssembler(), fromSrv: wire.NewAssembler()}
	c.s = Session{IP: ip}

	if d := t.policy.Connect(c.sess()); !d.Allow {
		t.refuseConn(c, d, "connect")
		return
	}
	if t.admitClient(ip) != "" {
		return
	}
	if !t.admit(c) {
		return
	}
	defer t.release(c)

	// The Hello, under the handshake bound: a client that opens a socket and says
	// nothing is a client holding a session slot.
	_ = c.client.SetReadDeadline(time.Now().Add(t.handshakeTimeout()))
	c.cliReader = wire.NewReader(c.client, t.maxChunk())
	first, err := c.cliReader.Next()
	if err != nil {
		t.deny(ip, "no_hello", err.Error())
		return
	}
	_ = c.client.SetReadDeadline(time.Time{})
	if d, ok := t.decideHandshake(c, first); !ok {
		t.refuseConn(c, d, first.Type.String())
		return
	}

	up, err := t.dial(c)
	if err != nil {
		t.deny(ip, "upstream_unavailable", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	c.up = up
	c.upReader = wire.NewReader(up, t.maxChunk())
	if err := c.writeUp(first.Raw); err != nil {
		t.deny(ip, "upstream_unavailable", err.Error())
		return
	}
	t.observe(c)
	t.relay(c)
}

// decideHandshake decides about the first message, which must be a Hello or a
// ReverseHello.
func (t *server) decideHandshake(c *conn, ch *wire.Chunk) (Decision, bool) {
	switch ch.Type {
	case wire.Hello:
		h, err := wire.ParseHello(ch.Body)
		if err != nil {
			return hard("unreadable_hello", err.Error(), wire.StatusBadTCPMessageTypeInvalid), false
		}
		if n := int(h.ReceiveBufferSize); n > t.maxChunk() {
			// Refused rather than rewritten. The answer to the negotiation is the
			// minimum of the two proposals, so lowering the client's number here
			// would make this relay a party to an agreement neither end made --
			// and the ends would then disagree with each other about what was
			// agreed, which is worse than a refusal at the first message.
			return hard("buffer_too_large",
				fmt.Sprintf("%d, past %d", n, t.maxChunk()),
				wire.StatusBadTCPMessageTooLarge), false
		}
		d := t.policy.Hello(c.sess(), h)
		c.update(func(s *Session) {
			s.Endpoint, s.Hello = h.EndpointURL, true
		})
		if !d.Allow {
			return d, false
		}
		if t.oc.LogRequests {
			t.logHello(c, h)
		}
		return d, true
	case wire.ReverseHello:
		h, err := wire.ParseReverseHello(ch.Body)
		if err != nil {
			return hard("unreadable_hello", err.Error(), wire.StatusBadTCPMessageTypeInvalid), false
		}
		d := t.policy.ReverseHello(h)
		c.update(func(s *Session) { s.Endpoint, s.Hello = h.EndpointURL, true })
		return d, d.Allow
	default:
		// A connection that starts with anything else is a peer skipping the
		// transport handshake, which no conforming implementation does and which
		// would leave the buffer sizes unnegotiated.
		return hard("no_hello", ch.Type.String(), wire.StatusBadTCPMessageTypeInvalid), false
	}
}

func (t *server) admit(c *conn) bool {
	ok, reason := t.gate.Enter(c.ip)
	if !ok {
		t.deny(c.ip, reason, "")
	}
	return ok
}

func (t *server) release(c *conn) { t.gate.Leave(c.ip) }

// dial opens the connection to the server.
func (t *server) dial(c *conn) (net.Conn, error) {
	pool := t.host.Pool(t.oc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.oc.Upstream)
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(c.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: 10 * time.Second}
		nc, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			continue
		}
		return nc, nil
	}
	return nil, errors.New("no reachable opcua endpoint")
}

// relay runs both directions.
func (t *server) relay(c *conn) {
	if d := t.oc.SessionDuration.D(); d > 0 {
		_ = c.client.SetDeadline(time.Now().Add(d))
		_ = c.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("opcua server reader")
		t.fromServer(c)
		_ = c.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("opcua client reader")
		t.fromClient(c)
		_ = c.up.Close()
	}()
	wg.Wait()
}

// fromClient reads the client's chunks and applies the policy.
func (t *server) fromClient(c *conn) {
	max := t.oc.MaxRequests
	for {
		if idle := t.oc.IdleTimeout.D(); idle > 0 {
			_ = c.client.SetReadDeadline(time.Now().Add(idle))
		}
		ch, err := c.cliReader.Next()
		if err != nil {
			if !ended(err) {
				t.deny(c.ip, "unreadable_message", err.Error())
			}
			return
		}
		if t.limiter != nil && !t.limiter.Allow(c.ip.String()) {
			// A rate limit ends the message and not the session: a plant session
			// is long-lived and a client over its limit for one second is not a
			// client to disconnect.
			t.refuseMessage(c, hard("rate_limited", "", wire.StatusBadTCPNotEnoughResources), "")
			continue
		}
		if n := c.count(); max > 0 && n > max {
			t.refuseConn(c, hard("too_many_requests", fmt.Sprint(max),
				wire.StatusBadTCPNotEnoughResources), "")
			return
		}
		forward, fatal := t.decide(c, ch)
		if fatal {
			return
		}
		if !forward {
			continue
		}
		if err := c.writeUp(ch.Raw); err != nil {
			return
		}
	}
}

// decide applies the policy to one chunk from the client.
func (t *server) decide(c *conn, ch *wire.Chunk) (forward, fatal bool) {
	switch ch.Type {
	case wire.Hello, wire.ReverseHello:
		// A second Hello on an established connection. The sizes are already
		// negotiated, so this is either a peer that lost track of its own state
		// or one trying to renegotiate them underneath the relay's bounds.
		t.refuseConn(c, hard("unexpected_message", ch.Type.String(),
			wire.StatusBadTCPMessageTypeInvalid), ch.Type.String())
		return false, true
	case wire.Acknowledge, wire.Error:
		// The server's messages, arriving from the client's side.
		t.refuseConn(c, hard("unexpected_message", ch.Type.String(),
			wire.StatusBadTCPMessageTypeInvalid), ch.Type.String())
		return false, true
	}

	s := c.sess()
	mode := s.Mode
	if ch.Type == wire.OpenSecureChannel {
		// An OPN's own body is secured asymmetrically and is readable: it has to
		// be, because it is where the mode is named.
		mode = wire.ModeNone
	}
	m, err := c.fromCli.Add(ch, mode)
	if err != nil {
		t.refuseConn(c, hard("unreadable_message", err.Error(), wire.StatusBadTCPMessageTooLarge), "")
		return false, true
	}
	if m == nil {
		// An intermediate chunk, or an abort. Forwarded either way: the decision
		// belongs to the assembled message, and an abort is the peer withdrawing
		// one this relay never decided about.
		return true, false
	}
	if m.Encrypted {
		// The channel encrypted the body, so there is nothing to read. The
		// message is still accounted for and still counted against the bounds,
		// and the service-level rules do not apply to it -- which is what
		// require_readable_bodies is for, and what the reference says.
		t.host.Counters().OPCUAOpaque.Add(1)
		// Recorded even so, and marked as opaque. A learning run that recorded
		// nothing for an encrypted channel would look like a run over an idle
		// listener, when what actually happened is that the relay could not read
		// what crossed it -- which is the finding.
		t.observeRequest(c, s, m.RequestID, 0, nil, true, true, time.Now())
		return true, false
	}
	call, err := wire.ParseCall(m.Body, true)
	if err != nil {
		t.refuseConn(c, hard("unreadable_service", err.Error(), wire.StatusBadServiceUnsupported), "")
		return false, true
	}
	c.remember(m.RequestID, call.Service)
	c.rememberHandle(m.RequestID, call.Header.RequestHandle)
	return t.decideCall(c, ch, m, call)
}

// decideCall applies the service-level policy to one assembled message.
func (t *server) decideCall(c *conn, ch *wire.Chunk, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	// The channel's own decisions first, because an OpenSecureChannel decides what
	// every message after it can be read as.
	if ch.Type == wire.OpenSecureChannel {
		return t.decideChannel(c, ch, call)
	}
	c.update(func(s *Session) { s.Channel, s.Token = m.Channel, m.Token })
	s := c.sess()

	d := t.policy.Request(s, call)
	if !d.Allow {
		// Recorded before the refusal is acted on, because a learning run wants to
		// know that the policy and the traffic disagree and which way.
		t.observeRequest(c, s, m.RequestID, call.Service, nil, false, false, time.Now())
		return t.refused(c, m, d, call.Service.String())
	}
	// The service's own body, for the services whose contents a policy is written
	// about. A service not in this switch is decided by its name alone, which is
	// what the coarse allow list is for.
	switch call.Service {
	case wire.SvcCreateSession:
		return t.decideCreateSession(c, m, call)
	case wire.SvcActivateSession:
		return t.decideActivate(c, m, call)
	case wire.SvcRead:
		return t.decideRead(c, m, call)
	case wire.SvcWrite:
		return t.decideWrite(c, m, call)
	case wire.SvcCall:
		return t.decideMethod(c, m, call)
	case wire.SvcBrowse:
		return t.decideBrowse(c, m, call)
	case wire.SvcCreateSubscription:
		return t.decideSubscription(c, m, call)
	case wire.SvcCreateMonitored:
		return t.decideMonitored(c, m, call)
	}
	if t.oc.LogRequests {
		t.logRequest(c, call, nil)
	}
	return true, false
}

// decideChannel decides about an OpenSecureChannel, which is where the policy and
// the mode are named.
func (t *server) decideChannel(c *conn, ch *wire.Chunk, call *wire.ServiceCall) (forward, fatal bool) {
	h, _, err := wire.ParseAsymmetric(ch.Body)
	if err != nil {
		t.refuseConn(c, hard("unreadable_message", err.Error(), wire.StatusBadSecurityChecksFailed), "")
		return false, true
	}
	if call.Service != wire.SvcOpenChannel {
		// An OPN chunk carrying something other than OpenSecureChannel. Nothing
		// else may travel on it, and a relay that forwarded one would be
		// forwarding a service on the one message type whose body it must read.
		t.refuseConn(c, hard("unexpected_service", call.Service.String(),
			wire.StatusBadSecurityChecksFailed), "")
		return false, true
	}
	o, err := wire.ParseOpenChannel(call.Body)
	if err != nil {
		t.refuseConn(c, hard("unreadable_service", err.Error(), wire.StatusBadSecurityChecksFailed), "")
		return false, true
	}
	d := t.policy.Channel(c.sess(), h.Policy, o)
	// The channel's terms are recorded whether or not they were allowed, so a
	// shadow listener's log line says what the channel would have been.
	c.update(func(s *Session) {
		s.Policy, s.Mode, s.Secured = h.Policy, o.Mode, true
		s.Channel = h.SecureChannelID
	})
	if !d.Allow {
		// An ERR and a close, never a ServiceFault, and the reason is the
		// cryptography rather than the policy: a fault answering an
		// OpenSecureChannel would have to be secured with the keys that
		// OpenSecureChannel exists to establish, and the client has none. It
		// would arrive as octets the client's record layer discards, which reads
		// to the operator as a timeout.
		//
		// A shadow listener forwards it instead, as everywhere else, unless the
		// decision was hard.
		if !t.enforcing() && !d.Hard {
			t.refusalOnly(c, d, h.Policy.Short()+"/"+o.Mode.String())
			return true, false
		}
		t.refuseConn(c, d, h.Policy.Short()+"/"+o.Mode.String())
		return false, true
	}
	t.host.Counters().OPCUAChannels.Add(1)
	if t.oc.LogRequests {
		t.logChannel(c, h, o)
	}
	return true, false
}

func (t *server) decideCreateSession(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	q, err := wire.ParseCreateSession(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	c.update(func(s *Session) {
		s.ApplicationURI, s.SessionName = q.ApplicationURI, q.SessionName
		s.HasCert = len(q.Certificate) > 0
		s.CertURIs = certificateURIs(q.Certificate)
		s.Created = true
	})
	if d := t.policy.CreateSession(c.sess(), q); !d.Allow {
		return t.refused(c, m, d, q.ApplicationURI)
	}
	if d := t.policy.CertificateURI(c.sess()); !d.Allow {
		return t.refused(c, m, d, q.ApplicationURI)
	}
	if t.oc.LogRequests {
		t.logRequest(c, call, []any{"application_uri", q.ApplicationURI,
			"session_name", q.SessionName})
	}
	return true, false
}

func (t *server) decideActivate(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	a, err := wire.ParseActivateSession(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	c.update(func(s *Session) {
		s.User, s.TokenKind, s.Activated = a.User, a.Kind, true
	})
	if d := t.policy.ActivateSession(c.sess(), a); !d.Allow {
		return t.refused(c, m, d, a.Kind.String())
	}
	t.host.Counters().OPCUASessions.Add(1)
	t.logActivation(c, a)
	return true, false
}

func (t *server) decideRead(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	q, err := wire.ParseRead(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	ops := make([]Operation, 0, len(q.Nodes))
	for _, n := range q.Nodes {
		ops = append(ops, Operation{Node: RefOf(n.Node), Attr: n.Attr})
	}
	sess := c.sess()
	d := t.policy.Operations(sess, call.Service, ops)
	t.observeRequest(c, sess, m.RequestID, call.Service, ops, d.Allow, false, time.Now())
	if !d.Allow {
		return t.refused(c, m, d, describeOps(ops))
	}
	if t.oc.LogRequests {
		t.logRequest(c, call, []any{"nodes", len(q.Nodes), "first", firstNode(ops)})
	}
	return true, false
}

func (t *server) decideWrite(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	w, err := wire.ParseWrite(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	ops := make([]Operation, 0, len(w.Values))
	for _, v := range w.Values {
		ops = append(ops, Operation{Node: RefOf(v.Node), Attr: v.Attr, Write: true})
	}
	sess := c.sess()
	d := t.policy.Operations(sess, call.Service, ops)
	t.observeRequest(c, sess, m.RequestID, call.Service, ops, d.Allow, false, time.Now())
	if !d.Allow {
		return t.refused(c, m, d, describeOps(ops))
	}
	t.logWrite(c, call, w)
	return true, false
}

func (t *server) decideMethod(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	k, err := wire.ParseCallRequest(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	ops := make([]Operation, 0, len(k.Methods))
	for _, mc := range k.Methods {
		method := RefOf(mc.Method)
		ops = append(ops, Operation{Node: RefOf(mc.Object), Write: true, Method: &method})
	}
	sess := c.sess()
	d := t.policy.Operations(sess, call.Service, ops)
	t.observeRequest(c, sess, m.RequestID, call.Service, ops, d.Allow, false, time.Now())
	if !d.Allow {
		return t.refused(c, m, d, describeOps(ops))
	}
	t.logMethod(c, call, k)
	return true, false
}

func (t *server) decideBrowse(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	b, err := wire.ParseBrowse(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	ops := make([]Operation, 0, len(b.Nodes))
	for _, n := range b.Nodes {
		ops = append(ops, Operation{Node: RefOf(n.Node)})
	}
	sess := c.sess()
	d := t.policy.Operations(sess, call.Service, ops)
	t.observeRequest(c, sess, m.RequestID, call.Service, ops, d.Allow, false, time.Now())
	if !d.Allow {
		return t.refused(c, m, d, describeOps(ops))
	}
	if t.oc.LogRequests {
		t.logRequest(c, call, []any{"nodes", len(b.Nodes), "first", firstNode(ops),
			"max_references", b.MaxReferences})
	}
	return true, false
}

func (t *server) decideSubscription(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	q, err := wire.ParseSubscription(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	sess := c.sess()
	d := t.policy.Subscription(sess, q)
	// The interval is recorded whether or not it was allowed, and it is one of the
	// numbers the report never proposes: a run that suggested the fastest interval
	// it saw would widen the bound that stops a thousand values a millisecond.
	t.observeSubscription(sess, q.Interval, time.Now())
	t.observeRequest(c, sess, m.RequestID, call.Service, nil, d.Allow, false, time.Now())
	if !d.Allow {
		return t.refused(c, m, d, fmt.Sprintf("%.0fms", q.Interval))
	}
	c.update(func(s *Session) { s.Subscriptions++ })
	if t.oc.LogRequests {
		t.logRequest(c, call, []any{"interval_ms", q.Interval, "priority", q.Priority})
	}
	return true, false
}

func (t *server) decideMonitored(c *conn, m *wire.Assembled, call *wire.ServiceCall) (forward, fatal bool) {
	q, err := wire.ParseMonitoredItems(call.Body)
	if err != nil {
		return t.unreadableBody(c, m, call, err)
	}
	sess := c.sess()
	t.observeMonitoredItems(sess, len(q.Items), fastestSampling(q), time.Now())
	if d := t.policy.MonitoredItems(sess, q); !d.Allow {
		t.observeRequest(c, sess, m.RequestID, call.Service, nil, false, false, time.Now())
		return t.refused(c, m, d, fmt.Sprintf("%d items", len(q.Items)))
	}
	ops := make([]Operation, 0, len(q.Items))
	for _, it := range q.Items {
		ops = append(ops, Operation{Node: RefOf(it.Item.Node), Attr: it.Item.Attr})
	}
	d := t.policy.Operations(sess, call.Service, ops)
	t.observeRequest(c, sess, m.RequestID, call.Service, ops, d.Allow, false, time.Now())
	if !d.Allow {
		return t.refused(c, m, d, describeOps(ops))
	}
	if t.oc.LogRequests {
		t.logRequest(c, call, []any{"items", len(q.Items), "first", firstNode(ops)})
	}
	return true, false
}

// fastestSampling is the smallest positive sampling interval a request asked for.
//
// Positive only: minus one means the subscription's own publishing interval, which is
// recorded where the subscription is, and zero means as fast as the device will
// answer -- which is not an interval to record as the fastest one seen, because it
// is not an interval at all.
func fastestSampling(q *wire.MonitoredItemsRequest) float64 {
	best := 0.0
	for _, it := range q.Items {
		if it.Sampling <= 0 {
			continue
		}
		if best == 0 || it.Sampling < best {
			best = it.Sampling
		}
	}
	return best
}

// unreadableBody is what happens when a service's own body did not parse.
//
// It ends the connection rather than refusing the one message, because the body of
// a service call is what the relay's decision rests on: a message whose body did
// not parse is one this relay cannot decide about, and the octets after it are at a
// position nothing agrees on.
func (t *server) unreadableBody(c *conn, m *wire.Assembled, call *wire.ServiceCall, err error) (forward, fatal bool) {
	_ = m
	t.refuseConn(c, hard("unreadable_service", call.Service.String()+": "+err.Error(),
		wire.StatusBadServiceUnsupported), call.Service.String())
	return false, true
}

// fromServer forwards the server's answers and reads what they say.
func (t *server) fromServer(c *conn) {
	for {
		ch, err := c.upReader.Next()
		if err != nil {
			return
		}
		t.readServer(c, ch)
		if err := c.writeClient(ch.Raw); err != nil {
			return
		}
	}
}

// readServer reads the server's side without deciding anything the client asked
// for.
//
// Three things are worth reading. An Acknowledge confirms the buffer sizes actually
// in force, which are the minimum of the two proposals and therefore not what
// either end asked for. An Error is the server ending the connection with a reason,
// which is the one place a server's own words reach this relay's log. And a
// ServiceFault is the server refusing something this relay allowed, which is the
// case where the two policies disagree -- on this protocol that usually means a
// user the server does not grant what the listener does.
func (t *server) readServer(c *conn, ch *wire.Chunk) {
	switch ch.Type {
	case wire.Acknowledge:
		a, err := wire.ParseAcknowledge(ch.Body)
		if err != nil {
			return
		}
		t.logAck(c, a)
		return
	case wire.Error:
		e, err := wire.ParseError(ch.Body)
		if err != nil {
			return
		}
		t.serverError(c, e)
		return
	}
	s := c.sess()
	mode := s.Mode
	if ch.Type == wire.OpenSecureChannel {
		mode = wire.ModeNone
	}
	m, err := c.fromSrv.Add(ch, mode)
	if err != nil || m == nil || m.Encrypted {
		return
	}
	call, err := wire.ParseCall(m.Body, false)
	if err != nil {
		return
	}
	svc, known := c.took(m.RequestID)
	c.forgetHandle(m.RequestID)
	if call.Service == wire.SvcFault || wire.Bad(call.Response.ServiceResult) {
		t.serverRefused(c, call, svc, known)
		// The learning run wants this most of all: it is the server refusing
		// something this relay allowed, and a rule proposed for it would permit a
		// thing that cannot happen.
		t.observeServerFault(c.sess(), svc, known, c.tookSubjects(m.RequestID))
	}
}

// ended says an error is the connection finishing rather than a peer misbehaving.
func ended(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// certificateURIs pulls the uniform resource identifiers out of a client's
// certificate, which is what the application URI is checked against.
//
// A certificate that does not parse yields no URIs rather than an error. That is
// deliberate: the policy's question is "does the certificate carry this URI", and
// the answer for a certificate nobody can read is no. The refusal then names the
// URI mismatch, which is the true reason, rather than a parse failure the operator
// would go looking for in the wrong place.
func certificateURIs(der []byte) []string {
	if len(der) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	return out
}

// observe records what this connection said about the server at the other end.
func (t *server) observe(c *conn) {
	s := c.sess()
	o := assets.Observation{
		Proto:    "opcua",
		Listener: t.name,
		Addr:     c.ip,
	}
	if s.Endpoint != "" {
		o.Description = "opcua endpoint " + s.Endpoint
	}
	t.host.ObserveAsset(o)
}

// describeOps renders the operations for a refusal's detail, bounded.
func describeOps(ops []Operation) string {
	if len(ops) == 0 {
		return ""
	}
	if len(ops) == 1 {
		return ops[0].Node.Key
	}
	return fmt.Sprintf("%s and %d more", ops[0].Node.Key, len(ops)-1)
}

func firstNode(ops []Operation) string {
	if len(ops) == 0 {
		return ""
	}
	return ops[0].Node.Key
}
