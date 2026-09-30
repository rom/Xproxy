// Package snmp serves a kind: snmp listener: an SNMP relay in front of the
// equipment that management protocol actually manages.
//
// SNMP runs every switch, router, printer, UPS and building controller in an
// estate. Versions 1 and 2c authenticate with a community string -- a
// cleartext password in every datagram, "public" to read and "private" to
// write on anything nobody reconfigured -- with no integrity, no replay
// protection and no confidentiality. One datagram reads a device's whole
// configuration; one changes it. Version 3 has a real security model and
// also has noAuthNoPriv, which is version 2c with more fields.
//
// The devices cannot be fixed: they are switches and printers and building
// controllers with firmware nobody ships updates for. So the relay is the
// only place a policy can live, and this is that place.
//
// Five things are deliberate in the data path.
//
// **Every message is parsed whole.** A relay that forwarded what it could
// not read would be forwarding what it could not decide about, and the agent
// behind it will read those octets somehow.
//
// **The amplification is bounded in two directions.** SNMP is a classic
// reflection vector: a forty-octet GETBULK with a repetition count of ten
// thousand asks for a response of megabytes, to whatever address the
// datagram claimed to come from. So a repetition count past the bound is
// *lowered* rather than refused -- a poller asking for more than it should
// get still gets an answer, which is what keeps this deployable -- and a
// response disproportionate to its request is refused outright.
//
// **The version can be upgraded downwards.** Managers speak v3 with
// authentication to this relay; the relay speaks v2c to a switch whose
// firmware has nothing else, with a community string the manager never needs
// to know. Upwards is impossible and is refused at load: there is no user,
// no engine and no key with which to authenticate a v3 message that arrived
// as v2c, and producing one would be inventing an authentication that did
// not happen.
//
// **A response is matched to its request.** SNMP's request identifier is the
// only thing that pairs them, so an answer nobody asked for is recognisable
// -- and on UDP it is the shape of a response-spoofing attack on the manager.
//
// **The values are not interpreted.** A varbind's type and extent are read;
// what a Counter64 *means* is not. A policy about values would need a MIB per
// estate, and a relay that mis-decoded one would corrupt a reading nobody
// could trace.
package snmp

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

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	wire "github.com/rom/xproxy/internal/snmp"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: snmp listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	m      *config.SNMPListener
	pc     net.PacketConn // udp
	ln     net.Listener   // tcp
	tlsCfg *tls.Config
	upTLS  *tls.Config

	policy *Policy
	decoy  *decoy
	usm    *usm
	// anomaly is the behavioural models, nil when the block is off.
	anomaly *anomaly.Detector
	// engineering recognises a SET for what it is on this protocol -- a
	// configuration change -- and ties it to an approved work order.
	engineering *engineering.Guard
	// names is RFC 6353's certificate-to-security-name table, nil when the
	// listener has none: a (D)TLS peer has proved it holds a key and that is
	// not yet an identity a rule can name. See certname.go.
	names *certNames
	// dtls is the translated DTLS configuration, nil unless dtls_mode asks
	// for one, and demux the per-peer splitter underneath it -- kept so that
	// the dropped-datagram count can be published.
	dtls  *dtlsx.Config
	demux atomic.Pointer[dtlsx.Mux]
	// orig is the identity this relay presents to the agent, when
	// upstream_usm gave it one. Nil means the relay forwards what arrived.
	orig    *originator
	limiter *limits.KeyedLimiter
	// upgrade is the version requests are forwarded in, or -1 to forward
	// the version that arrived.
	upgrade wire.Version

	open atomic.Int64
	// running is what a shutdown waits for: the accepted sessions, the
	// datagram reader and the reader towards the agents. It is acceptgroup
	// rather than a bare WaitGroup because the engine can call Shutdown
	// before serve has run its first Add -- and a WaitGroup's Add must not
	// race its Wait. The race detector found this one through
	// test/shutdown.
	running acceptgroup.Group
	mu      sync.Mutex
	once    sync.Once
	cons    map[net.Conn]struct{}
	done    chan struct{}

	// pend tracks the requests this relay has outstanding towards agents,
	// so that a response can be matched to the client that asked.
	pend *pending
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn, ln net.Listener, tc *tls.Config) (*server, error) {
	m := cfg.SNMP
	t := &server{host: host, cfg: cfg, m: m, pc: pc, ln: ln, tlsCfg: tc,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{}), upgrade: -1}
	var err error
	if t.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	if t.decoy, err = newDecoy(m.Deception, cfg.Name); err != nil {
		return nil, fmt.Errorf("snmp %s: %w", cfg.Name, err)
	}
	if t.orig, err = compileOriginator(m, host.Secrets()); err != nil {
		return nil, fmt.Errorf("snmp %s: %w", cfg.Name, err)
	}
	if t.usm, err = compileUSM(m, host.Secrets()); err != nil {
		return nil, fmt.Errorf("snmp %s: %w", cfg.Name, err)
	}
	if t.names, err = compileCertNames(m.CertToName); err != nil {
		return nil, fmt.Errorf("snmp %s: %w", cfg.Name, err)
	}
	if m.DTLSMode != "" && m.DTLSMode != "none" {
		// Built at load rather than at the first handshake, because a
		// certificate this listener cannot serve is a configuration fault and
		// a listener that discovered it on the first datagram would have
		// started, bound the port, and be refusing everything.
		if t.dtls, err = dtlsx.NewConfig("snmp", tc, t.dtlsBounds()); err != nil {
			return nil, fmt.Errorf("snmp %s: %w", cfg.Name, err)
		}
	}
	if m.UpgradeVersion != "" {
		v, ok := wire.VersionOf(m.UpgradeVersion)
		if !ok {
			return nil, fmt.Errorf("snmp upgrade_version: %q", m.UpgradeVersion)
		}
		if v == wire.V3 && t.orig == nil {
			// Without an identity of its own there is nothing to sign with,
			// and this relay does not forge an authentication that did not
			// happen. upstream_usm is what supplies one.
			return nil, errors.New("snmp upgrade_version: v3 needs upstream_usm, the identity this relay presents to the agent")
		}
		t.upgrade = v
	}
	if m.UpstreamTLSMode == "implicit" {
		uc, _, err := tlsconf.Client(m.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("snmp upstream_tls: %w", err)
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
	if t.anomaly, err = anomaly.FromConfig(m.Anomaly, time.Now()); err != nil {
		return nil, err
	}
	if t.engineering, err = engineering.FromConfig(m.Engineering, "snmp", cfg.Name,
		host.Access(), host.Logs().Error); err != nil {
		return nil, err
	}
	t.pend = newPending(t.maxPending(), t.requestTimeout())
	t.pend.onChange = t.publishPending
	return t, nil
}

// publishPending puts the outstanding-request count where an operator reads
// it. A table that is filling up is the signal that the agents are slow or
// that something is asking faster than they answer, and the bound refusing
// is the end of that story rather than the start.
func (t *server) publishPending(n int) {
	t.host.Counters().SNMPPending.Store(int64(n))
}

func (t *server) maxPending() int {
	if n := t.m.MaxPending; n > 0 {
		return n
	}
	return 32
}

func (t *server) requestTimeout() time.Duration {
	if d := t.m.RequestTimeout.D(); d > 0 {
		return d
	}
	return 5 * time.Second
}

func (t *server) idleTimeout() time.Duration {
	if d := t.m.IdleTimeout.D(); d > 0 {
		return d
	}
	return 60 * time.Second
}

func (t *server) maxMessage() int {
	if n := t.m.MaxMessageBytes; n > 0 {
		return n
	}
	return 8192
}

func (t *server) maxResponse() int {
	if n := t.m.MaxResponseBytes; n > 0 {
		return n
	}
	return 8192
}

// repetitionBound and varBindBound are the listener's own amplification
// bounds, which the fabrication is held to exactly as an agent's answer is.
func (t *server) repetitionBound(m *wire.Message) int {
	return t.policy.MaxRepetitions(request{msg: m}, "")
}

func (t *server) varBindBound() int {
	if n := t.m.MaxVarBinds; n > 0 {
		return n
	}
	return 128
}

func (t *server) maxRatio() int {
	if n := t.m.MaxResponseRatio; n > 0 {
		return n
	}
	return 50
}

// dtlsConfig is the translated DTLS configuration. It is only reached from the
// session path, which does not run unless newServer built one.
func (t *server) dtlsConfig() *dtlsx.Config { return t.dtls }

// requireSecurityName says whether a transport security model message whose
// certificate maps to no name is refused. Default true: the model carries no
// user, no engine and no digest, so a message with no derived name has no
// credential at all.
func (t *server) requireSecurityName() bool {
	return t.m.RequireSecurityName == nil || *t.m.RequireSecurityName
}

// enforcing says whether this listener refuses for policy or only records
// what it would have refused.
func (t *server) enforcing() bool { return !t.cfg.Shadowing() }

// alerts says whether a refusal writes a security event.
func (t *server) alerts() bool { return t.m.AlertOnDeny == nil || *t.m.AlertOnDeny }

// serve runs both transports. A listener with transport: udp still accepts
// the streams of RFC 3430 on the same port, because the engine bound that
// socket and a bound port nothing accepts on is worse than one that answers
// with the same policy: a client that connected would hang rather than be
// decided about.
func (t *server) serve() {
	if !t.running.Enter() {
		// Shut down before it started, which a reload can do.
		return
	}
	defer t.running.Leave()
	if t.pc != nil {
		go func() {
			if !t.running.Enter() {
				return
			}
			defer t.running.Leave()
			defer safe.Guard("snmp datagrams")
			if t.dtls != nil {
				t.serveDTLS()
				return
			}
			t.serveDatagrams()
		}()
	}
	if t.ln != nil {
		t.serveStreams()
		return
	}
	<-t.done
}

func (t *server) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		if t.pc != nil {
			_ = t.pc.Close()
		}
		if t.ln != nil {
			_ = t.ln.Close()
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

func (t *server) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
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

// exchange is one request in flight towards an agent, and who is waiting.
type exchange struct {
	client netip.Addr
	// from is the address to answer on a datagram listener.
	from net.Addr
	// requestID is what pairs the answer with the question. It is the only
	// thing that does, which is why an unsolicited response is recognisable.
	requestID int64
	// asked is how large the request was, for the amplification ratio.
	asked int
	// rule is the rule that allowed it, carried so the answer's access
	// line names the rule the question matched.
	rule string
	// version and community are what the manager spoke. A response is
	// rebuilt in them when the request was forwarded in another version,
	// because the manager is owed the version it asked in.
	version   wire.Version
	community string
	at        time.Time
	// peer is where the answer goes and how: into the DTLS session the
	// question arrived in, or to the address it came from.
	//
	// It is the exchange's rather than looked up again, because on a datagram
	// protocol the pairing is all there is: an answer written to the right
	// address in the wrong session, or the right session for the wrong
	// question, is an answer to somebody else.
	peer *peer
	// tsm is the transport security model envelope to rebuild the answer in,
	// nil unless the manager spoke that model. It is what makes a v2c answer
	// from a switch into a v3 message the manager's stack accepts.
	tsm *tsmEcho
	// pdu is the manager's own PDU, kept only where the upstream side is
	// originated as version 3: the relay may have to discover the agent's
	// engine before it can ask, and then it asks with this.
	//
	// It is the request's octets and not the whole message, so it holds no
	// credential of the manager's -- and it is released with the slot, so a
	// manager that stopped waiting leaves nothing behind.
	pdu []byte
}

// answer sends a response back to the client that asked.
func (e *exchange) answer(t *server, b []byte) error {
	if e.peer != nil {
		return e.peer.write(t, b)
	}
	_, err := t.pc.WriteTo(b, e.from)
	return err
}

// tsmEcho is what a response under the transport security model has to carry
// back from the request: its message identifier, the context it named, the
// size it will accept and the level the transport gave.
//
// None of it is this relay's to choose. The identifier is what the manager's
// stack pairs the answer with; the context is what the manager asked about; the
// level is the session's. Everything else about a TSM message -- which is to
// say the security -- is the session's too, which is why four fields are
// enough where a USM response would need keys.
type tsmEcho struct {
	messageID int64
	maxSize   int64
	level     wire.SecurityLevel
	engine    []byte
	context   string
}

// echoOf is the envelope to answer a message in, or nil for a message that is
// not under the transport security model.
func echoOf(m *wire.Message) *tsmEcho {
	if !m.IsTSM() {
		return nil
	}
	return &tsmEcho{messageID: m.V3.MessageID, maxSize: m.V3.MaxSize,
		level: m.V3.Level, engine: m.V3.ContextEngineID, context: m.V3.ContextName}
}

// pending is the table of requests outstanding towards agents.
//
// It is bounded and it expires, because the entries come off the network: a
// client that sent a thousand requests and read no answers would otherwise
// grow this table until something else broke. A full table refuses the new
// request rather than forgetting an old one, because forgetting would make
// the matching that detects an unsolicited response unreliable -- and that
// matching is the check, not a convenience.
type pending struct {
	mu   sync.Mutex
	byID map[int64]*exchange
	max  int
	ttl  time.Duration
	// dropped counts the requests the bound refused.
	dropped uint64
	// onChange publishes the table's size, so an operator can see it
	// filling up rather than only seeing the bound refuse.
	onChange func(int)
}

func newPending(max int, ttl time.Duration) *pending {
	if max <= 0 {
		max = 32
	}
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &pending{byID: map[int64]*exchange{}, max: max, ttl: ttl}
}

// add records a request in flight.
func (p *pending) add(e *exchange, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.at = now
	if _, held := p.byID[e.requestID]; !held && len(p.byID) >= p.max {
		p.expireLocked(now)
		if len(p.byID) >= p.max {
			p.dropped++
			return false
		}
	}
	p.byID[e.requestID] = e
	p.publishLocked()
	return true
}

// take consumes the request an answer belongs to, and says whether there was
// one. A response with no request is unsolicited: on UDP that is the shape
// of a response-spoofing attack against the manager.
func (p *pending) take(id int64, now time.Time) (*exchange, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, held := p.byID[id]
	if !held {
		return nil, false
	}
	delete(p.byID, id)
	p.publishLocked()
	if now.Sub(e.at) > p.ttl {
		// The answer came after the client stopped waiting. It is not
		// forwarded: the manager has timed out and a late answer would
		// arrive against a request identifier it has since reused.
		return e, false
	}
	return e, true
}

// drop removes a request that never left this relay, so the slot is free
// again at once and the count an operator reads stays true. A request that
// was forwarded is never dropped this way: its slot is what the answer will
// be matched against.
func (p *pending) drop(id int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, held := p.byID[id]; !held {
		return
	}
	delete(p.byID, id)
	p.publishLocked()
}

func (p *pending) expireLocked(now time.Time) {
	for id, e := range p.byID {
		if now.Sub(e.at) > p.ttl {
			delete(p.byID, id)
		}
	}
}

// publishLocked reports the table's size to whoever asked to know.
func (p *pending) publishLocked() {
	if p.onChange != nil {
		p.onChange(len(p.byID))
	}
}

// status is how many requests are outstanding and how many the bound
// refused.
func (p *pending) status() (int, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byID), p.dropped
}

// serveStreams accepts TCP connections, which is what RFC 3430 defines and
// what RFC 6353's TLS transport runs over.
func (t *server) serveStreams() {
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
			t.host.Counters().SNMPRejected.Add(1)
			t.host.Counters().Refuse("snmp", "max_connections")
			_ = c.Close()
			continue
		}
		if !t.track(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.running.Leave()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("snmp session")
			t.handleStream(c)
		}()
	}
}

// dialAgent opens a connection to an agent for a stream session.
func (t *server) dialAgent(client netip.Addr) (net.Conn, *upstream.Pool, *upstream.Endpoint, error) {
	pool := t.host.Pool(t.m.Upstream)
	if pool == nil {
		return nil, nil, nil, fmt.Errorf("upstream %q has no pool", t.m.Upstream)
	}
	timeout := t.m.ConnectTimeout.D()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(client.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			t.host.Logs().Error.Warn("snmp agent dial failed", "listener", t.cfg.Name,
				"endpoint", e.Address, "error", err.Error())
			continue
		}
		return c, pool, e, nil
	}
	return nil, pool, nil, errors.New("no reachable agent endpoint")
}
