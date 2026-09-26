package amqp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: amqp listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	ac     *config.AMQPListener
	policy *policy
	ln     net.Listener
	tlsCfg *tls.Config

	upTLSMode string
	upTLSCfg  *tls.Config

	// limiter bounds methods per second per client address.
	limiter *limits.KeyedLimiter

	// gate bounds the sessions held, altogether and per client address.
	gate *sesslimit.Gate

	// sessions tracks what has been accepted, so shutdown waits for it. A
	// bare WaitGroup would not do: its Add must not race its Wait, and an
	// accept loop Adds at exactly the moment a shutdown Waits.
	sessions acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tlsCfg *tls.Config) (*server, error) {
	p, err := compile(cfg.AMQP)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, ac: cfg.AMQP, policy: p,
		ln: ln, tlsCfg: tlsCfg, upTLSMode: cfg.AMQP.UpstreamTLSMode,
		gate: sesslimit.New(cfg.AMQP.MaxSessions, cfg.AMQP.MaxSessionsPerClient)}
	if t.upTLSMode == "" {
		t.upTLSMode = "disable"
	}
	if t.upTLSMode != "disable" {
		if t.upTLSCfg, _, err = tlsconf.Client(cfg.AMQP.UpstreamTLS); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_tls: %w", cfg.Name, err)
		}
	}
	if p.requireTLS && tlsCfg == nil {
		return nil, fmt.Errorf("listener %s: require_tls is set but the listener has no certificate", cfg.Name)
	}
	if n := cfg.AMQP.RateLimit; n > 0 {
		burst := cfg.AMQP.RateBurst
		if burst <= 0 {
			burst = n
		}
		t.limiter = limits.NewKeyedLimiter(float64(n), burst, 0)
	}
	return t, nil
}

func (t *server) enforcing() bool { return !t.ac.MonitorOnly && !t.cfg.Shadowing() }

func (t *server) serve() {
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
			defer safe.Guard("amqp session")
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
}

// handle runs one connection.
//
// The shape is fixed by the protocol: eight octets say which version the
// connection is, and that decides the framing of everything after it. So the
// header is read and decided before the broker is dialled -- a client asking
// for a version this listener does not serve never reaches the broker at all.
func (t *server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	ip := netutil.AddrOf(c.RemoteAddr().String())
	se := newSession(t, c, ip)

	if t.tlsCfg != nil {
		if err := t.upgradeClient(se); err != nil {
			t.deny(ip, "tls_handshake", err.Error())
			return
		}
	}
	if d := t.policy.Connect(se.sess()); !d.Allow {
		t.refused(se, d, "connect")
		return
	}
	if !t.admit(se) {
		return
	}
	defer t.release(se)

	// The protocol header, under the handshake timeout: a connection that
	// opens a socket and says nothing is a connection holding a slot.
	if d := t.ac.HandshakeTimeout.D(); d > 0 {
		_ = se.client.SetReadDeadline(time.Now().Add(d))
	} else {
		_ = se.client.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	se.cliReader = wire.NewReader(se.client, t.policy.MaxFrame())
	h, err := se.cliReader.Header()
	if err != nil {
		t.deny(ip, "no_protocol_header", err.Error())
		return
	}
	_ = se.client.SetReadDeadline(time.Time{})
	if d := t.policy.Version(h); !d.Allow {
		t.refused(se, d, h.String())
		// The protocol's own answer: a header this listener does serve,
		// and then the socket closes.
		if t.policy.nak {
			_ = se.writeClient(t.policy.preferredHeader())
		}
		return
	}
	se.setVersion(h.Version())
	t.observe(se, h)

	up, err := t.dial(se)
	if err != nil {
		t.deny(ip, "upstream_unavailable", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	se.up = up
	se.upReader = wire.NewReader(up, t.policy.MaxFrame())
	se.upReader.SetVersion(h.Version())
	if err := se.writeUp(h.Bytes()); err != nil {
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

// dial opens the connection to the broker, upgrading the leg when the mode
// asks.
func (t *server) dial(se *session) (net.Conn, error) {
	pool := t.host.Pool(t.ac.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.ac.Upstream)
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
		if t.upTLSMode == "disable" {
			return c, nil
		}
		tc, err := t.upgradeUpstream(c, e.Address)
		if err != nil {
			_ = c.Close()
			if t.upTLSMode == "require" {
				return nil, err
			}
			continue
		}
		return tc, nil
	}
	return nil, errors.New("no reachable amqp endpoint")
}

func (t *server) upgradeClient(se *session) error {
	tc := tls.Server(se.client, t.tlsCfg)
	ctx, cancel := context.WithTimeout(context.Background(), t.handshakeTimeout())
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	se.client = tc
	se.setSecure()
	return nil
}

func (t *server) upgradeUpstream(c net.Conn, address string) (net.Conn, error) {
	cfg := t.upTLSCfg.Clone()
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		cfg.ServerName = host
	}
	tc := tls.Client(c, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), t.handshakeTimeout())
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}

func (t *server) handshakeTimeout() time.Duration {
	if d := t.ac.HandshakeTimeout.D(); d > 0 {
		return d
	}
	return 30 * time.Second
}

// relay runs both directions.
//
// The two share one piece of state that has to be a flag rather than a
// sequence: on AMQP 1.0 a successful SASL exchange ends with *both* peers
// sending a fresh protocol header on the same socket (§5.3.2), and the
// broker's outcome is what says so. The reader towards the broker sets the
// flag for both directions when it forwards that outcome, which is safe
// because the client only sends its new header after receiving the outcome --
// and the outcome passes through this relay on its way there.
func (t *server) relay(se *session) {
	if d := t.ac.SessionDuration.D(); d > 0 {
		_ = se.client.SetDeadline(time.Now().Add(d))
		_ = se.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("amqp broker reader")
		t.fromBroker(se)
		_ = se.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("amqp client reader")
		t.fromClient(se)
		_ = se.up.Close()
	}()
	wg.Wait()
}

// fromClient reads the client's frames and applies the policy.
func (t *server) fromClient(se *session) {
	max := t.policy.MaxMethods(se.sess())
	for {
		if idle := t.ac.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		f, h, err := se.cliReader.NextOrHeader()
		if h != nil {
			// A protocol header in the middle of the stream, which is
			// what a 1.0 connection sends after its SASL exchange. It is
			// decided again rather than waved through: it is the same
			// choice of framing as the first one.
			if d := t.policy.Version(*h); !d.Allow {
				t.refuse(se, d, h.String())
				return
			}
			if err := se.writeUp(h.Bytes()); err != nil {
				return
			}
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				// A frame that is not AMQP, or one over the bound. The
				// connection ends with the protocol's own statement, because
				// a client library reports that and reconnects rather than
				// hanging.
				t.refuse(se, hardDeny("unreadable_frame", err.Error()), "")
			}
			return
		}
		if !f.KnownType() {
			t.refuse(se, hardDeny("frame_type_unknown", fmt.Sprint(f.Type)), "")
			return
		}
		if f.Heartbeat() {
			if err := se.writeUp(f.Raw); err != nil {
				return
			}
			continue
		}
		if t.limiter != nil && !t.limiter.Allow(se.ip.String()) {
			t.refuse(se, hardDeny("rate_limited", ""), "")
			return
		}
		if n := se.count(); max > 0 && n > max {
			t.refuse(se, hardDeny("too_many_methods", fmt.Sprint(max)), "")
			return
		}
		ok, fatal := t.decide(se, f)
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

// decide applies the policy to one frame from the client.
//
// It returns whether to forward the frame, and whether the connection is
// over. A refusal ends the connection: this protocol is stateful in both
// directions, and dropping one frame out of a conversation leaves the two
// sides disagreeing about what happened.
func (t *server) decide(se *session, f *wire.Frame) (forward, fatal bool) {
	if se.version == wire.V10 {
		return t.decide10(se, f)
	}
	switch f.Type {
	case wire.FrameMethod:
		return t.decideMethod(se, f)
	case wire.FrameHeader:
		return t.decideContent(se, f)
	case wire.FrameBody:
		total, over := se.body(f.Channel, len(f.Payload))
		if over {
			// A body longer than the content header declared, or a body
			// with no header before it. Either way the channel's framing
			// is not what it said it was.
			t.refuse(se, hardDeny("body_past_declared_size", fmt.Sprint(total)), "")
			return false, true
		}
		return true, false
	}
	return true, false
}

func (t *server) decideMethod(se *session, f *wire.Frame) (forward, fatal bool) {
	m, err := wire.ParseMethod(f.Payload)
	if err != nil {
		t.refuse(se, hardDeny("unreadable_frame", err.Error()), "")
		return false, true
	}
	s := se.sess()
	name := m.Name()
	d := t.policy.Method(s, m)
	if !d.Allow {
		return t.refusal(se, d, name)
	}

	// What the frame changes about this connection, recorded only once the
	// policy has allowed it.
	switch name {
	case "connection.start-ok":
		mech, user, ok := m.Mechanism()
		if !ok {
			t.refuse(se, hardDeny("arguments_unreadable", name), "")
			return false, true
		}
		if md := t.policy.Mechanism(mech); !md.Allow {
			return t.refusal(se, md, name)
		}
		if ud := t.policy.User(user); !ud.Allow {
			return t.refusal(se, ud, name)
		}
		se.expectAuth(mech, user)
	case "connection.tune-ok":
		ch, fr, hb, ok := m.Tune()
		if !ok {
			t.refuse(se, hardDeny("arguments_unreadable", name), "")
			return false, true
		}
		if td := t.policy.Tune(ch, fr, hb); !td.Allow {
			return t.refusal(se, td, name)
		}
	case "connection.open":
		vhost, ok := m.VirtualHost()
		if !ok {
			t.refuse(se, hardDeny("arguments_unreadable", name), "")
			return false, true
		}
		if vd := t.policy.Vhost(s, vhost); !vd.Allow {
			return t.refusal(se, vd, name)
		}
		se.setVhost(vhost)
	case "channel.open":
		if !se.openChannel(f.Channel, t.policy.MaxChannels()) {
			return t.refusal(se, hardDeny("too_many_channels",
				fmt.Sprint(t.policy.MaxChannels())), name)
		}
	case "channel.close", "channel.close-ok":
		se.closeChannel(f.Channel)
	}
	if t.ac.LogMethods {
		t.logMethod(se, name, m)
	}
	return true, false
}

// decideContent decides about a message's own properties, and records the
// size its header declared.
func (t *server) decideContent(se *session, f *wire.Frame) (forward, fatal bool) {
	h, err := wire.ParseContentHeader(f.Payload)
	if err != nil {
		t.refuse(se, hardDeny("unreadable_frame", err.Error()), "")
		return false, true
	}
	if d := t.policy.Content(se.sess(), h); !d.Allow {
		return t.refusal(se, d, "content")
	}
	se.declare(f.Channel, h.BodySize)
	return true, false
}

// decide10 is the AMQP 1.0 side.
func (t *server) decide10(se *session, f *wire.Frame) (forward, fatal bool) {
	p, err := wire.ParsePerformative(f.Payload)
	if err != nil {
		t.refuse(se, hardDeny("unreadable_frame", err.Error()), "")
		return false, true
	}
	s := se.sess()
	name := p.Name()
	if d := t.policy.Performative(s, p); !d.Allow {
		return t.refusal(se, d, name)
	}
	switch p.Code {
	case wire.PerfSASLInit:
		mech, user, hostname, ok := p.SASLInit()
		if !ok {
			t.refuse(se, hardDeny("arguments_unreadable", name), "")
			return false, true
		}
		if md := t.policy.Mechanism(mech); !md.Allow {
			return t.refusal(se, md, name)
		}
		if ud := t.policy.User(user); !ud.Allow {
			return t.refusal(se, ud, name)
		}
		se.expectAuth(mech, user)
		if hostname != "" {
			if vd := t.policy.Vhost(s, hostname); !vd.Allow {
				return t.refusal(se, vd, name)
			}
			se.setVhost(hostname)
		}
	case wire.PerfOpen:
		_, hostname, maxFrame, _, _, ok := p.Open()
		if !ok {
			t.refuse(se, hardDeny("arguments_unreadable", name), "")
			return false, true
		}
		if od := t.policy.Open(s, hostname, maxFrame); !od.Allow {
			return t.refusal(se, od, name)
		}
		se.setVhost(hostname)
	case wire.PerfBegin:
		if !se.openChannel(f.Channel, t.policy.MaxChannels()) {
			return t.refusal(se, hardDeny("too_many_channels",
				fmt.Sprint(t.policy.MaxChannels())), name)
		}
	case wire.PerfEnd:
		se.closeChannel(f.Channel)
	case wire.PerfAttach:
		lname, handle, role, source, target, ok := p.Attach()
		if !ok {
			t.refuse(se, hardDeny("arguments_unreadable", name), "")
			return false, true
		}
		addr := target
		if role == wire.RoleReceiver {
			addr = source
		}
		if !se.attach(f.Channel, handle, &link{name: lname, role: role, address: addr,
			at: time.Now()}, t.policy.MaxLinks()) {
			return t.refusal(se, hardDeny("too_many_links",
				fmt.Sprint(t.policy.MaxLinks())), name)
		}
	case wire.PerfDetach:
		if h, ok := p.Handle(); ok {
			se.detach(f.Channel, h)
		}
	case wire.PerfTransfer:
		if d := t.transfer(se, f, p); !d.Allow {
			return t.refusal(se, d, name)
		}
	}
	if t.ac.LogMethods {
		t.logPerformative(se, name, p)
	}
	return true, false
}

// transfer decides about a message on AMQP 1.0.
//
// The frame carries a link handle and the message's octets, and nothing else:
// the address is in the attach this relay saw earlier. So the handle is
// resolved to that address, and the size is the sum over a run of transfers
// with `more` set, because a message on this version may be split across
// them and bounding each frame would bound nothing.
func (t *server) transfer(se *session, f *wire.Frame, p *wire.Performative) Decision {
	handle, _, _, more, aborted, ok := p.Transfer()
	if !ok {
		return hardDeny("arguments_unreadable", "transfer")
	}
	if aborted {
		return allow()
	}
	l, known := se.linkFor(f.Channel, handle)
	if !known {
		// A transfer on a handle this relay never saw attached. The broker
		// will refuse it, and it is refused here too: the alternative is
		// forwarding a message whose address was never checked, which is
		// exactly what the handle table exists to prevent.
		return hardDeny("no_such_link", fmt.Sprint(handle))
	}
	total := se.transfer(f.Channel, l.address, len(f.Payload), more)
	if max := t.policy.MaxMessage(se.sess()); max > 0 && total > uint64(max) { //nolint:gosec // max is positive
		return hardDeny("message_too_large",
			fmt.Sprintf("%d octets on %s, over the %d this listener allows", total, l.address, max))
	}
	return allow()
}

// refusal turns a refused decision into what the relay does about it.
//
// In monitor mode a soft refusal is recorded and the frame goes on; a hard
// one ends the connection whatever the mode, because the refusals marked hard
// are the ones that cannot be undone after the fact -- a purge, a delete, a
// frame the relay could not read, a bound.
func (t *server) refusal(se *session, d Decision, what string) (forward, fatal bool) {
	se.refusal()
	t.refused(se, d, what)
	if !t.enforcing() && !d.Hard {
		return true, false
	}
	t.close(se, d)
	return false, true
}

// refuse is refusal for the cases that are always fatal.
func (t *server) refuse(se *session, d Decision, what string) {
	se.refusal()
	t.refused(se, d, what)
	t.close(se, d)
}

// close tells the client no in its own protocol and ends the connection.
func (t *server) close(se *session, d Decision) {
	if !t.policy.nak {
		return
	}
	msg := "refused by xproxy: " + d.Reason
	if d.Detail != "" {
		msg += " (" + d.Detail + ")"
	}
	switch {
	case se.version != wire.V10:
		_ = se.writeClient(closeFrame091(msg))
	case !se.sess().Authed:
		// Before the connection exists there is nothing to close, so the
		// refusal is the SASL layer's.
		_ = se.writeClient(saslOutcome10())
	default:
		_ = se.writeClient(closeFrame10(msg))
	}
}

// fromBroker forwards the broker's frames, and reads four things out of them.
//
// The broker's side is not where a policy is enforced -- it is where the
// answers are. Whether a credential was accepted, what bounds were offered,
// what the broker refused and why, and what it is handing to this client.
func (t *server) fromBroker(se *session) {
	for {
		f, h, err := se.upReader.NextOrHeader()
		if h != nil {
			// The broker's own header: its answer to a 1.0 client's, and
			// the way either version says "not that version" before
			// closing. Either way it is the client's to see.
			if err := se.writeClient(h.Bytes()); err != nil {
				return
			}
			continue
		}
		if err != nil {
			return
		}
		t.readBroker(se, f)
		if err := se.writeClient(f.Raw); err != nil {
			return
		}
	}
}

// readBroker reads what the broker said, without deciding anything the
// client asked for.
func (t *server) readBroker(se *session, f *wire.Frame) {
	if f.Heartbeat() {
		return
	}
	if se.version == wire.V10 {
		t.readBroker10(se, f)
		return
	}
	if f.Type != wire.FrameMethod {
		return
	}
	m, err := wire.ParseMethod(f.Payload)
	if err != nil {
		return
	}
	switch m.Name() {
	case "connection.start":
		// The mechanisms the broker offers. ANONYMOUS among them is worth
		// a line: it is a login with no identity, and a client that picks
		// it is refused here -- but the offer itself says the broker would
		// have accepted it from anything that reached it directly.
		if mechs, ok := m.Mechanisms(); ok {
			t.brokerMechanisms(se, mechs)
		}
	case "connection.tune":
		// A 0-9-1 broker that refuses a credential closes the connection
		// instead of tuning, so tune is the answer to "was the password
		// right". The same reasoning as the redis kind's reply to an AUTH:
		// the broker decides, and the relay reads its decision.
		se.authOK()
		t.authenticated(se)
	case "connection.close", "channel.close":
		if code, text, _, _, ok := m.CloseReason(); ok {
			t.brokerRefused(se, code, text)
		}
	case "basic.deliver", "basic.get-ok", "basic.return":
		if targets, ok := m.Targets(); ok {
			if d := t.policy.Delivery(se.sess(), targets); !d.Allow {
				t.refuse(se, d, m.Name())
			}
		}
	}
}

func (t *server) readBroker10(se *session, f *wire.Frame) {
	p, err := wire.ParsePerformative(f.Payload)
	if err != nil {
		return
	}
	switch p.Code {
	case wire.PerfSASLMechanisms:
		if mechs, ok := p.SASLMechanisms(); ok {
			t.brokerMechanisms(se, mechs)
		}
	case wire.PerfSASLOutcome:
		code, ok := p.SASLOutcome()
		if !ok {
			return
		}
		if code == 0 {
			se.authOK()
			t.authenticated(se)
			// Both peers now start again with a fresh protocol header,
			// which each reader recognises for itself.
			return
		}
		t.authFailed(se)
	case wire.PerfClose, wire.PerfEnd, wire.PerfDetach:
		if cond, desc, ok := p.CloseError(); ok && cond != "" {
			t.brokerError(se, cond, desc)
		}
	}
}

// observe records what this connection said about the machine at the other
// end.
func (t *server) observe(se *session, h wire.Header) {
	t.host.ObserveAsset(assets.Observation{
		Proto:    "amqp",
		Listener: t.name,
		Addr:     se.ip,
		// The version a client asked for is the strongest thing a broker
		// connection says about the software at the other end: 1.0 is a
		// modern library or a cloud SDK, and 0-9-1 is everything else.
		Description: "amqp " + h.String(),
	})
}
