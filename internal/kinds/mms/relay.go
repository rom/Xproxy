package mms

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
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/limits"
	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sesslimit"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: mms listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	name   string
	mc     *config.MMSListener
	policy *policy
	ln     net.Listener

	learner *learner
	limiter *limits.KeyedLimiter
	anomaly *anomaly.Detector
	// engineering recognises the substation's own tooling and ties it to an
	// approved grant.
	engineering *engineering.Guard
	gate        *sesslimit.Gate
	sessions    acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener) (*server, error) {
	p, err := compile(cfg.MMS)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{host: host, cfg: cfg, name: cfg.Name, mc: cfg.MMS, policy: p, ln: ln,
		gate: sesslimit.New(cfg.MMS.MaxSessions, cfg.MMS.MaxSessionsPerClient)}
	if l := cfg.MMS.Learn; l != nil && l.Enabled {
		t.learner = newLearner(&learnConfig{
			enabled: true, listener: cfg.Name, file: l.File,
			interval: l.Interval.D(), maxSubjects: l.MaxSubjects,
		})
	}
	if n := cfg.MMS.RateLimit; n > 0 {
		burst := cfg.MMS.RateBurst
		if burst <= 0 {
			burst = n
		}
		t.limiter = limits.NewKeyedLimiter(float64(n), burst, 0)
	}
	if t.anomaly, err = anomaly.FromConfig(cfg.MMS.Anomaly, time.Now()); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	if t.engineering, err = engineering.FromConfig(cfg.MMS.Engineering, "mms", cfg.Name,
		host.Access(), host.Logs().Error); err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	return t, nil
}

// enforcing says whether the policy decides or only records.
func (t *server) enforcing() bool { return t.enforcement().Enforcing() }

// enforcement folds this listener's reasons not to enforce into one answer, so
// that the precedence, and the name a status view reports, are the same on
// every kind.
func (t *server) enforcement() config.Enforcement {
	e := config.Enforcement{Shadow: t.cfg.Shadowing(), MonitorOnly: t.mc.MonitorOnly}
	if l := t.mc.Learn; l != nil {
		e.Learning, e.LearnEnforce = l.Enabled, l.Enforce
	}
	return e
}

func (t *server) maxFrame() int {
	if n := t.mc.MaxFrame; n > 0 {
		return n
	}
	return wire.DefaultMaxFrame
}

func (t *server) handshakeTimeout() time.Duration {
	if d := t.mc.HandshakeTimeout.D(); d > 0 {
		return d
	}
	return 30 * time.Second
}

func (t *server) maxPending() int {
	if n := t.mc.MaxPendingRequests; n > 0 {
		return n
	}
	return DefaultMaxPending
}

// DefaultMaxPending bounds the in-flight table when no bound is configured. A
// substation client with more than this many confirmed requests outstanding is not a
// client any estate has, and the table is one a peer would otherwise fill by opening
// invoke identifiers it never finishes.
const DefaultMaxPending = 64

func (t *server) serve() {
	if t.learner != nil {
		t.learner.Start(func(err error) {
			t.host.Logs().Error.Warn("mms learning report could not be written",
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
			_ = c.Close()
			return
		}
		go func() {
			defer t.sessions.Leave()
			defer safe.Guard("mms session")
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
		t.host.Logs().Error.Warn("mms learning report could not be written at shutdown",
			"listener", t.name, "error", err.Error())
	}
}

// conn is one association and the state the policy needs it to have.
type conn struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	// tap records the session for a pcapng capture, and is nil -- usable, and
	// doing nothing -- whenever no rule wants this one, which is the usual case.
	tap *capture.Tap

	cliReader *wire.Reader
	upReader  *wire.Reader

	cmu sync.Mutex
	umu sync.Mutex

	mu sync.Mutex
	a  Association
	// requests counts what the client has sent, denied what was refused.
	requests int
	denied   int
	// pending maps an invoke identifier to what its answer will need. One table
	// with one bound, and the bound is the point.
	pending map[uint64]*inflight
	// lastSubjects are the learning rows the request being decided was recorded
	// under, handed from the observer to the in-flight table.
	lastSubjects []learnKey
}

// inflight is what one invoke identifier is remembered for until its answer arrives.
type inflight struct {
	svc wire.Service
	// subjects are the learning rows the request was recorded under. An MMS error
	// answers a request and names nothing of its own, so one attributed by
	// identity and service alone would land on a row with no object in it and
	// leave the rows the request made reading as traffic the IED accepted.
	subjects []learnKey
	// selecting is the control object a select was for, so that the IED's
	// *positive* answer is what records the selection rather than the client's
	// asking for one. A relay that recorded the select on the request would let a
	// client operate an object the IED refused to select.
	selecting string
}

func (c *conn) assoc() Association {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.a
	a.At = time.Now()
	// The selection table is shared with the caller, which only reads it, and
	// every write to it goes through select()/deselect() under this lock.
	return a
}

func (c *conn) update(f func(*Association)) {
	c.mu.Lock()
	f(&c.a)
	c.mu.Unlock()
}

func (c *conn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	c.a.Requests = c.requests
	return c.requests
}

func (c *conn) refusal() {
	c.mu.Lock()
	c.denied++
	c.mu.Unlock()
}

// remember records what an invoke identifier carried.
func (c *conn) remember(id uint64, svc wire.Service, selecting string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = make(map[uint64]*inflight, 8)
	}
	if len(c.pending) >= c.t.maxPending() {
		// Past the bound the association is dropped rather than the table grown.
		// What is lost is the ability to name the service an answer belongs to,
		// which costs a log line its detail and costs no decision anything --
		// except the select, which is why a dropped select is also a selection
		// that will not be recorded, and an operate that will therefore be
		// refused rather than allowed.
		return
	}
	c.pending[id] = &inflight{svc: svc, selecting: selecting}
}

// recordSubjects adds the learning rows to a request already remembered.
func (c *conn) recordSubjects(id uint64, keys []learnKey) {
	if len(keys) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if f := c.pending[id]; f != nil {
		f.subjects = keys
	}
}

// took returns and forgets what an invoke identifier was remembered for.
func (c *conn) took(id uint64) (*inflight, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.pending[id]
	delete(c.pending, id)
	return f, ok
}

// MaxSelections bounds the selections one association may hold. A substation client
// selects one object at a time and operates it; the bound is loose enough for a
// sequence and tight enough that a client cannot make a table out of it.
const MaxSelections = 64

// selected records a selection the IED confirmed.
func (c *conn) selected(key string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.a.Selected == nil {
		c.a.Selected = make(map[string]time.Time, 4)
	}
	if len(c.a.Selected) >= MaxSelections {
		// Dropped rather than grown, and the consequence is the safe one: an
		// operate on an object whose selection was not recorded is refused.
		return
	}
	c.a.Selected[key] = until
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

// admitClient runs the shared admission point: the threat lists and the estate's
// authorization policy, before anything is read.
func (t *server) admitClient(c *conn) string {
	ip := c.ip
	h := t.host
	return admit.Client(admit.Deps{
		Lists: h.ThreatIntel(),
		// A behaviour pack holding this address out, where one is.
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
		// One fact per connection, to the cross-listener window: this
		// address was on this listener. It is what the questions no
		// listener can answer by itself are built from -- one host on
		// three control protocols is three of these facts and one actor.
		Observe: func(f correlate.Fact) { h.ObserveFact(ip, f) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "mms",
		Client:   ip,
		Target:   t.mc.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("mms", reason)
			h.Shadow().Record("mms", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(c, reason, detail) },
	})
}

// handle runs one association.
//
// Unlike the OPC UA relay, the IED is dialled before the first frame is decided
// about, and the reason is which layer carries the identity: there is nothing in the
// COTP connection request worth refusing on IEC 61850 -- the selectors are a
// convention -- so holding the dial back would buy nothing and would break the
// connection-request/confirm exchange the transport needs before anything else can
// be sent. What is refused before the dial is the client itself.
func (t *server) handle(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	ip := netutil.AddrOf(nc.RemoteAddr().String())
	c := &conn{t: t, ip: ip, client: nc}
	c.a = Association{IP: ip}
	// Opened before anything can refuse the session, because a refused session is
	// the one an operator most often wants and it never dials: after that point
	// there is nothing left to record. A nil tap wraps nothing and writes nothing.
	c.tap = t.host.Capture().Open("mms", t.name, "", nc.RemoteAddr())
	defer c.tap.Close()
	c.client = c.tap.Client(nc)

	if d := t.policy.Connect(c.assoc()); !d.Allow {
		t.refuseConn(c, d, "connect")
		return
	}
	if t.admitClient(c) != "" {
		return
	}
	if !t.admit(c) {
		return
	}
	defer t.release(c)

	up, err := t.dial(c)
	if err != nil {
		t.deny(c, "upstream_unavailable", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	c.up = c.tap.Upstream(up)
	c.cliReader = wire.NewReader(c.client, t.maxFrame())
	c.upReader = wire.NewReader(up, t.maxFrame())
	t.observeAssociation(c)
	t.relay(c)
}

func (t *server) admit(c *conn) bool {
	ok, reason := t.gate.Enter(c.ip)
	if !ok {
		t.deny(c, reason, "")
	}
	return ok
}

func (t *server) release(c *conn) { t.gate.Leave(c.ip) }

// dial opens the connection to the IED.
func (t *server) dial(c *conn) (net.Conn, error) {
	pool := t.host.Pool(t.mc.Upstream)
	if pool == nil {
		return nil, fmt.Errorf("upstream %q has no pool", t.mc.Upstream)
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
	return nil, errors.New("no reachable mms endpoint")
}

// relay runs both directions.
func (t *server) relay(c *conn) {
	if d := t.mc.SessionDuration.D(); d > 0 {
		_ = c.client.SetDeadline(time.Now().Add(d))
		_ = c.up.SetDeadline(time.Now().Add(d))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("mms ied reader")
		t.fromServer(c)
		_ = c.client.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("mms client reader")
		t.fromClient(c)
		_ = c.up.Close()
	}()
	wg.Wait()
}

// fromClient reads the client's frames and decides about each one.
func (t *server) fromClient(c *conn) {
	// The handshake bound covers the transport connection, the association and the
	// initiate, which is where a peer that opened a socket and said nothing sits.
	_ = c.client.SetReadDeadline(time.Now().Add(t.handshakeTimeout()))
	for {
		f, err := c.cliReader.Next()
		if err != nil {
			if !ended(err) {
				t.deny(c, "unreadable_frame", err.Error())
			}
			return
		}
		if c.assoc().Initiated {
			// Past the handshake the idle timeout takes over, or nothing where
			// none is configured: a substation association is long-lived and polls
			// continuously, and a listener that closed a quiet one would close the
			// link on the shift where nothing happens.
			if d := t.mc.IdleTimeout.D(); d > 0 {
				_ = c.client.SetReadDeadline(time.Now().Add(d))
			} else {
				_ = c.client.SetReadDeadline(time.Time{})
			}
		}
		forward, fatal := t.decide(c, f)
		if fatal {
			return
		}
		if !forward {
			continue
		}
		if err := c.writeUp(f.Raw); err != nil {
			return
		}
	}
}

// fromServer reads the IED's frames. They are forwarded, and read for three things:
// the association's answer, the presentation context list, and whether a select was
// confirmed.
func (t *server) fromServer(c *conn) {
	for {
		f, err := c.upReader.Next()
		if err != nil {
			if !ended(err) {
				t.serverError(c, err)
			}
			return
		}
		t.readServer(c, f)
		if err := c.writeClient(f.Raw); err != nil {
			return
		}
	}
}

// ended says an error is the association finishing rather than a peer misbehaving.
func ended(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}
