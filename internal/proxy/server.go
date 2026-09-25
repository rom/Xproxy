// Package proxy is the xproxy data plane: listeners, the request pipeline
// and the reverse proxy engine.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/intel"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/shadow"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/upstream"
)

// Server runs the listeners of one configuration and supports hot
// reload. It is the engine: the accept path, the sockets and their
// lifecycle, the state every listener kind shares, and the management
// plane. What a protocol does with a connection belongs to a kind.
type Server struct {
	logs  *logging.Logs
	stats *Stats

	rt         atomic.Pointer[runtime]
	generation atomic.Uint64

	// plane is the data plane this binary linked, or nil. It owns the
	// compiled policy its listeners share; the engine holds it only to
	// build a generation, take a snapshot and answer the management
	// views.
	plane atomic.Pointer[Plane]

	// fingerprints holds the TLS fingerprint of every open TLS connection.
	fingerprints *tlsconf.FingerprintTable
	connLimiter  *limits.ConnLimiter
	// drains records which endpoints and pools an operator has taken out
	// of rotation. It belongs to the process rather than to a
	// configuration generation, because a reload builds new pools and
	// must not undo somebody's decision to stop sending work to a
	// machine.
	drains *upstream.Drains
	// acceptRate is the process-wide accept rate from server.limits,
	// replaced wholesale on reload. A listener with its own
	// connection_rate section replaces it for that listener rather than
	// adding to it, so one number is the answer to "what bounds this
	// port".
	acceptRate atomic.Pointer[limits.AcceptRate]
	bans       atomic.Pointer[ban.List]
	intel      atomic.Pointer[intel.Set]
	cluster    atomic.Pointer[cluster.Node]
	sampler    *metrics.Sampler
	acme       *acme.Manager
	// handshake refuses clients in the ClientHello. It is read from
	// inside the TLS handshake, so it is swapped rather than locked.
	handshake atomic.Pointer[handshakePolicy]
	// capture writes exchanges as pcapng, kept across generations so a
	// recording survives a reload.
	capture atomic.Pointer[capture.Capturer]
	// live is the table of sessions this daemon is serving now, which
	// every kind that holds one registers with.
	live *sessions.Table
	// wouldDeny is what the listeners in shadow mode would have refused.
	wouldDeny *shadow.Ledger
	// tickets manages shared session ticket keys; nil without the section.
	tickets        *tlsconf.Tickets
	ticketMismatch bound.Notice
	// connRejected aggregates connections refused at accept. They are
	// driven by a client at packet rate, so one record each would be a
	// log-flood primitive. (The dns kind keeps its own, per listener.)
	connRejected bound.Notice

	mu        sync.Mutex
	listeners []*boundListener
	started   bool
	reloadMu  sync.Mutex
}

type boundListener struct {
	cfg config.Listener
	// acc owns the accept socket; front is this generation's view of it
	// and ln the wrapped listener the server accepts from.
	acc       *acceptor
	front     *front
	ln        net.Listener
	tlsReload *tlsconf.Reloadable
	activated bool
	// inst is the data plane of a registered listener kind; dns is the
	// status view's handle on the same object, for the one kind the
	// management API asks about by listener rather than by protocol.
	inst Instance
	dns  *dns.Server // kind: dns listeners
	// rate is the accept rate applied to this listener, the process's
	// own or this listener's replacement for it.
	rate *limits.AcceptRate
}

// rate is the process's current accept gate.
func (s *Server) rate() *limits.AcceptRate { return s.acceptRate.Load() }

// setAcceptRate installs the gate from a configuration. A reload
// replaces it, and listeners look it up per connection, so a rate
// change rebinds no socket.
func (s *Server) setAcceptRate(cfg *config.Config, logs *logging.Logs) {
	a := acceptRateFor(cfg.Server.Limits.ConnectionRate, cfg.Server.Limits.ConnectionRatePerSource)
	a.OnReject = s.rejectAccept(logs)
	// The count is carried across so the counter does not go backwards
	// on a reload, which a monotonic counter must never do.
	if old := s.acceptRate.Load(); old != nil {
		a.Rejected.Store(old.Rejected.Load())
	}
	s.acceptRate.Store(a)
}

// rejectAccept reports a connection the rate gate closed. It is
// aggregated for the same reason the limiter's own refusals are: this
// runs on the accept loop, and a client looping connections must not
// make each refusal cost a synchronous log write.
func (s *Server) rejectAccept(logs *logging.Logs) func(netip.Addr, string) {
	return func(addr netip.Addr, reason string) {
		s.connRejected.Hit(logs.Error, "connections refused at accept are aggregated",
			"reason", reason, "client_ip", addr.String())
	}
}

// acceptRateFor builds the gate for one accept rate configuration. It
// always returns a gate, inactive where nothing is configured, so no
// caller has to test for nil.
func acceptRateFor(r *config.ConnectionRate, sr *config.SourceRate) *limits.AcceptRate {
	var perSecond float64
	var burst int
	if r != nil {
		perSecond, burst = r.PerSecond, r.Burst
	}
	if sr == nil {
		return limits.NewAcceptRate(perSecond, burst, 0, 0, 0, 0, 0)
	}
	return limits.NewAcceptRate(perSecond, burst, sr.PerSecond, sr.Burst, sr.IPv4Prefix, sr.IPv6Prefix, sr.MaxSources)
}

// New creates a server for cfg. Listeners are not opened until Start.
func New(cfg *config.Config, logs *logging.Logs) (*Server, error) {
	s := &Server{
		logs: logs,
		stats: &Stats{StartedAt: time.Now(),
			RequestDuration: metrics.NewHistogram(metrics.DurationBuckets),
			UpstreamTTFB:    metrics.NewHistogram(metrics.DurationBuckets)},
		fingerprints: tlsconf.NewFingerprintTable(max(cfg.Server.Limits.MaxConnections, 1024)),
		connLimiter:  limits.NewConnLimiter(cfg.Server.Limits.MaxConnections, cfg.Server.Limits.MaxConnectionsPerIP),
		drains:       upstream.NewDrains(),
		live:         sessions.New(),
		wouldDeny:    shadow.NewLedger(shadowBound(cfg)),
	}
	// A contained panic is a bug in the proxy, not an event about the
	// client, so it goes to the error log with its stack rather than to
	// the security log. Set here because every deployment builds a
	// Server before any listener accepts.
	safe.Report = func(what string, value any, stack []byte) {
		logs.Error.Error("panic contained", "where", what, "panic", fmt.Sprint(value), "stack", string(stack))
	}
	if ti := cfg.ThreatIntel; ti != nil {
		set, err := newIntel(ti)
		if err != nil {
			return nil, err
		}
		s.intel.Store(set)
	}
	if st := cfg.Server.SessionTickets; st != nil {
		tk, err := tlsconf.NewTickets(st, logs.Error.With("component", "tickets"))
		if err != nil {
			return nil, err
		}
		tk.OnRotate = func(fp string) {
			s.publishEvent(cluster.Event{Kind: eventTicketKeys, Key: fp, Until: time.Now().Add(st.Rotate.D())})
		}
		s.tickets = tk
	}
	s.setAcceptRate(cfg, logs)
	s.connLimiter.OnReject = func(addr netip.Addr, reason string) {
		// This runs on the listener's accept loop and the file sink is a
		// locked write, so a banned client looping connections would pay
		// one SYN for one synchronous security record: a banned address
		// must not be more expensive to refuse than an ordinary one.
		// The exact rate stays available as
		// xproxy_connections_rejected_total.
		s.connRejected.Hit(logs.Error, "connections refused at accept are aggregated",
			"reason", reason, "client_ip", addr.String())
	}
	if cfg.Bans != nil {
		bl, err := ban.New(cfg.Bans, logs.Security)
		if err != nil {
			return nil, err
		}
		s.bans.Store(bl)
	}
	if cfg.Capture != nil {
		cp, err := capture.New(cfg.Capture)
		if err != nil {
			return nil, err
		}
		if cp != nil {
			s.capture.Store(cp)
		}
	}
	s.connLimiter.Banned = func(addr netip.Addr) bool {
		bl := s.bans.Load()
		return bl != nil && bl.DropsConnections() && bl.Banned(addr)
	}
	s.handshake.Store(newHandshakePolicy(cfg.Handshake))
	gen := s.generation.Add(1)
	rt, err := newRuntime(cfg, gen, logs.Error, s.drains)
	if err != nil {
		if bl := s.bans.Load(); bl != nil {
			bl.Close()
		}
		return nil, err
	}
	s.rt.Store(rt)
	// unwind releases what New has built so far. Once the plane is
	// committed it owns the JWKS refreshers, the ICAP pools and the
	// filters, which rt.stop no longer covers: the engine runtime holds
	// only the upstream pools since the data plane became a kind. A
	// failure after that point returns no Server, so nothing else will
	// ever call Shutdown to release them.
	unwind := func() {
		if pl := s.planeOrNil(); pl != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pl.Stop(ctx)
		}
		rt.stop()
		if bl := s.bans.Load(); bl != nil {
			bl.Close()
		}
	}
	// The data plane, where this binary linked one. It compiles its own
	// generation against the pools just built, so a route naming an
	// upstream that failed never reaches a listener.
	if newPlane != nil {
		pl, err := newPlane(s)
		if err != nil {
			unwind()
			return nil, err
		}
		// No Retire: this is the first generation, so there is nothing
		// for the plane to hand back.
		commit, _, err := pl.Prepare(Generation{
			Config: cfg, Number: gen, Pools: rt.pools, Trusted: rt.trusted, ICAP: rt.icap,
		})
		if err != nil {
			unwind()
			return nil, err
		}
		commit()
		s.plane.Store(&pl)
	}
	s.sampler = metrics.NewSampler(seriesCounters, seriesGauges, cfg.Metrics.SampleInterval.D(), cfg.Metrics.Retention.D(), s.sample)
	if cfg.ACME != nil {
		var groups [][]string
		for _, ln := range cfg.Server.Listeners {
			if ln.TLS != nil {
				for _, g := range ln.TLS.ACME {
					groups = append(groups, g.Hosts)
				}
			}
		}
		if len(groups) > 0 {
			m, err := acme.New(*cfg.ACME, groups, logs.Error)
			if err != nil {
				unwind()
				return nil, err
			}
			m.OnChange(func() { s.logs.Audit.Info("acme certificates updated") })
			s.acme = m
		}
	}
	if cfg.Cluster != nil {
		node, err := cluster.New(cfg.Cluster, rateSource{s: s}, logs.Error)
		if err != nil {
			unwind()
			return nil, err
		}
		node.AttachBans(banStore(s.bans.Load()))
		node.OnEvent(s.onClusterEvent)
		s.cluster.Store(node)
	}
	return s, nil
}

// banStore converts a possibly nil *ban.List into a cluster.BanStore
// without the typed-nil interface trap.
func banStore(bl *ban.List) cluster.BanStore {
	if bl == nil {
		return nil
	}
	return bl
}

// ThreatIntel returns the imported lists, or nil when the section is
// absent.
func (s *Server) ThreatIntel() *intel.Set { return s.intel.Load() }

// Bans returns the ban list, or nil when bans are not configured.
func (s *Server) Bans() *ban.List { return s.bans.Load() }

func (s *Server) cfg() *config.Config { return s.rt.Load().cfg }

// Config returns the active configuration.
func (s *Server) Config() *config.Config { return s.cfg() }

// Stats returns a snapshot of the counters.
func (s *Server) Stats() Snapshot {
	snap := s.stats.snapshot()
	snap.OpenConnections = s.connLimiter.Open()
	snap.RejectedConns = s.connLimiter.Rejected.Load()
	snap.RateRefusedConns = s.rate().Rejected.Load()
	s.mu.Lock()
	for _, bl := range s.listeners {
		if bl.rate != nil {
			snap.RateRefusedConns += bl.rate.Rejected.Load()
		}
	}
	s.mu.Unlock()
	s.mu.Lock()
	for _, bl := range s.listeners {
		if fc, ok := bl.inst.(FlowCounter); ok {
			snap.QUICFlowsOpen += fc.OpenFlows()
		}
	}
	s.mu.Unlock()
	s.dnsTotals(&snap)
	if bl := s.bans.Load(); bl != nil {
		snap.BansActive, snap.BansTotal = bl.Stats()
	}
	// The live sessions, so a status view says what the table says: how
	// many are on now, and how many an operator has closed.
	snap.Shadow = s.wouldDeny.Status()
	live := s.live.Status()
	snap.SessionsLive, snap.SessionsOpened = live.Live, live.Opened
	snap.SessionsClosed, snap.SessionsKilled = live.Closed, live.Killed
	snap.SessionsRefused = live.Refused
	if set := s.intel.Load(); set != nil {
		snap.ThreatLists = set.Status()
		snap.ThreatIntelReloads = set.Reloads.Load()
		snap.ThreatIntelWatching = set.Refreshing()
	}
	if node := s.cluster.Load(); node != nil {
		snap.ClusterPeers = len(node.Status().Peers)
		snap.ClusterConnected = node.ConnectedPeers()
	}
	if pl := s.planeOrNil(); pl != nil {
		pl.Snapshot(&snap)
	}
	ls := s.logs.Stats()
	snap.LogSyslogSent, snap.LogSyslogDropped, snap.LogJournalDropped, snap.LogRedaction = ls.SyslogSent, ls.SyslogDropped, ls.JournalDropped, ls.Redaction
	snap.LogSIEMSent, snap.LogSIEMDropped = ls.SIEMSent, ls.SIEMDropped
	snap.LogWriteErrors = ls.WriteErrors
	return snap
}

// ACME returns the certificate manager, or nil when not configured.
func (s *Server) ACME() *acme.Manager { return s.acme }

// CertificateExpiry returns the earliest file certificate expiry per TLS
// listener (listeners without file certificates are omitted).
func (s *Server) CertificateExpiry() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]time.Time{}
	for _, bl := range s.listeners {
		if bl.tlsReload != nil {
			if t := bl.tlsReload.NotAfter(); !t.IsZero() {
				out[bl.cfg.Name] = t
			}
		}
	}
	return out
}

// Tracing returns the tracer status, or nil when tracing is off. It is
// the data plane's: a daemon that terminates no requests emits no
// spans.
func (s *Server) Tracing() *tracing.Status {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Tracing()
	}
	return nil
}

// Certificates lists the served certificates per TLS listener with their
// OCSP staple and Certificate Transparency state.
func (s *Server) Certificates() map[string][]tlsconf.CertInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]tlsconf.CertInfo{}
	for _, bl := range s.listeners {
		if bl.tlsReload != nil {
			out[bl.cfg.Name] = bl.tlsReload.Certificates()
		}
	}
	return out
}

// KeyExchangeStatus is the management view of the key agreement policy
// and what clients actually negotiated.
type KeyExchangeStatus struct {
	// Groups is the offered list per TLS listener, in preference order.
	Groups map[string][]string `json:"groups"`
	// Negotiated counts completed handshakes by group.
	Negotiated map[string]uint64 `json:"negotiated"`
	// PostQuantum is how many of those used a hybrid group, which is
	// the number a rollout is measured by.
	PostQuantum uint64 `json:"post_quantum"`
}

// KeyExchange reports the configured groups and the negotiated ones.
func (s *Server) KeyExchange() KeyExchangeStatus {
	st := KeyExchangeStatus{Groups: map[string][]string{},
		Negotiated: s.stats.KeyExchangeCounts(), PostQuantum: s.stats.KeyExchangePQ.Load()}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bl := range s.listeners {
		if bl.cfg.TLS == nil {
			continue
		}
		names := bl.cfg.TLS.KeyExchange
		if len(names) == 0 {
			for _, id := range config.DefaultKeyExchange() {
				names = append(names, config.GroupName(id))
			}
		}
		st.Groups[bl.cfg.Name] = names
	}
	return st
}

// ECH reports the Encrypted Client Hello state per listener. A listener
// without the section is left out rather than reported as disabled, so
// an empty map means no listener accepts ECH.
func (s *Server) ECH() map[string]*tlsconf.ECHStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]*tlsconf.ECHStatus{}
	for _, bl := range s.listeners {
		if bl.tlsReload == nil {
			continue
		}
		if st := bl.tlsReload.ECH(); st != nil {
			out[bl.cfg.Name] = st
		}
	}
	return out
}

// Tickets returns the session ticket key status, nil without the section.
func (s *Server) Tickets() *tlsconf.TicketStatus { return s.tickets.Status() }

// Upstreams returns endpoint statistics per upstream.
func (s *Server) Upstreams() map[string][]upstream.Stats {
	rt := s.rt.Load()
	out := make(map[string][]upstream.Stats, len(rt.pools))
	for name, p := range rt.pools {
		out[name] = p.Stats()
	}
	return out
}

// Drains reports the operator decisions this process holds: the pools in
// maintenance and the endpoints taken out of rotation.
func (s *Server) Drains() upstream.Decisions { return s.drains.Decisions() }

// SetDrain records a decision to stop sending new work to one endpoint
// of a pool, or with no address to the whole pool, and reports whether a
// live pool or endpoint of that name was found. Nothing is closed: what
// is running finishes.
func (s *Server) SetDrain(pool, address string, draining bool) bool {
	if address == "" {
		return s.drains.SetPool(pool, draining)
	}
	return s.drains.SetEndpoint(pool, address, draining)
}

// Pools returns the pool level status (circuit breaker, queue) by name.
func (s *Server) Pools() map[string]upstream.PoolStatus {
	rt := s.rt.Load()
	out := make(map[string]upstream.PoolStatus, len(rt.pools))
	for name, p := range rt.pools {
		out[name] = p.Status()
	}
	return out
}

// Generation returns the configuration generation counter.
func (s *Server) Generation() uint64 { return s.rt.Load().generation }

// Start opens all listeners and begins serving. It returns once every
// listener is bound; serving continues in the background until Shutdown.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("already started")
	}
	cfg := s.cfg()
	act, err := activatedListeners()
	if err != nil {
		return fmt.Errorf("socket activation: %w", err)
	}
	if s.tickets != nil {
		s.tickets.Start()
		s.publishEvent(cluster.Event{Kind: eventTicketKeys, Key: s.tickets.Fingerprint(), Until: time.Now().Add(cfg.Server.SessionTickets.Rotate.D())})
	}
	activated := act
	for i := range cfg.Server.Listeners {
		lc := cfg.Server.Listeners[i]
		bl, err := s.bind(lc, activated)
		if err != nil {
			s.closeListenersLocked()
			return err
		}
		s.listeners = append(s.listeners, bl)
	}
	if node := s.cluster.Load(); node != nil {
		ln, act, err := listenerFor(activated, "cluster", cfg.Cluster.Listen, cfg.Cluster.LocalSocketMode())
		if err != nil {
			s.closeListenersLocked()
			return fmt.Errorf("cluster listener: %w", err)
		}
		s.logs.Error.Info("cluster listener bound", "address", ln.Addr().String(), "socket_activated", act)
		node.Start(ln)
	}
	for name, ln := range activated.streams {
		s.logs.Error.Warn("unused socket from systemd", "name", name)
		_ = ln.Close()
	}
	for name, pc := range activated.packets {
		s.logs.Error.Warn("unused datagram socket from systemd", "name", name)
		_ = pc.Close()
	}
	s.rt.Load().start()
	if pl := s.planeOrNil(); pl != nil {
		pl.Start()
	}
	s.sampler.Start()
	if set := s.intel.Load(); set != nil {
		set.Refresh(cfg.ThreatIntel.RefreshInterval().D(), func(err error) {
			s.logs.Error.Warn("threat intel list", "err", err.Error())
		})
	}
	if s.acme != nil {
		s.acme.Start()
	}
	for _, bl := range s.listeners {
		go s.serve(bl)
	}
	s.started = true
	return nil
}

func (s *Server) bind(lc config.Listener, activated *activated) (*boundListener, error) {
	// A datagram kind gets no accept socket: the engine opens its
	// packet socket here so the listener still has an address to be
	// named and logged by, and hands it to the kind.
	if k, linked := kindFor(lc.Kind); linked && k.Datagram {
		pc, act, err := packetFor(activated, lc.Name, lc.Address)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		acc := newAcceptor(newDatagramListener(pc.LocalAddr()))
		bl, err := s.buildWith(lc, acc, act, activated, pc)
		if err != nil {
			acc.close()
			_ = pc.Close()
			return nil, err
		}
		return bl, nil
	}
	ln, act, err := listenerFor(activated, lc.Name, lc.Address, 0)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
	}
	acc := newAcceptor(ln)
	bl, err := s.build(lc, acc, act, activated)
	if err != nil {
		acc.close()
		return nil, err
	}
	return bl, nil
}

// build assembles a listener around an accept socket. On error the
// resources created here are released; the socket stays with the caller.
func (s *Server) build(lc config.Listener, acc *acceptor, act bool, activated *activated) (*boundListener, error) {
	return s.buildWith(lc, acc, act, activated, nil)
}

// buildWith is build with a datagram socket the caller already opened,
// which the kind's first Packet("") call is handed instead of opening a
// second one on an address that is already taken.
func (s *Server) buildWith(lc config.Listener, acc *acceptor, act bool, activated *activated, pre net.PacketConn) (*boundListener, error) {
	ln := acc.raw
	fr := acc.newFront()
	// The rate gate is the inner wrapper, so it decides first: a
	// connection refused for arriving too fast should never have taken
	// a limiter slot, and the cheapest refusal is the earliest one.
	var own *limits.AcceptRate
	gate := func() *limits.AcceptRate { return s.rate() }
	if lc.ConnectionRate != nil || lc.ConnectionRatePerSource != nil {
		own = acceptRateFor(lc.ConnectionRate, lc.ConnectionRatePerSource)
		own.OnReject = s.rejectAccept(s.logs)
		gate = func() *limits.AcceptRate { return own }
	}
	bl := &boundListener{cfg: lc, acc: acc, front: fr,
		ln: s.connLimiter.Wrap(limits.WrapRate(fr, gate)), activated: act, rate: own}
	k, linked := kindFor(lc.Kind)
	if !linked {
		// The kind is one this project implements and this binary did
		// not link. Refusing is the point of the split: a listener that
		// quietly fell through to another kind would answer the wrong
		// protocol on the right port.
		_ = fr.Close()
		return nil, fmt.Errorf("listener %s: kind %q is served by %s, not by this daemon", lc.Name, lc.Kind, daemonFor(lc.Kind))
	}
	if lc.ProxyProtocol && k.ProxyHeader {
		bl.ln = &proxyListener{Listener: bl.ln,
			trusted:  func() []netip.Prefix { return s.rt.Load().trusted },
			onReject: s.connLimiter.Reject,
		}
	}
	// The kind owns everything from here: the engine has prepared the
	// socket and, where the kind asked for it, the TLS configuration,
	// and the kind builds its own data plane.
	su := &Setup{Host: s, Config: lc, Net: bl.ln, Plane: s.planeOrNil(),
		Packet: func(suffix string) (net.PacketConn, error) {
			if suffix == "" && pre != nil {
				pc := pre
				pre = nil
				return pc, nil
			}
			name := lc.Name
			if suffix != "" {
				name += "-" + suffix
			}
			addr := lc.Address
			if strings.HasSuffix(lc.Address, ":0") {
				addr = ln.Addr().String()
			}
			pc, _, err := packetFor(activated, name, addr)
			return pc, err
		}}
	if k.TLS && lc.TLS != nil {
		tc, rl, err := s.listenerTLS(lc)
		if err != nil {
			_ = fr.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		bl.tlsReload = rl
		su.TLS = tc
	}
	inst, err := k.New(su)
	if err != nil {
		_ = fr.Close()
		if bl.tlsReload != nil {
			bl.tlsReload.Close()
		}
		return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
	}
	bl.inst = inst
	bl.ln = su.Net // a kind may have wrapped the socket, as implicit TLS does
	s.attachKind(bl, inst)
	return bl, nil
}

func (s *Server) serve(bl *boundListener) {
	s.logs.Error.Info("listening", "listener", bl.cfg.Name, "address", bl.ln.Addr().String(), "tls", bl.cfg.TLS != nil, "kind", bl.cfg.Kind, "socket_activated", bl.activated)
	bl.inst.Serve()
}

// Addrs returns the bound addresses by listener name (useful for tests and
// for the status command when port 0 was configured).
func (s *Server) Addrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.listeners))
	for _, bl := range s.listeners {
		out[bl.cfg.Name] = bl.ln.Addr().String()
		// A kind that listens on more than the engine's accept socket
		// (an HTTP/3 endpoint, a second datagram port) says so, under
		// its listener's name and the suffix it chose.
		if a, ok := bl.inst.(ExtraAddrs); ok {
			for suffix, addr := range a.Addrs() {
				out[bl.cfg.Name+"/"+suffix] = addr
			}
		}
	}
	return out
}

// Reload swaps in a new configuration. Listeners are matched by name:
// new ones are bound and served, missing ones stop accepting and drain,
// and one whose settings changed beyond what applies in place
// (certificate files, forward policy, dns policy) is rebuilt, on the same
// accept socket when its address is unchanged. Every bind and build
// happens before anything is switched, so a failure leaves the old
// configuration and listener set active.
func (s *Server) Reload(cfg *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	old := s.rt.Load()
	s.mu.Lock()
	plan, err := s.planListeners(cfg.Server.Listeners)
	s.mu.Unlock()
	if err != nil {
		s.stats.ReloadFailures.Add(1)
		return err
	}
	if err := clusterCompatible(old.cfg.Cluster, cfg.Cluster); err != nil {
		s.stats.ReloadFailures.Add(1)
		return err
	}
	gen := s.generation.Add(1)
	rt, err := newRuntime(cfg, gen, s.logs.Error, s.drains)
	if err != nil {
		s.stats.ReloadFailures.Add(1)
		return err
	}
	// The data plane compiles its own generation against the pools just
	// built. Everything that can fail happens now; nothing is swapped
	// until every listener is bound too.
	commitPlane, discardPlane := func() {}, func() {}
	planeRetires := false
	if pl := s.planeOrNil(); pl != nil {
		planeRetires = true
		commitPlane, discardPlane, err = pl.Prepare(Generation{
			Config: cfg, Number: gen, Pools: rt.pools, Trusted: rt.trusted, ICAP: rt.icap,
			Retire: func() { old.stop() },
		})
		if err != nil {
			rt.stop()
			s.stats.ReloadFailures.Add(1)
			return err
		}
	}
	// Capture: rebuild it from the new rules, and carry the recording
	// state across so a reload during a reproduction does not silently
	// stop the capture. A section that disappeared closes its file.
	if err := s.reloadCapture(cfg); err != nil {
		discardPlane()
		rt.stop()
		s.stats.ReloadFailures.Add(1)
		return err
	}
	// The handshake policy is read from inside every TLS handshake, so
	// it is swapped whole; the refusal counter starts again with the
	// new policy, which is the honest reading of a changed rule set.
	s.handshake.Store(newHandshakePolicy(cfg.Handshake))
	// Ban list: reconfigure in place so active bans survive; create or
	// drop it when the section appears or disappears.
	oldBans := s.bans.Load()
	var newBans *ban.List
	switch {
	case cfg.Bans != nil && oldBans != nil:
		if oldBans.StateFile() == cfg.Bans.StateFile {
			oldBans.Reconfigure(cfg.Bans)
			newBans = oldBans
		} else {
			bl, err := ban.New(cfg.Bans, s.logs.Security)
			if err != nil {
				discardPlane()
				rt.stop()
				s.stats.ReloadFailures.Add(1)
				return err
			}
			newBans = bl
		}
	case cfg.Bans != nil:
		bl, err := ban.New(cfg.Bans, s.logs.Security)
		if err != nil {
			discardPlane()
			rt.stop()
			s.stats.ReloadFailures.Add(1)
			return err
		}
		newBans = bl
	}
	// The imported lists, read before the switch: a file that has gone
	// missing aborts the reload rather than leaving a section that
	// matches nothing.
	var newIntelSet *intel.Set
	if cfg.ThreatIntel != nil {
		set, err := newIntel(cfg.ThreatIntel)
		if err != nil {
			discardPlane()
			rt.stop()
			s.stats.ReloadFailures.Add(1)
			return err
		}
		newIntelSet = set
	}

	// Bind and build the added and replaced listeners, then reload the
	// certificates of the kept ones, before switching, so a port that
	// cannot be bound or a bad certificate aborts the reload as a whole.
	fresh := make([]freshListener, 0, len(plan.add)+len(plan.replace))
	abort := func(err error) error {
		for _, f := range fresh {
			s.discard(f)
		}
		discardPlane()
		rt.stop()
		s.stats.ReloadFailures.Add(1)
		return err
	}
	noAct := &activated{streams: map[string]net.Listener{}, packets: map[string]net.PacketConn{}}
	for _, lc := range plan.add {
		bl, err := s.bind(lc, noAct)
		if err != nil {
			return abort(err)
		}
		fresh = append(fresh, freshListener{bl: bl, owns: true})
	}
	for _, r := range plan.replace {
		var bl *boundListener
		var err error
		if r.reuse {
			bl, err = s.build(r.cfg, r.old.acc, r.old.activated, noAct)
		} else {
			bl, err = s.bind(r.cfg, noAct)
		}
		if err != nil {
			return abort(err)
		}
		fresh = append(fresh, freshListener{bl: bl, owns: !r.reuse})
	}
	s.mu.Lock()
	for _, bl := range plan.keep {
		// A kind whose policy can be replaced where it stands says so,
		// and a reload does not have to rebind its socket or drop what
		// is connected to it.
		if a, ok := bl.inst.(Applier); ok {
			for i := range cfg.Server.Listeners {
				if lc := cfg.Server.Listeners[i]; lc.Name == bl.cfg.Name {
					if err := a.Apply(lc); err != nil {
						s.mu.Unlock()
						return abort(fmt.Errorf("listener %s: %w", bl.cfg.Name, err))
					}
				}
			}
		}
		if bl.tlsReload == nil {
			continue
		}
		for i := range cfg.Server.Listeners {
			if cfg.Server.Listeners[i].Name == bl.cfg.Name {
				bl.cfg.TLS.Certificates = cfg.Server.Listeners[i].TLS.Certificates
			}
		}
		if err := bl.tlsReload.Load(); err != nil {
			s.mu.Unlock()
			return abort(fmt.Errorf("listener %s: %w", bl.cfg.Name, err))
		}
	}
	s.mu.Unlock()
	rt.start()
	s.connLimiter.SetLimits(cfg.Server.Limits.MaxConnections, cfg.Server.Limits.MaxConnectionsPerIP)
	s.setAcceptRate(cfg, s.logs)
	// Enforcement first, then the routes. Both gates are skipped when
	// their pointer is nil, so installing the new routes before the ban
	// list and the challenger leaves a window in which a route the
	// operator just gave challenge: {mode: always} is served
	// unchallenged. Installing them early is safe the other way round:
	// the old generation's routes carry no challenge, so nothing is
	// challenged before its time.
	if newBans != oldBans {
		s.bans.Store(newBans)
		if oldBans != nil {
			defer oldBans.Close()
		}
	}
	// The imported lists are swapped whole, and the old set's refresh
	// loop stops with it: two loops re-reading the same files would
	// each be right and one of them pointless.
	if old := s.intel.Swap(newIntelSet); old != newIntelSet {
		old.Stop()
		if newIntelSet != nil {
			newIntelSet.Refresh(cfg.ThreatIntel.RefreshInterval().D(), func(err error) {
				s.logs.Error.Warn("threat intel list", "err", err.Error())
			})
		}
	}
	s.rt.Store(rt)
	commitPlane()
	// Switch the listener set: the new listeners start serving on the new
	// generation, the replaced and removed ones stop accepting now and
	// drain their connections in the background.
	byName := map[string]*boundListener{}
	for _, bl := range plan.keep {
		byName[bl.cfg.Name] = bl
	}
	for _, f := range fresh {
		byName[f.bl.cfg.Name] = f.bl
	}
	set := make([]*boundListener, 0, len(cfg.Server.Listeners))
	for i := range cfg.Server.Listeners {
		set = append(set, byName[cfg.Server.Listeners[i].Name])
	}
	s.mu.Lock()
	s.listeners = set
	s.mu.Unlock()
	for _, f := range fresh {
		go s.serve(f.bl)
	}
	drain := cfg.Server.ShutdownTimeout.D()
	for _, r := range plan.replace {
		go s.retire(r.old, drain, !r.reuse, "replaced")
	}
	for _, bl := range plan.remove {
		go s.retire(bl, drain, true, "removed")
	}
	if node := s.cluster.Load(); node != nil {
		node.Reconfigure(cfg.Cluster)
		if newBans != oldBans {
			node.AttachBans(banStore(newBans))
		}
	}
	s.stats.Reloads.Add(1)
	// The old generation stops probing at once: its health state is no
	// longer consulted. Its pools stay open until the data plane reports
	// that the last request compiled against it has finished — a pool
	// closed under a long upload or an SSE stream cuts it — or, in a
	// daemon with no data plane, for the drain period.
	old.stopChecks()
	if !planeRetires {
		go func(old *runtime) {
			time.Sleep(cfg.Server.ShutdownTimeout.D())
			old.stop()
		}(old)
	}
	s.logs.Error.Info("configuration reloaded", "generation", rt.generation, "routes", len(cfg.Routes), "upstreams", len(cfg.Upstreams))
	s.logs.Audit.Info("reload", "generation", rt.generation)
	return nil
}

// clusterCompatible rejects cluster changes that need a restart: enabling
// or disabling clustering, the listen address, the node identity and the
// TLS material.
func clusterCompatible(old, new_ *config.Cluster) error {
	if (old == nil) != (new_ == nil) {
		return errors.New("reload: cluster enabled or disabled; restart required")
	}
	if old == nil {
		return nil
	}
	if old.Listen != new_.Listen || old.NodeID != new_.NodeID || fmt.Sprint(old.TLS) != fmt.Sprint(new_.TLS) {
		return errors.New("reload: cluster listen, node_id or tls changed; restart required")
	}
	// The socket's mode and the user ids allowed on it are settled when
	// the socket is created and when a peer connects, so changing either
	// in place would leave the running node admitting what the file no
	// longer says it should.
	if fmt.Sprint(old.Local) != fmt.Sprint(new_.Local) {
		return errors.New("reload: cluster.local changed; restart required")
	}
	return nil
}

// listenerPlan is what a reload does to the listener set.
type listenerPlan struct {
	keep    []*boundListener // unchanged beyond the settings applied in place
	add     []config.Listener
	replace []listenerReplace
	remove  []*boundListener
}

// listenerReplace rebuilds a listener; with reuse the accept socket of
// the old one is kept, so no connection is refused during the switch.
type listenerReplace struct {
	old   *boundListener
	cfg   config.Listener
	reuse bool
}

type freshListener struct {
	bl   *boundListener
	owns bool // the accept socket is not shared with a retiring listener
}

// planListeners matches the running listeners with the next
// configuration, by name and then by address (a renamed listener keeps
// its socket). Caller holds mu.
func (s *Server) planListeners(next []config.Listener) (*listenerPlan, error) {
	p := &listenerPlan{}
	byName := map[string]*boundListener{}
	for _, bl := range s.listeners {
		byName[bl.cfg.Name] = bl
	}
	used := map[*boundListener]bool{}
	var pending []config.Listener
	for i := range next {
		lc := next[i]
		old, ok := byName[lc.Name]
		if !ok {
			pending = append(pending, lc)
			continue
		}
		used[old] = true
		if listenerInPlace(old.cfg, lc) {
			p.keep = append(p.keep, old)
			continue
		}
		p.replace = append(p.replace, listenerReplace{old: old, cfg: lc, reuse: old.cfg.Address == lc.Address})
	}
	for _, lc := range pending {
		var match *boundListener
		for _, bl := range s.listeners {
			if !used[bl] && bl.cfg.Address == lc.Address {
				match = bl
				break
			}
		}
		if match == nil {
			p.add = append(p.add, lc)
			continue
		}
		used[match] = true
		p.replace = append(p.replace, listenerReplace{old: match, cfg: lc, reuse: true})
	}
	for _, r := range p.replace {
		// The UDP socket of the old listener (h3, quic relay, dns) stays
		// bound until it drains, so the new one cannot bind the same port.
		if r.reuse && config.ListenerHasUDP(r.old.cfg) {
			return nil, fmt.Errorf("reload: listener %s changed on the same address and has a UDP socket (h3, quic or dns); restart required", r.old.cfg.Name)
		}
	}
	for _, bl := range s.listeners {
		if !used[bl] {
			p.remove = append(p.remove, bl)
		}
	}
	return p, nil
}

// listenerInPlace reports whether the two configurations differ only in
// what Reload applies to a running listener: certificate files, the
// forward policy and the dns policy.
func listenerInPlace(o, n config.Listener) bool {
	norm := func(l config.Listener) config.Listener {
		l.Forward = nil
		if l.DNS != nil {
			l.DNS = &config.DNSListener{DoHPath: l.DNS.DoHPath}
		}
		if l.TLS != nil {
			t := *l.TLS
			t.Certificates = nil
			l.TLS = &t
		}
		return l
	}
	return reflect.DeepEqual(norm(o), norm(n))
}

// retire stops a listener that a reload replaced or removed: it stops
// accepting at once and drains its connections for at most drain.
func (s *Server) retire(bl *boundListener, drain time.Duration, closeSocket bool, why string) {
	ctx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	s.stopListener(ctx, bl, closeSocket)
	s.logs.Error.Info("listener retired", "listener", bl.cfg.Name, "address", bl.ln.Addr().String(), "reason", why)
}

// discard releases a listener that was built for a reload that failed
// and never served.
func (s *Server) discard(f freshListener) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.stopListener(ctx, f.bl, f.owns)
}

// stopListener stops accepting, drains within ctx and releases the
// listener's resources; with closeSocket the accept socket is closed too
// (not when a replacement inherited it).
//
// It reports nothing: a kind drains its own connections and says in the
// log what it could not finish, because only the kind knows what an
// unfinished session of its protocol means.
func (s *Server) stopListener(ctx context.Context, bl *boundListener, closeSocket bool) {
	_ = bl.front.Close()
	bl.inst.Shutdown(ctx)
	if c, ok := bl.inst.(Closer); ok {
		c.Close()
	}
	if bl.tlsReload != nil {
		bl.tlsReload.Close()
	}
	if closeSocket {
		bl.acc.close()
	}
}

// ReloadCertificates re-reads listener certificates and upstream client
// certificates without a full reload.
func (s *Server) ReloadCertificates() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bl := range s.listeners {
		if bl.tlsReload != nil {
			if err := bl.tlsReload.Load(); err != nil {
				return fmt.Errorf("listener %s: %w", bl.cfg.Name, err)
			}
		}
	}
	for _, p := range s.rt.Load().pools {
		if err := p.ReloadClientCertificate(); err != nil {
			return err
		}
	}
	return nil
}

// reloadCapture swaps the capturer for one built from the new
// configuration, keeping whether it was recording and for how long.
func (s *Server) reloadCapture(cfg *config.Config) error {
	old := s.capture.Load()
	cp, err := capture.New(cfg.Capture)
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	if old != nil {
		cp.CarryFrom(old)
		old.Close()
	}
	if cp == nil {
		s.capture.Store(nil)
		return nil
	}
	s.capture.Store(cp)
	return nil
}

// Capture returns the capturer, or nil when the configuration has no
// capture section.
func (s *Server) Capture() *capture.Capturer { return s.capture.Load() }

// Sessions is the table of live sessions, for the kinds that register
// and for the management plane that lists and closes them.
func (s *Server) Sessions() *sessions.Table { return s.live }

// Shadow is the ledger of what the listeners in shadow mode would have
// refused.
func (s *Server) Shadow() *shadow.Ledger { return s.wouldDeny }

// CaptureStatus reports the capture state, with Enabled false when the
// configuration has no capture section.
func (s *Server) CaptureStatus() capture.Stats { return s.capture.Load().Stats() }

// SetCapture turns recording on or off and reports the new state. A
// proxy without a capture section refuses: there is nothing to turn on,
// and silently doing nothing would leave an operator waiting for a file
// that is never written.
func (s *Server) SetCapture(on bool, d time.Duration) (capture.Stats, error) {
	cp := s.capture.Load()
	if cp == nil {
		return capture.Stats{}, capture.ErrNotEnabled
	}
	cp.SetActive(on, d)
	return cp.Stats(), nil
}

// Shutdown drains connections gracefully within ctx, then closes
// listeners and upstream pools.
//
// It always returns nil today: a listener that could not finish
// draining reports that itself, in the log of the kind that knows what
// an unfinished session of its protocol means. The error is in the
// signature because callers should keep checking one.
func (s *Server) Shutdown(ctx context.Context) error {
	s.tickets.Stop()
	s.intel.Load().Stop()
	// The capture file is flushed and closed here: a truncated pcapng is
	// readable, but the last exchange in it would be the one that is
	// missing, which is the one being investigated.
	if cp := s.capture.Load(); cp != nil {
		cp.Close()
	}
	s.mu.Lock()
	lns := s.listeners
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, bl := range lns {
		wg.Add(1)
		go func(bl *boundListener) {
			defer wg.Done()
			s.stopListener(ctx, bl, true)
		}(bl)
	}
	wg.Wait()
	if s.started {
		s.sampler.Stop()
		if s.acme != nil {
			s.acme.Stop()
		}
	}
	if node := s.cluster.Load(); node != nil {
		node.Stop()
	}
	// The data plane after the listeners: its generation is what they
	// were serving from, and releasing it first would close a filter
	// under a request still draining.
	if pl := s.planeOrNil(); pl != nil {
		pl.Stop(ctx)
	}
	s.rt.Load().stop()
	if bl := s.bans.Load(); bl != nil {
		bl.Close()
	}
	return nil
}

func (s *Server) closeListenersLocked() {
	for _, bl := range s.listeners {
		_ = bl.front.Close()
		bl.acc.close()
	}
	s.listeners = nil
}

// shadowBound is the ledger's size, from the estate's policy section.
func shadowBound(cfg *config.Config) int {
	if cfg != nil && cfg.Policy != nil {
		return cfg.Policy.MaxReasons
	}
	return 0
}
