// Package proxy is the xproxy data plane: listeners, the request pipeline
// and the reverse proxy engine.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/challenge"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/geoip"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/shed"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/upstream"
	"github.com/rom/xproxy/internal/waf"
)

// Server runs the data plane for one configuration and supports hot reload.
type Server struct {
	logs  *logging.Logs
	stats *Stats

	rt         atomic.Pointer[runtime]
	generation atomic.Uint64

	concurrency *limits.Concurrency
	tarpits     *limits.Concurrency // bound on requests held in a tarpit
	marks       *marks              // clients that hit a honeypot
	// fingerprints holds the TLS fingerprint of every open TLS connection.
	fingerprints *tlsconf.FingerprintTable
	// cache is the response cache, kept across reloads; nil when the
	// configuration has no cache section.
	cache       atomic.Pointer[cache.Cache]
	connLimiter *limits.ConnLimiter
	bans        atomic.Pointer[ban.List]
	cluster     atomic.Pointer[cluster.Node]
	shedder     atomic.Pointer[shed.Shedder]
	challenger  atomic.Pointer[challenge.Challenger]
	tracer      atomic.Pointer[tracing.Tracer]
	sampler     *metrics.Sampler
	acme        *acme.Manager
	// wafStats keeps per rule counters and learning across reloads.
	wafStats *waf.Stats
	// patches keeps virtual patch hit counters across generations.
	patches patchCounters
	// tickets manages shared session ticket keys; nil without the section.
	tickets        *tlsconf.Tickets
	ticketMismatch bound.Notice

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
	httpSrv   *http.Server
	tlsReload *tlsconf.Reloadable
	activated bool
	h3        *h3.Server
	tcp       *tcpServer     // kind: tcp listeners
	forward   *forwardServer // kind: forward listeners
	dns       *dns.Server    // kind: dns listeners
}

// New creates a server for cfg. Listeners are not opened until Start.
func New(cfg *config.Config, logs *logging.Logs) (*Server, error) {
	s := &Server{
		logs: logs,
		stats: &Stats{StartedAt: time.Now(),
			RequestDuration: metrics.NewHistogram(metrics.DurationBuckets),
			UpstreamTTFB:    metrics.NewHistogram(metrics.DurationBuckets)},
		concurrency:  limits.NewConcurrency(cfg.Server.Limits.MaxConcurrentRequests),
		tarpits:      limits.NewConcurrency(cfg.Server.Limits.MaxTarpits),
		marks:        newMarks(),
		fingerprints: tlsconf.NewFingerprintTable(max(cfg.Server.Limits.MaxConnections, 1024)),
		connLimiter:  limits.NewConnLimiter(cfg.Server.Limits.MaxConnections, cfg.Server.Limits.MaxConnectionsPerIP),
		wafStats:     waf.NewStats(),
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
	s.connLimiter.OnReject = func(addr netip.Addr, reason string) {
		s.logs.SecurityEvent(context.Background(), "drop_connection", reason, "client_ip", addr.String())
	}
	if cfg.Bans != nil {
		bl, err := ban.New(cfg.Bans, logs.Security)
		if err != nil {
			return nil, err
		}
		s.bans.Store(bl)
	}
	if cfg.Shedding != nil {
		s.shedder.Store(shed.New(cfg.Shedding, s.concurrency.InFlight, cfg.Server.Limits.MaxConcurrentRequests))
	}
	if cfg.Challenge != nil {
		ch, err := challenge.New(cfg.Challenge)
		if err != nil {
			if bl := s.bans.Load(); bl != nil {
				bl.Close()
			}
			return nil, err
		}
		s.challenger.Store(ch)
	}
	s.connLimiter.Banned = func(addr netip.Addr) bool {
		bl := s.bans.Load()
		return bl != nil && bl.DropsConnections() && bl.Banned(addr)
	}
	rt, err := newRuntime(cfg, s.generation.Add(1), logs.Error, newEventBus(s), s.wafStats, &s.patches)
	if err != nil {
		if bl := s.bans.Load(); bl != nil {
			bl.Close()
		}
		return nil, err
	}
	s.rt.Store(rt)
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
				rt.stop()
				if bl := s.bans.Load(); bl != nil {
					bl.Close()
				}
				return nil, err
			}
			m.OnChange(func() { s.logs.Audit.Info("acme certificates updated") })
			s.acme = m
		}
	}
	if cfg.Cache != nil {
		s.cache.Store(cache.New(cfg.Cache.MaxBytes, cfg.Cache.MaxObjectBytes))
	}
	if cfg.Tracing.IsEnabled() {
		tr, err := newTracer(cfg.Tracing, logs.Error)
		if err != nil {
			rt.stop()
			return nil, err
		}
		s.tracer.Store(tr)
	}
	if cfg.Cluster != nil {
		node, err := cluster.New(cfg.Cluster, rateSource{s: s}, logs.Error)
		if err != nil {
			rt.stop()
			if bl := s.bans.Load(); bl != nil {
				bl.Close()
			}
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
	snap.InFlight = s.concurrency.InFlight()
	snap.HoneypotMarked = len(s.marks.list(time.Now()))
	s.mu.Lock()
	for _, bl := range s.listeners {
		if bl.tcp != nil && bl.tcp.quic != nil {
			snap.QUICFlowsOpen += bl.tcp.quic.open()
		}
	}
	s.mu.Unlock()
	s.dnsTotals(&snap)
	if bl := s.bans.Load(); bl != nil {
		snap.BansActive, snap.BansTotal = bl.Stats()
	}
	if node := s.cluster.Load(); node != nil {
		snap.ClusterPeers = len(node.Status().Peers)
		snap.ClusterConnected = node.ConnectedPeers()
	}
	if sh := s.shedder.Load(); sh != nil {
		ss := sh.Snapshot()
		snap.LoadLevel = ss.Level
		snap.UpstreamLatencyMS = ss.LatencyMS
		snap.SheddingClasses = []string{}
		if ss.SheddingLow {
			snap.SheddingClasses = append(snap.SheddingClasses, "low")
		}
		if ss.SheddingNorm {
			snap.SheddingClasses = append(snap.SheddingClasses, "normal")
		}
		if ss.SheddingHigh {
			snap.SheddingClasses = append(snap.SheddingClasses, "high")
		}
	}
	if ch := s.challenger.Load(); ch != nil {
		snap.ChallengesIssued, snap.ChallengesPassed, snap.ChallengesFailed = ch.Stats()
	}
	ls := s.logs.Stats()
	snap.LogSyslogSent, snap.LogSyslogDropped, snap.LogJournalDropped, snap.LogRedaction = ls.SyslogSent, ls.SyslogDropped, ls.JournalDropped, ls.Redaction
	snap.LogSIEMSent, snap.LogSIEMDropped = ls.SIEMSent, ls.SIEMDropped
	snap.LogWriteErrors = ls.WriteErrors
	snap.TarpitActive = s.tarpits.InFlight()
	return snap
}

// ACME returns the certificate manager, or nil when not configured.
func (s *Server) ACME() *acme.Manager { return s.acme }

// ICAP returns the status of every configured ICAP service.
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

// Tracing returns the tracer status, or nil when tracing is off.
func (s *Server) Tracing() *tracing.Status {
	tr := s.tracer.Load()
	if tr == nil {
		return nil
	}
	st := tr.Status()
	return &st
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

// Tickets returns the session ticket key status, nil without the section.
func (s *Server) Tickets() *tlsconf.TicketStatus { return s.tickets.Status() }

// Cache returns the response cache, or nil when none is configured.
func (s *Server) Cache() *cache.Cache { return s.cache.Load() }

// GeoIP returns the country database status, or nil when none is configured.
func (s *Server) GeoIP() *geoip.Status {
	rt := s.rt.Load()
	if rt.geo == nil {
		return nil
	}
	st := rt.geo.Status()
	return &st
}

// Filters returns the configured middleware instances.
func (s *Server) Filters() []FilterStatus { return s.rt.Load().filterStatus() }

func (s *Server) ICAP() []icap.Status {
	rt := s.rt.Load()
	out := make([]icap.Status, 0, len(rt.icap))
	for _, svc := range rt.icap {
		out = append(out, svc.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Shedder returns the load shedder, or nil when shedding is not configured.
func (s *Server) Shedder() *shed.Shedder { return s.shedder.Load() }

// Challenger returns the challenge engine, or nil when not configured.
func (s *Server) Challenger() *challenge.Challenger { return s.challenger.Load() }

// Upstreams returns endpoint statistics per upstream.
func (s *Server) Upstreams() map[string][]upstream.Stats {
	rt := s.rt.Load()
	out := make(map[string][]upstream.Stats, len(rt.pools))
	for name, p := range rt.pools {
		out[name] = p.Stats()
	}
	return out
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

// WAFReport is the response of GET /v1/waf: the compiled profiles of the
// active generation, the route assignments, and the process wide rule
// statistics and learning proposals.
type WAFReport struct {
	Enabled  bool                `json:"enabled"`
	Profiles []waf.ProfileStatus `json:"profiles"`
	Routes   []WAFRoute          `json:"routes"`
	waf.Report
}

// WAFRoute is one route's WAF assignment.
type WAFRoute struct {
	Route   string `json:"route"`
	Profile string `json:"profile"`
	Mode    string `json:"mode"`
	// BlockPercent is the share of clients in block mode (100 unless
	// the route rolls block mode out gradually); BlockCIDRs are the
	// canary prefixes always in block mode.
	BlockPercent int      `json:"block_percent"`
	BlockCIDRs   []string `json:"block_cidrs,omitempty"`
}

// WAF builds the WAF report with at most top rules.
func (s *Server) WAF(top int) WAFReport {
	rt := s.rt.Load()
	rep := WAFReport{Profiles: []waf.ProfileStatus{}, Routes: []WAFRoute{}}
	if rt.waf != nil {
		rep.Enabled = true
		rep.Profiles = rt.waf.Profiles()
	}
	for _, cr := range rt.routes {
		if cr.wafMode != "" && cr.wafMode != string(waf.ModeOff) {
			p, _ := wafSelection(rt.cfg, cr.cfg)
			wr := WAFRoute{Route: cr.cfg.Name, Profile: p, Mode: cr.wafMode, BlockPercent: 100}
			if cr.wafMode == string(waf.ModeBlock) {
				wr.BlockPercent = cr.cfg.WAF.Percent()
				if cr.cfg.WAF != nil {
					wr.BlockCIDRs = cr.cfg.WAF.BlockCIDRs
				}
			} else {
				wr.BlockPercent = 0
			}
			rep.Routes = append(rep.Routes, wr)
		}
	}
	rep.Report = s.wafStats.Report(top, rt.routePaths())
	return rep
}

// WAFExclusions renders the learning proposals as SecLang.
func (s *Server) WAFExclusions() string { return s.wafStats.Exclusions(s.rt.Load().routePaths()) }

// WAFReset clears the WAF statistics and learning table.
func (s *Server) WAFReset() { s.wafStats.Reset() }

// routePaths maps every route to its first path prefix, "" for regex
// routes, for scoping exclusion proposals.
func (rt *runtime) routePaths() map[string]string {
	out := make(map[string]string, len(rt.routes))
	for _, cr := range rt.routes {
		if len(cr.cfg.PathRegex) == 0 && len(cr.cfg.Paths) > 0 {
			out[cr.cfg.Name] = cr.cfg.Paths[0]
		} else {
			out[cr.cfg.Name] = ""
		}
	}
	return out
}

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
		ln, act, err := listenerFor(activated, "cluster", cfg.Cluster.Listen)
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
	s.sampler.Start()
	if s.acme != nil {
		s.acme.Start()
	}
	for _, bl := range s.listeners {
		go s.serve(bl)
		if bl.h3 != nil {
			go s.serveH3(bl)
		}
	}
	s.started = true
	return nil
}

func (s *Server) bind(lc config.Listener, activated *activated) (*boundListener, error) {
	ln, act, err := listenerFor(activated, lc.Name, lc.Address)
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
	ln := acc.raw
	fr := acc.newFront()
	lim := s.cfg().Server.Limits
	bl := &boundListener{cfg: lc, acc: acc, front: fr, ln: s.connLimiter.Wrap(fr), activated: act}
	if lc.ProxyProtocol && lc.Kind != "tcp" && lc.Kind != "dns" {
		bl.ln = &proxyListener{Listener: bl.ln,
			trusted:  func() []netip.Prefix { return s.rt.Load().trusted },
			onReject: s.connLimiter.Reject,
		}
	}
	if lc.Kind == "tcp" {
		bl.tcp = newTCPServer(s, lc, bl.ln)
		if lc.TCP.QUIC {
			udpAddr := lc.Address
			if strings.HasSuffix(lc.Address, ":0") {
				udpAddr = ln.Addr().String()
			}
			pc, _, err := packetFor(activated, lc.Name, udpAddr)
			if err != nil {
				_ = fr.Close()
				return nil, fmt.Errorf("listener %s: quic: %w", lc.Name, err)
			}
			bl.tcp.quic = newQUICRelay(bl.tcp, pc)
		}
		return bl, nil
	}
	if lc.Kind == "dns" && lc.TLS != nil {
		// Encrypted: DNS over TLS and DNS over HTTPS on the TCP port, no
		// plain UDP.
		tc, rl, err := tlsconf.Server(lc.TLS, nil)
		s.tickets.Attach(tc)
		if err != nil {
			_ = fr.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		tc.NextProtos = []string{dns.ALPNDoT, dns.ALPNH2, dns.ALPNHTTP}
		rl.Fingerprints = s.fingerprints
		rl.StartStapling(s.logs.Error)
		bl.tlsReload = rl
		bl.ln = tls.NewListener(bl.ln, tc)
		d, err := s.newDNSServer(lc, nil, bl.ln)
		if err != nil {
			_ = fr.Close()
			rl.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		d.Encrypted = true
		d.DoHPath = lc.DNS.DoHPath
		bl.dns = d
		return bl, nil
	}
	if lc.Kind == "dns" {
		// UDP on the same port as TCP, also when the port was chosen by
		// the system (":0" in tests).
		udpAddr := lc.Address
		if strings.HasSuffix(lc.Address, ":0") {
			udpAddr = ln.Addr().String()
		}
		pc, _, err := packetFor(activated, lc.Name, udpAddr)
		if err != nil {
			_ = fr.Close()
			return nil, fmt.Errorf("listener %s: udp: %w", lc.Name, err)
		}
		d, err := s.newDNSServer(lc, pc, bl.ln)
		if err != nil {
			_ = fr.Close()
			_ = pc.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		bl.dns = d
		return bl, nil
	}
	h := &listenerHandler{srv: s, ln: &bl.cfg}
	var handler http.Handler = h
	if lc.Kind == "forward" {
		fw, err := newForwardServer(s, lc)
		if err != nil {
			_ = fr.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		bl.forward = fw
		handler = fw
	}
	bl.httpSrv = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: lim.ReadHeaderTimeout.D(),
		ReadTimeout:       lim.ReadTimeout.D(),
		WriteTimeout:      lim.WriteTimeout.D(),
		IdleTimeout:       lim.IdleTimeout.D(),
		MaxHeaderBytes:    lim.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.logs.Error.Handler(), slog.LevelDebug),
		// Disable automatic h2c and keep protocol choice to TLS ALPN.
		TLSNextProto: nil,
	}
	if lc.H2C {
		// HTTP/2 without TLS (prior knowledge and Upgrade) with the
		// stream and frame bounds of the TLS listeners.
		bl.httpSrv.Protocols = new(http.Protocols)
		bl.httpSrv.Protocols.SetHTTP1(true)
		bl.httpSrv.Protocols.SetUnencryptedHTTP2(true)
		bl.httpSrv.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 250, MaxReadFrameSize: 1 << 20}
	}
	if lc.TLS != nil {
		tc, rl, err := tlsconf.Server(lc.TLS, lc.Protocols)
		s.tickets.Attach(tc)
		if err != nil {
			_ = fr.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		if s.acme != nil && len(lc.TLS.ACME) > 0 {
			rl.Managed = s.acme.Certificates
			rl.Challenge = s.acme.TLSALPN01
		}
		rl.Fingerprints = s.fingerprints
		for _, w := range rl.CTWarnings() {
			s.logs.Security.Warn("certificate transparency", "listener", lc.Name, "issue", w)
		}
		rl.StartStapling(s.logs.Error)
		bl.httpSrv.ConnState = func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				s.fingerprints.Delete(c.RemoteAddr().String())
			}
		}
		bl.httpSrv.TLSConfig = tc
		bl.tlsReload = rl
		if !hasProto(lc.Protocols, config.ProtocolH2) {
			// Prevent the automatic HTTP/2 configuration.
			bl.httpSrv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
		if hasProto(lc.Protocols, config.ProtocolH3) {
			pc, act, err := packetFor(activated, lc.Name, lc.Address)
			if err != nil {
				_ = fr.Close()
				return nil, fmt.Errorf("listener %s: h3: %w", lc.Name, err)
			}
			_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
			port, _ := strconv.Atoi(portStr)
			h3srv, err := h3.New(h3.Options{
				Conn: pc, Port: port, TLS: tc, Handler: h, Limits: lim, H3: *lc.H3, WebTransport: lc.H3.WebTransport,
				Limiter: s.connLimiter, Log: s.logs.Error.With("listener", lc.Name, "proto", "h3"),
			})
			if err != nil {
				_ = pc.Close()
				_ = fr.Close()
				return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
			}
			bl.h3 = h3srv
			h.h3 = h3srv
			s.logs.Error.Info("h3 listener bound", "listener", lc.Name, "address", pc.LocalAddr().String(), "socket_activated", act)
		}
	}
	return bl, nil
}

func (s *Server) serveH3(bl *boundListener) {
	if err := bl.h3.Serve(); err != nil {
		s.logs.Error.Error("h3 listener stopped", "listener", bl.cfg.Name, "err", err.Error())
	}
}

func hasProto(ps []config.Protocol, p config.Protocol) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

func (s *Server) serve(bl *boundListener) {
	var err error
	s.logs.Error.Info("listening", "listener", bl.cfg.Name, "address", bl.ln.Addr().String(), "tls", bl.cfg.TLS != nil, "kind", bl.cfg.Kind, "socket_activated", bl.activated)
	if bl.tcp != nil {
		if bl.tcp.quic != nil {
			go bl.tcp.quic.serve()
		}
		bl.tcp.serve()
		return
	}
	if bl.dns != nil {
		bl.dns.Serve()
		return
	}
	if bl.cfg.TLS != nil {
		err = bl.httpSrv.ServeTLS(bl.ln, "", "")
	} else {
		err = bl.httpSrv.Serve(bl.ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		s.logs.Error.Error("listener stopped", "listener", bl.cfg.Name, "err", err.Error())
	}
}

// Addrs returns the bound addresses by listener name (useful for tests and
// for the status command when port 0 was configured).
func (s *Server) Addrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.listeners))
	for _, bl := range s.listeners {
		out[bl.cfg.Name] = bl.ln.Addr().String()
		if bl.h3 != nil {
			out[bl.cfg.Name+"/udp"] = bl.h3.Addr().String()
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
	rt, err := newRuntime(cfg, s.generation.Add(1), s.logs.Error, newEventBus(s), s.wafStats, &s.patches)
	if err != nil {
		s.stats.ReloadFailures.Add(1)
		return err
	}
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
				rt.stop()
				s.stats.ReloadFailures.Add(1)
				return err
			}
			newBans = bl
		}
	case cfg.Bans != nil:
		bl, err := ban.New(cfg.Bans, s.logs.Security)
		if err != nil {
			rt.stop()
			s.stats.ReloadFailures.Add(1)
			return err
		}
		newBans = bl
	}
	// Bind and build the added and replaced listeners, then reload the
	// certificates of the kept ones, before switching, so a port that
	// cannot be bound or a bad certificate aborts the reload as a whole.
	fresh := make([]freshListener, 0, len(plan.add)+len(plan.replace))
	abort := func(err error) error {
		for _, f := range fresh {
			s.discard(f)
		}
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
		if bl.forward != nil {
			for i := range cfg.Server.Listeners {
				if cfg.Server.Listeners[i].Name == bl.cfg.Name {
					if err := bl.forward.apply(cfg.Server.Listeners[i].Forward); err != nil {
						s.mu.Unlock()
						return abort(fmt.Errorf("listener %s: %w", bl.cfg.Name, err))
					}
				}
			}
		}
		if bl.dns != nil {
			for i := range cfg.Server.Listeners {
				if lc := cfg.Server.Listeners[i]; lc.Name == bl.cfg.Name && lc.DNS != nil {
					p, err := dnsPolicy(lc.DNS)
					if err != nil {
						s.mu.Unlock()
						return abort(fmt.Errorf("listener %s: %w", bl.cfg.Name, err))
					}
					bl.dns.Apply(p, lc.DNS.Cache.MaxEntries)
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
	s.rt.Store(rt)
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
		if f.bl.h3 != nil {
			go s.serveH3(f.bl)
		}
	}
	drain := cfg.Server.ShutdownTimeout.D()
	for _, r := range plan.replace {
		go s.retire(r.old, drain, !r.reuse, "replaced")
	}
	for _, bl := range plan.remove {
		go s.retire(bl, drain, true, "removed")
	}
	if newBans != oldBans {
		s.bans.Store(newBans)
		if oldBans != nil {
			oldBans.Close()
		}
	}
	if node := s.cluster.Load(); node != nil {
		node.Reconfigure(cfg.Cluster)
		if newBans != oldBans {
			node.AttachBans(banStore(newBans))
		}
	}
	switch sh := s.shedder.Load(); {
	case cfg.Shedding != nil && sh != nil:
		sh.Reconfigure(cfg.Shedding, cfg.Server.Limits.MaxConcurrentRequests)
	case cfg.Shedding != nil:
		s.shedder.Store(shed.New(cfg.Shedding, s.concurrency.InFlight, cfg.Server.Limits.MaxConcurrentRequests))
	case sh != nil:
		s.shedder.Store(nil)
	}
	// Tracing: rebuilt when its section changed, so a reload can move
	// the collector or the sampling share.
	if !sameTracing(old.cfg.Tracing, cfg.Tracing) {
		var next *tracing.Tracer
		if cfg.Tracing.IsEnabled() {
			if tr, err := newTracer(cfg.Tracing, s.logs.Error); err == nil {
				next = tr
			} else {
				s.logs.Error.Error("tracing exporter unavailable", "err", err.Error())
			}
		}
		if prev := s.tracer.Swap(next); prev != nil {
			go prev.Stop()
		}
	}
	switch ch := s.challenger.Load(); {
	case cfg.Challenge != nil && ch != nil:
		ch.Reconfigure(cfg.Challenge)
	case cfg.Challenge != nil:
		// Created above the swap would be cleaner, but a key generation
		// failure here is the only error path and it only disables the
		// challenge until the next reload; routes referencing it were
		// validated against the section, so log and continue.
		if nc, err := challenge.New(cfg.Challenge); err == nil {
			s.challenger.Store(nc)
		} else {
			s.logs.Error.Error("challenge key unavailable", "err", err.Error())
		}
	case ch != nil:
		s.challenger.Store(nil)
	}
	switch c := s.cache.Load(); {
	case cfg.Cache != nil && c != nil:
		c.Resize(cfg.Cache.MaxBytes, cfg.Cache.MaxObjectBytes)
	case cfg.Cache != nil:
		s.cache.Store(cache.New(cfg.Cache.MaxBytes, cfg.Cache.MaxObjectBytes))
	case c != nil:
		s.cache.Store(nil)
	}
	s.stats.Reloads.Add(1)
	// The old generation stops probing at once (its health state is no
	// longer consulted); in-flight requests on it get the drain period to
	// finish before its pools are torn down.
	go func(old *runtime) {
		old.stopChecks()
		time.Sleep(cfg.Server.ShutdownTimeout.D())
		old.stop()
	}(old)
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
	err := s.stopListener(ctx, bl, closeSocket)
	attrs := []any{"listener", bl.cfg.Name, "address", bl.ln.Addr().String(), "reason", why}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	s.logs.Error.Info("listener retired", attrs...)
}

// discard releases a listener that was built for a reload that failed
// and never served.
func (s *Server) discard(f freshListener) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.stopListener(ctx, f.bl, f.owns)
}

// stopListener stops accepting, drains within ctx and releases the
// listener's resources; with closeSocket the accept socket is closed too
// (not when a replacement inherited it).
func (s *Server) stopListener(ctx context.Context, bl *boundListener, closeSocket bool) error {
	var err error
	_ = bl.front.Close()
	switch {
	case bl.tcp != nil:
		bl.tcp.shutdown(ctx)
	case bl.dns != nil:
		bl.dns.Shutdown(ctx)
		bl.dns.Close()
		if bl.tlsReload != nil {
			bl.tlsReload.Close()
		}
	default:
		err = bl.httpSrv.Shutdown(ctx)
		if bl.tlsReload != nil {
			bl.tlsReload.Close()
		}
		if bl.forward != nil {
			bl.forward.shutdown(ctx)
		}
		if bl.h3 != nil {
			if err3 := bl.h3.Shutdown(ctx); err == nil {
				err = err3
			}
		}
	}
	if closeSocket {
		bl.acc.close()
	}
	return err
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

// Shutdown drains connections gracefully within ctx, then closes listeners
// and upstream pools.
func (s *Server) Shutdown(ctx context.Context) error {
	s.tickets.Stop()
	s.mu.Lock()
	lns := s.listeners
	s.mu.Unlock()
	var (
		errMu    sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	for _, bl := range lns {
		wg.Add(1)
		go func(bl *boundListener) {
			defer wg.Done()
			if err := s.stopListener(ctx, bl, true); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}(bl)
	}
	wg.Wait()
	if s.started {
		s.sampler.Stop()
		if s.acme != nil {
			s.acme.Stop()
		}
	}
	if tr := s.tracer.Load(); tr != nil {
		tr.Stop()
	}
	if node := s.cluster.Load(); node != nil {
		node.Stop()
	}
	s.rt.Load().stop()
	if bl := s.bans.Load(); bl != nil {
		bl.Close()
	}
	return firstErr
}

func (s *Server) closeListenersLocked() {
	for _, bl := range s.listeners {
		_ = bl.front.Close()
		bl.acc.close()
	}
	s.listeners = nil
}
