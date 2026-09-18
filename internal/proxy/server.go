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
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// Server runs the data plane for one configuration and supports hot reload.
type Server struct {
	logs  *logging.Logs
	stats *Stats

	rt         atomic.Pointer[runtime]
	generation atomic.Uint64

	concurrency *limits.Concurrency
	connLimiter *limits.ConnLimiter
	bans        atomic.Pointer[ban.List]
	cluster     atomic.Pointer[cluster.Node]

	mu        sync.Mutex
	listeners []*boundListener
	started   bool
	reloadMu  sync.Mutex
}

type boundListener struct {
	cfg       config.Listener
	ln        net.Listener
	httpSrv   *http.Server
	tlsReload *tlsconf.Reloadable
	activated bool
}

// New creates a server for cfg. Listeners are not opened until Start.
func New(cfg *config.Config, logs *logging.Logs) (*Server, error) {
	s := &Server{
		logs:        logs,
		stats:       &Stats{StartedAt: time.Now()},
		concurrency: limits.NewConcurrency(cfg.Server.Limits.MaxConcurrentRequests),
		connLimiter: limits.NewConnLimiter(cfg.Server.Limits.MaxConnections, cfg.Server.Limits.MaxConnectionsPerIP),
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
	s.connLimiter.Banned = func(addr netip.Addr) bool {
		bl := s.bans.Load()
		return bl != nil && bl.DropsConnections() && bl.Banned(addr)
	}
	rt, err := newRuntime(cfg, s.generation.Add(1), logs.Error)
	if err != nil {
		if bl := s.bans.Load(); bl != nil {
			bl.Close()
		}
		return nil, err
	}
	s.rt.Store(rt)
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
	if bl := s.bans.Load(); bl != nil {
		snap.BansActive, snap.BansTotal = bl.Stats()
	}
	if node := s.cluster.Load(); node != nil {
		snap.ClusterPeers = len(node.Status().Peers)
		snap.ClusterConnected = node.ConnectedPeers()
	}
	return snap
}

// Upstreams returns endpoint statistics per upstream.
func (s *Server) Upstreams() map[string][]upstream.Stats {
	rt := s.rt.Load()
	out := make(map[string][]upstream.Stats, len(rt.pools))
	for name, p := range rt.pools {
		out[name] = p.Stats()
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
	activated, err := activatedListeners()
	if err != nil {
		return fmt.Errorf("socket activation: %w", err)
	}
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
	for name := range activated {
		s.logs.Error.Warn("unused socket from systemd", "name", name)
		_ = activated[name].Close()
	}
	s.rt.Load().start()
	for _, bl := range s.listeners {
		go s.serve(bl)
	}
	s.started = true
	return nil
}

func (s *Server) bind(lc config.Listener, activated map[string]net.Listener) (*boundListener, error) {
	ln, act, err := listenerFor(activated, lc.Name, lc.Address)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
	}
	lim := s.cfg().Server.Limits
	bl := &boundListener{cfg: lc, ln: s.connLimiter.Wrap(ln), activated: act}
	h := &listenerHandler{srv: s, ln: &bl.cfg}
	bl.httpSrv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: lim.ReadHeaderTimeout.D(),
		ReadTimeout:       lim.ReadTimeout.D(),
		WriteTimeout:      lim.WriteTimeout.D(),
		IdleTimeout:       lim.IdleTimeout.D(),
		MaxHeaderBytes:    lim.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.logs.Error.Handler(), slog.LevelDebug),
		// Disable automatic h2c and keep protocol choice to TLS ALPN.
		TLSNextProto: nil,
	}
	if lc.TLS != nil {
		tc, rl, err := tlsconf.Server(lc.TLS, lc.Protocols)
		if err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
		bl.httpSrv.TLSConfig = tc
		bl.tlsReload = rl
		if !hasProto(lc.Protocols, config.ProtocolH2) {
			// Prevent the automatic HTTP/2 configuration.
			bl.httpSrv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
	}
	return bl, nil
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
	s.logs.Error.Info("listening", "listener", bl.cfg.Name, "address", bl.ln.Addr().String(), "tls", bl.cfg.TLS != nil, "socket_activated", bl.activated)
	if bl.cfg.TLS != nil {
		err = bl.httpSrv.ServeTLS(bl.ln, "", "")
	} else {
		err = bl.httpSrv.Serve(bl.ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	}
	return out
}

// Reload swaps in a new configuration. Listener addresses and TLS settings
// other than the certificate files cannot change without a restart; such a
// change is rejected and the old configuration stays active.
func (s *Server) Reload(cfg *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	old := s.rt.Load()
	if err := listenersCompatible(old.cfg.Server.Listeners, cfg.Server.Listeners); err != nil {
		s.stats.ReloadFailures.Add(1)
		return err
	}
	if err := clusterCompatible(old.cfg.Cluster, cfg.Cluster); err != nil {
		s.stats.ReloadFailures.Add(1)
		return err
	}
	rt, err := newRuntime(cfg, s.generation.Add(1), s.logs.Error)
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
	// Reload certificates before switching so a bad certificate aborts the
	// reload as a whole.
	s.mu.Lock()
	for _, bl := range s.listeners {
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
			rt.stop()
			s.stats.ReloadFailures.Add(1)
			return fmt.Errorf("listener %s: %w", bl.cfg.Name, err)
		}
	}
	s.mu.Unlock()
	rt.start()
	s.connLimiter.SetLimits(cfg.Server.Limits.MaxConnections, cfg.Server.Limits.MaxConnectionsPerIP)
	s.rt.Store(rt)
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
	s.stats.Reloads.Add(1)
	// Give in-flight requests on the old generation time to finish before
	// tearing down its pools; the transport keeps serving until then.
	go func(old *runtime) {
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

func listenersCompatible(old, new_ []config.Listener) error {
	if len(old) != len(new_) {
		return errors.New("reload: listener set changed; restart required")
	}
	for i := range old {
		o, n := old[i], new_[i]
		if o.Name != n.Name || o.Address != n.Address || (o.TLS == nil) != (n.TLS == nil) || o.ProxyProtocol != n.ProxyProtocol || o.RedirectToHTTPS != n.RedirectToHTTPS {
			return fmt.Errorf("reload: listener %s changed; restart required", o.Name)
		}
		if o.TLS != nil {
			if o.TLS.MinVersion != n.TLS.MinVersion || o.TLS.ClientAuth != n.TLS.ClientAuth || o.TLS.ClientCAFile != n.TLS.ClientCAFile || fmt.Sprint(o.TLS.CipherSuites) != fmt.Sprint(n.TLS.CipherSuites) || fmt.Sprint(o.Protocols) != fmt.Sprint(n.Protocols) {
				return fmt.Errorf("reload: listener %s TLS settings changed; restart required", o.Name)
			}
		}
	}
	return nil
}

// ReloadCertificates re-reads certificate files without a full reload.
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
	return nil
}

// Shutdown drains connections gracefully within ctx, then closes listeners
// and upstream pools.
func (s *Server) Shutdown(ctx context.Context) error {
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
			if err := bl.httpSrv.Shutdown(ctx); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}(bl)
	}
	wg.Wait()
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
		_ = bl.ln.Close()
	}
	s.listeners = nil
}
