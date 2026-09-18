// Package mgmt is the xproxy control plane: a small JSON API served on a
// Unix domain socket. It is deliberately separate from the data plane
// listeners, never reachable over the network in this version, and every
// mutating call is written to the audit log together with the kernel
// reported credentials of the caller.
package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/version"
)

// Actions are the operations the control plane can trigger on the process.
type Actions struct {
	// Reload re-reads the configuration file and applies it.
	Reload func() error
	// ReloadCerts re-reads certificate files only.
	ReloadCerts func() error
	// ReopenLogs closes and reopens log files.
	ReopenLogs func() error
}

// Server serves the management API.
type Server struct {
	cfg     config.Management
	proxy   *proxy.Server
	logs    *logging.Logs
	actions Actions
	http    *http.Server
	ln      net.Listener
	once    sync.Once
}

// New creates a management server. Start must be called to listen.
func New(cfg config.Management, p *proxy.Server, logs *logging.Logs, a Actions) *Server {
	s := &Server{cfg: cfg, proxy: p, logs: logs, actions: a}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/stats", s.stats)
	mux.HandleFunc("GET /v1/upstreams", s.upstreams)
	mux.HandleFunc("GET /v1/config", s.config)
	mux.HandleFunc("POST /v1/reload", s.reload)
	mux.HandleFunc("POST /v1/reload-certs", s.reloadCerts)
	mux.HandleFunc("POST /v1/logs/reopen", s.reopenLogs)
	mux.HandleFunc("GET /v1/bans", s.listBans)
	mux.HandleFunc("POST /v1/bans", s.addBan)
	mux.HandleFunc("DELETE /v1/bans", s.removeBan)
	mux.HandleFunc("GET /v1/cluster", s.clusterStatus)
	mux.HandleFunc("GET /v1/acme", func(w http.ResponseWriter, _ *http.Request) {
		if s.proxy.ACME() == nil {
			writeJSON(w, 404, result{Error: "acme is not configured"})
			return
		}
		writeJSON(w, 200, s.proxy.ACME().Status())
	})
	mux.HandleFunc("POST /v1/acme/renew", func(w http.ResponseWriter, r *http.Request) {
		m := s.proxy.ACME()
		if m == nil {
			writeJSON(w, 404, result{Error: "acme is not configured"})
			return
		}
		s.audited("acme_renew", func() error {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
			defer cancel()
			return m.Renew(ctx)
		})(w, r)
	})
	mux.HandleFunc("GET /v1/icap", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.ICAP()) })
	mux.HandleFunc("GET /v1/cache", func(w http.ResponseWriter, _ *http.Request) {
		if c := s.proxy.Cache(); c != nil {
			writeJSON(w, 200, c.Stats())
			return
		}
		writeJSON(w, 404, result{Error: "cache is not configured"})
	})
	mux.HandleFunc("DELETE /v1/cache", func(w http.ResponseWriter, r *http.Request) {
		c := s.proxy.Cache()
		if c == nil {
			writeJSON(w, 404, result{Error: "cache is not configured"})
			return
		}
		host, prefix := r.URL.Query().Get("host"), r.URL.Query().Get("path")
		n := c.Purge(host, prefix)
		peer := peerFromContext(r.Context())
		s.logs.Audit.Info("management action", "action", "cache-purge", "host", host, "path", prefix, "removed", n, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK)
		writeJSON(w, 200, map[string]any{"ok": true, "removed": n})
	})
	mux.HandleFunc("GET /v1/geoip", func(w http.ResponseWriter, _ *http.Request) {
		if st := s.proxy.GeoIP(); st != nil {
			writeJSON(w, 200, st)
			return
		}
		writeJSON(w, 404, result{Error: "geoip is not configured"})
	})
	mux.HandleFunc("GET /v1/filters", func(w http.ResponseWriter, _ *http.Request) {
		kinds := filter.Kinds()
		ks := make([]FilterKind, 0, len(kinds))
		for _, k := range kinds {
			ks = append(ks, FilterKind{Name: k.Name, Description: k.Description})
		}
		writeJSON(w, 200, FiltersView{APIVersion: filter.APIVersion, Kinds: ks, Filters: s.proxy.Filters()})
	})
	mux.HandleFunc("GET /metrics", s.serveMetrics)
	mux.HandleFunc("GET /v1/series", s.serveSeries)
	s.http = &http.Server{
		Handler:           http.MaxBytesHandler(mux, 1<<20),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ConnContext:       connContext,
	}
	return s
}

// Start binds the Unix socket. A stale socket file from a previous run is
// removed only if nothing is listening on it.
func (s *Server) Start() error {
	if s.cfg.Socket == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.Socket), 0o750); err != nil {
		return fmt.Errorf("management socket directory: %w", err)
	}
	if _, err := os.Stat(s.cfg.Socket); err == nil {
		d := net.Dialer{Timeout: time.Second}
		if c, err := d.DialContext(context.Background(), "unix", s.cfg.Socket); err == nil {
			_ = c.Close()
			return fmt.Errorf("management socket %s is already in use", s.cfg.Socket)
		}
		if err := os.Remove(s.cfg.Socket); err != nil {
			return fmt.Errorf("remove stale management socket: %w", err)
		}
	}
	mode, _ := strconv.ParseUint(s.cfg.SocketMode, 8, 32)
	old := syscallUmask(0o077)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", s.cfg.Socket)
	syscallUmask(old)
	if err != nil {
		return fmt.Errorf("management socket: %w", err)
	}
	if err := os.Chmod(s.cfg.Socket, os.FileMode(mode)); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod management socket: %w", err)
	}
	s.ln = ln
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logs.Error.Error("management server stopped", "err", err.Error())
		}
	}()
	s.logs.Error.Info("management API listening", "socket", s.cfg.Socket)
	return nil
}

// Addr returns the socket path, or "" if disabled.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown stops the server and removes the socket file.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.ln == nil {
		return nil
	}
	var err error
	s.once.Do(func() {
		err = s.http.Shutdown(ctx)
		_ = os.Remove(s.cfg.Socket)
	})
	return err
}

// Status is the response of GET /v1/status.
type Status struct {
	Version    string            `json:"version"`
	PID        int               `json:"pid"`
	Generation uint64            `json:"generation"`
	Listeners  map[string]string `json:"listeners"`
	Routes     int               `json:"routes"`
	Upstreams  int               `json:"upstreams"`
	Stats      proxy.Snapshot    `json:"stats"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, result{OK: true})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	cfg := s.proxy.Config()
	writeJSON(w, 200, Status{
		Version:    version.String(),
		PID:        os.Getpid(),
		Generation: s.proxy.Generation(),
		Listeners:  s.proxy.Addrs(),
		Routes:     len(cfg.Routes),
		Upstreams:  len(cfg.Upstreams),
		Stats:      s.proxy.Stats(),
	})
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.proxy.Stats())
}

func (s *Server) upstreams(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.proxy.Upstreams())
}

func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	b, err := yaml.Marshal(s.proxy.Config())
	if err != nil {
		writeJSON(w, 500, result{Error: err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

func (s *Server) audited(name string, fn func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		peer := peerFromContext(r.Context())
		if fn == nil {
			writeJSON(w, 501, result{Error: name + " not available"})
			return
		}
		err := fn()
		attrs := []any{"action", name, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK}
		if err != nil {
			s.logs.Audit.Warn("management action failed", append(attrs, "err", err.Error())...)
			writeJSON(w, 409, result{Error: err.Error()})
			return
		}
		s.logs.Audit.Info("management action", attrs...)
		writeJSON(w, 200, result{OK: true})
	}
}

// FiltersView is the response of GET /v1/filters.
type FiltersView struct {
	APIVersion int                  `json:"api_version"`
	Kinds      []FilterKind         `json:"kinds"`
	Filters    []proxy.FilterStatus `json:"filters"`
}

// FilterKind is one registered kind.
type FilterKind struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// BanRequest is the body of POST /v1/bans.
type BanRequest struct {
	Target   string `json:"target"`   // address or CIDR
	Duration string `json:"duration"` // Go duration, e.g. "1h"
	Reason   string `json:"reason"`
}

func (s *Server) listBans(w http.ResponseWriter, _ *http.Request) {
	bl := s.proxy.Bans()
	if bl == nil {
		writeJSON(w, 404, result{Error: "bans are not configured"})
		return
	}
	entries := bl.Entries()
	if entries == nil {
		entries = []ban.Entry{}
	}
	writeJSON(w, 200, entries)
}

func (s *Server) addBan(w http.ResponseWriter, r *http.Request) {
	bl := s.proxy.Bans()
	if bl == nil {
		writeJSON(w, 404, result{Error: "bans are not configured"})
		return
	}
	var req BanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, result{Error: "bad request body"})
		return
	}
	d, err := time.ParseDuration(req.Duration)
	if err != nil {
		writeJSON(w, 400, result{Error: "bad duration"})
		return
	}
	if len(req.Reason) > 256 {
		writeJSON(w, 400, result{Error: "reason too long"})
		return
	}
	peer := peerFromContext(r.Context())
	e, err := bl.Ban(req.Target, d, req.Reason)
	attrs := []any{"action", "ban", "target", req.Target, "duration", req.Duration, "reason", req.Reason, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK}
	if err != nil {
		s.logs.Audit.Warn("management action failed", append(attrs, "err", err.Error())...)
		writeJSON(w, 400, result{Error: err.Error()})
		return
	}
	s.logs.Audit.Info("management action", attrs...)
	writeJSON(w, 200, e)
}

func (s *Server) removeBan(w http.ResponseWriter, r *http.Request) {
	bl := s.proxy.Bans()
	if bl == nil {
		writeJSON(w, 404, result{Error: "bans are not configured"})
		return
	}
	target := r.URL.Query().Get("target")
	peer := peerFromContext(r.Context())
	err := bl.Unban(target)
	attrs := []any{"action", "unban", "target", target, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK}
	if err != nil {
		s.logs.Audit.Warn("management action failed", append(attrs, "err", err.Error())...)
		status := 400
		if errors.Is(err, ban.ErrNotFound) {
			status = 404
		}
		writeJSON(w, status, result{Error: err.Error()})
		return
	}
	s.logs.Audit.Info("management action", attrs...)
	writeJSON(w, 200, result{OK: true})
}

func (s *Server) clusterStatus(w http.ResponseWriter, _ *http.Request) {
	node := s.proxy.Cluster()
	if node == nil {
		writeJSON(w, 404, result{Error: "cluster is not configured"})
		return
	}
	writeJSON(w, 200, node.Status())
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	s.audited("reload", s.actions.Reload)(w, r)
}

func (s *Server) reloadCerts(w http.ResponseWriter, r *http.Request) {
	s.audited("reload_certs", s.actions.ReloadCerts)(w, r)
}

func (s *Server) reopenLogs(w http.ResponseWriter, r *http.Request) {
	s.audited("reopen_logs", s.actions.ReopenLogs)(w, r)
}
