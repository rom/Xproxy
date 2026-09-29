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
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/shadow"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/unixsock"
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
	// Ingress reports the ingress controller status, or nil when off.
	Ingress func() any
	// OTLP reports the OpenTelemetry exporter status, or nil when off.
	OTLP func() metrics.OTLPStatus
	// DryRun loads and validates the configuration file and reports what
	// applying it would change, without applying it.
	DryRun func() (*config.Changes, error)
	// History lists recorded configurations, newest first.
	History func() ([]config.Entry, error)
	// Rollback applies a recorded configuration.
	Rollback func(id string) error
	// Diff compares two configurations named "active", "file" or a
	// history id.
	Diff func(from, to string) (*config.Changes, error)
	// Sandbox reports the in-process hardening status, nil before it is
	// applied or when the process runs without it (tests).
	Sandbox func() *sandbox.Status
	// Fleet reports the fleet agent status, or nil when the node is not
	// managed by a controller.
	Fleet func() any
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
	mux.HandleFunc("GET /v1/pools", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Pools()) })
	mux.HandleFunc("GET /v1/tls", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Certificates()) })
	mux.HandleFunc("GET /v1/tls/expiring", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, s.proxy.ExpiringCertificates())
	})
	mux.HandleFunc("GET /v1/handshake", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Handshake()) })
	mux.HandleFunc("GET /v1/tls/key-exchange", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.KeyExchange()) })
	mux.HandleFunc("GET /v1/masque", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Masque()) })
	mux.HandleFunc("GET /v1/websocket", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.WebSocketGuards()) })
	mux.HandleFunc("GET /v1/tls/ech", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.ECH()) })
	mux.HandleFunc("GET /v1/degradation", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Degradation()) })
	mux.HandleFunc("GET /v1/deceive", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Deceptions()) })
	mux.HandleFunc("GET /v1/tls/tickets", func(w http.ResponseWriter, _ *http.Request) {
		if st := s.proxy.Tickets(); st != nil {
			writeJSON(w, 200, st)
			return
		}
		writeJSON(w, 404, result{Error: "session_tickets is not configured"})
	})
	mux.HandleFunc("GET /v1/quotas", func(w http.ResponseWriter, r *http.Request) {
		top := 10
		if v, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && v >= 0 && v <= 1000 {
			top = v
		}
		writeJSON(w, 200, s.proxy.Quotas(top))
	})
	mux.HandleFunc("GET /v1/waf", func(w http.ResponseWriter, r *http.Request) {
		top := 50
		if v, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && v >= 0 && v <= 10000 {
			top = v
		}
		writeJSON(w, 200, s.proxy.WAF(top))
	})
	mux.HandleFunc("GET /v1/waf/exclusions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, s.proxy.WAFExclusions())
	})
	mux.HandleFunc("POST /v1/waf/reset", s.audited("waf_reset", func() error { s.proxy.WAFReset(); return nil }))
	mux.HandleFunc("GET /v1/sandbox", func(w http.ResponseWriter, _ *http.Request) {
		if st := s.sandbox(); st != nil {
			writeJSON(w, 200, st)
			return
		}
		writeJSON(w, 404, result{Error: "sandbox status not available"})
	})
	s.mfaRoutes(mux)
	mux.HandleFunc("GET /v1/config", s.config)
	mux.HandleFunc("POST /v1/reload", s.reload)
	mux.HandleFunc("GET /v1/history", func(w http.ResponseWriter, _ *http.Request) {
		if s.actions.History == nil {
			writeJSON(w, 501, result{Error: "history not available"})
			return
		}
		entries, err := s.actions.History()
		if err != nil {
			writeJSON(w, 409, result{Error: err.Error()})
			return
		}
		writeJSON(w, 200, entries)
	})
	mux.HandleFunc("POST /v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if s.actions.Rollback == nil {
			writeJSON(w, 501, result{Error: "rollback not available"})
			return
		}
		s.audited("rollback "+id, func() error { return s.actions.Rollback(id) })(w, r)
	})
	mux.HandleFunc("GET /v1/diff", func(w http.ResponseWriter, r *http.Request) {
		if s.actions.Diff == nil {
			writeJSON(w, 501, result{Error: "diff not available"})
			return
		}
		from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
		if from == "" {
			from = "active"
		}
		if to == "" {
			to = "file"
		}
		ch, err := s.actions.Diff(from, to)
		if err != nil {
			writeJSON(w, 409, result{Error: err.Error()})
			return
		}
		writeJSON(w, 200, ch)
	})
	mux.HandleFunc("POST /v1/reload-certs", s.reloadCerts)
	mux.HandleFunc("POST /v1/logs/reopen", s.reopenLogs)
	mux.HandleFunc("GET /v1/drain", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.Drains()) })
	mux.HandleFunc("POST /v1/drain", s.setDrain)
	mux.HandleFunc("GET /v1/ready", s.ready)
	mux.HandleFunc("POST /v1/ready", s.setServing)
	mux.HandleFunc("GET /v1/bans", s.listBans)
	mux.HandleFunc("POST /v1/bans", s.addBan)
	mux.HandleFunc("DELETE /v1/bans", s.removeBan)
	// What the listeners in shadow mode would have refused, and emptying
	// it: an operator reads the report, fixes the policy, clears the
	// ledger, and reads the next week's report about the new one.
	mux.HandleFunc("GET /v1/policy", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, PolicyReport{
			Status:  s.proxy.Shadow().Status(),
			Entries: s.proxy.Shadow().Report(),
		})
	})
	mux.HandleFunc("DELETE /v1/policy", s.audited("policy_report_reset", func() error {
		s.proxy.Shadow().Reset()
		return nil
	}))
	// Just-in-time access: the grants a gate listener admits sessions
	// against, and the four calls that change them.
	s.accessRoutes(mux)
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, s.proxy.Sessions().List())
	})
	// Closing a session is an operation on the estate, so it is audited
	// like a ban: who asked, which session, and what it was.
	mux.HandleFunc("DELETE /v1/sessions", s.killSession)
	// The device inventory: what is on the network, and what the estate
	// says is supposed to be.
	mux.HandleFunc("GET /v1/assets", s.listAssets)
	mux.HandleFunc("POST /v1/assets/baseline", s.freezeAssets)
	mux.HandleFunc("DELETE /v1/assets/baseline", s.thawAssets)
	mux.HandleFunc("GET /v1/assets/advisories", s.listAdvisories)
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
	mux.HandleFunc("GET /v1/telemetry", func(w http.ResponseWriter, _ *http.Request) {
		view := TelemetryView{Traces: s.proxy.Tracing(), Logs: s.logs.OTLP(), SIEM: s.logs.SIEM()}
		if s.actions.OTLP != nil {
			m := s.actions.OTLP()
			view.Metrics = &m
		}
		writeJSON(w, 200, view)
	})
	mux.HandleFunc("GET /v1/otlp", func(w http.ResponseWriter, _ *http.Request) {
		if s.actions.OTLP == nil {
			writeJSON(w, 200, map[string]bool{"enabled": false})
			return
		}
		writeJSON(w, 200, s.actions.OTLP())
	})
	mux.HandleFunc("GET /v1/ingress", func(w http.ResponseWriter, _ *http.Request) {
		if s.actions.Ingress == nil {
			writeJSON(w, 200, map[string]bool{"enabled": false})
			return
		}
		writeJSON(w, 200, s.actions.Ingress())
	})
	mux.HandleFunc("GET /v1/fleet", func(w http.ResponseWriter, _ *http.Request) {
		if s.actions.Fleet == nil {
			writeJSON(w, 200, map[string]bool{"enabled": false})
			return
		}
		writeJSON(w, 200, s.actions.Fleet())
	})
	mux.HandleFunc("GET /v1/dns", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.DNS()) })
	mux.HandleFunc("DELETE /v1/dns", func(w http.ResponseWriter, r *http.Request) {
		n := s.proxy.PurgeDNS()
		s.audit(r, "dns_purge", "purged", n)
		writeJSON(w, 200, map[string]int{"purged": n})
	})
	mux.HandleFunc("GET /v1/patches", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.VirtualPatches()) })
	mux.HandleFunc("GET /v1/capture", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, s.proxy.CaptureStatus())
	})
	mux.HandleFunc("POST /v1/capture", s.setCapture)
	mux.HandleFunc("GET /v1/maintenance", func(w http.ResponseWriter, _ *http.Request) {
		on, configured := s.proxy.Maintenance(nil)
		writeJSON(w, 200, MaintenanceStatus{Configured: configured, On: on})
	})
	mux.HandleFunc("POST /v1/maintenance", s.setMaintenance)
	mux.HandleFunc("GET /v1/origin-check", func(w http.ResponseWriter, r *http.Request) {
		res, err := s.proxy.OriginCheck(r.URL.Query().Get("upstream"), r.URL.Query().Get("host"), r.URL.Query().Get("path"))
		if err != nil {
			writeJSON(w, 400, result{Error: err.Error()})
			return
		}
		writeJSON(w, 200, res)
	})
	mux.HandleFunc("GET /v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		top := 50
		if t := r.URL.Query().Get("top"); t != "" {
			n, err := strconv.Atoi(t)
			if err != nil || n < 0 || n > 100000 {
				writeJSON(w, 400, result{Error: "top must be between 0 and 100000"})
				return
			}
			top = n
		}
		writeJSON(w, 200, s.proxy.Accounts(top))
	})
	mux.HandleFunc("GET /v1/botscore", func(w http.ResponseWriter, r *http.Request) {
		top := 50
		if t := r.URL.Query().Get("top"); t != "" {
			n, err := strconv.Atoi(t)
			if err != nil || n < 0 || n > 100000 {
				writeJSON(w, 400, result{Error: "top must be between 0 and 100000"})
				return
			}
			top = n
		}
		writeJSON(w, 200, s.proxy.BotScore(top))
	})
	mux.HandleFunc("GET /v1/api", func(w http.ResponseWriter, r *http.Request) {
		top := 100
		if t := r.URL.Query().Get("top"); t != "" {
			n, err := strconv.Atoi(t)
			if err != nil || n < 1 || n > 100000 {
				writeJSON(w, 400, result{Error: "top must be between 1 and 100000"})
				return
			}
			top = n
		}
		view := r.URL.Query().Get("view")
		switch view {
		case "", "all":
			view = "all"
		case "shadow", "zombie", "versions", "documented", "undocumented":
		default:
			writeJSON(w, 400, result{Error: "view must be all, shadow, zombie, versions, documented or undocumented"})
			return
		}
		rep := s.proxy.APIInventory(view, top)
		if r.URL.Query().Get("format") == "openapi" {
			out, err := apiinv.SkeletonYAML(rep, r.URL.Query().Get("title"), time.Now())
			if err != nil {
				writeJSON(w, 500, result{Error: err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(200)
			_, _ = w.Write(out)
			return
		}
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("GET /v1/honeypot", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"marks": s.proxy.HoneypotMarks(), "marks_dropped": s.proxy.HoneypotMarksDropped(),
			"decoys": s.proxy.Decoys(), "honeytokens": s.proxy.Honeytokens(),
			// The fabricated devices of the protocol kinds. They belong in
			// the same view as the HTTP honeypot's: an operator asking
			// "what has been probing us" should not have to know which
			// listener kind answered.
			"device_decoys": s.proxy.DeviceDecoys()})
	})
	mux.HandleFunc("DELETE /v1/honeypot", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "ip: not an address"})
			return
		}
		removed := s.proxy.UnmarkHoneypot(ip)
		s.audit(r, "honeypot_unmark", "ip", ip.String(), "removed", removed)
		writeJSON(w, 200, map[string]bool{"removed": removed})
	})
	mux.HandleFunc("GET /v1/icap", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.proxy.ICAP()) })
	mux.HandleFunc("GET /v1/cache", func(w http.ResponseWriter, _ *http.Request) {
		if st, ok := s.proxy.CacheStats(); ok {
			writeJSON(w, 200, st)
			return
		}
		writeJSON(w, 404, result{Error: "cache is not configured"})
	})
	mux.HandleFunc("DELETE /v1/cache", func(w http.ResponseWriter, r *http.Request) {
		host, prefix := r.URL.Query().Get("host"), r.URL.Query().Get("path")
		n, ok := s.proxy.PurgeCache(host, prefix)
		if !ok {
			writeJSON(w, 404, result{Error: "cache is not configured"})
			return
		}
		peer := peerFromContext(r.Context())
		s.logs.Audit.Info("management action", "action", "cache-purge", "host", host, "path", prefix, "removed", n, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK)
		writeJSON(w, 200, map[string]any{"ok": true, "removed": n})
	})
	mux.HandleFunc("GET /v1/geoip", func(w http.ResponseWriter, _ *http.Request) {
		if st, ok := s.proxy.GeoIP(); ok {
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
	mode, _ := strconv.ParseUint(s.cfg.SocketMode, 8, 32)
	ln, err := unixsock.Listen(s.cfg.Socket, os.FileMode(mode))
	if err != nil {
		return fmt.Errorf("management socket: %w", err)
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
	// Sandbox summarises the in-process hardening; nil when not applied.
	Sandbox *sandbox.Status `json:"sandbox,omitempty"`
}

// sandbox returns the hardening status, or nil.
func (s *Server) sandbox() *sandbox.Status {
	if s.actions.Sandbox == nil {
		return nil
	}
	return s.actions.Sandbox()
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
	// Note carries a remark about an action that succeeded but may not
	// have done what the caller assumed.
	Note string `json:"note,omitempty"`
}

// healthResult is what /v1/health answers. The process is serving, so
// ok stays true, but a hardening mechanism that did not take effect is
// named here as well: without sandbox.strict a missing one was a line
// in the start-up log and nothing else, and nothing watches a start-up
// log. An operator who wants it to be fatal sets strict.
type healthResult struct {
	OK       bool     `json:"ok"`
	Degraded bool     `json:"degraded,omitempty"`
	Reasons  []string `json:"degraded_reasons,omitempty"`
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	res := healthResult{OK: true}
	if st := s.sandbox(); st != nil && st.Enabled {
		for _, m := range st.Mechanism {
			if m.State == sandbox.StateUnavailable || m.State == sandbox.StateFailed {
				res.Degraded = true
				res.Reasons = append(res.Reasons, "sandbox "+m.Name+": "+m.State)
			}
		}
	}
	writeJSON(w, 200, res)
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
		Sandbox:    s.sandbox(),
	})
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.proxy.Stats())
}

func (s *Server) upstreams(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.proxy.Upstreams())
}

// config dumps the active configuration as one self-contained document:
// included fragments are already expanded into it, so `includes` is
// cleared (a copy fed back would otherwise append them a second time) and
// the files that were read are listed in a leading comment.
//
// Header operation values are redacted, so this is a document to read,
// not one to feed back: the credential a route sends to its origin
// lives in request_headers.set, and this response travels further than
// the file on disk. The history keeps the real values for rollback.
func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	b, err := config.DumpRedacted(s.proxy.Config())
	if err != nil {
		writeJSON(w, 500, result{Error: err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(200)
	if files := s.proxy.Config().IncludedFiles; len(files) > 0 {
		_, _ = fmt.Fprintf(w, "# includes expanded from: %s\n", strings.Join(files, ", "))
	}
	_, _ = w.Write(b)
}

// audit records a completed management action with the caller's identity,
// for handlers whose response carries data (audited covers the plain ones).
func (s *Server) audit(r *http.Request, name string, extra ...any) {
	peer := peerFromContext(r.Context())
	attrs := append([]any{"action", name, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK}, extra...)
	s.logs.Audit.Info("management action", attrs...)
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

// TelemetryView is the response of GET /v1/telemetry: every OpenTelemetry
// exporter with its counters, nil when not configured.
type TelemetryView struct {
	Metrics *metrics.OTLPStatus `json:"metrics"`
	Traces  *tracing.Status     `json:"traces"`
	Logs    *logging.OTLPStatus `json:"logs"`
	SIEM    *logging.SIEMStatus `json:"siem"`
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

// killSession closes one live session, or every session matching a
// filter. A request that names nothing is refused rather than read as
// "all of them": an operator who meant every session says so with a
// filter that matches it.
func (s *Server) killSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, kind, listener, user := q.Get("id"), q.Get("kind"), q.Get("listener"), q.Get("user")
	if id == "" && kind == "" && listener == "" && user == "" {
		writeJSON(w, 400, result{Error: "name a session with id, or a filter with kind, listener or user"})
		return
	}
	table := s.proxy.Sessions()
	var closed []sessions.View
	if id != "" {
		v, ok := table.Kill(id)
		if !ok {
			writeJSON(w, 404, result{Error: "no live session with that id"})
			return
		}
		closed = []sessions.View{v}
	} else {
		closed = table.KillWhere(func(v sessions.View) bool {
			return (kind == "" || v.Kind == kind) &&
				(listener == "" || v.Listener == listener) &&
				(user == "" || v.User == user)
		})
	}
	for _, v := range closed {
		s.audit(r, "session_kill", "session_id", v.ID, "kind", v.Kind, "listener", v.Listener,
			"client", v.Client, "user", v.User, "target", v.Target, "duration_ms", v.DurationMS)
	}
	writeJSON(w, 200, closed)
}

// PolicyReport is what GET /v1/policy answers: the ledger's totals and
// every decision a listener in shadow mode made and did not enforce.
type PolicyReport struct {
	Status  shadow.Status  `json:"status"`
	Entries []shadow.Entry `json:"entries"`
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

// CaptureRequest is the body of POST /v1/capture. Duration is a Go
// duration string ("10m"); empty or zero asks for the configured
// maximum, and anything longer than it is shortened to it.
type CaptureRequest struct {
	Active   bool   `json:"active"`
	Duration string `json:"duration,omitempty"`
}

// setCapture turns packet capture on or off. It is audited like every
// other mutating call: a capture writes decrypted traffic to disk, so
// who turned it on and when has to be in the record.
func (s *Server) setCapture(w http.ResponseWriter, r *http.Request) {
	var req CaptureRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&req); err != nil {
		writeJSON(w, 400, result{Error: "bad request body"})
		return
	}
	var d time.Duration
	if req.Duration != "" {
		v, err := time.ParseDuration(req.Duration)
		if err != nil || v < 0 {
			writeJSON(w, 400, result{Error: "duration: not a duration"})
			return
		}
		d = v
	}
	st, err := s.proxy.SetCapture(req.Active, d)
	if err != nil {
		writeJSON(w, 404, result{Error: err.Error()})
		return
	}
	peer := peerFromContext(r.Context())
	s.logs.Audit.Info("management action", "action", "capture", "active", st.Active, "until", st.Until,
		"peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK)
	writeJSON(w, 200, st)
}

// MaintenanceStatus is the body of GET /v1/maintenance.
type MaintenanceStatus struct {
	Configured bool `json:"configured"`
	On         bool `json:"on"`
}

// MaintenanceRequest is the body of POST /v1/maintenance.
type MaintenanceRequest struct {
	On bool `json:"on"`
}

func (s *Server) setMaintenance(w http.ResponseWriter, r *http.Request) {
	var req MaintenanceRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&req); err != nil {
		writeJSON(w, 400, result{Error: "bad request body"})
		return
	}
	on, configured := s.proxy.Maintenance(&req.On)
	if !configured {
		writeJSON(w, 400, result{Error: "no maintenance section configured"})
		return
	}
	peer := peerFromContext(r.Context())
	s.logs.Audit.Info("management action", "action", "maintenance", "on", on, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK)
	writeJSON(w, 200, MaintenanceStatus{Configured: true, On: on})
}

// DrainRequest takes an endpoint out of rotation, or a whole pool, or
// puts one back. Naming an address drains that endpoint; naming only the
// pool puts the pool into maintenance.
type DrainRequest struct {
	Pool    string `json:"pool"`
	Address string `json:"address,omitempty"`
	// Drain false restores. The field is explicit rather than two
	// endpoints, because "drain" and "undrain" as separate verbs is how
	// an operator ends up not knowing which state something is in.
	Drain bool `json:"drain"`
}

// setDrain records an operator's decision to stop sending new work to an
// endpoint or a pool. Nothing is closed: what is already running
// finishes, which is what makes this usable for a rolling restart.
// ServingRequest steps this node down or back up.
type ServingRequest struct {
	Serving bool   `json:"serving"`
	Reason  string `json:"reason,omitempty"`
}

// ready answers whether this node should be carrying traffic. The two
// judgement calls -- whether an upstream pool with nothing healthy in it,
// or a hardening mechanism that did not apply, should move an address --
// are the caller's to make, because the answer depends on the estate
// (docs/HA.md). They arrive as query parameters so that a check script is
// one URL.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	opt := proxy.ReadinessOptions{
		RequireUpstreams:  r.URL.Query().Get("require_upstreams") == "1",
		RequireUndegraded: r.URL.Query().Get("require_undegraded") == "1",
	}
	res := s.proxy.Readiness(opt).WithDegraded(s.degradedMechanisms(), opt.RequireUndegraded)
	// The status code is the answer as well as the body, so that a check
	// that reads neither JSON nor exit codes still works.
	code := 200
	if !res.Serving {
		code = 503
	}
	writeJSON(w, code, res)
}

// degradedMechanisms names the hardening mechanisms that are not doing
// their job.
func (s *Server) degradedMechanisms() []string {
	st := s.sandbox()
	if st == nil || !st.Enabled {
		return nil
	}
	var out []string
	for _, m := range st.Mechanism {
		if m.State == sandbox.StateUnavailable || m.State == sandbox.StateFailed {
			out = append(out, m.Name+": "+m.State)
		}
	}
	return out
}

func (s *Server) setServing(w http.ResponseWriter, r *http.Request) {
	var req ServingRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, result{Error: "bad request body"})
		return
	}
	if len(req.Reason) > 256 {
		writeJSON(w, 400, result{Error: "reason too long"})
		return
	}
	peer := peerFromContext(r.Context())
	res := s.proxy.SetServing(req.Serving, req.Reason)
	s.logs.Audit.Info("management action", "action", "node_serving", "serving", req.Serving,
		"reason", req.Reason, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK)
	writeJSON(w, 200, res)
}

func (s *Server) setDrain(w http.ResponseWriter, r *http.Request) {
	var req DrainRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, result{Error: "bad request body"})
		return
	}
	if req.Pool == "" {
		writeJSON(w, 400, result{Error: "pool is required"})
		return
	}
	if len(req.Pool) > 256 || len(req.Address) > 256 {
		writeJSON(w, 400, result{Error: "pool or address too long"})
		return
	}
	peer := peerFromContext(r.Context())
	action := "pool_maintenance"
	if req.Address != "" {
		action = "endpoint_drain"
	}
	found := s.proxy.SetDrain(req.Pool, req.Address, req.Drain)
	attrs := []any{"action", action, "pool", req.Pool, "address", req.Address, "drain", req.Drain,
		"peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK}
	s.logs.Audit.Info("management action", attrs...)
	if !found {
		// The decision is recorded anyway: an endpoint may be about to
		// arrive from discovery, and a pool may be about to be added by
		// a reload. Saying so is more useful than either refusing or
		// pretending.
		writeJSON(w, 200, result{OK: true, Note: "recorded; no live pool or endpoint of that name yet"})
		return
	}
	writeJSON(w, 200, result{OK: true})
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

// reload applies the file, or with ?dry_run=1 reports what applying it
// would change (validation included) without touching the running
// generation. A dry run is read only and not audited.
func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if q := r.URL.Query().Get("dry_run"); q == "1" || q == "true" {
		_, _ = io.Copy(io.Discard, r.Body)
		if s.actions.DryRun == nil {
			writeJSON(w, 501, result{Error: "dry run not available"})
			return
		}
		ch, err := s.actions.DryRun()
		if err != nil {
			writeJSON(w, 409, result{Error: err.Error()})
			return
		}
		writeJSON(w, 200, ch)
		return
	}
	s.audited("reload", s.actions.Reload)(w, r)
}

func (s *Server) reloadCerts(w http.ResponseWriter, r *http.Request) {
	s.audited("reload_certs", s.actions.ReloadCerts)(w, r)
}

func (s *Server) reopenLogs(w http.ResponseWriter, r *http.Request) {
	s.audited("reopen_logs", s.actions.ReopenLogs)(w, r)
}
