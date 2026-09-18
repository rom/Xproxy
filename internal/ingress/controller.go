package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Status is the management view.
type Status struct {
	Enabled      bool      `json:"enabled"`
	Class        string    `json:"class"`
	LastSync     time.Time `json:"last_sync"`
	LastChange   time.Time `json:"last_change"`
	LastError    string    `json:"last_error"`
	Syncs        uint64    `json:"syncs"`
	Errors       uint64    `json:"errors"`
	Ingresses    int       `json:"ingresses"`
	Gateways     int       `json:"gateways"`
	HTTPRoutes   int       `json:"httproutes"`
	GatewayAPI   bool      `json:"gateway_api"`
	Watching     int       `json:"watching"`
	WatchEvents  uint64    `json:"watch_events"`
	Routes       int       `json:"routes"`
	Upstreams    int       `json:"upstreams"`
	Certificates int       `json:"certificates"`
	Warnings     []string  `json:"warnings"`
}

// Controller polls the API server and keeps the latest snapshot.
type Controller struct {
	cfg      config.Ingress
	client   *client
	log      *slog.Logger
	onChange func()

	mu     sync.Mutex
	snap   Snapshot
	certs  []config.Certificate
	hash   string
	status Status

	stop chan struct{}
	wg   sync.WaitGroup
	once sync.Once

	// kick is signalled by watch events; Start debounces it into a Sync.
	kick     chan struct{}
	watching atomic.Int32
	events   atomic.Uint64
	gwAPI    atomic.Bool
}

// New builds a controller; Sync and Start do the work.
func New(cfg config.Ingress, log *slog.Logger, onChange func()) (*Controller, error) {
	c, err := newClient(cfg.APIServer, cfg.TokenFile, cfg.CAFile, cfg.Timeout.D())
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
		return nil, fmt.Errorf("cert_dir: %w", err)
	}
	return &Controller{cfg: cfg, client: c, log: log.With("component", "ingress"), onChange: onChange, stop: make(chan struct{}),
		kick: make(chan struct{}, 1), status: Status{Enabled: true, Class: cfg.Class}}, nil
}

// Snapshot returns the latest translation and the certificate files
// written for it.
func (c *Controller) Snapshot() (Snapshot, []config.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snap, c.certs
}

// Status reports counters and the last error.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.status
	st.Warnings = append([]string(nil), c.snap.Warnings...)
	st.Watching = int(c.watching.Load())
	st.WatchEvents = c.events.Load()
	st.GatewayAPI = c.gwAPI.Load()
	return st
}

// watchPaths are the collections whose events trigger a sync.
var watchPaths = []string{
	"/apis/networking.k8s.io/v1/ingresses",
	"/api/v1/services",
	"/apis/discovery.k8s.io/v1/endpointslices",
	"/api/v1/secrets",
	"/apis/gateway.networking.k8s.io/v1/gateways",
	"/apis/gateway.networking.k8s.io/v1/httproutes",
}

// Start syncs on watch events (debounced) and every resync as a
// fallback, until Stop. Watches reconnect with backoff; a collection
// the cluster does not serve is retried slowly.
func (c *Controller) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	if c.cfg.Watches() {
		for _, p := range watchPaths {
			c.wg.Add(1)
			go c.watchLoop(ctx, p)
		}
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer cancel()
		t := time.NewTicker(c.cfg.Resync.D())
		defer t.Stop()
		var debounce <-chan time.Time
		for {
			select {
			case <-c.stop:
				return
			case <-c.kick:
				if debounce == nil {
					debounce = time.After(c.cfg.Debounce.D())
				}
				continue
			case <-debounce:
				debounce = nil
			case <-t.C:
			}
			changed, err := c.Sync(context.Background())
			if err != nil {
				c.log.Warn("ingress sync failed", "err", err.Error())
				continue
			}
			if changed && c.onChange != nil {
				c.onChange()
			}
		}
	}()
}

func (c *Controller) watchLoop(ctx context.Context, path string) {
	defer c.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c.watching.Add(1)
		start := time.Now()
		err := c.client.watch(ctx, path, func(kind string) {
			if kind == "BOOKMARK" {
				return
			}
			c.events.Add(1)
			select {
			case c.kick <- struct{}{}:
			default:
			}
		})
		c.watching.Add(-1)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil || time.Since(start) > time.Minute:
			backoff = time.Second // a stream that lived a while ended normally
		case isNotFound(err):
			backoff = 5 * time.Minute // the resource is not served here
		default:
			backoff = min(backoff*2, 30*time.Second)
			c.log.Debug("ingress watch ended", "path", path, "err", err.Error(), "retry_in", backoff.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// Stop ends polling.
func (c *Controller) Stop() {
	c.once.Do(func() { close(c.stop) })
	c.wg.Wait()
}

// Sync fetches, translates, writes certificate files and reports whether
// the snapshot changed.
func (c *Controller) Sync(ctx context.Context) (bool, error) {
	in, err := c.fetch(ctx)
	c.mu.Lock()
	c.status.Syncs++
	c.status.LastSync = time.Now()
	c.mu.Unlock()
	if err != nil {
		c.fail(err)
		return false, err
	}
	snap := Translate(in, c.cfg.Class)
	certs, err := c.writeCerts(snap.Certificates)
	if err != nil {
		c.fail(err)
		return false, err
	}
	h := hashSnapshot(snap)
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := h != c.hash
	c.snap, c.certs, c.hash = snap, certs, h
	c.status.LastError = ""
	c.status.Ingresses, c.status.Gateways, c.status.HTTPRoutes = snap.Ingresses, snap.Gateways, snap.HTTPRoutes
	c.status.Routes, c.status.Upstreams, c.status.Certificates = len(snap.Routes), len(snap.Upstreams), len(certs)
	if changed {
		c.status.LastChange = time.Now()
		c.log.Info("ingress snapshot changed", "ingresses", snap.Ingresses, "routes", len(snap.Routes), "upstreams", len(snap.Upstreams), "certificates", len(certs), "warnings", len(snap.Warnings))
		for _, w := range snap.Warnings {
			c.log.Warn("ingress translation", "warning", w)
		}
	}
	return changed, nil
}

func (c *Controller) fail(err error) {
	c.mu.Lock()
	c.status.Errors++
	c.status.LastError = err.Error()
	c.mu.Unlock()
}

func (c *Controller) fetch(ctx context.Context) (Input, error) {
	var in Input
	namespaces := c.cfg.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}
	for _, ns := range namespaces {
		ings, err := c.client.ingresses(ctx, ns)
		if err != nil {
			return in, fmt.Errorf("ingresses: %w", err)
		}
		in.Ingresses = append(in.Ingresses, ings...)
		svcs, err := c.client.services(ctx, ns)
		if err != nil {
			return in, fmt.Errorf("services: %w", err)
		}
		in.Services = append(in.Services, svcs...)
		sl, err := c.client.endpointSlices(ctx, ns)
		if err != nil {
			return in, fmt.Errorf("endpointslices: %w", err)
		}
		in.Slices = append(in.Slices, sl...)
		// The Gateway API is optional: a cluster without its CRDs answers
		// 404, which is not an error.
		gws, err := c.client.gateways(ctx, ns)
		switch {
		case isNotFound(err):
			c.gwAPI.Store(false)
		case err != nil:
			return in, fmt.Errorf("gateways: %w", err)
		default:
			c.gwAPI.Store(true)
			in.Gateways = append(in.Gateways, gws...)
			hrs, err := c.client.httpRoutes(ctx, ns)
			if err != nil && !isNotFound(err) {
				return in, fmt.Errorf("httproutes: %w", err)
			}
			in.HTTPRoutes = append(in.HTTPRoutes, hrs...)
		}
	}
	in.Secrets = map[string]*Secret{}
	want := func(ns, name string) {
		key := ns + "/" + name
		if name == "" {
			return
		}
		if _, seen := in.Secrets[key]; seen {
			return
		}
		s, err := c.client.secret(ctx, ns, name)
		if err != nil {
			c.log.Warn("ingress tls secret", "namespace", ns, "secret", name, "err", err.Error())
			in.Secrets[key] = nil
			return
		}
		in.Secrets[key] = s
	}
	for i := range in.Ingresses {
		ing := &in.Ingresses[i]
		if !matchesClass(ing, c.cfg.Class) {
			continue
		}
		for _, t := range ing.Spec.TLS {
			want(ing.Metadata.Namespace, t.SecretName)
		}
	}
	for i := range in.Gateways {
		g := &in.Gateways[i]
		if g.Spec.GatewayClassName != c.cfg.Class {
			continue
		}
		for _, l := range g.Spec.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, ref := range l.TLS.CertificateRefs {
				ns := ref.Namespace
				if ns == "" {
					ns = g.Metadata.Namespace
				}
				want(ns, ref.Name)
			}
		}
	}
	return in, nil
}

// writeCerts writes secret material to cert_dir (0600) and removes files
// of secrets no longer referenced.
func (c *Controller) writeCerts(certs []CertPEM) ([]config.Certificate, error) {
	keep := map[string]bool{}
	out := make([]config.Certificate, 0, len(certs))
	for _, ce := range certs {
		base := filepath.Join(c.cfg.CertDir, ce.Namespace+"--"+ce.Name)
		crt, key := base+".crt", base+".key"
		if err := writeIfChanged(crt, ce.Cert); err != nil {
			return nil, err
		}
		if err := writeIfChanged(key, ce.Key); err != nil {
			return nil, err
		}
		keep[filepath.Base(crt)], keep[filepath.Base(key)] = true, true
		out = append(out, config.Certificate{CertFile: crt, KeyFile: key})
	}
	entries, err := os.ReadDir(c.cfg.CertDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		certFile := strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".key")
		if e.IsDir() || keep[n] || !certFile || !strings.Contains(n, "--") {
			continue
		}
		_ = os.Remove(filepath.Join(c.cfg.CertDir, n))
	}
	return out, nil
}

func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && string(old) == string(data) { //nolint:gosec // controller owned directory
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func decodeB64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return b, nil
}

func hashSnapshot(s Snapshot) string {
	h := sha256.New()
	for _, r := range s.Routes {
		_, _ = fmt.Fprintf(h, "route %s %v %v %v %s %d %v %s %v %v %v %d %s %s %s %v %v %v\n", r.Name, r.Hosts, r.Paths, r.Methods, r.Upstream, r.Priority, r.WebSocket, r.PriorityClass, r.RateLimits, r.Filters, r.Timeout, deref(r.MaxBodyBytes), r.StripPrefix, r.RewritePath, r.HostHeader, r.Redirect, r.RequestHeaders, r.ResponseHeaders)
	}
	for _, u := range s.Upstreams {
		_, _ = fmt.Fprintf(h, "upstream %s %s", u.Name, u.Balancer)
		for _, e := range u.Endpoints {
			_, _ = fmt.Fprintf(h, " %s/%d", e.Address, e.Weight)
		}
		_, _ = fmt.Fprintln(h)
	}
	certs := append([]CertPEM(nil), s.Certificates...)
	sort.Slice(certs, func(i, j int) bool { return certs[i].Namespace+certs[i].Name < certs[j].Namespace+certs[j].Name })
	for _, c := range certs {
		_, _ = fmt.Fprintf(h, "cert %s/%s %x %x\n", c.Namespace, c.Name, sha256.Sum256(c.Cert), sha256.Sum256(c.Key))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ErrNotEnabled is returned by Merge when the section is off.
var ErrNotEnabled = errors.New("ingress: not enabled")
