package openapi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// guard holds the compiled description and keeps it current: a file is
// re-read when it changes (checked at most every refresh on the request
// path), a URL is fetched again every refresh in the background. A
// description that fails to load keeps the previous one and is logged.
type guard struct {
	name string
	cfg  *Config
	log  *slog.Logger

	api     atomic.Pointer[api]
	checkMu sync.Mutex
	checked time.Time
	digest  [32]byte
	modTime time.Time
	size    int64
	etag    string
	client  *http.Client
	now     func() time.Time
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once

	// Reloads counts descriptions swapped in after the first;
	// Failures the loads that kept the previous one.
	Reloads, Failures atomic.Uint64
}

func newGuard(name string, cfg *Config, env filter.Env) (*guard, error) {
	g := &guard{name: name, cfg: cfg, log: env.Log, now: time.Now, stop: make(chan struct{}), done: make(chan struct{})}
	if g.log == nil {
		g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.SpecURL == "" {
		data, info, err := readFile(cfg.SpecFile)
		if err != nil {
			return nil, fmt.Errorf("spec_file: %w", err)
		}
		if err := g.install(data); err != nil {
			return nil, fmt.Errorf("spec_file: %w", err)
		}
		g.modTime, g.size = info.ModTime(), info.Size()
		close(g.done)
		return g, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: no certificates")
		}
		tc.RootCAs = pool
	}
	g.client = &http.Client{Timeout: cfg.timeout, Transport: &http.Transport{
		TLSClientConfig: tc, DialContext: (&net.Dialer{Timeout: cfg.timeout}).DialContext, TLSHandshakeTimeout: cfg.timeout, MaxIdleConns: 2, IdleConnTimeout: time.Minute,
	}}
	if err := g.fetch(); err != nil {
		cached, cerr := g.readCache()
		if cerr != nil {
			return nil, fmt.Errorf("spec_url: %w (no usable cache: %w)", err, cerr)
		}
		if ierr := g.install(cached); ierr != nil {
			return nil, fmt.Errorf("spec_url: %w (cache: %w)", err, ierr)
		}
		g.log.Warn("openapi description served from the cache file", "filter", name, "url", cfg.SpecURL, "err", err.Error())
	}
	go g.refreshLoop()
	return g, nil
}

// Close stops the background refresh.
func (g *guard) Close() error {
	g.once.Do(func() {
		close(g.stop)
		if g.cfg.SpecURL != "" {
			<-g.done
		}
	})
	return nil
}

func readFile(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSpecBytes+1))
	return data, info, err
}

// install compiles data and swaps it in when it differs from the
// current description.
func (g *guard) install(data []byte) error {
	sum := sha256.Sum256(data)
	if g.api.Load() != nil && sum == g.digest {
		return nil
	}
	a, err := compileSpec(data, g.cfg.BasePath)
	if err != nil {
		return err
	}
	if g.api.Load() != nil {
		g.Reloads.Add(1)
		g.log.Info("openapi description reloaded", "filter", g.name, "paths", len(a.exact)+len(a.templ))
	}
	g.api.Store(a)
	g.digest = sum
	return nil
}

// current returns the description, re-reading a file that changed when
// the refresh interval has passed.
func (g *guard) current() *api {
	a := g.api.Load()
	if g.cfg.SpecURL != "" {
		return a
	}
	g.checkMu.Lock()
	defer g.checkMu.Unlock()
	now := g.now()
	if now.Sub(g.checked) < g.cfg.refresh {
		return a
	}
	g.checked = now
	info, err := os.Stat(g.cfg.SpecFile)
	if err != nil || (info.ModTime().Equal(g.modTime) && info.Size() == g.size) {
		return a
	}
	data, info, err := readFile(g.cfg.SpecFile)
	if err != nil {
		g.Failures.Add(1)
		g.log.Error("openapi description not reloaded", "filter", g.name, "file", g.cfg.SpecFile, "err", err.Error())
		return a
	}
	g.modTime, g.size = info.ModTime(), info.Size()
	if err := g.install(data); err != nil {
		g.Failures.Add(1)
		g.log.Error("openapi description not reloaded", "filter", g.name, "file", g.cfg.SpecFile, "err", err.Error())
		return a
	}
	return g.api.Load()
}

func (g *guard) refreshLoop() {
	defer close(g.done)
	t := time.NewTicker(g.cfg.refresh)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			if err := g.fetch(); err != nil {
				g.Failures.Add(1)
				g.log.Error("openapi description not refreshed", "filter", g.name, "url", g.cfg.SpecURL, "err", err.Error())
			}
		}
	}
}

// fetch downloads the description, honouring ETags, installs it and
// writes the cache file.
func (g *guard) fetch() error {
	ctx, cancel := context.WithTimeout(context.Background(), g.cfg.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.SpecURL, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")
	req.Header.Set("User-Agent", "xproxy-openapi/1")
	g.checkMu.Lock()
	etag := g.etag
	g.checkMu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified && g.api.Load() != nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSpecBytes+1))
	if err != nil {
		return err
	}
	g.checkMu.Lock()
	defer g.checkMu.Unlock()
	if err := g.install(data); err != nil {
		return err
	}
	g.etag = resp.Header.Get("ETag")
	g.writeCache(data)
	return nil
}

func (g *guard) readCache() ([]byte, error) {
	if g.cfg.CacheFile == "" {
		return nil, errors.New("no cache_file")
	}
	return os.ReadFile(g.cfg.CacheFile) //nolint:gosec // validated configuration path
}

func (g *guard) writeCache(data []byte) {
	if g.cfg.CacheFile == "" {
		return
	}
	tmp := g.cfg.CacheFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		g.log.Warn("openapi cache not written", "file", g.cfg.CacheFile, "err", err.Error())
		return
	}
	if err := os.Rename(tmp, g.cfg.CacheFile); err != nil {
		_ = os.Remove(tmp)
		g.log.Warn("openapi cache not written", "file", g.cfg.CacheFile, "err", err.Error())
	}
}
