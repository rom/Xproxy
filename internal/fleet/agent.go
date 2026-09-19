package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/rom/xproxy/internal/config"
)

// markerFile records the digest of the last bundle the agent applied,
// so a restart knows what the node runs.
const markerFile = ".xproxy-fleet.json"

// Hooks are what the agent needs from the proxy.
type Hooks struct {
	// Apply reloads the configuration from the files on disk (the
	// ordinary reload path, with validation and the sandbox check).
	Apply func() error
	// Status fills the node's report; the agent adds its own fields.
	Status func() NodeStatus
}

// NodeStatus is what a node reports to the controller.
type NodeStatus struct {
	NodeID     string    `json:"node_id"`
	Hostname   string    `json:"hostname,omitempty"`
	Version    string    `json:"version"`
	Tags       []string  `json:"tags,omitempty"`
	Uptime     float64   `json:"uptime_seconds"`
	Generation uint64    `json:"generation"`
	ReportedAt time.Time `json:"reported_at"`
	// Applied is the last bundle the node applied (or tried to).
	Applied Result `json:"applied"`
	// Pending is the digest of a bundle received but not applied
	// (apply: false), "" otherwise.
	Pending string `json:"pending_digest,omitempty"`
	// Health summary.
	Requests         uint64    `json:"requests"`
	Responses5xx     uint64    `json:"responses_5xx"`
	Denied           uint64    `json:"denied"`
	OpenConnections  int64     `json:"open_connections"`
	InFlight         int64     `json:"in_flight"`
	UpstreamsTotal   int       `json:"upstreams"`
	UpstreamsHealthy int       `json:"upstreams_healthy"`
	EndpointsTotal   int       `json:"endpoints"`
	EndpointsHealthy int       `json:"endpoints_healthy"`
	BansActive       int       `json:"bans_active"`
	CertExpiry       time.Time `json:"cert_expiry,omitempty"`
	Sandbox          string    `json:"sandbox,omitempty"`
}

// Result is the outcome of applying a bundle.
type Result struct {
	Digest string    `json:"digest,omitempty"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

// AgentStatus is the management view (GET /v1/fleet).
type AgentStatus struct {
	Enabled       bool      `json:"enabled"`
	Controller    string    `json:"controller,omitempty"`
	NodeID        string    `json:"node_id,omitempty"`
	Dir           string    `json:"dir,omitempty"`
	Interval      string    `json:"interval,omitempty"`
	Apply         bool      `json:"apply"`
	Polls         uint64    `json:"polls"`
	Reports       uint64    `json:"reports"`
	Applies       uint64    `json:"applies"`
	Failures      uint64    `json:"failures"`
	LastPoll      time.Time `json:"last_poll,omitempty"`
	LastReport    time.Time `json:"last_report,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Applied       Result    `json:"applied"`
	PendingDigest string    `json:"pending_digest,omitempty"`
	// Assigned is false while the controller has no bundle for the node.
	Assigned bool `json:"assigned"`
}

// Agent is the node side.
type Agent struct {
	cfg   config.Fleet
	dir   string
	hooks Hooks
	http  *http.Client
	log   *slog.Logger

	mu     sync.Mutex
	st     AgentStatus
	stop   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
	wakeup chan struct{}
}

// NewAgent builds an agent; cfgPath is the proxy's configuration file,
// whose directory receives bundles when fleet.dir is unset.
func NewAgent(cfg config.Fleet, cfgPath string, hooks Hooks, log *slog.Logger) (*Agent, error) {
	dir := cfg.Dir
	if dir == "" {
		dir = filepath.Dir(cfgPath)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	dir = abs
	if cp, err := filepath.Abs(cfgPath); err == nil && filepath.Dir(cp) != dir {
		return nil, fmt.Errorf("fleet.dir %s must be the directory of the configuration file %s", dir, cp)
	}
	if filepath.Base(cfgPath) != ConfigFile {
		return nil, fmt.Errorf("fleet: the configuration file must be named %s, not %s", ConfigFile, filepath.Base(cfgPath))
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("fleet certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.TLS.CAFile) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, fmt.Errorf("fleet CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("fleet CA file contains no certificates")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: cfg.TLS.ServerName}
	a := &Agent{cfg: cfg, dir: dir, hooks: hooks, log: log.With("component", "fleet"), stop: make(chan struct{}), wakeup: make(chan struct{}, 1)}
	a.http = &http.Client{Timeout: cfg.Interval.D() + cfg.Timeout.D(),
		Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 2 * cfg.Interval.D(), DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}
	a.st = AgentStatus{Enabled: true, Controller: cfg.Controller, NodeID: cfg.NodeID, Dir: dir, Interval: cfg.Interval.D().String(), Apply: cfg.Applies()}
	if data, err := os.ReadFile(filepath.Join(dir, markerFile)); err == nil { //nolint:gosec // inside the configuration directory
		_ = json.Unmarshal(data, &a.st.Applied)
	}
	return a, nil
}

// Start runs the poll loop until Stop.
func (a *Agent) Start() {
	a.wg.Add(1)
	go a.loop()
}

// Stop ends the loop and waits for it.
func (a *Agent) Stop() {
	a.once.Do(func() { close(a.stop) })
	a.wg.Wait()
}

// Status returns the management view.
func (a *Agent) Status() AgentStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.st
}

// Poke makes the agent poll now (tests).
func (a *Agent) Poke() {
	select {
	case a.wakeup <- struct{}{}:
	default:
	}
}

func (a *Agent) loop() {
	defer a.wg.Done()
	backoff := time.Second
	for {
		err := a.cycle()
		delay := time.Duration(0)
		if err != nil {
			a.mu.Lock()
			a.st.LastError = err.Error()
			a.st.Failures++
			a.mu.Unlock()
			a.log.Warn("fleet cycle failed", "err", err.Error())
			delay = backoff
			backoff = min(backoff*2, a.cfg.Interval.D())
		} else {
			backoff = time.Second
		}
		select {
		case <-a.stop:
			return
		case <-a.wakeup:
		case <-time.After(delay):
		}
	}
}

// cycle long polls for a bundle, applies one when it arrives and
// reports the node's status.
func (a *Agent) cycle() error {
	pollErr := a.poll()
	if err := a.report(); err != nil {
		if pollErr != nil {
			return errors.Join(pollErr, fmt.Errorf("report: %w", err))
		}
		return err
	}
	return pollErr
}

func (a *Agent) nodeURL(suffix string) string {
	return strings.TrimSuffix(a.cfg.Controller, "/") + "/v1/fleet/nodes/" + url.PathEscape(a.cfg.NodeID) + suffix
}

func (a *Agent) poll() error {
	a.mu.Lock()
	current := a.st.Applied.Digest
	if a.st.PendingDigest != "" {
		current = a.st.PendingDigest
	}
	a.mu.Unlock()
	q := url.Values{"digest": {current}, "wait": {a.cfg.Interval.D().String()}}
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.Interval.D()+a.cfg.Timeout.D())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.nodeURL("/config?"+q.Encode()), http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "xproxy-fleet-agent/1")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	a.mu.Lock()
	a.st.Polls++
	a.st.LastPoll = time.Now()
	a.mu.Unlock()
	switch resp.StatusCode {
	case http.StatusNotModified:
		a.setAssigned(true)
		return nil
	case http.StatusNotFound:
		a.setAssigned(false)
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("poll: controller answered HTTP %d", resp.StatusCode)
	}
	a.setAssigned(true)
	var b Bundle
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBundleBytes*2)).Decode(&b); err != nil {
		return fmt.Errorf("poll: decoding bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		a.setResult(Result{Digest: b.Digest, Error: "rejected: " + err.Error(), At: time.Now()})
		return fmt.Errorf("bundle %s rejected: %w", short(b.Digest), err)
	}
	if !a.cfg.Applies() {
		a.mu.Lock()
		a.st.PendingDigest = b.Digest
		a.mu.Unlock()
		a.log.Info("fleet bundle pending (apply is off)", "digest", short(b.Digest))
		return nil
	}
	return a.apply(&b)
}

func (a *Agent) setAssigned(v bool) {
	a.mu.Lock()
	a.st.Assigned = v
	a.mu.Unlock()
}

func (a *Agent) setResult(r Result) {
	a.mu.Lock()
	a.st.Applied = r
	if r.OK {
		a.st.PendingDigest = ""
		a.st.LastError = ""
	}
	a.mu.Unlock()
}

// apply writes the bundle, reloads, and restores the previous files
// when the reload refuses the new configuration.
func (a *Agent) apply(b *Bundle) error {
	restore, err := Write(a.dir, b)
	if err != nil {
		if restore != nil {
			_ = restore()
		}
		a.setResult(Result{Digest: b.Digest, Error: "write: " + err.Error(), At: time.Now()})
		return fmt.Errorf("bundle %s: writing files: %w", short(b.Digest), err)
	}
	if err := a.hooks.Apply(); err != nil {
		if rerr := restore(); rerr != nil {
			a.log.Error("fleet restore after failed reload", "err", rerr.Error())
		}
		a.setResult(Result{Digest: b.Digest, Error: "reload: " + err.Error(), At: time.Now()})
		return fmt.Errorf("bundle %s: reload refused, previous files restored: %w", short(b.Digest), err)
	}
	res := Result{Digest: b.Digest, OK: true, At: time.Now()}
	// The marker is written and the counters advanced before the result
	// is published, so a reader that sees the applied digest also sees
	// everything that belongs to it.
	if data, err := json.Marshal(res); err == nil {
		if root, err := os.OpenRoot(a.dir); err == nil {
			_ = writeFile(root, markerFile, data, 0o600)
			_ = root.Close()
		}
	}
	a.mu.Lock()
	a.st.Applied = res
	a.st.PendingDigest = ""
	a.st.LastError = ""
	a.st.Applies++
	a.mu.Unlock()
	a.log.Info("fleet bundle applied", "digest", short(b.Digest), "files", len(b.Files))
	return nil
}

func (a *Agent) report() error {
	st := NodeStatus{}
	if a.hooks.Status != nil {
		st = a.hooks.Status()
	}
	st.NodeID = a.cfg.NodeID
	st.Tags = a.cfg.Tags
	st.ReportedAt = time.Now().UTC()
	if st.Hostname == "" {
		st.Hostname, _ = os.Hostname()
	}
	a.mu.Lock()
	st.Applied = a.st.Applied
	st.Pending = a.st.PendingDigest
	a.mu.Unlock()
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.Timeout.D())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.nodeURL("/status"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xproxy-fleet-agent/1")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("report: controller answered HTTP %d", resp.StatusCode)
	}
	a.mu.Lock()
	a.st.Reports++
	a.st.LastReport = time.Now()
	a.mu.Unlock()
	return nil
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
