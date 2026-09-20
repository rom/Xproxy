package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/bound"
)

// Controller serves bundles and collects status. Its directory holds
// common/ (files every node gets), nodes/<id>/ (a node's own files,
// overriding common ones) and status/ (the last report per node, kept
// across restarts). A scan every Scan interval rebuilds the bundles;
// a node whose files no longer parse keeps its last good bundle and the
// error shows in the node list.
type Controller struct {
	dir  string
	scan time.Duration
	log  *slog.Logger
	// requireName demands that the client certificate name equals the
	// node id in the path.
	requireName bool
	// nameMap is the explicit exception list: node id to the certificate
	// name that may act for it. It exists so a deployment whose
	// certificate names and node ids differ does not have to reach for
	// -any-name, which turns the binding off for every node at once.
	nameMap map[string]string
	// mapped and anyName make the exceptions audible: an authorisation
	// that only succeeded through the map, and one that only succeeded
	// because the binding is off, are counted and warned about.
	mapped  bound.Notice
	anyName bound.Notice

	mu      sync.Mutex
	bundles map[string]*assignment
	nodes   map[string]*nodeRecord
	changed chan struct{}
	scans   uint64
	lastErr string
}

// assignment is one node's bundle state.
type assignment struct {
	bundle  *Bundle
	err     string
	scanned time.Time
}

type nodeRecord struct {
	Status   NodeStatus `json:"status"`
	LastSeen time.Time  `json:"last_seen"`
	Remote   string     `json:"remote,omitempty"`
	CertName string     `json:"cert_name,omitempty"`
}

var nodeIDRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62})$`)

// New creates a controller over dir.
func New(dir string, scan time.Duration, requireName bool, nameMap map[string]string, log *slog.Logger) (*Controller, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for _, sub := range []string{"common", "nodes", "status"} {
		if err := os.MkdirAll(filepath.Join(abs, sub), 0o750); err != nil {
			return nil, err
		}
	}
	if scan <= 0 {
		scan = 2 * time.Second
	}
	c := &Controller{dir: abs, scan: scan, log: log, requireName: requireName, nameMap: nameMap,
		bundles: map[string]*assignment{}, nodes: map[string]*nodeRecord{}, changed: make(chan struct{})}
	if !requireName {
		log.Warn("fleet: certificate names are not bound to node ids (-any-name): any certificate this CA issued can fetch any node's bundle and report as any node; use -name-map instead")
	}
	c.loadStatus()
	c.Scan()
	return c, nil
}

// Dir returns the controller directory.
func (c *Controller) Dir() string { return c.dir }

// loadStatus restores the last reports.
func (c *Controller) loadStatus() {
	entries, err := os.ReadDir(filepath.Join(c.dir, "status"))
	if err != nil {
		return
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !nodeIDRE.MatchString(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.dir, "status", e.Name())) //nolint:gosec // controller directory
		if err != nil {
			continue
		}
		var rec nodeRecord
		if json.Unmarshal(data, &rec) == nil && rec.Status.NodeID == id {
			c.nodes[id] = &rec
		}
	}
}

// Run scans until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(c.scan)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Scan()
		}
	}
}

// Scan rebuilds every node's bundle from the directory and wakes the
// pollers of nodes whose digest changed.
func (c *Controller) Scan() {
	entries, err := os.ReadDir(filepath.Join(c.dir, "nodes"))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scans++
	if err != nil {
		c.lastErr = err.Error()
		return
	}
	c.lastErr = ""
	seen := map[string]bool{}
	changed := false
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() || !nodeIDRE.MatchString(e.Name()) {
			continue
		}
		id := e.Name()
		seen[id] = true
		as := c.bundles[id]
		if as == nil {
			as = &assignment{}
			c.bundles[id] = as
			changed = true
		}
		b, err := Read(filepath.Join(c.dir, "common"), filepath.Join(c.dir, "nodes", id))
		if err == nil {
			err = b.Validate()
		}
		as.scanned = now
		if err != nil {
			if as.err != err.Error() {
				c.log.Warn("fleet bundle invalid; last good bundle kept", "node", id, "err", err.Error())
			}
			as.err = err.Error()
			continue
		}
		as.err = ""
		if as.bundle == nil || as.bundle.Digest != b.Digest {
			as.bundle = b
			changed = true
			c.log.Info("fleet bundle updated", "node", id, "digest", short(b.Digest), "files", len(b.Files))
		}
	}
	for id := range c.bundles {
		if !seen[id] {
			delete(c.bundles, id)
			changed = true
		}
	}
	if changed {
		close(c.changed)
		c.changed = make(chan struct{})
	}
}

// Assignment returns a node's bundle (nil when none) and the scan error.
func (c *Controller) Assignment(id string) (*Bundle, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	as := c.bundles[id]
	if as == nil {
		return nil, ""
	}
	return as.bundle, as.err
}

// NodeView is one row of the node list.
type NodeView struct {
	NodeID   string    `json:"node_id"`
	Assigned bool      `json:"assigned"`
	Digest   string    `json:"digest,omitempty"`
	Files    int       `json:"files,omitempty"`
	ScanErr  string    `json:"scan_error,omitempty"`
	Seen     bool      `json:"seen"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Stale is true when the last report is older than three intervals
	// of the report period the node announced (or five minutes).
	Stale    bool       `json:"stale"`
	InSync   bool       `json:"in_sync"`
	Status   NodeStatus `json:"status,omitzero"`
	Remote   string     `json:"remote,omitempty"`
	CertName string     `json:"cert_name,omitempty"`
}

// Overview is the controller's own status.
type Overview struct {
	Dir       string     `json:"dir"`
	Scans     uint64     `json:"scans"`
	ScanError string     `json:"scan_error,omitempty"`
	Nodes     []NodeView `json:"nodes"`
}

// Nodes lists every assigned or reporting node.
func (c *Controller) Nodes() Overview {
	c.mu.Lock()
	defer c.mu.Unlock()
	ov := Overview{Dir: c.dir, Scans: c.scans, ScanError: c.lastErr, Nodes: []NodeView{}}
	ids := map[string]bool{}
	for id := range c.bundles {
		ids[id] = true
	}
	for id := range c.nodes {
		ids[id] = true
	}
	now := time.Now()
	for id := range ids {
		v := NodeView{NodeID: id}
		if as := c.bundles[id]; as != nil {
			v.ScanErr = as.err
			if as.bundle != nil {
				v.Assigned, v.Digest, v.Files = true, as.bundle.Digest, len(as.bundle.Files)
			}
		}
		if rec := c.nodes[id]; rec != nil {
			v.Seen, v.LastSeen, v.Status, v.Remote, v.CertName = true, rec.LastSeen, rec.Status, rec.Remote, rec.CertName
			v.Stale = now.Sub(rec.LastSeen) > 5*time.Minute
			v.InSync = v.Assigned && rec.Status.Applied.OK && rec.Status.Applied.Digest == v.Digest
		}
		ov.Nodes = append(ov.Nodes, v)
	}
	sort.Slice(ov.Nodes, func(i, j int) bool { return ov.Nodes[i].NodeID < ov.Nodes[j].NodeID })
	return ov
}

// record stores a node report and persists it.
func (c *Controller) record(id string, st NodeStatus, remote, certName string) {
	rec := &nodeRecord{Status: st, LastSeen: time.Now(), Remote: remote, CertName: certName}
	c.mu.Lock()
	c.nodes[id] = rec
	c.mu.Unlock()
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if root, err := os.OpenRoot(filepath.Join(c.dir, "status")); err == nil {
		if err := writeFile(root, id+".json", data, 0o640); err != nil {
			c.log.Warn("fleet status write failed", "node", id, "err", err.Error())
		}
		_ = root.Close()
	}
}

// NodeHandler serves the agents: GET config (long poll) and POST status.
// It expects to run behind ServerTLS so that the peer certificate is
// present; the certificate name must equal the node id when required.
func (c *Controller) NodeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/fleet/nodes/{id}/config", func(w http.ResponseWriter, r *http.Request) {
		id, ok := c.authorise(w, r)
		if !ok {
			return
		}
		wait := 30 * time.Second
		if s := r.URL.Query().Get("wait"); s != "" {
			if d, err := time.ParseDuration(s); err == nil && d > 0 {
				wait = min(d, 2*time.Minute)
			}
		}
		have := r.URL.Query().Get("digest")
		deadline := time.NewTimer(wait)
		defer deadline.Stop()
		for {
			c.mu.Lock()
			as := c.bundles[id]
			ch := c.changed
			var b *Bundle
			if as != nil {
				b = as.bundle
			}
			c.mu.Unlock()
			if as == nil {
				http.Error(w, "no bundle assigned to this node", http.StatusNotFound)
				return
			}
			if b != nil && b.Digest != have {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("ETag", `"`+b.Digest+`"`)
				_ = json.NewEncoder(w).Encode(b)
				return
			}
			select {
			case <-ch:
			case <-deadline.C:
				w.WriteHeader(http.StatusNotModified)
				return
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("POST /v1/fleet/nodes/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id, ok := c.authorise(w, r)
		if !ok {
			return
		}
		var st NodeStatus
		if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&st); err != nil {
			http.Error(w, "bad status: "+err.Error(), http.StatusBadRequest)
			return
		}
		if st.NodeID != id {
			http.Error(w, "node_id does not match the path", http.StatusBadRequest)
			return
		}
		if st.ReportedAt.IsZero() {
			st.ReportedAt = time.Now().UTC()
		}
		c.record(id, st, r.RemoteAddr, peerName(r))
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// authorise checks the node id and, when required, the certificate name.
func (c *Controller) authorise(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !nodeIDRE.MatchString(id) {
		http.Error(w, "bad node id", http.StatusBadRequest)
		return "", false
	}
	if !c.requireName {
		c.anyName.Hit(c.log, "fleet: node authorised without a certificate name binding (-any-name)", "node", id)
		return id, true
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return "", false
	}
	leaf := r.TLS.PeerCertificates[0]
	if certMatches(leaf, id) {
		return id, true
	}
	if want, ok := c.nameMap[id]; ok && certMatches(leaf, want) {
		c.mapped.Hit(c.log, "fleet: node authorised through the name map", "node", id, "certificate", want)
		return id, true
	}
	http.Error(w, "certificate name does not match the node id", http.StatusForbidden)
	return "", false
}

func certMatches(leaf *x509.Certificate, id string) bool {
	if strings.EqualFold(leaf.Subject.CommonName, id) {
		return true
	}
	for _, d := range leaf.DNSNames {
		if strings.EqualFold(d, id) {
			return true
		}
	}
	return false
}

func peerName(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// AdminHandler serves operators (a local socket): the node list, one
// node, and a node's bundle metadata.
func (c *Controller) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/fleet/nodes", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, c.Nodes()) })
	mux.HandleFunc("GET /v1/fleet/nodes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		for _, n := range c.Nodes().Nodes {
			if n.NodeID == id {
				writeJSON(w, n)
				return
			}
		}
		http.Error(w, "unknown node", http.StatusNotFound)
	})
	mux.HandleFunc("GET /v1/fleet/nodes/{id}/bundle", func(w http.ResponseWriter, r *http.Request) {
		b, scanErr := c.Assignment(r.PathValue("id"))
		if b == nil {
			http.Error(w, "no bundle: "+scanErr, http.StatusNotFound)
			return
		}
		type meta struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Size int    `json:"size"`
		}
		out := struct {
			Digest    string    `json:"digest"`
			Generated time.Time `json:"generated"`
			ScanError string    `json:"scan_error,omitempty"`
			Files     []meta    `json:"files"`
		}{Digest: b.Digest, Generated: b.Generated, ScanError: scanErr}
		for _, f := range b.Files {
			out.Files = append(out.Files, meta{Path: f.Path, Mode: fmt.Sprintf("%04o", f.Mode), Size: len(f.Content)})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /v1/fleet/scan", func(w http.ResponseWriter, _ *http.Request) {
		c.Scan()
		writeJSON(w, c.Nodes())
	})
	return mux
}

// ServerTLS builds the mutual TLS configuration of the node listener.
func ServerTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("fleet certificate: %w", err)
	}
	caPEM, err := os.ReadFile(caFile) //nolint:gosec // operator supplied path
	if err != nil {
		return nil, fmt.Errorf("fleet CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("fleet CA file contains no certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}}, nil
}

// ValidateDir reads and validates every node bundle under dir and
// returns the problems by node id (empty when all parse).
func ValidateDir(dir string) (map[string]string, []string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "nodes"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%s has no nodes directory", dir)
		}
		return nil, nil, err
	}
	problems := map[string]string{}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		ids = append(ids, id)
		if !nodeIDRE.MatchString(id) {
			problems[id] = "not a valid node id"
			continue
		}
		b, err := Read(filepath.Join(dir, "common"), filepath.Join(dir, "nodes", id))
		if err == nil {
			err = b.Validate()
		}
		if err != nil {
			problems[id] = err.Error()
		}
	}
	sort.Strings(ids)
	return problems, ids, nil
}
