// Package apiinv keeps an inventory of the API endpoints the proxy
// actually serves: every proxied request is attributed to a host,
// method and path template (identifiers folded into "*", or the
// OpenAPI template when the route validates against a description),
// with first and last seen times, counts, status classes, the kinds of
// credentials clients present, media types and the API version in the
// path. From it the proxy reports shadow APIs (traffic to endpoints an
// OpenAPI description does not document), zombie APIs (documented
// endpoints nobody has called for a long time) and superseded versions
// (a v1 still in use next to a v2 of the same endpoint).
package apiinv

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
)

// Describer is what an OpenAPI validating filter exposes: whether a
// request matches a documented operation, and every operation it knows.
type Describer interface {
	// Documented returns the operation's path template when method and
	// path match a documented operation.
	Documented(method, path string) (template string, ok bool)
	// Operations lists the documented operations.
	Operations() []Operation
}

// Operation is one documented method and path template.
type Operation struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Config is the active setting.
type Config struct {
	Enabled      bool
	MaxEndpoints int
	ZombieAfter  time.Duration
	StateFile    string
	SaveInterval time.Duration
}

// Observation is one finished request.
type Observation struct {
	Host, Method, Path, Route string
	Status                    int
	Auth                      string
	RequestType, ResponseType string
	// Template overrides the heuristic path template (the documented
	// operation's template); Documented is unknown when the route has no
	// description, else whether the request matched one.
	Template   string
	Documented Tri
}

// Tri is a three valued flag.
type Tri int

// Tri values.
const (
	Unknown Tri = iota
	Yes
	No
)

const (
	shards        = 64
	maxSetEntries = 6
	defaultMax    = 10000
	// MaxMediaTypeBytes bounds strings retained for every inventory endpoint.
	// It is exported so protocol handlers can reject oversized values before
	// parsing them, while Observe enforces the bound at the storage boundary.
	MaxMediaTypeBytes = 256
)

type entry struct {
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Route     string    `json:"route"`
	Version   string    `json:"version,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Requests  uint64    `json:"requests"`
	Status    [4]uint64 `json:"status"`
	Auth      []string  `json:"auth,omitempty"`
	ReqTypes  []string  `json:"request_types,omitempty"`
	RespTypes []string  `json:"response_types,omitempty"`
	Docu      Tri       `json:"documented"`
}

type shard struct {
	mu      sync.Mutex
	entries map[string]*entry
}

// warnLogger is what the table needs from a logger.
type warnLogger interface{ Warn(string, ...any) }

// Table is the inventory; one lives for the process.
type Table struct {
	cfg     atomic.Pointer[Config]
	shards  [shards]shard
	count   atomic.Int64
	dropped bound.Notice
	// started and log are written by Configure and Reset — a reload and
	// a management call — and read on the report and save paths, so
	// they are atomics rather than plain fields: a word-sized read
	// racing a word-sized write is benign in practice and undefined
	// under the Go memory model.
	started atomic.Int64 // Unix nanoseconds
	log     atomic.Pointer[warnLogger]

	stop chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// New creates an empty table.
func New() *Table {
	t := &Table{stop: make(chan struct{})}
	t.started.Store(time.Now().UnixNano())
	for i := range t.shards {
		t.shards[i].entries = map[string]*entry{}
	}
	return t
}

// Configure applies a generation's settings; the first configuration
// with a state file loads it and starts the periodic save.
func (t *Table) Configure(c Config, log interface{ Warn(string, ...any) }) {
	if c.MaxEndpoints <= 0 {
		c.MaxEndpoints = defaultMax
	}
	prev := t.cfg.Load()
	t.cfg.Store(&c)
	if log != nil {
		wl := warnLogger(log)
		t.log.Store(&wl)
	}
	if c.Enabled && c.StateFile != "" && (prev == nil || prev.StateFile != c.StateFile) {
		if err := t.load(c.StateFile); err != nil && !errors.Is(err, os.ErrNotExist) && log != nil {
			log.Warn("api inventory state not loaded", "file", c.StateFile, "err", err.Error())
		}
	}
	if c.Enabled && c.StateFile != "" && prev == nil && c.SaveInterval > 0 {
		t.wg.Add(1)
		go t.saver(c.SaveInterval)
	}
}

func (t *Table) config() *Config {
	if c := t.cfg.Load(); c != nil {
		return c
	}
	return &Config{}
}

// Enabled reports whether observations are recorded.
func (t *Table) Enabled() bool { return t.config().Enabled }

func (t *Table) saver(interval time.Duration) {
	defer t.wg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tk.C:
			t.saveNow()
		}
	}
}

func (t *Table) saveNow() {
	c := t.config()
	if c.StateFile == "" {
		return
	}
	if err := t.Save(c.StateFile); err != nil {
		if wl := t.log.Load(); wl != nil {
			(*wl).Warn("api inventory state not saved", "file", c.StateFile, "err", err.Error())
		}
	}
}

// Stop ends the periodic save and writes the state a last time.
func (t *Table) Stop() {
	t.once.Do(func() { close(t.stop) })
	t.wg.Wait()
	t.saveNow()
}

var versionRE = regexp.MustCompile(`^v[0-9]{1,4}$`)

// versionOf returns the version segment of a path template and the
// template with it replaced by {v}.
func versionOf(path string) (string, string) {
	parts := strings.Split(path, "/")
	for i, seg := range parts {
		if versionRE.MatchString(strings.ToLower(seg)) {
			parts[i] = "{v}"
			return strings.ToLower(seg), strings.Join(parts, "/")
		}
	}
	return "", path
}

func key(host, method, path string) string { return host + "\x00" + method + "\x00" + path }

func shardOf(k string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k))
	return int(h.Sum32() % shards)
}

func addSet(set []string, v string) []string {
	if v == "" || len(v) > MaxMediaTypeBytes {
		return set
	}
	for _, s := range set {
		if s == v {
			return set
		}
	}
	if len(set) >= maxSetEntries {
		return set
	}
	return append(set, v)
}

// Observe records one request.
func (t *Table) Observe(o Observation, now time.Time) {
	c := t.config()
	if !c.Enabled || o.Method == "" || o.Path == "" {
		return
	}
	k := key(o.Host, o.Method, o.Path)
	sh := &t.shards[shardOf(k)]
	sh.mu.Lock()
	e := sh.entries[k]
	if e == nil {
		if t.count.Load() >= int64(c.MaxEndpoints) {
			sh.mu.Unlock()
			t.dropped.Hit(nil, "api inventory full; further endpoints are not recorded", "table", "api_inventory", "max", c.MaxEndpoints)
			return
		}
		e = &entry{Host: o.Host, Method: o.Method, Path: o.Path, Route: o.Route, FirstSeen: now}
		e.Version, _ = versionOf(o.Path)
		sh.entries[k] = e
		t.count.Add(1)
	}
	e.LastSeen = now
	e.Requests++
	if o.Status >= 200 && o.Status < 600 {
		e.Status[o.Status/100-2]++
	}
	e.Auth = addSet(e.Auth, o.Auth)
	e.ReqTypes = addSet(e.ReqTypes, o.RequestType)
	e.RespTypes = addSet(e.RespTypes, o.ResponseType)
	if o.Documented != Unknown {
		e.Docu = o.Documented
	}
	if o.Route != "" {
		e.Route = o.Route
	}
	sh.mu.Unlock()
}

// Endpoint is one inventory row.
type Endpoint struct {
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Route     string    `json:"route,omitempty"`
	Version   string    `json:"version,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Requests  uint64    `json:"requests"`
	Status2xx uint64    `json:"status_2xx"`
	Status3xx uint64    `json:"status_3xx"`
	Status4xx uint64    `json:"status_4xx"`
	Status5xx uint64    `json:"status_5xx"`
	Auth      []string  `json:"auth,omitempty"`
	ReqTypes  []string  `json:"request_types,omitempty"`
	RespTypes []string  `json:"response_types,omitempty"`
	// Documented is "yes", "no" or "" when the route has no description.
	Documented string `json:"documented,omitempty"`
	// Shadow marks traffic to an undocumented operation of a described
	// route; Zombie a documented operation without traffic for
	// zombie_after (or ever); Superseded a version with a newer one on
	// the same host and path.
	Shadow     bool `json:"shadow"`
	Zombie     bool `json:"zombie"`
	Superseded bool `json:"superseded"`
}

// Report is the management view.
type Report struct {
	Enabled      bool       `json:"enabled"`
	Since        time.Time  `json:"since"`
	Endpoints    int        `json:"endpoints"`
	MaxEndpoints int        `json:"max_endpoints"`
	Dropped      uint64     `json:"dropped"`
	Shadow       int        `json:"shadow"`
	Zombie       int        `json:"zombie"`
	Superseded   int        `json:"superseded"`
	ZombieAfter  string     `json:"zombie_after"`
	View         string     `json:"view"`
	Items        []Endpoint `json:"items"`
}

// Report builds the view: all, shadow, zombie, versions (endpoints with
// a version in the path), documented or undocumented, at most top
// items sorted by requests. docs maps route names to their documented
// operations, for zombie detection.
func (t *Table) Report(view string, top int, docs map[string][]Operation, now time.Time) Report {
	c := t.config()
	rep := Report{Enabled: c.Enabled, Since: time.Unix(0, t.started.Load()), MaxEndpoints: c.MaxEndpoints, Dropped: t.dropped.Total(), ZombieAfter: c.ZombieAfter.String(), View: view, Items: []Endpoint{}}
	var all []Endpoint
	seen := map[string]bool{} // route|method|path of observed documented endpoints
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for _, e := range sh.entries {
			ep := Endpoint{Host: e.Host, Method: e.Method, Path: e.Path, Route: e.Route, Version: e.Version, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
				Requests: e.Requests, Status2xx: e.Status[0], Status3xx: e.Status[1], Status4xx: e.Status[2], Status5xx: e.Status[3],
				Auth: append([]string(nil), e.Auth...), ReqTypes: append([]string(nil), e.ReqTypes...), RespTypes: append([]string(nil), e.RespTypes...)}
			switch e.Docu {
			case Yes:
				ep.Documented = "yes"
				seen[e.Route+"|"+e.Method+"|"+e.Path] = true
				if c.ZombieAfter > 0 && now.Sub(e.LastSeen) > c.ZombieAfter {
					ep.Zombie = true
				}
			case No:
				ep.Documented = "no"
				ep.Shadow = true
			}
			all = append(all, ep)
		}
		sh.mu.Unlock()
	}
	rep.Endpoints = len(all)
	// Documented operations never observed (since the table started, or
	// since the state file's oldest record) are zombies too.
	for route, ops := range docs {
		for _, op := range ops {
			if seen[route+"|"+op.Method+"|"+op.Path] {
				continue
			}
			ver, _ := versionOf(op.Path)
			all = append(all, Endpoint{Method: op.Method, Path: op.Path, Route: route, Version: ver, Documented: "yes", Zombie: true})
		}
	}
	// Superseded versions: a lower version next to a higher one for the
	// same host, method and versionless path.
	newest := map[string]int{}
	for _, ep := range all {
		if ep.Version == "" {
			continue
		}
		_, base := versionOf(ep.Path)
		n, _ := strconv.Atoi(ep.Version[1:])
		k := ep.Host + "|" + ep.Method + "|" + base
		if n > newest[k] {
			newest[k] = n
		}
	}
	for i := range all {
		ep := &all[i]
		if ep.Version == "" {
			continue
		}
		_, base := versionOf(ep.Path)
		n, _ := strconv.Atoi(ep.Version[1:])
		if n < newest[ep.Host+"|"+ep.Method+"|"+base] && ep.Requests > 0 {
			ep.Superseded = true
		}
	}
	for _, ep := range all {
		if ep.Shadow {
			rep.Shadow++
		}
		if ep.Zombie {
			rep.Zombie++
		}
		if ep.Superseded {
			rep.Superseded++
		}
		switch view {
		case "shadow":
			if !ep.Shadow {
				continue
			}
		case "zombie":
			if !ep.Zombie {
				continue
			}
		case "versions":
			if ep.Version == "" {
				continue
			}
		case "documented":
			if ep.Documented != "yes" {
				continue
			}
		case "undocumented":
			if ep.Documented == "yes" {
				continue
			}
		}
		rep.Items = append(rep.Items, ep)
	}
	sort.Slice(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Method < b.Method
	})
	if top > 0 && len(rep.Items) > top {
		rep.Items = rep.Items[:top]
	}
	return rep
}

// Reset empties the table.
func (t *Table) Reset() {
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		sh.entries = map[string]*entry{}
		sh.mu.Unlock()
	}
	t.count.Store(0)
	t.started.Store(time.Now().UnixNano())
}

type state struct {
	Started time.Time `json:"started"`
	Entries []*entry  `json:"entries"`
}

// Save writes the table to path atomically (mode 0600).
func (t *Table) Save(path string) error {
	st := state{Started: time.Unix(0, t.started.Load())}
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for _, e := range sh.entries {
			cp := *e
			st.Entries = append(st.Entries, &cp)
		}
		sh.mu.Unlock()
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// load merges a saved state into the table.
func (t *Table) load(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // validated configuration path
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if !st.Started.IsZero() && st.Started.UnixNano() < t.started.Load() {
		t.started.Store(st.Started.UnixNano())
	}
	limit := int64(t.config().MaxEndpoints)
	for _, e := range st.Entries {
		if e.Host == "" && e.Path == "" || e.Method == "" {
			continue
		}
		k := key(e.Host, e.Method, e.Path)
		sh := &t.shards[shardOf(k)]
		sh.mu.Lock()
		if _, ok := sh.entries[k]; !ok && t.count.Load() < limit {
			sh.entries[k] = e
			t.count.Add(1)
		}
		sh.mu.Unlock()
	}
	return nil
}
