package capture

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// Redacted stands in for a header value the configuration keeps out of
// the file. It is a fixed string rather than the value's length, which
// would leak what it is a length of.
const Redacted = "REDACTED"

// Exchange is one request and its response as the proxy saw them, ready
// to be written as a flow. The caller fills what it has; a field it
// leaves empty is left out of the synthesised conversation rather than
// guessed at.
type Exchange struct {
	Start          time.Time
	Client, Server netip.AddrPort
	RequestID      string
	// Kind and Listener are the listener this arrived on and the protocol
	// it speaks. They are what a rule selects on for a session that has
	// no host, route, method or path -- which is every protocol but HTTP.
	Kind, Listener string
	// User is the login the protocol named, where it named one. HTTP
	// carries identity in its headers and leaves this empty.
	User   string
	Route  string
	Host   string
	Method string
	Path   string
	Status int
	Denied string
	// Request and Response are the serialised head and, when bodies are
	// captured, the bytes that followed it.
	Request  []byte
	Response []byte
	// RequestTruncated and ResponseTruncated say that the bound cut the
	// body, so a reader knows the stream is short rather than that the
	// client stopped.
	RequestTruncated, ResponseTruncated bool
}

// subject is what a rule decides about.
//
// An HTTP exchange is identified by what was asked for; a relayed session has
// none of that -- there is no host, route, method or path before a byte is read --
// and is identified by the listener it arrived on, the protocol that listener
// speaks, and where it came from. One struct rather than two means the selectors
// they share (the client networks, denied, the sample, the bound) are written
// once and behave the same either way.
type subject struct {
	kind, listener string
	host, route    string
	method, path   string
	client         netip.Addr
	status         int
	reason         string
	// session marks a subject with no HTTP identity, so a rule that
	// selects on one is not quietly matching every session as well.
	session bool
}

// Session is one relayed or gated session: the bytes each way as the proxy
// parsed them, which is the view a capture on the wire cannot produce when the
// proxy terminates TLS.
//
// The two directions are written as one blob each rather than interleaved, the
// same way an HTTP request and response are. A session's order is recoverable
// from the protocol; what a reader needs is the bytes.
type Session struct {
	Start          time.Time
	Client, Server netip.AddrPort
	// Kind is the listener kind ("mysql"), Listener its configured name.
	Kind, Listener string
	// ID is the session identifier the access log and the session table
	// use, so a capture can be found from a log line and the other way.
	ID string
	// User is the login the protocol named, where it named one.
	User string
	// Denied is the refusal reason, empty when the session was allowed.
	Denied string
	// ToServer and ToClient are the bytes each way, bounded by max_body.
	ToServer, ToClient                   []byte
	ToServerTruncated, ToClientTruncated bool
}

// Stats is what the management views report.
type Stats struct {
	Enabled       bool       `json:"enabled"`
	Active        bool       `json:"active"`
	Until         time.Time  `json:"until,omitempty"`
	File          string     `json:"file,omitempty"`
	Rules         []RuleStat `json:"rules,omitempty"`
	Captured      uint64     `json:"captured"`
	Skipped       uint64     `json:"skipped"`
	Truncated     uint64     `json:"truncated"`
	DroppedFull   uint64     `json:"dropped_full"`
	WriteFailures uint64     `json:"write_failures"`
	Bytes         uint64     `json:"bytes"`
	Files         int        `json:"files"`
}

// RuleStat reports what one rule has taken, so an operator can see
// which selector is answering and which is exhausted.
type RuleStat struct {
	Name     string `json:"name"`
	Captured uint64 `json:"captured"`
	Limit    uint64 `json:"limit,omitempty"`
}

// rule is one compiled selector set. A rule with no selectors matches
// every exchange, which is how "capture everything" is written.
type rule struct {
	name     string
	hosts    []string
	suffixes []string
	routes   map[string]bool
	methods  map[string]bool
	prefixes []string
	clients  []netip.Prefix
	statuses map[int]bool
	classes  map[int]bool
	reasons  map[string]bool
	// listeners and kinds select a session, which has no other identity.
	listeners map[string]bool
	kinds     map[string]bool
	// denied selects by whether the proxy refused at all, independent of
	// the reason: "capture what I turned away" is the common ask.
	denied  bool
	percent int
	limit   uint64
	taken   atomic.Uint64
}

// Capturer decides which exchanges to write and writes them. The zero
// value is not usable; New builds one from the configuration.
type Capturer struct {
	cfg   config.Capture
	rules []*rule

	mu      sync.Mutex
	w       *writer
	bw      *bufio.Writer
	file    *os.File
	name    string
	written int64
	files   []string

	// active is the runtime switch. The configuration decides whether
	// the subsystem exists at all; this decides whether it is recording
	// right now, so an operator can turn it on for one reproduction and
	// off again without a reload.
	active atomic.Bool
	until  atomic.Int64

	captured, skipped, truncated, droppedFull, writeFailures atomic.Uint64
	bytes                                                    atomic.Uint64
}

// New compiles the configuration. A disabled section returns nil, which
// every method below tolerates, so the caller needs no nil checks.
func New(c *config.Capture) (*Capturer, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	cp := &Capturer{cfg: *c}
	for i := range c.Rules {
		r, err := compileRule(&c.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("capture.rules[%d] (%s): %w", i, c.Rules[i].Name, err)
		}
		cp.rules = append(cp.rules, r)
	}
	if len(cp.rules) == 0 {
		// No rules at all means every exchange, which is what an
		// operator who wrote only a directory meant.
		cp.rules = []*rule{{name: "all", percent: 100}}
	}
	cp.active.Store(c.StartActive)
	return cp, nil
}

func compileRule(c *config.CaptureRule) (*rule, error) {
	r := &rule{name: c.Name, percent: c.Percent, limit: uint64(c.MaxFlows), denied: c.Denied} //nolint:gosec // validated non-negative
	if r.percent <= 0 {
		r.percent = 100
	}
	for _, h := range c.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if strings.HasPrefix(h, "*.") {
			r.suffixes = append(r.suffixes, h[1:])
			continue
		}
		r.hosts = append(r.hosts, h)
	}
	if len(c.Routes) > 0 {
		r.routes = map[string]bool{}
		for _, n := range c.Routes {
			r.routes[n] = true
		}
	}
	if len(c.Methods) > 0 {
		r.methods = map[string]bool{}
		for _, m := range c.Methods {
			r.methods[strings.ToUpper(m)] = true
		}
	}
	r.prefixes = append(r.prefixes, c.Paths...)
	for _, cidr := range c.ClientCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("client_cidrs: %q is not a CIDR", cidr)
		}
		r.clients = append(r.clients, p.Masked())
	}
	for _, s := range c.Statuses {
		switch {
		case s >= 100 && s <= 599:
			if r.statuses == nil {
				r.statuses = map[int]bool{}
			}
			r.statuses[s] = true
		case s >= 1 && s <= 5:
			if r.classes == nil {
				r.classes = map[int]bool{}
			}
			r.classes[s] = true
		default:
			return nil, fmt.Errorf("statuses: %d is neither a status nor a class (1 to 5)", s)
		}
	}
	if len(c.Reasons) > 0 {
		r.reasons = map[string]bool{}
		for _, n := range c.Reasons {
			r.reasons[n] = true
		}
	}
	if len(c.Listeners) > 0 {
		r.listeners = map[string]bool{}
		for _, n := range c.Listeners {
			r.listeners[strings.TrimSpace(n)] = true
		}
	}
	if len(c.Kinds) > 0 {
		r.kinds = map[string]bool{}
		for _, n := range c.Kinds {
			r.kinds[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}
	return r, nil
}

// Active reports whether the capturer is recording right now.
func (c *Capturer) Active() bool {
	if c == nil || !c.active.Load() {
		return false
	}
	if until := c.until.Load(); until != 0 && time.Now().UnixNano() > until {
		// The window closed. Turning it off here rather than on a timer
		// keeps the decision on the request path, where it is read.
		c.active.Store(false)
		c.until.Store(0)
		c.closeFile()
		return false
	}
	return true
}

// CarryFrom takes over the recording state of a capturer this one
// replaces, so a reload during a reproduction does not silently stop
// the capture — and does not give an indefinite one a deadline it never
// had. The files are separate: the new capturer opens its own.
func (c *Capturer) CarryFrom(old *Capturer) {
	if c == nil || old == nil || !old.Active() {
		return
	}
	c.until.Store(old.until.Load())
	c.active.Store(true)
}

// SetActive turns recording on or off. A zero duration records until it
// is turned off; a positive one closes the window on its own, so a
// capture started during an incident cannot be left running for a month.
func (c *Capturer) SetActive(on bool, d time.Duration) {
	if c == nil {
		return
	}
	if !on {
		c.active.Store(false)
		c.until.Store(0)
		c.closeFile()
		return
	}
	if d <= 0 || d > c.cfg.MaxDuration.D() {
		d = c.cfg.MaxDuration.D()
	}
	c.until.Store(time.Now().Add(d).UnixNano())
	c.active.Store(true)
}

// Wants reports whether an exchange with these attributes could still
// be captured. The caller asks before it starts buffering bodies, so a
// request nobody wants costs nothing; the selectors on the answer are
// not decided here, because there is no answer yet.
func (c *Capturer) Wants(listener, host, route, method, path string, client netip.Addr) bool {
	if !c.Active() {
		return false
	}
	s := subject{kind: "http", listener: listener, host: host, route: route,
		method: method, path: path, client: client}
	if c.match(s, true) == nil {
		c.skipped.Add(1)
		return false
	}
	return true
}

// WantsSession is Wants for a protocol that has no host, route, method or path:
// the listener it arrived on, what that listener speaks, and where it came from
// are everything that is true of a session before a byte is read.
//
// A nil Capturer is the usual case -- no capture section at all -- so it answers
// rather than panicking, which is what lets a kind ask without first checking.
func (c *Capturer) WantsSession(kind, listener string, client netip.Addr) bool {
	if c == nil || !c.Active() {
		return false
	}
	if c.match(subject{kind: kind, listener: listener, client: client, session: true}, true) == nil {
		c.skipped.Add(1)
		return false
	}
	return true
}

// match returns the first rule that admits the exchange. Before the
// answer is known, pre is set and the selectors that need one are left
// out rather than guessed at: a rule for "the 403s" has to hold the
// request until there is a status to compare.
func (c *Capturer) match(s subject, pre bool) *rule {
	for _, r := range c.rules {
		if r.selects(s, pre) {
			return r
		}
	}
	return nil
}

func (r *rule) selects(s subject, pre bool) bool {
	// The two selectors every subject can answer.
	if r.listeners != nil && !r.listeners[s.listener] {
		return false
	}
	if r.kinds != nil && !r.kinds[strings.ToLower(s.kind)] {
		return false
	}
	// A rule written about what was asked for -- a host, a route, a method, a
	// path -- is a rule about an HTTP exchange. A session has none of those,
	// and treating "no host" as "any host" would make such a rule capture
	// every session on the estate as well as the requests it was written for.
	if s.session && (r.routes != nil || r.methods != nil || len(r.hosts) > 0 ||
		len(r.suffixes) > 0 || len(r.prefixes) > 0 || r.statuses != nil || r.classes != nil) {
		return false
	}
	host, route, method, path := s.host, s.route, s.method, s.path
	client, status, reason := s.client, s.status, s.reason
	if r.routes != nil && !r.routes[route] {
		return false
	}
	if r.methods != nil && !r.methods[strings.ToUpper(method)] {
		return false
	}
	if len(r.hosts) > 0 || len(r.suffixes) > 0 {
		ok := false
		for _, h := range r.hosts {
			if h == host {
				ok = true
				break
			}
		}
		if !ok {
			for _, s := range r.suffixes {
				if strings.HasSuffix(host, s) && len(host) > len(s) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.prefixes) > 0 {
		ok := false
		for _, p := range r.prefixes {
			if strings.HasPrefix(path, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.clients) > 0 && !netutil.Contains(r.clients, client) {
		return false
	}
	// Selectors on the answer only apply once there is one.
	if pre {
		return true
	}
	if r.statuses != nil || r.classes != nil {
		if status == 0 {
			return false
		}
		if !r.statuses[status] && !r.classes[status/100] {
			return false
		}
	}
	if r.reasons != nil {
		if reason == "" {
			return false
		}
		// The access log joins a reason and its detail with a colon; a
		// rule names the reason.
		base, _, _ := strings.Cut(reason, ":")
		if !r.reasons[base] && !r.reasons[reason] {
			return false
		}
	}
	// A rule selecting refusals needs a reason, which exists only once
	// the exchange is over and only when the proxy refused it.
	if r.denied && reason == "" {
		return false
	}
	return true
}

// take charges a rule's own bound and its sampling. It is called once,
// when the exchange is about to be written.
func (r *rule) take() bool {
	if r.percent < 100 && rand.IntN(100) >= r.percent { //nolint:gosec // sampling, not a secret
		return false
	}
	if r.limit == 0 {
		r.taken.Add(1)
		return true
	}
	// Claim a slot without ever passing the bound, so the reported
	// count is the number written rather than the number attempted.
	for {
		n := r.taken.Load()
		if n >= r.limit {
			return false
		}
		if r.taken.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// Write records one exchange. Every refusal is counted rather than
// logged: a capture is a diagnostic, and one that fills the error log
// under load has made the problem worse.
func (c *Capturer) Write(e *Exchange) {
	if !c.Active() {
		return
	}
	kind := e.Kind
	if kind == "" {
		kind = "http"
	}
	r := c.match(subject{kind: kind, listener: e.Listener, host: e.Host, route: e.Route,
		method: e.Method, path: e.Path, client: e.Client.Addr(), status: e.Status,
		reason: e.Denied}, false)
	if r == nil {
		c.skipped.Add(1)
		return
	}
	if !r.take() {
		c.skipped.Add(1)
		return
	}
	if e.RequestTruncated || e.ResponseTruncated {
		c.truncated.Add(1)
	}
	if err := c.writeFlow(e); err != nil {
		c.writeFailures.Add(1)
		return
	}
	c.captured.Add(1)
}

func (c *Capturer) writeFlow(e *Exchange) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureFileLocked(); err != nil {
		return err
	}
	f := newFlow(e.Client, e.Server, comment(e))
	t := e.Start
	if t.IsZero() {
		t = time.Now()
	}
	if err := f.open(c.w, t); err != nil {
		return err
	}
	if err := f.send(c.w, t, true, e.Request); err != nil {
		return err
	}
	if err := f.send(c.w, t, false, e.Response); err != nil {
		return err
	}
	if err := f.close(c.w, t); err != nil {
		return err
	}
	// The counter is cumulative across files: it is exported as a
	// Prometheus counter, and one that fell back to zero on every
	// rotation would read as a restart.
	c.bytes.Add(uint64(max(c.w.written-c.written, 0))) //nolint:gosec // non-negative
	c.written = c.w.written
	if c.cfg.MaxFileBytes > 0 && c.written >= c.cfg.MaxFileBytes {
		c.rotateLocked()
	}
	return nil
}

// comment is the pcapng per-packet comment. It is what lets a frame in
// Wireshark and a line in the access log name each other.
func comment(e *Exchange) string {
	var b strings.Builder
	b.WriteString("request_id=")
	b.WriteString(sanitise(e.RequestID))
	// The protocol and the listener, for a capture that is not HTTP: a reader
	// opening the file months later has no access log beside it, and "which of
	// my twenty listeners was this" is the first question.
	if e.Kind != "" && e.Kind != "http" {
		b.WriteString(" kind=")
		b.WriteString(sanitise(e.Kind))
	}
	if e.Listener != "" {
		b.WriteString(" listener=")
		b.WriteString(sanitise(e.Listener))
	}
	if e.User != "" {
		b.WriteString(" user=")
		b.WriteString(sanitise(e.User))
	}
	if e.Route != "" {
		b.WriteString(" route=")
		b.WriteString(sanitise(e.Route))
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " status=%d", e.Status)
	}
	if e.Denied != "" {
		b.WriteString(" denied=")
		b.WriteString(sanitise(e.Denied))
	}
	if e.RequestTruncated {
		b.WriteString(" request=truncated")
	}
	if e.ResponseTruncated {
		b.WriteString(" response=truncated")
	}
	return b.String()
}

// sanitise keeps a comment to printable ASCII. Every value in it came
// from a request, and a capture file is opened by a person.
func sanitise(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e || s[i] == ' ' {
			out = append(out, '?')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// ensureFileLocked opens a file when there is none.
func (c *Capturer) ensureFileLocked() error {
	if c.file != nil {
		return nil
	}
	name := filepath.Join(c.cfg.Directory, fmt.Sprintf("%s-%s.pcapng",
		c.cfg.FilePrefix, time.Now().UTC().Format("20060102-150405.000")))
	// The file holds decrypted request and response bytes, so it is the
	// proxy user's alone from the moment it exists.
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // operator configured directory, proxy generated name
	if err != nil {
		return err
	}
	c.file, c.name = f, name
	c.bw = bufio.NewWriterSize(f, 64<<10)
	c.w = &writer{w: c.bw}
	c.written = 0
	snap := uint32(c.cfg.SnapLen) //nolint:gosec // validated positive
	if err := c.w.header(snap); err != nil {
		c.closeFileLocked()
		return err
	}
	c.files = append(c.files, name)
	c.pruneLocked()
	return nil
}

// rotateLocked closes the current file so the next write opens a new
// one, and removes the oldest beyond max_files.
func (c *Capturer) rotateLocked() {
	c.closeFileLocked()
	c.pruneLocked()
}

func (c *Capturer) pruneLocked() {
	if c.cfg.MaxFiles <= 0 {
		return
	}
	for len(c.files) > c.cfg.MaxFiles {
		oldest := c.files[0]
		c.files = c.files[1:]
		if oldest == c.name {
			c.closeFileLocked()
		}
		_ = os.Remove(oldest)
	}
}

func (c *Capturer) closeFile() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeFileLocked()
}

func (c *Capturer) closeFileLocked() {
	if c.file == nil {
		return
	}
	if c.bw != nil {
		_ = c.bw.Flush()
	}
	_ = c.file.Close()
	c.file, c.bw, c.w, c.name = nil, nil, nil, ""
}

// Flush writes what is buffered without closing the file, so a capture
// can be read while it is still running.
func (c *Capturer) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bw != nil {
		_ = c.bw.Flush()
	}
}

// Close ends the capture. It is safe to call more than once.
func (c *Capturer) Close() { c.closeFile() }

// Stats reports what the capturer has done.
func (c *Capturer) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	name, files := c.name, len(c.files)
	c.mu.Unlock()
	st := Stats{
		Enabled: true, Active: c.Active(), File: name, Files: files,
		Captured: c.captured.Load(), Skipped: c.skipped.Load(),
		Truncated: c.truncated.Load(), DroppedFull: c.droppedFull.Load(),
		WriteFailures: c.writeFailures.Load(), Bytes: c.bytes.Load(),
	}
	if until := c.until.Load(); until != 0 {
		st.Until = time.Unix(0, until)
	}
	for _, r := range c.rules {
		st.Rules = append(st.Rules, RuleStat{Name: r.name, Captured: r.taken.Load(), Limit: r.limit})
	}
	return st
}

// MaxBody is how much of each body the caller should keep, or 0 when
// bodies are not captured at all.
func (c *Capturer) MaxBody() int {
	if c == nil || !c.cfg.Bodies {
		return 0
	}
	return c.cfg.MaxBodyBytes
}

// Redact reports the header names whose values must not reach the file.
func (c *Capturer) Redact() []string {
	if c == nil {
		return nil
	}
	return c.cfg.Redact
}

// ErrNotEnabled is returned for a proxy with no capture section, so an
// operator is told to configure one rather than left wondering why
// nothing happened.
var ErrNotEnabled = errors.New("capture is not enabled")
