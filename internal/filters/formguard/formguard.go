// Package formguard is a built-in filter kind that catches the two
// things a form-filling bot does and a person does not: it fills in
// every field it finds, including the one nobody can see, and it
// submits faster than anyone could have read the page.
//
//	filters:
//	  - name: signup-guard
//	    kind: form_guard
//	    options:
//	      fields: [contact_reason, website]   # must arrive empty or absent
//	      min_seconds: 2                      # after the form page was fetched
//	      max_seconds: 3600                   # and not from a page fetched yesterday
//	      form_paths: [/signup]               # GETs that count as fetching the form
//	      require_fetch: false                # deny a submission with no fetch on record
//	      methods: [POST, PUT]                # what counts as a submission
//	      max_body_bytes: 65536               # buffered and replayed
//	      status: 403
//	      reason: form_guard
//
// The hidden field is the classic: an input the stylesheet hides and
// `autocomplete="off"` keeps a password manager out of, with a name
// that sounds worth filling in. A person never sees it; a bot that
// walks the DOM fills it, and the filter has a signal with no false
// positives to trade away.
//
// The timing check needs no JavaScript and no cookie: the filter
// remembers when this client last fetched the form page and compares.
// A client with no fetch on record is allowed by default, because a
// form page can be cached, prerendered or served by another node; set
// require_fetch when the deployment makes that impossible.
package formguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// Config is the options schema.
type Config struct {
	Fields       []string `json:"fields"`
	MinSeconds   float64  `json:"min_seconds"`
	MaxSeconds   float64  `json:"max_seconds"`
	FormPaths    []string `json:"form_paths"`
	RequireFetch bool     `json:"require_fetch"`
	Methods      []string `json:"methods"`
	MaxBodyBytes int64    `json:"max_body_bytes"`
	MaxClients   int      `json:"max_clients"`
	Status       int      `json:"status"`
	Reason       string   `json:"reason"`
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if len(c.Fields) == 0 && c.MinSeconds == 0 && c.MaxSeconds == 0 {
		errs = append(errs, errors.New("fields, min_seconds or max_seconds must be set, or the filter checks nothing"))
	}
	for i, f := range c.Fields {
		if f == "" || len(f) > 128 || strings.ContainsAny(f, " \t\r\n") {
			errs = append(errs, fmt.Errorf("fields[%d]: %q is not a form field name", i, f))
		}
	}
	if c.MinSeconds < 0 || c.MinSeconds > 3600 {
		errs = append(errs, errors.New("min_seconds: must be between 0 and 3600"))
	}
	if c.MaxSeconds < 0 || c.MaxSeconds > 30*24*3600 {
		errs = append(errs, errors.New("max_seconds: must be between 0 and 2592000"))
	}
	if c.MaxSeconds > 0 && c.MinSeconds > c.MaxSeconds {
		errs = append(errs, errors.New("min_seconds: is greater than max_seconds"))
	}
	for i, p := range c.FormPaths {
		if !strings.HasPrefix(p, "/") {
			errs = append(errs, fmt.Errorf("form_paths[%d]: %q must start with /", i, p))
		}
	}
	if (c.MinSeconds > 0 || c.MaxSeconds > 0 || c.RequireFetch) && len(c.FormPaths) == 0 {
		errs = append(errs, errors.New("form_paths: required to time a submission; name the paths that serve the form"))
	}
	for i := range c.Methods {
		c.Methods[i] = strings.ToUpper(c.Methods[i])
		if c.Methods[i] != http.MethodPost && c.Methods[i] != http.MethodPut && c.Methods[i] != http.MethodPatch {
			errs = append(errs, fmt.Errorf("methods[%d]: %q is not a submission method", i, c.Methods[i]))
		}
	}
	if len(c.Methods) == 0 {
		c.Methods = []string{http.MethodPost}
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 64 << 10
	}
	if c.MaxBodyBytes < 1024 || c.MaxBodyBytes > 8<<20 {
		errs = append(errs, errors.New("max_body_bytes: must be between 1024 and 8 MiB"))
	}
	if c.MaxClients == 0 {
		c.MaxClients = 65536
	}
	if c.MaxClients < 128 || c.MaxClients > 1<<20 {
		errs = append(errs, errors.New("max_clients: must be between 128 and 1048576"))
	}
	if c.Status == 0 {
		c.Status = http.StatusForbidden
	}
	if c.Status < 400 || c.Status > 499 {
		errs = append(errs, fmt.Errorf("status: %d must be a 4xx code", c.Status))
	}
	return &c, errors.Join(errs...)
}

// fetches remembers when each client last fetched a form page. It is a
// bounded table: a client chooses how many addresses it arrives from,
// so the table sweeps the oldest half when it is full rather than
// growing on somebody else's say-so.
type fetches struct {
	mu   sync.Mutex
	max  int
	seen map[netip.Addr]time.Time
	now  func() time.Time
}

func newFetches(max int) *fetches {
	return &fetches{max: max, seen: make(map[netip.Addr]time.Time), now: time.Now}
}

func (f *fetches) put(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) >= f.max {
		f.evictLocked()
	}
	f.seen[ip] = f.now()
}

// evictLocked drops the older half by time. Dropping a fetch makes the
// timing check fall back to its "no record" behaviour, which is
// permissive by default: a full table must not start refusing people.
func (f *fetches) evictLocked() {
	cutoff := f.median()
	for k, v := range f.seen {
		if !v.After(cutoff) {
			delete(f.seen, k)
		}
	}
	// A table of identical timestamps would survive the sweep; clear it
	// rather than loop.
	if len(f.seen) >= f.max {
		clear(f.seen)
	}
}

// median is an approximation good enough to halve the table: the
// midpoint between the oldest and newest entries.
func (f *fetches) median() time.Time {
	var oldest, newest time.Time
	for _, v := range f.seen {
		if oldest.IsZero() || v.Before(oldest) {
			oldest = v
		}
		if v.After(newest) {
			newest = v
		}
	}
	return oldest.Add(newest.Sub(oldest) / 2)
}

func (f *fetches) get(ip netip.Addr) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.seen[ip]
	return t, ok
}

type guard struct {
	name    string
	cfg     *Config
	fetched *fetches
	methods map[string]bool
	paths   []string
	fields  []string
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{g: g, client: info.ClientIP}
}

type instance struct {
	g      *guard
	client netip.Addr
	attrs  []any
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	// The form page itself: remember when this client asked for it.
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && g.isFormPath(r.URL.Path) {
		g.fetched.put(in.client)
		return filter.Continue
	}
	if !g.methods[r.Method] {
		return filter.Continue
	}
	if v, done := in.checkTiming(); done {
		return v
	}
	return in.checkFields(r)
}

// checkTiming compares the submission against the fetch of the form.
func (in *instance) checkTiming() (filter.Verdict, bool) {
	g := in.g
	if g.cfg.MinSeconds == 0 && g.cfg.MaxSeconds == 0 && !g.cfg.RequireFetch {
		return filter.Continue, false
	}
	when, ok := g.fetched.get(in.client)
	if !ok {
		if g.cfg.RequireFetch {
			return in.deny("no_form_fetch"), true
		}
		// A form page can be cached, prerendered, or served by another
		// node. Not knowing is not evidence.
		return filter.Continue, false
	}
	elapsed := time.Since(when).Seconds()
	if g.cfg.MinSeconds > 0 && elapsed < g.cfg.MinSeconds {
		in.attrs = append(in.attrs, "form_seconds", elapsed)
		return in.deny("too_fast"), true
	}
	if g.cfg.MaxSeconds > 0 && elapsed > g.cfg.MaxSeconds {
		in.attrs = append(in.attrs, "form_seconds", elapsed)
		return in.deny("too_old"), true
	}
	return filter.Continue, false
}

// checkFields looks for the fields nobody can see. The body is
// buffered up to the bound and replayed, so the application receives
// exactly what the client sent.
func (in *instance) checkFields(r *http.Request) filter.Verdict {
	g := in.g
	if len(g.fields) == 0 || r.Body == nil || r.Body == http.NoBody {
		return filter.Continue
	}
	// A hidden field can also be smuggled in the query string of a
	// submission, so both are searched.
	if name := g.filled(r.URL.Query()); name != "" {
		return in.deny("field:" + name)
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		// Only the encoding a plain HTML form submits. A JSON API that
		// happens to share the route is none of this filter's business.
		return filter.Continue
	}
	if r.ContentLength > g.cfg.MaxBodyBytes {
		return filter.Continue
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, g.cfg.MaxBodyBytes+1))
	if err != nil {
		return filter.Continue
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if int64(len(data)) > g.cfg.MaxBodyBytes {
		// Past the bound: not inspected, and not refused for being
		// large — that is the body limit's job, not this filter's.
		return filter.Continue
	}
	values, err := url.ParseQuery(string(data))
	if err != nil {
		return filter.Continue
	}
	if name := g.filled(values); name != "" {
		return in.deny("field:" + name)
	}
	return filter.Continue
}

// filled returns the first guarded field that carries a value.
func (g *guard) filled(values url.Values) string {
	for _, f := range g.fields {
		for _, v := range values[f] {
			if strings.TrimSpace(v) != "" {
				return f
			}
		}
	}
	return ""
}

// isFormPath reports whether a GET of this path serves a form page. A
// configured path matches itself and anything below it, with or without
// the trailing slash, because the two spellings are the same page.
func (g *guard) isFormPath(path string) bool {
	for _, p := range g.paths {
		base := strings.TrimSuffix(p, "/")
		if path == base || strings.HasPrefix(path, base+"/") {
			return true
		}
	}
	return false
}

func (in *instance) deny(detail string) filter.Verdict {
	in.attrs = append(in.attrs, "form_guard", detail)
	return filter.Verdict{Deny: true, Status: in.g.cfg.Status, Reason: in.g.cfg.Reason, Detail: detail}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any { return in.attrs }

func init() {
	filter.Register(filter.Kind{
		Name:        "form_guard",
		Description: "Catch form bots with a hidden field and the time between the form and its submission.",
		BuffersBody: true,
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			if c.Reason == "" {
				c.Reason = name
			}
			g := &guard{name: name, cfg: c, fetched: newFetches(c.MaxClients),
				methods: map[string]bool{}, paths: c.FormPaths, fields: c.Fields}
			for _, m := range c.Methods {
				g.methods[m] = true
			}
			return g, nil
		},
	})
}
