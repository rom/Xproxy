// Package accountguard is a built-in filter kind that protects the
// endpoints where accounts are attacked: login (credential stuffing,
// brute force, password spraying), registration (fake accounts,
// disposable addresses), password reset (enumeration, flooding),
// cart and checkout (inventory hoarding) and catalogue pages
// (scraping). It counts failures or requests per client address, per
// account, per address and account pair, distinct accounts per address
// and distinct addresses per account over a window, and answers with a
// ladder of progressive actions: log, delay, the browser challenge and
// a timed block. A campaign spread over many addresses, each below its
// own threshold, is detected on the endpoint as a whole.
//
//	filters:
//	  - name: accounts
//	    kind: account_guard
//	    options:
//	      endpoints:
//	        - name: login
//	          class: login
//	          paths: [/api/login]
//	          identity: {json: username, form: username}
//	          failure: {statuses: [401]}
//	        - name: signup
//	          class: register
//	          paths: [/api/register]
//	          identity: {json: email}
//	          disposable: challenge
//
// Each class carries a default ladder (see docs/CONFIG.md); `steps`
// replaces it. Identities are hashed before they are counted or
// logged. Blocks are shared with cluster peers.
package accountguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/filter"
)

// Reason is the deny reason of every block, the ban trigger category
// and the security event name.
const Reason = "account_abuse"

// EventKind is the cluster event kind blocks and campaigns travel under.
const EventKind = "account_guard"

// Identity says where the account identifier of a request lives.
type Identity struct {
	// Form is a field of an application/x-www-form-urlencoded body.
	Form string `json:"form"`
	// JSON is a field of a JSON body; dots descend into objects.
	JSON string `json:"json"`
	// Header is a request header.
	Header string `json:"header"`
	// Query is a query parameter.
	Query string `json:"query"`
}

// Outcome describes how a failed attempt is recognised in the response.
type Outcome struct {
	// Statuses are response statuses that mean failure. Default 401 and
	// 403 for the login class.
	Statuses []int `json:"statuses"`
	// BodyRegex marks a failure when it matches the response body of a
	// 2xx response (buffered up to max_bytes).
	BodyRegex string `json:"body_regex"`
	// LocationRegex marks a failure when it matches the Location header
	// of a redirect.
	LocationRegex string `json:"location_regex"`
	// MaxBytes bounds the body inspected. Default 65536.
	MaxBytes int64 `json:"max_bytes"`
	body     *regexp.Regexp
	location *regexp.Regexp
	statuses map[int]bool
}

// Step is one rung of the action ladder: it fires when any listed
// count reaches its threshold; the highest firing step acts.
type Step struct {
	// Action is log, delay, challenge, captcha or block.
	Action string `json:"action"`
	// Delay is how long a delay step holds the request (at most 10s).
	Delay string `json:"delay"`
	// Duration is how long a block lasts (default the window).
	Duration string `json:"duration"`
	// Thresholds per count; zero means not considered.
	IP         int `json:"ip"`
	Account    int `json:"account"`
	Pair       int `json:"pair"`
	IPAccounts int `json:"ip_accounts"`
	AccountIPs int `json:"account_ips"`
	IPPaths    int `json:"ip_paths"`
	// Device and DeviceAccounts count per device identifier from the
	// challenge cookie (events, and distinct accounts per device); a
	// client without a cookie has no device and these never fire.
	Device         int `json:"device"`
	DeviceAccounts int `json:"device_accounts"`
	delay          time.Duration
	duration       time.Duration
}

// Distributed detects a campaign on the endpoint as a whole.
type Distributed struct {
	// IPs is the number of distinct addresses producing events in the
	// window; Events the number of events. Both must be reached.
	IPs    int `json:"ips"`
	Events int `json:"events"`
	// Action applies to every request of the endpoint while the
	// campaign lasts: challenge (default), captcha or block.
	Action string `json:"action"`
	// Duration is how long the campaign state lasts. Default the window.
	Duration string `json:"duration"`
	duration time.Duration
}

// Endpoint is one protected endpoint.
type Endpoint struct {
	Name string `json:"name"`
	// Class is login, register, reset, cart, scrape or custom.
	Class string `json:"class"`
	// Paths match the request path exactly, or as a prefix when they
	// end in *.
	Paths []string `json:"paths"`
	// Methods default per class (POST for login, register, reset and
	// cart; GET for scrape; any for custom).
	Methods []string `json:"methods"`
	// Count is failures (events are failed attempts, recognised in the
	// response) or requests. Default failures for login, requests
	// otherwise.
	Count    string   `json:"count"`
	Identity Identity `json:"identity"`
	Failure  *Outcome `json:"failure"`
	// Window is the counting window. Default 10m.
	Window string `json:"window"`
	Steps  []Step `json:"steps"`
	// Distributed enables campaign detection; on by default for login.
	Distributed *Distributed `json:"distributed"`
	// Disposable is what happens to a registration with an address on
	// a disposable e-mail domain: off (default), log, challenge, captcha
	// or block.
	Disposable string `json:"disposable"`
	// Automation is what happens to a client whose challenge cookie
	// carries automation markers (WebDriver and the like): off
	// (default), log, challenge, captcha or block.
	Automation string `json:"automation"`
	window     time.Duration
	methods    map[string]bool
	exact      map[string]bool
	prefixes   []string
	failures   bool
	table      *table
}

// Config is the options schema.
type Config struct {
	Endpoints []Endpoint `json:"endpoints"`
	// BlockStatus answers a blocked request. Default 429.
	BlockStatus int `json:"block_status"`
	// MaxBodyBytes bounds the request body buffered to read an identity.
	// Default 65536.
	MaxBodyBytes int64 `json:"max_body_bytes"`
	// MaxDelayed bounds requests held in delay steps at once; beyond it
	// the delay is skipped. Default 256.
	MaxDelayed int `json:"max_delayed"`
	// DisposableDomains extend the built-in list.
	DisposableDomains []string `json:"disposable_domains"`
}

const (
	maxDelay     = 10 * time.Second
	maxEntries   = 65536
	maxDistinct  = 64
	maxPaths     = 256
	maxCampaign  = 8192
	hashLen      = 16
	defaultBytes = 64 << 10
)

var classes = map[string]bool{"login": true, "register": true, "reset": true, "cart": true, "scrape": true, "custom": true}

// defaultSteps is the ladder of each class over a ten minute window.
func defaultSteps(class string) []Step {
	switch class {
	// A count keyed on the account (account, account_ips) belongs to the
	// person being attacked, not to the attacker: anyone can type someone
	// else's name. Those counts raise the ladder as far as a challenge, so
	// the real owner can still prove themselves and get in, but they never
	// reach a block by default. Blocks key on what the attacker owns: the
	// address, the address/account pair and the device.
	case "login":
		return []Step{
			{Action: "delay", Delay: "2s", IP: 5, Account: 3, Pair: 3},
			{Action: "challenge", IP: 15, Account: 5, Pair: 5, IPAccounts: 10, AccountIPs: 5, DeviceAccounts: 10},
			{Action: "block", Duration: "15m", IP: 50, Pair: 10, IPAccounts: 30, Device: 50, DeviceAccounts: 30},
		}
	case "register":
		return []Step{
			{Action: "delay", Delay: "2s", IP: 2},
			{Action: "challenge", IP: 3, Account: 2, Device: 3},
			{Action: "block", Duration: "1h", IP: 10, Device: 10},
		}
	case "reset":
		return []Step{
			{Action: "delay", Delay: "2s", IP: 3, Account: 2},
			{Action: "challenge", IP: 5, Account: 3, Device: 5},
			{Action: "block", Duration: "1h", IP: 20, Device: 20},
		}
	case "cart":
		return []Step{
			{Action: "delay", Delay: "1s", IP: 30, Account: 30, Device: 30},
			{Action: "challenge", IP: 60, Account: 60, Device: 60},
			{Action: "block", Duration: "30m", IP: 150, Device: 150},
		}
	case "scrape":
		return []Step{
			{Action: "delay", Delay: "1s", IP: 200, IPPaths: 100},
			{Action: "challenge", IP: 400, IPPaths: 200},
			{Action: "block", Duration: "1h", IP: 1000},
		}
	}
	return nil
}

func parseDur(field, s string, def, minimum, maximum time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < minimum || d > maximum {
		return 0, fmt.Errorf("%s: must be a duration between %s and %s", field, minimum, maximum)
	}
	return d, nil
}

func (e *Endpoint) compile(p string) error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(p+"."+format, a...)) }
	if e.Name == "" || len(e.Name) > 64 {
		fail("name: required, at most 64 characters")
	}
	if e.Class == "" {
		e.Class = "custom"
	}
	if !classes[e.Class] {
		fail("class: must be login, register, reset, cart, scrape or custom")
	}
	if len(e.Paths) == 0 {
		fail("paths: at least one path")
	}
	e.exact = map[string]bool{}
	for i, path := range e.Paths {
		switch {
		case !strings.HasPrefix(path, "/"):
			fail("paths[%d]: must start with /", i)
		case strings.HasSuffix(path, "*"):
			e.prefixes = append(e.prefixes, strings.TrimSuffix(path, "*"))
		default:
			e.exact[path] = true
		}
	}
	if len(e.Methods) == 0 {
		switch e.Class {
		case "login", "register", "reset", "cart":
			e.Methods = []string{"POST"}
		case "scrape":
			e.Methods = []string{"GET"}
		}
	}
	e.methods = map[string]bool{}
	for _, m := range e.Methods {
		e.methods[strings.ToUpper(m)] = true
	}
	switch e.Count {
	case "":
		e.failures = e.Class == "login"
	case "failures":
		e.failures = true
	case "requests":
	default:
		fail("count: must be failures or requests")
	}
	if e.failures {
		if e.Failure == nil {
			e.Failure = &Outcome{}
		}
		f := e.Failure
		if len(f.Statuses) == 0 && f.BodyRegex == "" && f.LocationRegex == "" {
			f.Statuses = []int{401, 403}
		}
		f.statuses = map[int]bool{}
		for _, s := range f.Statuses {
			if s < 100 || s > 599 {
				fail("failure.statuses: %d is not a status", s)
			}
			f.statuses[s] = true
		}
		if f.MaxBytes == 0 {
			f.MaxBytes = defaultBytes
		}
		if f.MaxBytes < 1 || f.MaxBytes > 1<<20 {
			fail("failure.max_bytes: must be between 1 and 1048576")
		}
		var err error
		if f.BodyRegex != "" {
			if f.body, err = regexp.Compile(f.BodyRegex); err != nil {
				fail("failure.body_regex: %v", err)
			}
		}
		if f.LocationRegex != "" {
			if f.location, err = regexp.Compile(f.LocationRegex); err != nil {
				fail("failure.location_regex: %v", err)
			}
		}
	} else if e.Failure != nil {
		fail("failure: only with count failures")
	}
	if h := e.Identity.Header; h != "" && strings.ContainsAny(h, " :\r\n") {
		fail("identity.header: %q is not a header name", h)
	}
	if e.Identity == (Identity{}) && (e.Class == "login" || e.Class == "register" || e.Class == "reset") {
		fail("identity: a %s endpoint needs the account identifier (form, json, header or query)", e.Class)
	}
	var err error
	if e.window, err = parseDur("window", e.Window, 10*time.Minute, time.Minute, 24*time.Hour); err != nil {
		fail("%v", err)
	}
	if len(e.Steps) == 0 {
		e.Steps = defaultSteps(e.Class)
	}
	if len(e.Steps) == 0 || len(e.Steps) > 8 {
		fail("steps: between 1 and 8 steps (the %s class has no defaults)", e.Class)
	}
	for i := range e.Steps {
		s := &e.Steps[i]
		sp := fmt.Sprintf("steps[%d]", i)
		switch s.Action {
		case "log", "delay", "challenge", "captcha", "block":
		default:
			fail("%s.action: must be log, delay, challenge, captcha or block", sp)
		}
		if s.delay, err = parseDur(sp+".delay", s.Delay, time.Second, 10*time.Millisecond, maxDelay); err != nil {
			fail("%v", err)
		}
		if s.duration, err = parseDur(sp+".duration", s.Duration, e.window, time.Second, 7*24*time.Hour); err != nil {
			fail("%v", err)
		}
		if s.IP <= 0 && s.Account <= 0 && s.Pair <= 0 && s.IPAccounts <= 0 && s.AccountIPs <= 0 && s.IPPaths <= 0 && s.Device <= 0 && s.DeviceAccounts <= 0 {
			fail("%s: at least one threshold (ip, account, pair, ip_accounts, account_ips, ip_paths, device, device_accounts)", sp)
		}
		for name, v := range map[string]int{"ip": s.IP, "account": s.Account, "pair": s.Pair, "ip_accounts": s.IPAccounts, "account_ips": s.AccountIPs, "ip_paths": s.IPPaths, "device": s.Device, "device_accounts": s.DeviceAccounts} {
			if v < 0 || v > 1_000_000 {
				fail("%s.%s: must be between 0 and 1000000", sp, name)
			}
		}
	}
	if e.Distributed == nil && e.Class == "login" {
		e.Distributed = &Distributed{IPs: 50, Events: 200}
	}
	if d := e.Distributed; d != nil {
		if d.IPs < 2 || d.IPs > maxCampaign {
			fail("distributed.ips: must be between 2 and %d", maxCampaign)
		}
		if d.Events < d.IPs || d.Events > 10_000_000 {
			fail("distributed.events: must be at least ips and at most 10000000")
		}
		if d.Action == "" {
			d.Action = "challenge"
		}
		if d.Action != "challenge" && d.Action != "captcha" && d.Action != "block" {
			fail("distributed.action: must be challenge, captcha or block")
		}
		if d.duration, err = parseDur("distributed.duration", d.Duration, e.window, time.Minute, 24*time.Hour); err != nil {
			fail("%v", err)
		}
	}
	switch e.Disposable {
	case "", "off", "log", "challenge", "captcha", "block":
	default:
		fail("disposable: must be off, log, challenge, captcha or block")
	}
	if e.Disposable != "" && e.Disposable != "off" && e.Identity == (Identity{}) {
		fail("disposable: needs an identity")
	}
	switch e.Automation {
	case "", "off", "log", "challenge", "captcha", "block":
	default:
		fail("automation: must be off, log, challenge, captcha or block")
	}
	return errors.Join(errs...)
}

func parse(opts filter.Options) (*Config, error) {
	c := Config{}
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if len(c.Endpoints) == 0 || len(c.Endpoints) > 64 {
		errs = append(errs, errors.New("endpoints: between 1 and 64 endpoints"))
	}
	names := map[string]bool{}
	for i := range c.Endpoints {
		e := &c.Endpoints[i]
		if err := e.compile(fmt.Sprintf("endpoints[%d]", i)); err != nil {
			errs = append(errs, err)
		}
		if names[e.Name] {
			errs = append(errs, fmt.Errorf("endpoints[%d].name: duplicate %q", i, e.Name))
		}
		names[e.Name] = true
	}
	if c.BlockStatus == 0 {
		c.BlockStatus = http.StatusTooManyRequests
	}
	if c.BlockStatus < 400 || c.BlockStatus > 599 {
		errs = append(errs, errors.New("block_status: must be a 4xx or 5xx status"))
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaultBytes
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 8<<20 {
		errs = append(errs, errors.New("max_body_bytes: must be between 1 and 8388608"))
	}
	if c.MaxDelayed == 0 {
		c.MaxDelayed = 256
	}
	if c.MaxDelayed < 1 || c.MaxDelayed > 100000 {
		errs = append(errs, errors.New("max_delayed: must be between 1 and 100000"))
	}
	for i, d := range c.DisposableDomains {
		if d == "" || strings.ContainsAny(d, " @/") || d != strings.ToLower(d) {
			errs = append(errs, fmt.Errorf("disposable_domains[%d]: %q is not a lower case domain", i, d))
		}
	}
	return &c, errors.Join(errs...)
}

// entry is the state of one key (an address, an account or a pair).
type entry struct {
	start        time.Time // window start
	updated      time.Time
	n            int
	distinct     map[string]struct{} // accounts of an address, addresses of an account
	paths        map[string]struct{}
	blockedUntil time.Time
	blockedBy    string
}

// table is the state of one endpoint.
type table struct {
	mu       sync.Mutex
	ips      map[string]*entry
	accounts map[string]*entry
	pairs    map[string]*entry
	devices  map[string]*entry
	// campaign detection
	cStart        time.Time
	cEvents       int
	cIPs          map[string]struct{}
	campaignUntil time.Time
	full          bound.Notice
}

func newTable() *table {
	return &table{ips: map[string]*entry{}, accounts: map[string]*entry{}, pairs: map[string]*entry{}, devices: map[string]*entry{}, cIPs: map[string]struct{}{}}
}

type guard struct {
	name       string
	cfg        *Config
	disposable map[string]bool
	events     filter.Events
	log        *slog.Logger
	now        func() time.Time
	delaying   atomic.Int64
	skipped    bound.Notice
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(ctx context.Context, info *filter.Info) filter.Instance {
	return &instance{g: g, ctx: ctx, info: *info}
}

// counts are the numbers one request is judged by.
type counts struct {
	ip, account, pair, ipAccounts, accountIPs, ipPaths, device, deviceAccounts int
}

func (c counts) String() string {
	s := fmt.Sprintf("ip:%d account:%d pair:%d ip_accounts:%d account_ips:%d ip_paths:%d", c.ip, c.account, c.pair, c.ipAccounts, c.accountIPs, c.ipPaths)
	if c.device > 0 {
		s += fmt.Sprintf(" device:%d device_accounts:%d", c.device, c.deviceAccounts)
	}
	return s
}

// reached reports whether the step fires on the counts.
func (s *Step) reached(c counts) (string, bool) {
	switch {
	case s.IP > 0 && c.ip >= s.IP:
		return "ip", true
	case s.Account > 0 && c.account >= s.Account:
		return "account", true
	case s.Pair > 0 && c.pair >= s.Pair:
		return "pair", true
	case s.IPAccounts > 0 && c.ipAccounts >= s.IPAccounts:
		return "ip_accounts", true
	case s.AccountIPs > 0 && c.accountIPs >= s.AccountIPs:
		return "account_ips", true
	case s.IPPaths > 0 && c.ipPaths >= s.IPPaths:
		return "ip_paths", true
	case s.Device > 0 && c.device >= s.Device:
		return "device", true
	case s.DeviceAccounts > 0 && c.deviceAccounts >= s.DeviceAccounts:
		return "device_accounts", true
	}
	return "", false
}

type instance struct {
	g        *guard
	ctx      context.Context
	info     filter.Info
	ep       *Endpoint
	ip       string
	hash     string
	device   string
	action   string
	by       string
	counts   counts
	campaign bool
	outcome  string
}

func (g *guard) match(path, method string) *Endpoint {
	for i := range g.cfg.Endpoints {
		e := &g.cfg.Endpoints[i]
		if len(e.methods) > 0 && !e.methods[method] {
			continue
		}
		if e.exact[path] {
			return e
		}
		for _, p := range e.prefixes {
			if strings.HasPrefix(path, p) {
				return e
			}
		}
	}
	return nil
}

func hashIdentity(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])[:hashLen]
}

// identity extracts and normalises the account identifier, buffering
// and replaying the body when it lives there.
func (in *instance) identity(r *http.Request) string {
	id := in.ep.Identity
	if id.Header != "" {
		if v := r.Header.Get(id.Header); v != "" {
			return normalise(v)
		}
	}
	if id.Query != "" {
		if v := r.URL.Query().Get(id.Query); v != "" {
			return normalise(v)
		}
	}
	if (id.Form == "" && id.JSON == "") || r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return ""
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if (mt == "application/x-www-form-urlencoded" && id.Form == "") || (strings.HasSuffix(mt, "json") && id.JSON == "") || (mt != "application/x-www-form-urlencoded" && !strings.HasSuffix(mt, "json")) {
		return ""
	}
	limit := in.g.cfg.MaxBodyBytes
	if r.ContentLength > limit {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(strings.NewReader(string(data)), r.Body), r.Body}
		return ""
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(data)))
	if mt == "application/x-www-form-urlencoded" {
		vals, err := url.ParseQuery(string(data))
		if err != nil {
			return ""
		}
		return normalise(vals.Get(id.Form))
	}
	var doc any
	if json.Unmarshal(data, &doc) != nil {
		return ""
	}
	cur := doc
	for _, part := range strings.Split(id.JSON, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[part]
	}
	switch v := cur.(type) {
	case string:
		return normalise(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func normalise(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	in.ep = g.match(in.info.Path, r.Method)
	if in.ep == nil {
		return filter.Continue
	}
	ep := in.ep
	defer func() {
		if in.action != "" {
			countAction(ep.Class, in.action)
		}
	}()
	in.ip = in.info.ClientIP.String()
	in.device = in.info.DeviceID
	id := in.identity(r)
	if id != "" {
		in.hash = hashIdentity(id)
	}
	now := g.now()
	t := ep.table
	t.mu.Lock()
	blocked, by, until := t.blocked(now, in.ip, in.hash, in.device)
	if !blocked && !ep.failures {
		t.event(now, ep, in.ip, in.hash, in.device, in.info.Path)
		g.checkCampaign(now, ep)
	}
	in.counts = t.counts(now, in.ip, in.hash, in.device, ep.window)
	in.campaign = ep.Distributed != nil && now.Before(t.campaignUntil)
	t.mu.Unlock()
	if blocked {
		in.action, in.by, in.outcome = "block", by, "blocked"
		return in.deny(ep.Name+":blocked:"+by+":until "+until.UTC().Format(time.RFC3339), "block")
	}
	// Disposable registration addresses.
	if ep.Disposable != "" && ep.Disposable != "off" && id != "" && g.disposableAddress(id) {
		in.by = "disposable_email"
		counters.disposable.Add(1)
		switch ep.Disposable {
		case "block":
			in.action = "block"
			return in.deny(ep.Name+":disposable_email", "block")
		case "challenge", "captcha":
			in.action = ep.Disposable
			if !in.verified(ep.Disposable) {
				return in.deny(ep.Name+":disposable_email", ep.Disposable)
			}
		default:
			in.action = "log"
		}
	}
	// Automation markers from the challenge cookie.
	if ep.Automation != "" && ep.Automation != "off" && len(in.info.Automation) > 0 {
		in.by = "automation"
		counters.automation.Add(1)
		switch ep.Automation {
		case "block":
			in.action = "block"
			return in.deny(ep.Name+":automation:"+strings.Join(in.info.Automation, "+"), "block")
		case "challenge", "captcha":
			in.action = ep.Automation
			if !in.verified(ep.Automation) {
				return in.deny(ep.Name+":automation:"+strings.Join(in.info.Automation, "+"), ep.Automation)
			}
		default:
			if in.action == "" {
				in.action = "log"
			}
		}
	}
	// The ladder.
	var step *Step
	for i := range ep.Steps {
		if by, ok := ep.Steps[i].reached(in.counts); ok {
			step, in.by = &ep.Steps[i], by
		}
	}
	action := ""
	if step != nil {
		action = step.Action
	}
	campaignActs := in.campaign && rank[ep.Distributed.Action] > rank[action]
	if campaignActs {
		action, in.by = ep.Distributed.Action, "campaign"
	}
	if action == "" {
		return filter.Continue
	}
	if rank[action] > rank[in.action] {
		in.action = action
	}
	switch action {
	case "log":
	case "delay":
		in.delay(step.delay)
	case "challenge", "captcha":
		if !in.verified(action) {
			return in.deny(ep.Name+":"+action+":"+in.by, action)
		}
	case "block":
		d := ep.window
		if step != nil && step.Action == "block" {
			d = step.duration
		}
		if !campaignActs {
			// A campaign blocks by presence, not per key.
			t.mu.Lock()
			key := t.block(now, in.by, in.ip, in.hash, in.device, d, ep.window)
			t.mu.Unlock()
			g.publish(ep.Name, in.by, key, now.Add(d))
		}
		return in.deny(ep.Name+":block:"+in.by, "block")
	}
	return filter.Continue
}

// rank orders actions by severity.
var rank = map[string]int{"": 0, "log": 1, "delay": 2, "challenge": 3, "captcha": 4, "block": 5}

// verified reports whether the client already holds the tier an action
// asks for.
func (in *instance) verified(action string) bool {
	if action == "captcha" {
		return in.info.CaptchaVerified
	}
	return in.info.ChallengeVerified
}

// delay holds the request, bounded in time and in concurrent holders.
func (in *instance) delay(d time.Duration) {
	g := in.g
	if g.delaying.Add(1) > int64(g.cfg.MaxDelayed) {
		g.delaying.Add(-1)
		g.skipped.Hit(g.log, "account guard delay slots exhausted; delays skipped", "filter", g.name, "max", g.cfg.MaxDelayed)
		return
	}
	defer g.delaying.Add(-1)
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-in.ctx.Done():
	}
}

func (in *instance) deny(detail, action string) filter.Verdict {
	status := in.g.cfg.BlockStatus
	challenge := action == "challenge" || action == "captcha"
	if challenge {
		status = http.StatusForbidden
	}
	return filter.Verdict{Deny: true, Challenge: challenge, Captcha: action == "captcha", Status: status, Reason: Reason, Detail: detail,
		Headers: map[string]string{"Cache-Control": "no-store"}, Attrs: in.attrs()}
}

func (in *instance) attrs() []any {
	out := []any{"account_endpoint", in.ep.Name, "account_action", in.action, "account_by", in.by, "account_counts", in.counts.String()}
	if in.hash != "" {
		out = append(out, "account_hash", in.hash)
	}
	if in.device != "" {
		out = append(out, "account_device", in.device)
	}
	if in.campaign {
		out = append(out, "account_campaign")
	}
	if in.outcome != "" {
		out = append(out, "account_outcome", in.outcome)
	}
	return out
}

// Response recognises failed attempts on endpoints counting failures.
func (in *instance) Response(resp *http.Response) filter.Verdict {
	ep := in.ep
	if ep == nil || !ep.failures {
		return filter.Continue
	}
	f := ep.Failure
	failed := f.statuses[resp.StatusCode]
	if !failed && f.location != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		failed = f.location.MatchString(resp.Header.Get("Location"))
	}
	if !failed && f.body != nil && resp.StatusCode < 300 && resp.Body != nil && (resp.ContentLength < 0 || resp.ContentLength <= f.MaxBytes) {
		data, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
		if err == nil && int64(len(data)) <= f.MaxBytes {
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(strings.NewReader(string(data)))
			failed = f.body.Match(data)
		} else {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(strings.NewReader(string(data)), resp.Body), resp.Body}
		}
	}
	now := in.g.now()
	t := ep.table
	t.mu.Lock()
	if failed {
		in.outcome = "failure"
		t.event(now, ep, in.ip, in.hash, in.device, in.info.Path)
		in.g.checkCampaign(now, ep)
	} else if resp.StatusCode < 400 {
		in.outcome = "success"
		// A successful login clears the account's failures; the address
		// keeps its history.
		if in.hash != "" {
			if e := t.accounts[in.hash]; e != nil {
				e.n = 0
			}
			if e := t.pairs[in.ip+"|"+in.hash]; e != nil {
				e.n = 0
			}
		}
	}
	in.counts = t.counts(now, in.ip, in.hash, in.device, ep.window)
	t.mu.Unlock()
	return filter.Continue
}

func (in *instance) End() []any {
	if in.ep == nil {
		return nil
	}
	if in.action == "" {
		in.action = "none"
	}
	return in.attrs()
}

// get returns the entry of key in m, created if missing and reset when
// its window has passed;
// caller holds the lock.
func (t *table) get(m map[string]*entry, key string, now time.Time, window time.Duration) *entry {
	e := m[key]
	if e == nil {
		if len(m) >= maxEntries {
			t.full.Hit(nil, "account guard table full; the oldest entries are evicted", "table", "account_guard", "max", maxEntries)
			evict(m, now, window)
		}
		e = &entry{start: now}
		m[key] = e
	}
	if now.Sub(e.start) > window {
		e.start, e.n, e.distinct, e.paths = now, 0, nil, nil
	}
	e.updated = now
	return e
}

func evict(m map[string]*entry, now time.Time, window time.Duration) {
	type kv struct {
		k  string
		at time.Time
	}
	all := make([]kv, 0, len(m))
	for k, e := range m {
		if now.Sub(e.updated) > window && e.blockedUntil.Before(now) {
			delete(m, k)
			continue
		}
		all = append(all, kv{k, e.updated})
	}
	if len(m) < maxEntries {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, e := range all[:len(all)/4] {
		delete(m, e.k)
	}
}

func add(set *map[string]struct{}, v string, limit int) {
	if *set == nil {
		*set = map[string]struct{}{}
	}
	if len(*set) < limit {
		(*set)[v] = struct{}{}
	}
}

// event records one counted event; caller holds the lock.
func (t *table) event(now time.Time, ep *Endpoint, ip, hash, device, path string) {
	counters.events.Add(1)
	w := ep.window
	ie := t.get(t.ips, ip, now, w)
	ie.n++
	add(&ie.paths, path, maxPaths)
	if hash != "" {
		add(&ie.distinct, hash, maxDistinct)
		ae := t.get(t.accounts, hash, now, w)
		ae.n++
		add(&ae.distinct, ip, maxDistinct)
		t.get(t.pairs, ip+"|"+hash, now, w).n++
	}
	if device != "" {
		de := t.get(t.devices, device, now, w)
		de.n++
		if hash != "" {
			add(&de.distinct, hash, maxDistinct)
		}
	}
	if ep.Distributed != nil {
		if now.Sub(t.cStart) > w {
			t.cStart, t.cEvents, t.cIPs = now, 0, map[string]struct{}{}
		}
		t.cEvents++
		if len(t.cIPs) < maxCampaign {
			t.cIPs[ip] = struct{}{}
		}
	}
}

// counts reads the current numbers without creating entries; caller
// holds the lock.
func (t *table) counts(now time.Time, ip, hash, device string, w time.Duration) counts {
	var c counts
	live := func(e *entry, window time.Duration) *entry {
		if e == nil || now.Sub(e.start) > window {
			return nil
		}
		return e
	}
	if e := live(t.ips[ip], w); e != nil {
		c.ip, c.ipAccounts, c.ipPaths = e.n, len(e.distinct), len(e.paths)
	}
	if hash != "" {
		if e := live(t.accounts[hash], w); e != nil {
			c.account, c.accountIPs = e.n, len(e.distinct)
		}
		if e := live(t.pairs[ip+"|"+hash], w); e != nil {
			c.pair = e.n
		}
	}
	if device != "" {
		if e := live(t.devices[device], w); e != nil {
			c.device, c.deviceAccounts = e.n, len(e.distinct)
		}
	}
	return c
}

// blocked reports an active block on the address, the account or the
// pair; caller holds the lock.
func (t *table) blocked(now time.Time, ip, hash, device string) (bool, string, time.Time) {
	check := func(e *entry) (bool, string, time.Time) {
		if e != nil && now.Before(e.blockedUntil) {
			return true, e.blockedBy, e.blockedUntil
		}
		return false, "", time.Time{}
	}
	if ok, by, until := check(t.ips[ip]); ok {
		return ok, by, until
	}
	if hash != "" {
		if ok, by, until := check(t.accounts[hash]); ok {
			return ok, by, until
		}
		if ok, by, until := check(t.pairs[ip+"|"+hash]); ok {
			return ok, by, until
		}
	}
	if device != "" {
		if ok, by, until := check(t.devices[device]); ok {
			return ok, by, until
		}
	}
	return false, "", time.Time{}
}

// block marks the key behind a reached threshold and returns the
// cluster key (kind|key); caller holds the lock.
func (t *table) block(now time.Time, by, ip, hash, device string, d, window time.Duration) string {
	m, kind, key := t.ips, "ip", ip
	switch by {
	case "account", "account_ips":
		if hash != "" {
			m, kind, key = t.accounts, "account", hash
		}
	case "pair":
		if hash != "" {
			m, kind, key = t.pairs, "pair", ip+"|"+hash
		}
	case "device", "device_accounts":
		if device != "" {
			m, kind, key = t.devices, "device", device
		}
	}
	e := t.get(m, key, now, window)
	if until := now.Add(d); until.After(e.blockedUntil) {
		e.blockedUntil, e.blockedBy = until, by
	}
	counters.blocks.Add(1)
	return kind + "|" + key
}

// checkCampaign starts the campaign state when the endpoint's totals
// reach the distributed thresholds; caller holds the table lock.
func (g *guard) checkCampaign(now time.Time, ep *Endpoint) {
	t := ep.table
	d := ep.Distributed
	if d == nil || now.Before(t.campaignUntil) || t.cEvents < d.Events || len(t.cIPs) < d.IPs {
		return
	}
	t.campaignUntil = now.Add(d.duration)
	counters.campaigns.Add(1)
	g.publish(ep.Name, "campaign", "campaign", t.campaignUntil)
	if g.log != nil {
		g.log.Warn("account guard: distributed campaign detected", "filter", g.name, "endpoint", ep.Name, "events", t.cEvents, "ips", len(t.cIPs), "until", t.campaignUntil)
	}
}

// publish shares a block or a campaign with cluster peers.
func (g *guard) publish(endpoint, by, key string, until time.Time) {
	if g.events == nil {
		return
	}
	g.events.Publish(filter.Event{Kind: EventKind, Key: g.name + "|" + endpoint + "|" + by + "|" + key, Until: until})
}

// receive applies a peer's block or campaign.
func (g *guard) receive(e filter.Event) {
	parts := strings.SplitN(e.Key, "|", 4)
	if len(parts) != 4 || parts[0] != g.name {
		return
	}
	var ep *Endpoint
	for i := range g.cfg.Endpoints {
		if g.cfg.Endpoints[i].Name == parts[1] {
			ep = &g.cfg.Endpoints[i]
		}
	}
	if ep == nil {
		return
	}
	now := g.now()
	t := ep.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if parts[2] == "campaign" {
		if ep.Distributed != nil && e.Until.After(t.campaignUntil) {
			t.campaignUntil = e.Until
		}
		return
	}
	kind, key, ok := strings.Cut(parts[3], "|")
	if !ok || key == "" {
		return
	}
	var m map[string]*entry
	switch kind {
	case "ip":
		m = t.ips
	case "account":
		m = t.accounts
	case "pair":
		m = t.pairs
	case "device":
		m = t.devices
	default:
		return
	}
	en := t.get(m, key, now, ep.window)
	if e.Until.After(en.blockedUntil) {
		en.blockedUntil, en.blockedBy = e.Until, parts[2]
	}
}

// disposableAddress reports an e-mail identity on a disposable domain.
func (g *guard) disposableAddress(id string) bool {
	at := strings.LastIndexByte(id, '@')
	if at < 0 {
		return false
	}
	domain := id[at+1:]
	for {
		if g.disposable[domain] {
			return true
		}
		dot := strings.IndexByte(domain, '.')
		if dot < 0 || strings.IndexByte(domain[dot+1:], '.') < 0 {
			return false
		}
		domain = domain[dot+1:]
	}
}

// DisposableDomains is the built-in list of throwaway e-mail providers.
var DisposableDomains = []string{
	"mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "sharklasers.com", "10minutemail.com",
	"10minutemail.net", "temp-mail.org", "tempmail.com", "tempmail.net", "throwawaymail.com", "yopmail.com", "yopmail.fr",
	"trashmail.com", "trashmail.net", "dispostable.com", "getnada.com", "maildrop.cc", "mailnesia.com", "fakeinbox.com",
	"mohmal.com", "emailondeck.com", "mintemail.com", "tempr.email", "discard.email", "spamgourmet.com", "mytemp.email",
	"burnermail.io", "tempinbox.com", "mailcatch.com", "spam4.me", "grr.la", "guerrillamailblock.com", "pokemail.net",
	"anonbox.net", "tmpmail.org", "tmpmail.net", "temp-mail.io", "moakt.com", "inboxkitten.com", "harakirimail.com",
	"33mail.com", "mail-temp.com", "luxusmail.org", "crazymailing.com", "emailfake.com", "generator.email", "1secmail.com",
	"1secmail.net", "1secmail.org", "dropmail.me", "mailsac.com", "tempmailo.com", "minuteinbox.com", "mail7.io",
}

func newGuard(name string, opts filter.Options, env filter.Env) (*guard, error) {
	cfg, err := parse(opts)
	if err != nil {
		return nil, err
	}
	g := &guard{name: name, cfg: cfg, events: env.Events, now: time.Now, disposable: map[string]bool{}}
	g.log = env.Log
	for _, d := range DisposableDomains {
		g.disposable[d] = true
	}
	for _, d := range cfg.DisposableDomains {
		g.disposable[d] = true
	}
	for i := range cfg.Endpoints {
		cfg.Endpoints[i].table = newTable()
	}
	if g.events != nil {
		g.events.Subscribe(EventKind, g.receive)
	}
	register(g)
	return g, nil
}

func init() {
	filter.Register(filter.Kind{
		Name:        "account_guard",
		Description: "credential stuffing, brute force, registration, reset, hoarding and scraping protection with progressive delay, challenge and block actions per address, account and pair, and detection of campaigns spread over many addresses",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			return newGuard(name, opts, env)
		},
	})
}
