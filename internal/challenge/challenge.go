// Package challenge implements the browser proof-of-work challenge
// (docs/AMR.md, AMR-023) and its optional CAPTCHA tier.
//
// An unverified client receives a 503 page with a signed nonce and a
// small script. The script finds a counter such that
// SHA-256(nonce ":" counter) has the configured number of leading zero
// bits, posts it back to the verification path, and receives a signed
// cookie that is optionally bound to the client address. The cost is paid
// by the client in CPU; the proxy pays one HMAC per page and one HMAC plus
// one SHA-256 per verification. Nonces are single use and expire.
//
// With a CAPTCHA provider configured, a verdict that asks for the CAPTCHA
// tier (or every page, in mode always) renders the provider's widget in
// place of the proof of work; the token is verified with the provider
// and the cookie records the higher tier. The script also derives a
// device identifier from stable browser properties, which the cookie
// carries for logs, filters and rate limits; it is client supplied and
// therefore advisory, but it cannot change without solving again.
package challenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/secret"
)

// Tiers of a verified cookie.
const (
	TierNone    = 0
	TierProof   = 1
	TierCaptcha = 2
	deviceLen   = 8
)

// Automation markers the challenge script reports, in bit order. The
// cookie carries them as one byte.
var Signals = []string{"webdriver", "driver_globals", "chromedriver", "headless_ua", "no_languages", "no_plugins", "zero_window"}

// Cookie is what a verified challenge cookie says about its client.
type Cookie struct {
	Tier   int
	Device string
	// Automation lists the markers the script observed when the
	// challenge was solved (a subset of Signals).
	Automation []string
}

func parseSignals(s string) byte {
	var b byte
	for _, name := range strings.Split(s, ",") {
		for i, known := range Signals {
			if name == known {
				b |= 1 << i
			}
		}
	}
	return b
}

func signalNames(b byte) []string {
	var out []string
	for i, name := range Signals {
		if b&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// Reserved paths served by the proxy on every host.
const (
	VerifyPath = "/.xproxy/challenge"
	ScriptPath = "/.xproxy/challenge.js"
	// nonceTTL bounds how long a page may take to be solved.
	nonceTTL = 10 * time.Minute
	macLen   = 16
	maxSeen  = 65536
)

//go:embed challenge.js
var script []byte

//go:embed page.html
var pageSrc string

var page = template.Must(template.New("challenge").Parse(pageSrc))

// Challenger issues and verifies challenges.
type Challenger struct {
	mu         sync.Mutex
	keys       [][]byte // primary first; every key verifies
	keyPath    string
	difficulty int
	ttl        time.Duration
	bindIP     bool
	bindJA4    bool
	// hostScoped binds a pass cookie to the host that issued it
	// (challenge.cookie_scope: host).
	hostScoped bool
	// hosts are the route host names, the allowlist the CAPTCHA
	// hostname check uses when challenge.captcha.hostnames is empty.
	hosts   map[string]bool
	cookie  string
	exempt  []netip.Prefix
	title   string
	captcha *captcha
	device  bool
	seen    map[[macLen]byte]int64 // nonce mac -> expiry unix
	now     func() time.Time
	full    bound.Notice

	Issued, Passed, Failed uint64
	CaptchaPassed          uint64
}

// New creates a challenger, loading or generating the key.
func New(cfg *config.Challenge) (*Challenger, error) {
	ring, err := secret.LoadOrCreate(cfg.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("challenge secret: %w", err)
	}
	c := &Challenger{keys: ring.All(), keyPath: cfg.SecretFile, seen: make(map[[macLen]byte]int64), now: time.Now}
	if cfg.Captcha != nil {
		cp, err := loadCaptcha(cfg.Captcha)
		if err != nil {
			return nil, err
		}
		c.captcha = cp
	}
	c.Reconfigure(cfg)
	return c, nil
}

// HasCaptcha reports whether a CAPTCHA tier is configured.
func (c *Challenger) HasCaptcha() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.captcha != nil
}

// Reconfigure applies settings and re-reads the secret file when one is
// configured, so a rotation (xproxyctl rotate-secret) takes effect on the
// next reload while cookies signed with the previous key stay valid. An
// unreadable file keeps the keys in memory.
// SetRouteHosts records the host names this proxy's routes are
// configured for. The CAPTCHA hostname check compares the hostname the
// provider reports against them (see captcha.hostnameOK); the request
// host is not an allowlist, because the client chooses it.
func (c *Challenger) SetRouteHosts(hosts []string) {
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if i := strings.IndexByte(h, ':'); i >= 0 && !strings.HasSuffix(h, "]") {
			h = h[:i]
		}
		if h != "" && !strings.ContainsRune(h, '*') {
			set[h] = true
		}
	}
	c.mu.Lock()
	c.hosts = set
	c.mu.Unlock()
}

func (c *Challenger) routeHosts() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hosts
}

func (c *Challenger) Reconfigure(cfg *config.Challenge) {
	var keys [][]byte
	if cfg.SecretFile != "" {
		if ring, err := secret.Load(cfg.SecretFile); err == nil {
			keys = ring.All()
		}
	}
	var cp *captcha
	if cfg.Captcha != nil {
		var err error
		if cp, err = loadCaptcha(cfg.Captcha); err != nil {
			slog.Warn("challenge: captcha not reconfigured", "error", err)
			c.mu.Lock()
			cp = c.captcha
			c.mu.Unlock()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if keys != nil {
		c.keys = keys
	}
	c.captcha = cp
	c.device = cfg.DevicesOn()
	c.keyPath = cfg.SecretFile
	c.difficulty = cfg.Difficulty
	c.ttl = cfg.TTL.D()
	c.bindIP = cfg.BindsIP()
	c.bindJA4 = cfg.BindsJA4()
	c.hostScoped = cfg.BindsHost()
	c.cookie = cfg.CookieName
	c.exempt = netutil.ParsePrefixes(cfg.ExemptCIDRs)
	c.title = cfg.Title
}

func macWith(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:macLen]
}

// mac signs with the primary key.
func (c *Challenger) mac(parts ...[]byte) []byte { return macWith(c.keys[0], parts...) }

// macOK accepts a signature by any key of the ring.
func (c *Challenger) macOK(sig []byte, parts ...[]byte) bool {
	ok := 0
	for _, k := range c.keys {
		ok |= subtle.ConstantTimeCompare(macWith(k, parts...), sig)
	}
	return ok == 1
}

func (c *Challenger) ipBytes(ip netip.Addr) []byte {
	if !c.bindIP {
		return nil
	}
	b := ip.Unmap().As16()
	return b[:]
}

// ja4CtxKey is the context key under which the proxy stores the client's
// JA4 fingerprint for cookie binding.
type ja4CtxKey struct{}

// WithJA4 attaches the client's JA4 fingerprint to ctx so that a
// bind_ja4 cookie's signature can cover it.
func WithJA4(ctx context.Context, ja4 string) context.Context {
	return context.WithValue(ctx, ja4CtxKey{}, ja4)
}

func ja4From(ctx context.Context) string {
	v, _ := ctx.Value(ja4CtxKey{}).(string)
	return v
}

// ja4Bytes is the JA4 contribution to a cookie's binding, or nil when
// bind_ja4 is off. When on it is always 8 bytes — a hash of the fingerprint,
// or zeros when none is available — so a fingerprinted client and an
// unfingerprinted one never share a valid cookie.
func (c *Challenger) ja4Bytes(r *http.Request) []byte {
	if !c.bindJA4 {
		return nil
	}
	var out [8]byte
	if ja4 := ja4From(r.Context()); ja4 != "" {
		sum := sha256.Sum256([]byte(ja4))
		copy(out[:], sum[:8])
	}
	return out[:]
}

// bind is the per-client value a cookie's MAC covers: the address (bind_ip)
// followed by the JA4 hash (bind_ja4), so a stolen cookie is refused from a
// different address or TLS client.
func (c *Challenger) bind(r *http.Request, ip netip.Addr) []byte {
	b := c.ipBytes(ip)
	if j := c.ja4Bytes(r); j != nil {
		b = append(append([]byte{}, b...), j...)
	}
	// With cookie_scope: host the pass covers the host that issued it.
	// The nonce is already host-bound, so without this a client can
	// solve the cheapest host's challenge and present the cookie to the
	// host that asked for the most work.
	if c.hostScoped {
		b = append(append([]byte{}, b...), hostKey(r.Host)...)
	}
	return b
}

// Exempt reports whether ip is never challenged.
func (c *Challenger) Exempt(ip netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return netutil.Contains(c.exempt, ip)
}

// Verified reports whether the request carries a valid challenge cookie
// of any tier.
func (c *Challenger) Verified(r *http.Request, ip netip.Addr) bool {
	tier, _ := c.Check(r, ip)
	return tier >= TierProof
}

// Check reads the challenge cookie: the tier it was earned at (TierNone
// without a valid cookie) and the device identifier it carries (16 hex
// characters, or "").
func (c *Challenger) Check(r *http.Request, ip netip.Addr) (int, string) {
	ck := c.Inspect(r, ip)
	return ck.Tier, ck.Device
}

// Inspect reads the challenge cookie in full; the zero Cookie means no
// valid cookie.
func (c *Challenger) Inspect(r *http.Request, ip netip.Addr) Cookie {
	c.mu.Lock()
	name := c.cookie
	c.mu.Unlock()
	ck, err := r.Cookie(name)
	if err != nil || len(ck.Value) > 64 {
		return Cookie{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil {
		return Cookie{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Cookie{Tier: TierProof}
	switch len(raw) {
	case 8 + macLen: // cookies issued before the tiered format
		if !c.macOK(raw[8:], []byte("cookie"), raw[:8], c.bind(r, ip)) {
			return Cookie{}
		}
	case 8 + 1 + deviceLen + macLen, 8 + 1 + deviceLen + 1 + macLen:
		headLen := len(raw) - macLen
		label := "cookie2"
		if headLen == 8+1+deviceLen+1 {
			label = "cookie3"
			out.Automation = signalNames(raw[9+deviceLen])
		}
		if !c.macOK(raw[headLen:], []byte(label), raw[:headLen], c.bind(r, ip)) {
			return Cookie{}
		}
		out.Tier = int(raw[8])
		if out.Tier < TierProof || out.Tier > TierCaptcha {
			return Cookie{}
		}
		var zero [deviceLen]byte
		if dev := raw[9 : 9+deviceLen]; !bytes.Equal(dev, zero[:]) {
			out.Device = hex.EncodeToString(dev)
		}
	default:
		return Cookie{}
	}
	exp := binary.BigEndian.Uint64(raw[:8])
	if exp >= 1<<62 || int64(exp) <= c.now().Unix() { //nolint:gosec // range checked
		return Cookie{}
	}
	return out
}

// issueCookie returns a cookie value valid for ttl carrying the tier, the
// device identifier and the automation markers.
func (c *Challenger) issueCookie(r *http.Request, ip netip.Addr, now time.Time, tier int, device []byte, signals byte) string {
	head := 8 + 1 + deviceLen + 1
	buf := make([]byte, head, head+macLen)
	binary.BigEndian.PutUint64(buf, uint64(now.Add(c.ttl).Unix())) //nolint:gosec // positive time
	buf[8] = byte(tier)
	copy(buf[9:], device)
	buf[9+deviceLen] = signals
	buf = append(buf, c.mac([]byte("cookie3"), buf[:head], c.bind(r, ip))...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// parseDevice accepts the script's hexadecimal device hash (16 to 64
// characters) and keeps its first eight bytes; anything else is no device.
func parseDevice(s string) []byte {
	if len(s) < 2*deviceLen || len(s) > 64 || len(s)%2 != 0 {
		return nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return raw[:deviceLen]
}

// newNonce returns a signed nonce: ts(8) || rand(8) || mac(16). The MAC
// covers the client address and the host the page was served on, so a
// nonce issued on one site cannot be redeemed on another.
func (c *Challenger) newNonce(ip netip.Addr, host string, now time.Time) string {
	buf := make([]byte, 16, 16+macLen)
	binary.BigEndian.PutUint64(buf, uint64(now.Unix())) //nolint:gosec // positive time
	_, _ = rand.Read(buf[8:16])
	buf = append(buf, c.mac([]byte("nonce"), buf[:16], c.ipBytes(ip), []byte(hostKey(host)))...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// hostKey is the host as bound into a nonce: lower case, without port.
func hostKey(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	return strings.ToLower(host)
}

// checkNonce validates the signature and age. The caller marks the nonce
// used with markUsed after a correct proof, so a wrong guess does not burn
// the nonce the browser is still working on.
func (c *Challenger) checkNonce(nonce string, ip netip.Addr, host string, now time.Time) ([macLen]byte, error) {
	var key [macLen]byte
	if len(nonce) > 64 {
		return key, errors.New("nonce too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 16+macLen {
		return key, errors.New("malformed nonce")
	}
	if !c.macOK(raw[16:], []byte("nonce"), raw[:16], c.ipBytes(ip), []byte(hostKey(host))) {
		return key, errors.New("bad nonce signature")
	}
	ts := binary.BigEndian.Uint64(raw[:8])
	if ts > 1<<62 || now.Unix()-int64(ts) > int64(nonceTTL.Seconds()) || int64(ts) > now.Unix()+60 { //nolint:gosec // range checked
		return key, errors.New("nonce expired")
	}
	copy(key[:], raw[16:])
	if _, used := c.seen[key]; used {
		return key, errors.New("nonce already used")
	}
	return key, nil
}

// markUsed records a solved nonce; it returns false if it was used
// concurrently or the table is full of live nonces.
func (c *Challenger) markUsed(key [macLen]byte, now time.Time) error {
	if _, used := c.seen[key]; used {
		return errors.New("nonce already used")
	}
	if len(c.seen) >= maxSeen {
		for k, exp := range c.seen {
			if exp < now.Unix() {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= maxSeen {
			// Table full of live nonces: refuse rather than allow replay.
			c.full.Hit(nil, "challenge verification table full; solved challenges are refused until nonces expire", "table", "challenge_nonces", "max", maxSeen)
			return errors.New("verification table full")
		}
	}
	c.seen[key] = now.Add(nonceTTL).Unix()
	return nil
}

// Solves reports whether counter is a valid proof for nonce at the given
// difficulty. Exported for tests and tooling.
func Solves(nonce, counter string, difficulty int) bool {
	sum := sha256.Sum256([]byte(nonce + ":" + counter))
	return leadingZeroBits(sum[:]) >= difficulty
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for m := byte(0x80); m != 0 && x&m == 0; m >>= 1 {
			n++
		}
		break
	}
	return n
}

// Solve finds a counter for nonce. Used by tests and by xproxyctl to
// verify a deployment; not on any request path.
func Solve(nonce string, difficulty int) string {
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		if Solves(nonce, s, difficulty) {
			return s
		}
	}
}

type pageData struct {
	Title      string
	Nonce      string
	Difficulty int
	Return     string
	Verify     string
	Script     string
	Device     bool
	// Captcha fields are set when the page renders the provider widget.
	Captcha        bool
	Provider       string
	SiteKey        string
	Widget         string
	ProviderScript string
}

// Serve writes the proof of work page for r (the CAPTCHA page in mode
// always).
func (c *Challenger) Serve(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	c.ServeTier(w, r, ip, false)
}

// ServeTier writes the challenge page; captcha asks for the CAPTCHA
// widget, served when a provider is configured and otherwise replaced by
// the proof of work.
func (c *Challenger) ServeTier(w http.ResponseWriter, r *http.Request, ip netip.Addr, captcha bool) {
	now := c.now()
	c.mu.Lock()
	c.Issued++
	d := pageData{Title: c.title, Nonce: c.newNonce(ip, r.Host, now), Difficulty: c.difficulty, Return: safeReturn(r.URL.RequestURI()), Verify: VerifyPath, Script: ScriptPath, Device: c.device}
	cp := c.captcha
	c.mu.Unlock()
	csp := "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"
	if cp != nil && (captcha || cp.always) {
		d.Captcha, d.Provider, d.SiteKey, d.Widget, d.ProviderScript = true, cp.name, cp.siteKey, cp.widget, cp.script
		csp = "default-src 'none'; script-src 'self' " + cp.scripts + "; frame-src " + cp.frames + "; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"
		if cp.connect != "" {
			csp += "; connect-src " + cp.connect
		}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", csp)
	h.Set("Retry-After", "5")
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method != http.MethodHead {
		_ = page.Execute(w, d)
	}
}

// ServeScript writes the challenge script.
func (c *Challenger) ServeScript(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/javascript; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(script)
	}
}

// Verify handles the proof submission. On success it sets the cookie and
// redirects to the return path; on failure it answers 403.
func (c *Challenger) Verify(w http.ResponseWriter, r *http.Request, ip netip.Addr, secure bool) (ok bool, reason string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return false, "method"
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return false, "form"
	}
	nonce := r.PostForm.Get("nonce")
	counter := r.PostForm.Get("counter")
	ret := safeReturn(r.PostForm.Get("r"))
	now := c.now()
	c.mu.Lock()
	difficulty := c.difficulty
	cp := c.captcha
	var device []byte
	var signals byte
	if c.device {
		device = parseDevice(r.PostForm.Get("device"))
		signals = parseSignals(r.PostForm.Get("signals"))
	}
	c.mu.Unlock()
	// A provider token selects the CAPTCHA tier; otherwise the proof.
	token := ""
	if cp != nil {
		token = r.PostForm.Get(cp.field)
	}
	tier := TierProof
	if token == "" && (len(counter) == 0 || len(counter) > 20 || strings.Trim(counter, "0123456789") != "") {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return false, "counter"
	}
	c.mu.Lock()
	key, err := c.checkNonce(nonce, ip, r.Host, now)
	c.mu.Unlock()
	if err != nil {
		c.fail(w, err.Error())
		return false, err.Error()
	}
	if token != "" {
		ctx, cancel := context.WithTimeout(r.Context(), cp.client.Timeout)
		// The provider reports the host the widget page was loaded on. The
		// nonce just verified binds this request to the host the challenge
		// page was served on, so r.Host is that host and not a value the
		// verifier chose freely.
		ok, reason := cp.check(ctx, token, c.routeHosts(), ip)
		cancel()
		if !ok {
			c.fail(w, reason)
			return false, reason
		}
		tier = TierCaptcha
	} else if !Solves(nonce, counter, difficulty) {
		c.fail(w, "wrong proof")
		return false, "proof"
	}
	c.mu.Lock()
	if err := c.markUsed(key, now); err != nil {
		c.mu.Unlock()
		c.fail(w, err.Error())
		return false, err.Error()
	}
	c.Passed++
	if tier == TierCaptcha {
		c.CaptchaPassed++
	}
	value := c.issueCookie(r, ip, now, tier, device, signals)
	name := c.cookie
	maxAge := int(c.ttl.Seconds())
	c.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, ret, http.StatusSeeOther)
	return true, ""
}

// ClientFault reports whether a Verify failure reason is the client's
// doing. A refusal the proxy caused itself — the replay table being full
// of other people's nonces, or a nonce submitted twice because a form
// was retried — must not be counted against the client: feeding it to a
// ban trigger turns a local resource limit into a ban of everyone who
// solves a challenge correctly.
func ClientFault(reason string) bool {
	// An allow list, not a deny list. Everything the proxy or the
	// CAPTCHA provider can fail at must stay off it: a provider outage
	// would otherwise count every visitor who solved the widget as a
	// failure and, with a challenge ban trigger configured, ban them
	// all. Only reasons that describe something the client actually did
	// wrong belong here, so a reason added later is harmless by default.
	switch reason {
	case "method", "form", "counter", "proof",
		"malformed nonce", "bad nonce signature", "nonce expired", "nonce too long",
		"captcha token", "captcha rejected", "captcha score", "captcha hostname":
		return true
	}
	return false
}

func (c *Challenger) fail(w http.ResponseWriter, _ string) {
	c.mu.Lock()
	c.Failed++
	c.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "403 Forbidden", http.StatusForbidden)
}

// safeReturn keeps only same-origin absolute paths.
func safeReturn(p string) string {
	if p == "" || len(p) > 2048 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.HasPrefix(p, VerifyPath) || strings.HasPrefix(p, ScriptPath) {
		return "/"
	}
	// No control bytes at all: browsers strip tab and newline before
	// parsing a Location, so "/\t/evil" would become "//evil" — an open
	// redirect that url.Parse (which rejects controls) would not clean.
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return "/"
		}
	}
	return p
}

// Stats returns counters: pages issued, verifications passed (captcha
// among them) and failed.
func (c *Challenger) Stats() (issued, passed, failed, captcha uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Issued, c.Passed, c.Failed, c.CaptchaPassed
}
