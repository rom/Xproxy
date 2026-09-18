// Package challenge implements the browser proof-of-work challenge
// (docs/AMR.md, AMR-023).
//
// An unverified client receives a 503 page with a signed nonce and a
// small script. The script finds a counter such that
// SHA-256(nonce ":" counter) has the configured number of leading zero
// bits, posts it back to the verification path, and receives a signed
// cookie that is optionally bound to the client address. The cost is paid
// by the client in CPU; the proxy pays one HMAC per page and one HMAC plus
// one SHA-256 per verification. Nonces are single use and expire.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

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
	key        []byte
	difficulty int
	ttl        time.Duration
	bindIP     bool
	cookie     string
	exempt     []netip.Prefix
	title      string
	seen       map[[macLen]byte]int64 // nonce mac -> expiry unix
	now        func() time.Time

	Issued, Passed, Failed uint64
}

// New creates a challenger, loading or generating the key.
func New(cfg *config.Challenge) (*Challenger, error) {
	key, err := loadOrCreateKey(cfg.SecretFile)
	if err != nil {
		return nil, err
	}
	c := &Challenger{key: key, seen: make(map[[macLen]byte]int64), now: time.Now}
	c.Reconfigure(cfg)
	return c, nil
}

// Reconfigure applies settings other than the key.
func (c *Challenger) Reconfigure(cfg *config.Challenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.difficulty = cfg.Difficulty
	c.ttl = cfg.TTL.D()
	c.bindIP = cfg.BindsIP()
	c.cookie = cfg.CookieName
	c.exempt = netutil.ParsePrefixes(cfg.ExemptCIDRs)
	c.title = cfg.Title
}

func loadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		k := make([]byte, 32)
		_, err := rand.Read(k)
		return k, err
	}
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // operator configured path
		if len(b) < 32 {
			return nil, fmt.Errorf("challenge secret %s is shorter than 32 bytes", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read challenge secret: %w", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, fmt.Errorf("create challenge secret: %w", err)
	}
	return k, nil
}

func (c *Challenger) mac(parts ...[]byte) []byte {
	m := hmac.New(sha256.New, c.key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:macLen]
}

func (c *Challenger) ipBytes(ip netip.Addr) []byte {
	if !c.bindIP {
		return nil
	}
	b := ip.Unmap().As16()
	return b[:]
}

// Exempt reports whether ip is never challenged.
func (c *Challenger) Exempt(ip netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return netutil.Contains(c.exempt, ip)
}

// Verified reports whether the request carries a valid challenge cookie.
func (c *Challenger) Verified(r *http.Request, ip netip.Addr) bool {
	c.mu.Lock()
	name := c.cookie
	c.mu.Unlock()
	ck, err := r.Cookie(name)
	if err != nil || len(ck.Value) > 64 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(raw) != 8+macLen {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if subtle.ConstantTimeCompare(c.mac([]byte("cookie"), raw[:8], c.ipBytes(ip)), raw[8:]) != 1 {
		return false
	}
	exp := binary.BigEndian.Uint64(raw[:8])
	return exp < 1<<62 && int64(exp) > c.now().Unix() //nolint:gosec // range checked
}

// issueCookie returns a cookie value valid for ttl.
func (c *Challenger) issueCookie(ip netip.Addr, now time.Time) string {
	buf := make([]byte, 8, 8+macLen)
	binary.BigEndian.PutUint64(buf, uint64(now.Add(c.ttl).Unix())) //nolint:gosec // positive time
	buf = append(buf, c.mac([]byte("cookie"), buf[:8], c.ipBytes(ip))...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// newNonce returns a signed nonce: ts(8) || rand(8) || mac(16).
func (c *Challenger) newNonce(ip netip.Addr, now time.Time) string {
	buf := make([]byte, 16, 16+macLen)
	binary.BigEndian.PutUint64(buf, uint64(now.Unix())) //nolint:gosec // positive time
	_, _ = rand.Read(buf[8:16])
	buf = append(buf, c.mac([]byte("nonce"), buf[:16], c.ipBytes(ip))...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// checkNonce validates the signature and age. The caller marks the nonce
// used with markUsed after a correct proof, so a wrong guess does not burn
// the nonce the browser is still working on.
func (c *Challenger) checkNonce(nonce string, ip netip.Addr, now time.Time) ([macLen]byte, error) {
	var key [macLen]byte
	if len(nonce) > 64 {
		return key, errors.New("nonce too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 16+macLen {
		return key, errors.New("malformed nonce")
	}
	if subtle.ConstantTimeCompare(c.mac([]byte("nonce"), raw[:16], c.ipBytes(ip)), raw[16:]) != 1 {
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
}

// Serve writes the challenge page for r.
func (c *Challenger) Serve(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	now := c.now()
	c.mu.Lock()
	c.Issued++
	d := pageData{Title: c.title, Nonce: c.newNonce(ip, now), Difficulty: c.difficulty, Return: safeReturn(r.URL.RequestURI()), Verify: VerifyPath, Script: ScriptPath}
	c.mu.Unlock()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
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
	if len(counter) == 0 || len(counter) > 20 || strings.Trim(counter, "0123456789") != "" {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return false, "counter"
	}
	now := c.now()
	c.mu.Lock()
	difficulty := c.difficulty
	key, err := c.checkNonce(nonce, ip, now)
	c.mu.Unlock()
	if err != nil {
		c.fail(w, err.Error())
		return false, err.Error()
	}
	if !Solves(nonce, counter, difficulty) {
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
	value := c.issueCookie(ip, now)
	name := c.cookie
	maxAge := int(c.ttl.Seconds())
	c.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, ret, http.StatusSeeOther)
	return true, ""
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
	if p == "" || len(p) > 2048 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.HasPrefix(p, VerifyPath) || strings.HasPrefix(p, ScriptPath) || strings.ContainsAny(p, "\r\n") {
		return "/"
	}
	return p
}

// Stats returns counters.
func (c *Challenger) Stats() (issued, passed, failed uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Issued, c.Passed, c.Failed
}
