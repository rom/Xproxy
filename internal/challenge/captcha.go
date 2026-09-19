package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// provider describes a hosted CAPTCHA service: where its widget script
// lives, the widget class and response field its script uses, its
// verification endpoint and the origins the page's Content Security
// Policy must admit.
type provider struct {
	name    string
	script  string
	widget  string
	field   string
	verify  string
	scripts string
	frames  string
	connect string
}

var providers = map[string]provider{
	"turnstile": {
		name: "turnstile", script: "https://challenges.cloudflare.com/turnstile/v0/api.js", widget: "cf-turnstile", field: "cf-turnstile-response",
		verify: "https://challenges.cloudflare.com/turnstile/v0/siteverify", scripts: "https://challenges.cloudflare.com", frames: "https://challenges.cloudflare.com",
	},
	"hcaptcha": {
		name: "hcaptcha", script: "https://js.hcaptcha.com/1/api.js", widget: "h-captcha", field: "h-captcha-response",
		verify: "https://api.hcaptcha.com/siteverify", scripts: "https://js.hcaptcha.com https://*.hcaptcha.com", frames: "https://*.hcaptcha.com", connect: "https://*.hcaptcha.com",
	},
	"recaptcha": {
		name: "recaptcha", script: "https://www.google.com/recaptcha/api.js", widget: "g-recaptcha", field: "g-recaptcha-response",
		verify: "https://www.google.com/recaptcha/api/siteverify", scripts: "https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/", frames: "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/",
	},
}

// captcha is the configured provider with its secret.
type captcha struct {
	provider
	siteKey  string
	secret   string
	verify   string
	minScore float64
	always   bool
	client   *http.Client
}

// loadCaptcha reads the provider secret; a missing or empty secret file
// is an error because the widget would render but never verify.
func loadCaptcha(cfg *config.Captcha) (*captcha, error) {
	p, ok := providers[cfg.Provider]
	if !ok {
		return nil, fmt.Errorf("captcha provider %q unknown", cfg.Provider)
	}
	raw, err := os.ReadFile(cfg.SecretFile) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, fmt.Errorf("captcha secret: %w", err)
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" || len(secret) > 512 {
		return nil, errors.New("captcha secret: file must hold the provider secret on one line")
	}
	verify := cfg.VerifyURL
	if verify == "" {
		verify = p.verify
	}
	c := &captcha{provider: p, siteKey: cfg.SiteKey, secret: secret, verify: verify, minScore: cfg.MinScore, always: cfg.Mode == "always"}
	// A dedicated client: no environment proxy, short dial, bounded
	// response.
	c.client = &http.Client{Timeout: cfg.Timeout.D(), Transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: cfg.Timeout.D()}).DialContext,
		TLSHandshakeTimeout: cfg.Timeout.D(), MaxIdleConns: 4, IdleConnTimeout: time.Minute, ForceAttemptHTTP2: true,
	}}
	return c, nil
}

// siteverifyResponse is the common shape of the three providers' answers.
type siteverifyResponse struct {
	Success    bool     `json:"success"`
	Score      *float64 `json:"score"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

// check verifies a widget token with the provider. The reason names the
// failure class without the provider's detail.
func (c *captcha) check(ctx context.Context, token string, ip netip.Addr) (bool, string) {
	if token == "" || len(token) > 8192 {
		return false, "captcha token"
	}
	form := url.Values{"secret": {c.secret}, "response": {token}}
	if ip.IsValid() {
		form.Set("remoteip", ip.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.verify, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "captcha request"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return false, "captcha unreachable"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, "captcha provider error"
	}
	var sv siteverifyResponse
	if json.Unmarshal(body, &sv) != nil {
		return false, "captcha provider error"
	}
	if !sv.Success {
		return false, "captcha rejected"
	}
	if c.minScore > 0 && (sv.Score == nil || *sv.Score < c.minScore) {
		return false, "captcha score"
	}
	return true, ""
}
