package jwt

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
)

// Token exchange, RFC 8693, and the thing it stops.
//
// A token the client sent to the gateway is a token the gateway forwards,
// and everything behind the gateway then holds a credential that works at
// the gateway. That is the whole of the confused-deputy problem in one
// sentence: a backend with a bug -- a log line, an error page, an outbound
// request to somewhere it should not go -- leaks a token that reaches the
// front door again, with all of the client's scopes on it.
//
// Exchange replaces it. The gateway presents the client's token to the
// authorization server and asks for one issued *for this backend*: a
// different audience, usually fewer scopes, and no standing anywhere else.
// The backend never sees the client's token at all, so there is nothing
// there to leak that would work at the gateway. The client's identity
// survives -- the authorization server puts the same subject in the new
// token, which is what makes this an exchange and not an impersonation.
//
// The exchange happens after the client's token has been verified, never
// before. Sending an unverified token to the authorization server would be
// asking it to decide, at this proxy's expense, what to do with whatever a
// client posted -- and caching the answer against the token's digest would
// then let one client's garbage occupy the table.

// ErrExchange is returned when the token endpoint cannot be asked. It is a
// 503: the client's token was good and the proxy could not finish.
var ErrExchange = errors.New("token exchange unavailable")

// ErrExchangeRefused is returned when the authorization server refuses to
// exchange the token. It is a 403: the token is valid and this backend is
// not somewhere it reaches.
var ErrExchangeRefused = errors.New("token exchange refused")

// The URNs RFC 8693 defines. They are written out because a typo in one is
// a request the authorization server answers with invalid_request and an
// operator cannot see the difference in a configuration file.
const (
	// These two are URNs from the RFC's own registry, not credentials;
	// gosec pattern-matches the words in them.
	grantTokenExchange  = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // an RFC 8693 identifier
	typeAccessToken     = "urn:ietf:params:oauth:token-type:access_token"   //nolint:gosec // an RFC 8693 identifier
	typeJWT             = "urn:ietf:params:oauth:token-type:jwt"
	maxExchangeInflight = 32
	maxExchangeCache    = 32768
	maxExchangeBody     = 64 << 10
)

// exchanger swaps a verified client token for one issued to a backend,
// caching by the client token's digest.
type exchanger struct {
	cfg    config.TokenExchange
	secret string
	client *http.Client

	mu    sync.Mutex
	cache map[[32]byte]exchanged
	full  bound.Notice
	// sem bounds the calls in flight, so a flood of distinct tokens
	// cannot be amplified into an unbounded load on the authorization
	// server -- which would take the login flow down with the API.
	sem chan struct{}

	// counters
	Calls, Errors, Hits, Refusals atomic.Uint64
}

type exchanged struct {
	token string
	err   error
	until time.Time
}

func newExchanger(cfg config.TokenExchange) (*exchanger, error) {
	b, err := os.ReadFile(cfg.ClientSecretFile) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("token_exchange ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	timeout := cfg.Timeout.D()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &exchanger{cfg: cfg, secret: strings.TrimSpace(string(b)), cache: map[[32]byte]exchanged{},
		sem: make(chan struct{}, maxExchangeInflight),
		client: &http.Client{
			Timeout: timeout,
			// No environment proxy: the authorization server is named in
			// the configuration, and a proxy read from the environment is
			// a third party in the middle of a credential exchange.
			Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 8,
				IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: timeout, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") },
		}}, nil
}

// exchange returns the token to forward for this client token.
func (x *exchanger) exchange(ctx context.Context, token string, now time.Time) (string, error) {
	key := sha256.Sum256([]byte(token))
	x.mu.Lock()
	if c, ok := x.cache[key]; ok {
		if now.Before(c.until) {
			x.mu.Unlock()
			x.Hits.Add(1)
			return c.token, c.err
		}
		delete(x.cache, key)
	}
	x.mu.Unlock()
	select {
	case x.sem <- struct{}{}:
	case <-ctx.Done():
		x.Errors.Add(1)
		return "", fmt.Errorf("%w: %d calls in flight", ErrExchange, maxExchangeInflight)
	}
	out, ttl, err := x.ask(ctx, token)
	<-x.sem
	if errors.Is(err, ErrExchange) {
		// An unreachable endpoint is not cached: the next request should
		// try again rather than inherit a failure that may be over.
		return "", err
	}
	x.store(key, out, err, ttl, now)
	return out, err
}

// store caches one outcome, bounded by the configured TTL and by what the
// authorization server said the new token's life is.
//
// A refusal is cached too, and for the same time. It is the authorization
// server's decision about this client and this backend, and asking again
// on every request would turn one client's misconfiguration into a load
// the login flow shares.
func (x *exchanger) store(key [32]byte, token string, err error, ttl, now time.Time) {
	keep := x.cfg.CacheTTL.D()
	if keep <= 0 {
		return
	}
	until := now.Add(keep)
	// Never past the new token's own expiry: a cached token that outlives
	// what was issued is a backend receiving something already dead.
	if !ttl.IsZero() && ttl.Before(until) {
		until = ttl
	}
	if !until.After(now) {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.cache) >= maxExchangeCache {
		x.full.Hit(nil, "token exchange cache full; tokens are exchanged on every request until entries expire",
			"table", "token_exchange_cache", "max", maxExchangeCache)
		for k, c := range x.cache {
			if !now.Before(c.until) {
				delete(x.cache, k)
			}
		}
	}
	if len(x.cache) < maxExchangeCache {
		x.cache[key] = exchanged{token: token, err: err, until: until}
	}
}

// exchangeResponse is the RFC 8693 answer.
type exchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	Error           string `json:"error"`
	Description     string `json:"error_description"`
}

// ask performs one exchange. It returns the new token and the moment it
// expires (zero when the server did not say).
func (x *exchanger) ask(ctx context.Context, token string) (string, time.Time, error) {
	x.Calls.Add(1)
	form := url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {token},
		"subject_token_type": {typeAccessToken},
	}
	if x.cfg.Audience != "" {
		form.Set("audience", x.cfg.Audience)
	}
	if x.cfg.Resource != "" {
		form.Set("resource", x.cfg.Resource)
	}
	if len(x.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(x.cfg.Scopes, " "))
	}
	if x.cfg.RequestedTokenType != "" {
		form.Set("requested_token_type", x.cfg.RequestedTokenType)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.cfg.URL, strings.NewReader(form.Encode()))
	if err != nil {
		x.Errors.Add(1)
		return "", time.Time{}, errors.Join(ErrExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(x.cfg.ClientID), url.QueryEscape(x.secret))
	resp, err := x.client.Do(req)
	if err != nil {
		x.Errors.Add(1)
		return "", time.Time{}, errors.Join(ErrExchange, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxExchangeBody))
	var out exchangeResponse
	if rerr == nil {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.UseNumber()
		_ = dec.Decode(&out)
	}
	switch {
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		// The authorization server considered the request and said no.
		// That is an answer, not an outage, and it belongs to the client.
		x.Refusals.Add(1)
		reason := out.Error
		if reason == "" {
			reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", time.Time{}, fmt.Errorf("%w: %s", ErrExchangeRefused, reason)
	case resp.StatusCode != http.StatusOK || rerr != nil:
		x.Errors.Add(1)
		return "", time.Time{}, fmt.Errorf("%w: HTTP %d", ErrExchange, resp.StatusCode)
	case out.AccessToken == "":
		x.Errors.Add(1)
		return "", time.Time{}, fmt.Errorf("%w: no access_token in the response", ErrExchange)
	}
	// RFC 8693 section 2.2.1 requires issued_token_type, and it is worth
	// checking rather than assuming: a server that answered with a
	// refresh token would otherwise have it forwarded as an access token.
	switch out.IssuedTokenType {
	case "", typeAccessToken, typeJWT:
	default:
		x.Errors.Add(1)
		return "", time.Time{}, fmt.Errorf("%w: issued_token_type is %q", ErrExchange, out.IssuedTokenType)
	}
	var expiry time.Time
	if out.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return out.AccessToken, expiry, nil
}

// cacheLen is the number of cached exchanges, for the status view.
func (x *exchanger) cacheLen() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.cache)
}

// scheme is how the exchanged token is presented to the backend. The
// header name is the operator's, because the backend is theirs.
func (x *exchanger) place(h http.Header, token string) {
	name, scheme := x.cfg.Header, "Bearer "
	if name == "" {
		name = "Authorization"
	}
	if !strings.EqualFold(name, "Authorization") {
		scheme = ""
	}
	h.Set(name, scheme+token)
}
