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

// ErrInactive is returned for a token the introspection endpoint reports
// as not active.
var ErrInactive = errors.New("token not active")

// ErrIntrospection is returned when the endpoint cannot be asked.
var ErrIntrospection = errors.New("introspection unavailable")

// introspector asks an RFC 7662 endpoint about tokens and caches the
// answers by token digest, bounded in size and by the token's expiry.
type introspector struct {
	cfg    config.TokenIntrospection
	secret string
	client *http.Client

	mu    sync.Mutex
	cache map[[32]byte]cached
	full  bound.Notice

	// counters
	Calls, Errors, Hits atomic.Uint64
}

type cached struct {
	claims Claims
	err    error
	until  time.Time
}

// maxIntrospectionCache bounds cached decisions per provider.
const maxIntrospectionCache = 65536

func newIntrospector(cfg config.TokenIntrospection) (*introspector, error) {
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
			return nil, errors.New("introspection ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	return &introspector{cfg: cfg, secret: strings.TrimSpace(string(b)), cache: map[[32]byte]cached{},
		client: &http.Client{
			Timeout:       cfg.Timeout.D(),
			Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 8, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: cfg.Timeout.D(), DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") },
		}}, nil
}

// looksLikeJWS reports whether token has the shape of a compact JWS.
func looksLikeJWS(token string) bool {
	return strings.Count(token, ".") == 2 && !strings.HasPrefix(token, ".") && !strings.HasSuffix(token, ".")
}

// verify returns the claims of an active token. Only the exp of a cached
// entry limits its life; a negative answer is cached for the same time
// so a revoked token does not cost a call per request.
func (in *introspector) verify(ctx context.Context, token string, now time.Time) (Claims, error) {
	key := sha256.Sum256([]byte(token))
	in.mu.Lock()
	if c, ok := in.cache[key]; ok {
		if now.Before(c.until) {
			in.mu.Unlock()
			in.Hits.Add(1)
			return c.claims, c.err
		}
		delete(in.cache, key)
	}
	in.mu.Unlock()
	claims, err := in.ask(ctx, token)
	if errors.Is(err, ErrIntrospection) {
		return nil, err // an unavailable endpoint is not cached
	}
	if ttl := in.cfg.CacheTTL.D(); ttl > 0 {
		until := now.Add(ttl)
		if exp, ok := numeric(claims["exp"]); ok && err == nil {
			if e := time.Unix(int64(exp), 0); e.Before(until) {
				until = e
			}
		}
		in.mu.Lock()
		if len(in.cache) >= maxIntrospectionCache {
			in.full.Hit(nil, "introspection cache full; decisions are not cached until entries expire", "table", "introspection_cache", "max", maxIntrospectionCache)
			for k, c := range in.cache {
				if !now.Before(c.until) {
					delete(in.cache, k)
				}
			}
		}
		if len(in.cache) < maxIntrospectionCache {
			in.cache[key] = cached{claims: claims, err: err, until: until}
		}
		in.mu.Unlock()
	}
	return claims, err
}

// ask performs one introspection call.
func (in *introspector) ask(ctx context.Context, token string) (Claims, error) {
	in.Calls.Add(1)
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.cfg.URL, strings.NewReader(form.Encode()))
	if err != nil {
		in.Errors.Add(1)
		return nil, errors.Join(ErrIntrospection, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(in.cfg.ClientID), url.QueryEscape(in.secret))
	resp, err := in.client.Do(req)
	if err != nil {
		in.Errors.Add(1)
		return nil, errors.Join(ErrIntrospection, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		in.Errors.Add(1)
		return nil, fmt.Errorf("%w: HTTP %d", ErrIntrospection, resp.StatusCode)
	}
	var claims Claims
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || claims == nil {
		in.Errors.Add(1)
		return nil, fmt.Errorf("%w: bad response", ErrIntrospection)
	}
	if active, _ := claims["active"].(bool); !active {
		return nil, ErrInactive
	}
	delete(claims, "active")
	return claims, nil
}

// cacheLen returns the number of cached decisions (status and tests).
func (in *introspector) cacheLen() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.cache)
}
