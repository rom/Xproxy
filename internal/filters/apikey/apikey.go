package apikey

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// Config is the options schema.
type Config struct {
	KeysFile            string   `json:"keys_file"`
	Source              string   `json:"source"`
	RequiredScopes      []string `json:"required_scopes"`
	ForwardIDHeader     *string  `json:"forward_id_header"`
	ForwardScopesHeader *string  `json:"forward_scopes_header"`
	Strip               *bool    `json:"strip"`
	Reload              string   `json:"reload"`
	ExpiryWarning       string   `json:"expiry_warning"`

	reload, warning time.Duration
	idHeader        string
	scopesHeader    string
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.KeysFile == "" || !strings.HasPrefix(c.KeysFile, "/") {
		errs = append(errs, errors.New("keys_file: an absolute path is required"))
	} else if st, err := os.Stat(c.KeysFile); err != nil {
		errs = append(errs, fmt.Errorf("keys_file: %w", err))
	} else if st.Mode().Perm()&0o004 != 0 {
		errs = append(errs, fmt.Errorf("keys_file: %s must not be world readable", c.KeysFile))
	} else if _, err := Load(c.KeysFile); err != nil {
		errs = append(errs, err)
	}
	if c.Source == "" {
		c.Source = "header:X-Api-Key"
	}
	switch {
	case c.Source == "bearer":
	case strings.HasPrefix(c.Source, "header:") && len(c.Source) > 7 && !strings.ContainsAny(c.Source[7:], " \r\n"):
	case strings.HasPrefix(c.Source, "query:") && len(c.Source) > 6 && !strings.ContainsAny(c.Source[6:], " &=\r\n"):
	default:
		errs = append(errs, fmt.Errorf("source: %q must be bearer, header:<Name> or query:<name>", c.Source))
	}
	for _, s := range c.RequiredScopes {
		if s == "" || strings.ContainsAny(s, ", \r\n|") {
			errs = append(errs, fmt.Errorf("required_scopes: %q is not a scope", s))
		}
	}
	c.idHeader, c.scopesHeader = "X-Api-Key-Id", "X-Api-Key-Scopes"
	if c.ForwardIDHeader != nil {
		c.idHeader = *c.ForwardIDHeader
	}
	if c.ForwardScopesHeader != nil {
		c.scopesHeader = *c.ForwardScopesHeader
	}
	for _, h := range []string{c.idHeader, c.scopesHeader} {
		if h != "" && (strings.ContainsAny(h, " :\r\n") || strings.EqualFold(h, "Authorization") || strings.EqualFold(h, "Host")) {
			errs = append(errs, fmt.Errorf("%q is not a usable header name", h))
		}
	}
	c.reload = 30 * time.Second
	if c.Reload != "" {
		d, err := time.ParseDuration(c.Reload)
		if err != nil || d < time.Second || d > time.Hour {
			errs = append(errs, errors.New("reload: must be a duration between 1s and 1h"))
		} else {
			c.reload = d
		}
	}
	c.warning = 7 * 24 * time.Hour
	if c.ExpiryWarning != "" {
		d, err := time.ParseDuration(c.ExpiryWarning)
		if err != nil || d < 0 || d > 365*24*time.Hour {
			errs = append(errs, errors.New("expiry_warning: must be a duration between 0 and 8760h"))
		} else {
			c.warning = d
		}
	}
	return &c, errors.Join(errs...)
}

// keyTable is one loaded generation of the file.
type keyTable struct {
	byHash map[string]*Key
	byID   map[string]*Key
	digest [32]byte // of the file contents, to notice a change
	count  int
}

type auth struct {
	name string
	cfg  *Config
	env  filter.Env

	table   atomic.Pointer[keyTable]
	checkMu sync.Mutex
	checked time.Time
	warned  map[string]time.Time

	// counters
	Allowed, Denied atomic.Uint64
}

func newAuth(name string, cfg *Config, env filter.Env) (*auth, error) {
	a := &auth{name: name, cfg: cfg, env: env, warned: map[string]time.Time{}}
	if err := a.load(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *auth) load() error {
	data, err := os.ReadFile(a.cfg.KeysFile)
	if err != nil {
		return err
	}
	return a.install(data)
}

// install parses data and swaps the table in.
func (a *auth) install(data []byte) error {
	keys, err := Parse(data, a.cfg.KeysFile)
	if err != nil {
		return err
	}
	t := &keyTable{byHash: map[string]*Key{}, byID: map[string]*Key{}, digest: sha256.Sum256(data), count: len(keys)}
	for i := range keys {
		k := &keys[i]
		t.byHash[k.Hash] = k
		t.byID[k.ID] = k
		if k.PrevHash != "" {
			t.byHash[k.PrevHash] = k
		}
	}
	a.table.Store(t)
	a.checked = time.Now()
	return nil
}

// current returns the key table, re-reading the file when its change
// time moved and the reload interval passed. A file that fails to load
// keeps the previous table and logs.
func (a *auth) current() *keyTable {
	t := a.table.Load()
	a.checkMu.Lock()
	defer a.checkMu.Unlock()
	if time.Since(a.checked) < a.cfg.reload {
		return t
	}
	a.checked = time.Now()
	data, err := os.ReadFile(a.cfg.KeysFile)
	if err != nil || sha256.Sum256(data) == t.digest {
		return t
	}
	if err := a.install(data); err != nil {
		a.env.Log.Error("api keys file not reloaded", "file", a.cfg.KeysFile, "err", err.Error())
		return t
	}
	a.env.Log.Info("api keys reloaded", "file", a.cfg.KeysFile, "keys", a.table.Load().count)
	return a.table.Load()
}

func (a *auth) Name() string { return a.name }

func (a *auth) Begin(context.Context, *filter.Info) filter.Instance { return &instance{a: a} }

type instance struct {
	a     *auth
	keyID string
}

// extract returns the presented key and whether one was present.
func (in *instance) extract(r *http.Request) (string, bool) {
	src := in.a.cfg.Source
	switch {
	case src == "bearer":
		v := r.Header.Get("Authorization")
		for _, scheme := range []string{"Bearer ", "ApiKey ", "Api-Key "} {
			if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
				return strings.TrimSpace(v[len(scheme):]), true
			}
		}
		return "", false
	case strings.HasPrefix(src, "header:"):
		v := r.Header.Get(src[7:])
		return v, v != ""
	default:
		v := r.URL.Query().Get(src[6:])
		return v, v != ""
	}
}

func (in *instance) strip(r *http.Request) {
	src := in.a.cfg.Source
	switch {
	case src == "bearer":
		r.Header.Del("Authorization")
	case strings.HasPrefix(src, "header:"):
		r.Header.Del(src[7:])
	default:
		q := r.URL.Query()
		q.Del(src[6:])
		r.URL.RawQuery = q.Encode()
	}
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	a := in.a
	cfg := a.cfg
	// Identity headers from the client are never trusted.
	if cfg.idHeader != "" {
		r.Header.Del(cfg.idHeader)
	}
	if cfg.scopesHeader != "" {
		r.Header.Del(cfg.scopesHeader)
	}
	plain, ok := in.extract(r)
	if !ok || len(plain) > 512 {
		return in.deny(http.StatusUnauthorized, "missing", "")
	}
	t := a.current()
	k, found := t.byHash[HashKey(plain)]
	now := time.Now()
	switch {
	case !found:
		return in.deny(http.StatusUnauthorized, "unknown", IDOf(plain))
	case k.State != "active":
		return in.deny(http.StatusUnauthorized, "revoked", k.ID)
	case !k.Expires.IsZero() && now.After(k.Expires):
		return in.deny(http.StatusUnauthorized, "expired", k.ID)
	case k.Hash != HashKey(plain) && (k.PrevUntil.IsZero() || now.After(k.PrevUntil)):
		return in.deny(http.StatusUnauthorized, "rotated", k.ID)
	}
	for _, want := range cfg.RequiredScopes {
		if !hasScope(k.Scopes, want) {
			return in.deny(http.StatusForbidden, "scope:"+want, k.ID)
		}
	}
	a.warnExpiry(k, now)
	in.keyID = k.ID
	a.Allowed.Add(1)
	if cfg.Strip == nil || *cfg.Strip {
		in.strip(r)
	}
	if cfg.idHeader != "" {
		r.Header.Set(cfg.idHeader, k.ID)
	}
	if cfg.scopesHeader != "" && len(k.Scopes) > 0 {
		r.Header.Set(cfg.scopesHeader, strings.Join(k.Scopes, " "))
	}
	return filter.Continue
}

func hasScope(have []string, want string) bool {
	for _, s := range have {
		if s == want || s == "*" {
			return true
		}
		// A scope "orders" covers "orders:read".
		if strings.HasPrefix(want, s+":") {
			return true
		}
	}
	return false
}

// warnExpiry logs once a day per key inside the warning window.
func (a *auth) warnExpiry(k *Key, now time.Time) {
	if a.cfg.warning <= 0 || k.Expires.IsZero() || k.Expires.Sub(now) > a.cfg.warning {
		return
	}
	a.checkMu.Lock()
	last, ok := a.warned[k.ID]
	if ok && now.Sub(last) < 24*time.Hour {
		a.checkMu.Unlock()
		return
	}
	a.warned[k.ID] = now
	a.checkMu.Unlock()
	a.env.Log.Warn("api key expires soon", "key", k.ID, "expires", k.Expires.Format(time.RFC3339), "in", k.Expires.Sub(now).Round(time.Hour).String())
}

func (in *instance) deny(status int, detail, id string) filter.Verdict {
	in.a.Denied.Add(1)
	v := filter.Verdict{Deny: true, Status: status, Reason: in.a.name, Detail: detail,
		Headers: map[string]string{"WWW-Authenticate": `ApiKey realm="` + in.a.name + `"`}}
	if id != "" {
		v.Attrs = []any{"api_key", id}
	}
	return v
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if in.keyID == "" {
		return nil
	}
	return []any{"api_key", in.keyID}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "api_key",
		Description: "API keys from a managed file: scopes, expiry, rotation with grace and revocation",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			cfg, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return newAuth(name, cfg, env)
		},
	})
}
