// Package basicauth is a built-in filter kind that requires HTTP Basic
// credentials from a users file of PBKDF2 hashes (`xproxyctl htpasswd`).
// Verified credentials are cached by digest for cache_ttl so the hash
// cost is paid once per client session, not per request.
//
//	filters:
//	  - name: staff
//	    kind: basic_auth
//	    options:
//	      users_file: /etc/xproxy/staff.htpasswd   # name:hash per line
//	      realm: staff                              # default "restricted"
//	      cache_ttl: 5m                             # default 5m, 0 disables
//	      forward_user_header: X-Remote-User        # default none
//	      strip: true                               # remove Authorization upstream; default true
package basicauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/passwd"
)

// Config is the options schema.
type Config struct {
	UsersFile         string `json:"users_file"`
	Realm             string `json:"realm"`
	CacheTTL          string `json:"cache_ttl"`
	ForwardUserHeader string `json:"forward_user_header"`
	Strip             *bool  `json:"strip"`
	ttl               time.Duration
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.UsersFile == "" {
		errs = append(errs, errors.New("users_file is required"))
	} else if st, err := os.Stat(c.UsersFile); err != nil {
		errs = append(errs, fmt.Errorf("users_file: %w", err))
	} else if st.Mode().Perm()&0o004 != 0 {
		errs = append(errs, fmt.Errorf("users_file: %s must not be world readable", c.UsersFile))
	}
	if c.Realm == "" {
		c.Realm = "restricted"
	}
	if strings.ContainsAny(c.Realm, "\"\r\n") {
		errs = append(errs, errors.New("realm: must not contain quotes or line breaks"))
	}
	c.ttl = 5 * time.Minute
	if c.CacheTTL != "" {
		d, err := time.ParseDuration(c.CacheTTL)
		if err != nil || d < 0 || d > 24*time.Hour {
			errs = append(errs, errors.New("cache_ttl: must be a duration between 0 and 24h"))
		} else {
			c.ttl = d
		}
	}
	if h := c.ForwardUserHeader; h != "" && strings.ContainsAny(h, " :\r\n") {
		errs = append(errs, fmt.Errorf("forward_user_header: %q is not a header name", h))
	}
	return &c, errors.Join(errs...)
}

type auth struct {
	name  string
	cfg   *Config
	users map[string]string
	log   *slog.Logger

	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
	sem   chan struct{}
}

type cacheEntry struct {
	user string
	ok   bool
	exp  time.Time
}

func (a *auth) Name() string { return a.name }

func (a *auth) Begin(context.Context, *filter.Info) filter.Instance { return &instance{a: a} }

type instance struct {
	a    *auth
	user string
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	user, pass, ok := r.BasicAuth()
	if !ok || !in.a.check(user, pass) {
		return filter.Verdict{Deny: true, Status: http.StatusUnauthorized, Reason: in.a.name, Detail: "credentials",
			Headers: map[string]string{"WWW-Authenticate": `Basic realm="` + in.a.cfg.Realm + `", charset="UTF-8"`}}
	}
	in.user = user
	filter.SetIdentity(r.Context(), "basic", user)
	if in.a.cfg.Strip == nil || *in.a.cfg.Strip {
		r.Header.Del("Authorization")
	}
	if h := in.a.cfg.ForwardUserHeader; h != "" {
		r.Header.Set(h, user)
	}
	return filter.Continue
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if in.user == "" {
		return nil
	}
	return []any{"auth_user", in.user}
}

// check verifies credentials, through the cache when enabled. Wrong
// credentials are cached too so a guessing client pays the hash once per
// distinct attempt but cannot make the proxy hash on every request.
func (a *auth) check(user, pass string) bool {
	hash, known := a.users[user]
	if !known {
		return false
	}
	key := sha256.Sum256([]byte(user + "\x00" + pass))
	now := time.Now()
	if a.cfg.ttl > 0 {
		a.mu.Lock()
		e, hit := a.cache[key]
		a.mu.Unlock()
		if hit && now.Before(e.exp) {
			return e.ok
		}
	}
	a.sem <- struct{}{}
	ok := passwd.Verify(hash, pass)
	<-a.sem
	if a.cfg.ttl > 0 {
		a.mu.Lock()
		if len(a.cache) >= 4096 {
			for k, e := range a.cache {
				if now.After(e.exp) {
					delete(a.cache, k)
				}
			}
			if len(a.cache) >= 4096 { // still full: drop everything rather than grow
				a.cache = map[[32]byte]cacheEntry{}
			}
		}
		a.cache[key] = cacheEntry{user: user, ok: ok, exp: now.Add(a.cfg.ttl)}
		a.mu.Unlock()
	}
	return ok
}

func init() {
	filter.Register(filter.Kind{
		Name:        "basic_auth",
		Description: "HTTP Basic authentication against a file of PBKDF2 hashes.",
		Validate: func(opts filter.Options) error {
			c, err := parse(opts)
			if err != nil {
				return err
			}
			_, err = passwd.LoadUsers(c.UsersFile)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			users, err := passwd.LoadUsers(c.UsersFile)
			if err != nil {
				return nil, err
			}
			return &auth{name: name, cfg: c, users: users, log: env.Log, cache: map[[32]byte]cacheEntry{}, sem: make(chan struct{}, 8)}, nil
		},
	})
}
