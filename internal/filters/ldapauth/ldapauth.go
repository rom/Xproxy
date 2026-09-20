// Package ldapauth is a built-in filter kind that authenticates HTTP Basic
// credentials against an LDAP or Active Directory server. It supports both a
// direct bind (bind_dn_template) and a search-then-bind with a service
// account (bind_dn, base_dn, user_filter), and an optional group
// requirement. Verified credentials are cached by digest for cache_ttl so a
// bind is not paid on every request.
//
//	filters:
//	  - name: staff
//	    kind: ldap_auth
//	    options:
//	      url: ldaps://ad.example.com:636
//	      bind_dn: "cn=svc,ou=svc,dc=example,dc=com"
//	      bind_password_file: /etc/xproxy/ldap.secret
//	      base_dn: "ou=people,dc=example,dc=com"
//	      user_filter: "(sAMAccountName=%s)"
//	      require_group: "cn=staff,ou=groups,dc=example,dc=com"
//	      realm: staff
package ldapauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/passwd"
)

// Config is the options schema.
type Config struct {
	URL                string `json:"url"`
	StartTLS           bool   `json:"start_tls"`
	AllowPlaintext     bool   `json:"allow_plaintext"`
	CAFile             string `json:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	BindDNTemplate     string `json:"bind_dn_template"`
	BindDN             string `json:"bind_dn"`
	BindPasswordFile   string `json:"bind_password_file"`
	BaseDN             string `json:"base_dn"`
	UserFilter         string `json:"user_filter"`
	RequireGroup       string `json:"require_group"`
	GroupAttr          string `json:"group_attr"`
	Realm              string `json:"realm"`
	CacheTTL           string `json:"cache_ttl"`
	ForwardUserHeader  string `json:"forward_user_header"`
	Strip              *bool  `json:"strip"`
	Timeout            string `json:"timeout"`

	ttl     time.Duration
	timeout time.Duration
}

// searchBind reports whether the config uses a service account search
// rather than a direct bind template.
func (c *Config) searchBind() bool { return c.BindDNTemplate == "" }

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	switch {
	case c.URL == "":
		errs = append(errs, errors.New("url is required"))
	case !strings.HasPrefix(c.URL, "ldap://") && !strings.HasPrefix(c.URL, "ldaps://"):
		errs = append(errs, errors.New("url: must be ldap:// or ldaps://"))
	case strings.HasPrefix(c.URL, "ldap://") && !c.StartTLS && !c.AllowPlaintext:
		// Every user password and the service account password cross this
		// connection; plain ldap:// sends them in clear.
		errs = append(errs, errors.New("url: ldap:// without start_tls sends passwords in clear; set start_tls, use ldaps://, or set allow_plaintext for a loopback or IPsec-protected directory"))
	}
	switch {
	case c.BindDNTemplate != "" && (c.BindDN != "" || c.BaseDN != "" || c.UserFilter != ""):
		errs = append(errs, errors.New("bind_dn_template is exclusive with bind_dn, base_dn and user_filter"))
	case c.BindDNTemplate != "":
		if !strings.Contains(c.BindDNTemplate, "%s") {
			errs = append(errs, errors.New("bind_dn_template: must contain %s for the username"))
		}
	default:
		if c.BaseDN == "" {
			errs = append(errs, errors.New("base_dn is required (or set bind_dn_template)"))
		}
		if c.UserFilter == "" {
			errs = append(errs, errors.New("user_filter is required (or set bind_dn_template)"))
		} else if !strings.Contains(c.UserFilter, "%s") {
			errs = append(errs, errors.New("user_filter: must contain %s for the username"))
		} else if _, err := ldap.ParseFilter(strings.ReplaceAll(c.UserFilter, "%s", "probe")); err != nil {
			errs = append(errs, fmt.Errorf("user_filter: %w", err))
		}
		if c.BindDN != "" && c.BindPasswordFile == "" {
			errs = append(errs, errors.New("bind_password_file is required with bind_dn"))
		}
	}
	if c.BindPasswordFile != "" {
		// The service account password must exist and not be readable by
		// everyone on the host (same rule as basic_auth users files).
		if st, err := os.Stat(c.BindPasswordFile); err != nil {
			errs = append(errs, fmt.Errorf("bind_password_file: %w", err))
		} else if st.Mode().Perm()&0o004 != 0 {
			errs = append(errs, fmt.Errorf("bind_password_file: %s must not be world readable", c.BindPasswordFile))
		}
	}
	if c.RequireGroup != "" && c.searchBind() && c.GroupAttr == "" {
		c.GroupAttr = "memberOf"
	}
	if c.RequireGroup != "" && !c.searchBind() {
		errs = append(errs, errors.New("require_group needs base_dn and user_filter, not bind_dn_template"))
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
	c.timeout = 5 * time.Second
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d < time.Second || d > time.Minute {
			errs = append(errs, errors.New("timeout: must be a duration between 1s and 1m"))
		} else {
			c.timeout = d
		}
	}
	if h := c.ForwardUserHeader; h != "" && strings.ContainsAny(h, " :\r\n") {
		errs = append(errs, fmt.Errorf("forward_user_header: %q is not a header name", h))
	}
	if c.InsecureSkipVerify && c.CAFile != "" {
		errs = append(errs, errors.New("insecure_skip_verify: exclusive with ca_file"))
	}
	return &c, errors.Join(errs...)
}

type auth struct {
	name         string
	cfg          *Config
	tls          *tls.Config
	bindPassword string
	log          *slog.Logger

	mu      sync.Mutex
	cache   map[[32]byte]cacheEntry
	sem     chan struct{}
	waiting atomic.Int32 // callers queued on sem
}

type cacheEntry struct {
	ok  bool
	exp time.Time
}

func (a *auth) Name() string { return a.name }

func (a *auth) Begin(context.Context, *filter.Info) filter.Instance { return &instance{a: a} }

type instance struct {
	a    *auth
	user string
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || pass == "" || !in.a.check(r.Context(), user, pass) {
		return filter.Verdict{Deny: true, Status: http.StatusUnauthorized, Reason: in.a.name, Detail: "credentials",
			Headers: map[string]string{"WWW-Authenticate": `Basic realm="` + in.a.cfg.Realm + `", charset="UTF-8"`}}
	}
	in.user = user
	filter.SetIdentity(r.Context(), "ldap", user)
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

// check verifies credentials against the directory, through the cache.
func (a *auth) check(ctx context.Context, user, pass string) bool {
	key := sha256.Sum256([]byte(a.cfg.URL + "\x00" + user + "\x00" + pass))
	now := time.Now()
	if a.cfg.ttl > 0 {
		a.mu.Lock()
		e, hit := a.cache[key]
		a.mu.Unlock()
		if hit && now.Before(e.exp) {
			return e.ok
		}
	}
	if !passwd.Acquire(ctx, a.sem, &a.waiting) {
		return false // the client left, or the queue is full: refused, not cached
	}
	ok, err := a.authenticate(user, pass)
	<-a.sem
	if err != nil {
		// A directory or network failure is not a credential decision; do
		// not cache it, and log so operators see an outage.
		a.log.Warn("ldap authentication error", "user", user, "err", err.Error())
		return false
	}
	if a.cfg.ttl > 0 {
		a.mu.Lock()
		if len(a.cache) >= 4096 {
			for k, e := range a.cache {
				if now.After(e.exp) {
					delete(a.cache, k)
				}
			}
			if len(a.cache) >= 4096 {
				a.cache = map[[32]byte]cacheEntry{}
			}
		}
		a.cache[key] = cacheEntry{ok: ok, exp: now.Add(a.cfg.ttl)}
		a.mu.Unlock()
	}
	return ok
}

// authenticate returns whether the credentials are valid. A nil error with
// false means the directory rejected them; a non-nil error means the check
// could not be completed (dial, protocol) and must not be cached.
func (a *auth) authenticate(user, pass string) (bool, error) {
	conn, err := ldap.Dial(ldap.Options{URL: a.cfg.URL, StartTLS: a.cfg.StartTLS, TLS: a.tls, Timeout: a.cfg.timeout})
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	if a.cfg.searchBind() {
		return a.searchBind(conn, user, pass)
	}
	return a.directBind(conn, user, pass)
}

// directBind binds straight as the templated user DN.
func (a *auth) directBind(conn *ldap.Conn, user, pass string) (bool, error) {
	dn := strings.ReplaceAll(a.cfg.BindDNTemplate, "%s", ldap.EscapeDN(user))
	if err := conn.Bind(dn, pass); err != nil {
		if errors.Is(err, ldap.ErrInvalidCredentials) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// searchBind binds a service account, finds the user entry, binds as it and
// checks the group requirement.
func (a *auth) searchBind(conn *ldap.Conn, user, pass string) (bool, error) {
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.bindPassword); err != nil {
			return false, fmt.Errorf("service bind: %w", err)
		}
	}
	filterStr := strings.ReplaceAll(a.cfg.UserFilter, "%s", ldap.EscapeFilter(user))
	f, err := ldap.ParseFilter(filterStr)
	if err != nil {
		return false, err
	}
	var attrs []string
	if a.cfg.RequireGroup != "" {
		attrs = []string{a.cfg.GroupAttr}
	}
	entries, err := conn.Search(a.cfg.BaseDN, ldap.ScopeSub, f, attrs, 2)
	if err != nil {
		return false, err
	}
	if len(entries) != 1 {
		// Zero: no such user. More than one: ambiguous, refuse.
		return false, nil
	}
	entry := entries[0]
	if err := conn.Bind(entry.DN, pass); err != nil {
		if errors.Is(err, ldap.ErrInvalidCredentials) {
			return false, nil
		}
		return false, err
	}
	if a.cfg.RequireGroup != "" && !hasGroup(entry.Attrs[a.cfg.GroupAttr], a.cfg.RequireGroup) {
		return false, nil
	}
	return true, nil
}

// hasGroup reports whether want is among the group values, comparing DNs
// case-insensitively as directories treat them.
func hasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g), want) {
			return true
		}
	}
	return false
}

// buildTLS assembles the client TLS configuration from the config.
func buildTLS(c *Config) (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in only, guarded by validation and documented
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: no certificates found")
		}
		t.RootCAs = pool
	}
	return t, nil
}

func init() {
	filter.Register(filter.Kind{
		Name:        "ldap_auth",
		Description: "HTTP Basic authentication against an LDAP or Active Directory server.",
		Validate: func(opts filter.Options) error {
			c, err := parse(opts)
			if err != nil {
				return err
			}
			_, err = buildTLS(c)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			tlsCfg, err := buildTLS(c)
			if err != nil {
				return nil, err
			}
			a := &auth{name: name, cfg: c, tls: tlsCfg, log: env.Log, cache: map[[32]byte]cacheEntry{}, sem: make(chan struct{}, 8)}
			if c.BindPasswordFile != "" {
				b, err := os.ReadFile(c.BindPasswordFile)
				if err != nil {
					return nil, fmt.Errorf("bind_password_file: %w", err)
				}
				a.bindPassword = strings.TrimRight(string(b), "\r\n")
			}
			return a, nil
		},
	})
}
