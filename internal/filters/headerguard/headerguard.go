// Package headerguard is a built-in filter kind that requires or denies
// requests by header contents. It is the reference extension: pure, no
// state, options validated at load.
//
//	filters:
//	  - name: api-key
//	    kind: header_guard
//	    options:
//	      require:                       # every rule must match
//	        - {header: X-API-Key, pattern: "^[a-f0-9]{32}$"}
//	      deny:                          # any match denies
//	        - {header: User-Agent, pattern: "(?i)sqlmap|nikto|masscan"}
//	      status: 403                    # default 403
//	      reason: api_key                # deny reason in logs; default the filter name
package headerguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/rom/xproxy/internal/filter"
)

// Rule is one header pattern.
type Rule struct {
	Header  string `json:"header"`
	Pattern string `json:"pattern"`
	re      *regexp.Regexp
}

// Config is the options schema.
type Config struct {
	Require []Rule `json:"require"`
	Deny    []Rule `json:"deny"`
	Status  int    `json:"status"`
	Reason  string `json:"reason"`
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if len(c.Require) == 0 && len(c.Deny) == 0 {
		errs = append(errs, errors.New("require or deny must have at least one rule"))
	}
	compile := func(list []Rule, what string) {
		for i := range list {
			r := &list[i]
			if r.Header == "" || strings.ContainsAny(r.Header, " :\r\n") {
				errs = append(errs, fmt.Errorf("%s[%d].header: %q is not a header name", what, i, r.Header))
			}
			if len(r.Pattern) > 1024 {
				errs = append(errs, fmt.Errorf("%s[%d].pattern: too long", what, i))
				continue
			}
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s[%d].pattern: %w", what, i, err))
				continue
			}
			r.re = re
		}
	}
	compile(c.Require, "require")
	compile(c.Deny, "deny")
	if c.Status == 0 {
		c.Status = http.StatusForbidden
	}
	if c.Status < 400 || c.Status > 499 {
		errs = append(errs, fmt.Errorf("status: %d must be a 4xx code", c.Status))
	}
	return &c, errors.Join(errs...)
}

type guard struct {
	name string
	cfg  *Config
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance { return g }

func (g *guard) Request(r *http.Request) filter.Verdict {
	for i := range g.cfg.Deny {
		rule := &g.cfg.Deny[i]
		if rule.re.MatchString(r.Header.Get(rule.Header)) {
			return g.deny("denied by " + rule.Header)
		}
	}
	for i := range g.cfg.Require {
		rule := &g.cfg.Require[i]
		if !rule.re.MatchString(r.Header.Get(rule.Header)) {
			return g.deny("required " + rule.Header)
		}
	}
	return filter.Continue
}

func (g *guard) deny(detail string) filter.Verdict {
	return filter.Verdict{Deny: true, Status: g.cfg.Status, Reason: g.cfg.Reason, Detail: detail}
}

func (g *guard) Response(*http.Response) filter.Verdict { return filter.Continue }

func (g *guard) End() []any { return nil }

func init() {
	filter.Register(filter.Kind{
		Name:        "header_guard",
		Description: "Require or deny requests by header patterns.",
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
			return &guard{name: name, cfg: c}, nil
		},
	})
}
