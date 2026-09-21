// Package authz is a built-in filter kind that decides what a verified
// identity may do.
//
//	filters:
//	  - name: policy
//	    kind: authz
//	    options:
//	      default: deny                 # deny (the default) or allow
//	      require_authenticated: true   # an anonymous request matches no rule
//	      rules:
//	        - name: read-orders
//	          allow: true
//	          methods: [GET, HEAD]
//	          paths: [/v1/orders, /v1/orders/**]
//	          scopes: [orders:read]
//	        - name: admin
//	          allow: true
//	          groups: ["cn=admins,ou=groups,dc=example,dc=com"]
//	        - name: no-deletes-from-the-field
//	          allow: false
//	          methods: [DELETE]
//	          not_networks: ["10.0.0.0/8"]
//
// Every authenticating filter here answers "who". None of them answers
// "what may they do", so each grew its own small allow list — required
// scopes on the API key, a required group on the directory bind, claims
// on the session — and an allow list per filter is a policy nobody can
// read in one place. This reads the identity those filters verified and
// decides once, where the decision can be seen.
//
// It decides nothing on its own authority: the subject, the groups, the
// scopes and the claims all come from a filter that verified them, so a
// header a client sent cannot reach a rule here. Which also means the
// filter must run after the ones that authenticate — on a route whose
// filter list puts it first, there is nothing to decide about, which is
// what require_authenticated exists to make obvious.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/rom/xproxy/internal/filter"
)

// Config is the options schema.
type Config struct {
	Default              string `json:"default"`
	RequireAuthenticated *bool  `json:"require_authenticated"`
	Rules                []Rule `json:"rules"`
	// ForwardGroupsHeader and ForwardScopesHeader pass what was decided
	// on to the backend, so it does not have to ask again. They are set
	// by the proxy and any client value is removed first.
	ForwardGroupsHeader string `json:"forward_groups_header"`
	ForwardScopesHeader string `json:"forward_scopes_header"`
	// Status answers a refusal: 403 (the default) says the request was
	// understood and refused, 404 says nothing at all.
	Status int `json:"status"`
}

// Rule is one decision. Every selector a rule names has to hold; a rule
// that names none matches everything, which is how a catch-all is
// written.
type Rule struct {
	Name     string            `json:"name"`
	Allow    bool              `json:"allow"`
	Methods  []string          `json:"methods"`
	Paths    []string          `json:"paths"`
	Subjects []string          `json:"subjects"`
	Groups   []string          `json:"groups"`
	Scopes   []string          `json:"scopes"`
	Kinds    []string          `json:"kinds"`
	Claims   map[string]string `json:"claims"`
	Networks []string          `json:"networks"`
	// The negative forms, which say "everybody but". They are separate
	// keys rather than a "!" prefix because a group name can start with
	// anything.
	NotSubjects []string `json:"not_subjects"`
	NotGroups   []string `json:"not_groups"`
	NotNetworks []string `json:"not_networks"`

	methods  map[string]bool
	subjects map[string]bool
	groups   map[string]bool
	scopes   map[string]bool
	kinds    map[string]bool
	notSubj  map[string]bool
	notGroup map[string]bool
	nets     []netip.Prefix
	notNets  []netip.Prefix
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.Default == "" {
		c.Default = "deny"
	}
	if c.Default != "deny" && c.Default != "allow" {
		errs = append(errs, errors.New("default: must be deny or allow"))
	}
	if c.RequireAuthenticated == nil {
		t := true
		c.RequireAuthenticated = &t
	}
	if c.Status == 0 {
		c.Status = http.StatusForbidden
	}
	if c.Status != http.StatusForbidden && c.Status != http.StatusNotFound {
		errs = append(errs, errors.New("status: must be 403 or 404"))
	}
	if len(c.Rules) == 0 {
		errs = append(errs, errors.New("rules: at least one is required"))
	}
	names := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		where := fmt.Sprintf("rules[%d]", i)
		if r.Name == "" {
			errs = append(errs, fmt.Errorf("%s.name: required; it is what a decision is logged as", where))
		} else if names[r.Name] {
			errs = append(errs, fmt.Errorf("%s.name: %q is used twice", where, r.Name))
		}
		names[r.Name] = true
		r.methods = upperSet(r.Methods)
		r.subjects = set(r.Subjects)
		r.groups = foldSet(r.Groups)
		r.scopes = set(r.Scopes)
		r.kinds = set(r.Kinds)
		r.notSubj = set(r.NotSubjects)
		r.notGroup = foldSet(r.NotGroups)
		for j, m := range r.Methods {
			if strings.TrimSpace(m) == "" {
				errs = append(errs, fmt.Errorf("%s.methods[%d]: empty", where, j))
			}
		}
		for j, p := range r.Paths {
			if p == "" || !strings.HasPrefix(p, "/") {
				errs = append(errs, fmt.Errorf("%s.paths[%d]: %q must begin with /", where, j, p))
			}
		}
		for _, l := range []struct {
			key  string
			list []string
			out  *[]netip.Prefix
		}{{"networks", r.Networks, &r.nets}, {"not_networks", r.NotNetworks, &r.notNets}} {
			for j, n := range l.list {
				p, err := netip.ParsePrefix(n)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s.%s[%d]: %q is not a CIDR", where, l.key, j, n))
					continue
				}
				*l.out = append(*l.out, p)
			}
		}
		if r.Allow && len(r.Methods) == 0 && len(r.Paths) == 0 && len(r.Subjects) == 0 &&
			len(r.Groups) == 0 && len(r.Scopes) == 0 && len(r.Kinds) == 0 &&
			len(r.Claims) == 0 && len(r.Networks) == 0 &&
			len(r.NotSubjects) == 0 && len(r.NotGroups) == 0 && len(r.NotNetworks) == 0 {
			// A rule with no selectors matches every request. As a deny
			// that is a legitimate backstop; as an allow it is a policy
			// that says yes to everything, which is worth having to
			// write as default: allow instead of hiding in a list.
			errs = append(errs, fmt.Errorf("%s: an allow rule with no selectors allows everything; write default: allow if that is what is meant", where))
		}
	}
	return &c, errors.Join(errs...)
}

func set(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

func upperSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	return m
}

// foldSet is for group names, which directories treat without regard to
// case and which an operator will write either way.
func foldSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}

type policy struct {
	name string
	cfg  *Config
	log  *slog.Logger

	allowed atomic.Uint64
	refused atomic.Uint64
}

func (p *policy) Name() string { return p.name }

func (p *policy) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{p: p, ip: info.ClientIP}
}

type instance struct {
	p    *policy
	ip   netip.Addr
	rule string
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	p := in.p
	id := filter.IdentityFrom(r.Context())
	subject := id.Any()
	if *p.cfg.RequireAuthenticated && subject == "" {
		// Nothing has been verified, so there is nothing to decide
		// about. Refusing is the only honest answer: the alternative
		// is deciding on values a client supplied.
		p.refused.Add(1)
		in.rule = "unauthenticated"
		return in.deny(r, "unauthenticated")
	}
	groups := id.Groups()
	scopes := id.Scopes()
	kinds := id.Kinds()
	for i := range p.cfg.Rules {
		rule := &p.cfg.Rules[i]
		if !in.matches(rule, r, id, subject, groups, scopes, kinds) {
			continue
		}
		in.rule = rule.Name
		if !rule.Allow {
			p.refused.Add(1)
			return in.deny(r, rule.Name)
		}
		p.allowed.Add(1)
		in.forward(r, groups, scopes)
		return filter.Continue
	}
	if p.cfg.Default == "allow" {
		in.rule = "default"
		p.allowed.Add(1)
		in.forward(r, groups, scopes)
		return filter.Continue
	}
	in.rule = "default"
	p.refused.Add(1)
	return in.deny(r, "default")
}

// matches applies one rule. Every selector it names has to hold.
func (in *instance) matches(rule *Rule, r *http.Request, id *filter.Identity,
	subject string, groups, scopes, kinds []string) bool {
	switch {
	case rule.methods != nil && !rule.methods[strings.ToUpper(r.Method)]:
		return false
	case len(rule.Paths) > 0 && !matchPath(rule.Paths, r.URL.Path):
		return false
	case rule.subjects != nil && !rule.subjects[subject]:
		return false
	case rule.notSubj != nil && rule.notSubj[subject]:
		return false
	case rule.groups != nil && !anyIn(rule.groups, groups, true):
		return false
	case rule.notGroup != nil && anyIn(rule.notGroup, groups, true):
		return false
	case rule.scopes != nil && !allIn(rule.scopes, scopes):
		return false
	case rule.kinds != nil && !anyIn(rule.kinds, kinds, false):
		return false
	case len(rule.nets) > 0 && !inAny(rule.nets, in.ip):
		return false
	case len(rule.notNets) > 0 && inAny(rule.notNets, in.ip):
		return false
	}
	for name, want := range rule.Claims {
		if id.Claim(name) != want {
			return false
		}
	}
	return true
}

// anyIn reports whether the identity carries any of the wanted values.
// Groups are compared without regard to case, as directories treat
// them.
func anyIn(want map[string]bool, have []string, fold bool) bool {
	for _, h := range have {
		if fold {
			h = strings.ToLower(strings.TrimSpace(h))
		}
		if want[h] {
			return true
		}
	}
	return false
}

// allIn reports whether the identity carries every wanted value, which
// is what scopes mean: a credential that carries two of the three a
// rule names does not satisfy it.
func allIn(want map[string]bool, have []string) bool {
	got := make(map[string]bool, len(have))
	for _, h := range have {
		got[h] = true
	}
	for w := range want {
		if !got[w] {
			return false
		}
	}
	return true
}

func inAny(nets []netip.Prefix, ip netip.Addr) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// matchPath compares a request path against a rule's paths. A pattern
// ending in "/**" covers a tree; otherwise it is the path exactly. A
// prefix that is not a path boundary is not a match: "/v1/orders" must
// not cover "/v1/orders-internal".
func matchPath(patterns []string, path string) bool {
	for _, p := range patterns {
		switch {
		case strings.HasSuffix(p, "/**"):
			base := strings.TrimSuffix(p, "/**")
			if path == base || strings.HasPrefix(path, base+"/") {
				return true
			}
		case p == path:
			return true
		}
	}
	return false
}

// forward passes what was decided on to the backend, so it does not
// have to ask again. Any value the client sent under those names was
// removed before the decision, not after.
func (in *instance) forward(r *http.Request, groups, scopes []string) {
	if h := in.p.cfg.ForwardGroupsHeader; h != "" {
		r.Header.Del(h)
		if len(groups) > 0 {
			r.Header.Set(h, strings.Join(groups, ","))
		}
	}
	if h := in.p.cfg.ForwardScopesHeader; h != "" {
		r.Header.Del(h)
		if len(scopes) > 0 {
			r.Header.Set(h, strings.Join(scopes, " "))
		}
	}
}

func (in *instance) deny(r *http.Request, rule string) filter.Verdict {
	p := in.p
	// The client is told it was refused and nothing about why: which
	// rule, which group it would have needed and whether the path even
	// exists are all things a prober would like to know.
	p.log.Info("authorisation refused", "filter", p.name, "rule", rule,
		"method", r.Method, "path", r.URL.Path,
		"subject", filter.IdentityFrom(r.Context()).Any())
	return filter.Verdict{Deny: true, Status: p.cfg.Status,
		Reason: p.name, Detail: "rule:" + rule}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

// End names the rule that decided, which is the only way an operator
// can tell a policy that allowed from one that never matched.
func (in *instance) End() []any {
	if in.rule == "" {
		return nil
	}
	return []any{"authz_rule", in.rule}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "authz",
		Description: "Decides what a verified identity may do: subjects, groups, scopes, claims, methods, paths.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return &policy{name: name, cfg: c, log: env.Log}, nil
		},
	})
}
