// Package openapi is a built-in filter kind that validates requests
// against an OpenAPI 3 description before they reach the API: the path
// must exist, the method must be defined for it, required parameters
// must be present and typed, the content type must be one the operation
// declares and a JSON body must satisfy its schema. Unknown paths and
// methods are refused, so the API surface an attacker can probe is the
// documented one.
//
//	filters:
//	  - name: orders-api
//	    kind: openapi
//	    options:
//	      spec_file: /etc/xproxy/openapi/orders.yaml   # OpenAPI 3.0 or 3.1, JSON or YAML
//	      base_path: /api                              # default: from servers[0].url
//	      unknown_paths: deny                          # or allow; default deny
//	      strict_query: false                          # deny undeclared query parameters; default false
//	      validate_body: true                          # default true
//	      max_body_bytes: 1048576                      # bodies above this are refused; default 1 MiB
package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/jsonschema"
	"github.com/rom/xproxy/internal/netutil"
)

// Config is the options schema.
type Config struct {
	// SpecFile is the description on disk, re-read when it changes;
	// SpecURL fetches it over HTTPS and refreshes it in the background.
	// Exactly one is set.
	SpecFile string `json:"spec_file"`
	SpecURL  string `json:"spec_url"`
	// Refresh is how often the file is checked for a change (default
	// 30s) or the URL fetched again (default 5m).
	Refresh string `json:"refresh"`
	// Timeout bounds one fetch. Default 10s.
	Timeout string `json:"timeout"`
	// CAFile verifies the URL's server with a private CA.
	CAFile string `json:"ca_file"`
	// CacheFile keeps the last good fetched description, used when the
	// URL is unreachable at start.
	CacheFile    string `json:"cache_file"`
	BasePath     string `json:"base_path"`
	UnknownPaths string `json:"unknown_paths"`
	StrictQuery  bool   `json:"strict_query"`
	ValidateBody *bool  `json:"validate_body"`
	MaxBodyBytes int64  `json:"max_body_bytes"`
	// RequireSecurity refuses a request that does not carry a credential
	// the operation's security section asks for. Default false, because
	// turning it on refuses whatever was reaching the API without one.
	RequireSecurity bool `json:"require_security"`
	// ReadOnly is what to do with a body that carries a property the
	// description marks readOnly: allow (default), log or deny.
	ReadOnly string `json:"read_only"`
	refresh  time.Duration
	timeout  time.Duration
}

const (
	defaultMaxBody = 1 << 20
	maxSpecBytes   = 32 << 20
)

// parse decodes and checks the options; the description itself is
// loaded by newGuard (and, for a file, checked at validation too).
func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	switch {
	case c.SpecFile != "" && c.SpecURL != "":
		errs = append(errs, errors.New("spec_file and spec_url are exclusive"))
	case c.SpecFile != "":
		if !strings.HasPrefix(c.SpecFile, "/") {
			errs = append(errs, errors.New("spec_file: an absolute path is required"))
		}
	case c.SpecURL != "":
		if !specURLOK(c.SpecURL) {
			errs = append(errs, errors.New("spec_url: must be an https URL (plain http only to localhost)"))
		}
	default:
		errs = append(errs, errors.New("spec_file or spec_url is required"))
	}
	switch c.ReadOnly {
	case "", "allow", "log", "deny":
	default:
		errs = append(errs, errors.New("read_only: must be allow, log or deny"))
	}
	if c.CAFile != "" && !strings.HasPrefix(c.CAFile, "/") {
		errs = append(errs, errors.New("ca_file: must be an absolute path"))
	}
	if c.CacheFile != "" && (!strings.HasPrefix(c.CacheFile, "/") || c.SpecURL == "") {
		errs = append(errs, errors.New("cache_file: an absolute path, only with spec_url"))
	}
	c.refresh = 30 * time.Second
	if c.SpecURL != "" {
		c.refresh = 5 * time.Minute
	}
	if c.Refresh != "" {
		d, err := time.ParseDuration(c.Refresh)
		if err != nil || d < time.Second || d > 24*time.Hour {
			errs = append(errs, errors.New("refresh: must be a duration between 1s and 24h"))
		} else {
			c.refresh = d
		}
	}
	c.timeout = 10 * time.Second
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d < time.Second || d > time.Minute {
			errs = append(errs, errors.New("timeout: must be a duration between 1s and 1m"))
		} else {
			c.timeout = d
		}
	}
	if c.ReadOnly == "" {
		c.ReadOnly = "allow"
	}
	switch c.UnknownPaths {
	case "":
		c.UnknownPaths = "deny"
	case "deny", "allow":
	default:
		errs = append(errs, errors.New("unknown_paths: must be deny or allow"))
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaultMaxBody
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 64<<20 {
		errs = append(errs, errors.New("max_body_bytes: must be between 1 and 67108864"))
	}
	if c.BasePath != "" && (!strings.HasPrefix(c.BasePath, "/") || strings.HasSuffix(c.BasePath, "/")) {
		errs = append(errs, errors.New("base_path: must start with / and not end with one"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &c, nil
}

// specURLOK accepts https anywhere and plain http to the local host.
func specURLOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	return u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")
}

// validate checks the options and, for a file, that the description
// compiles, so a broken file fails the configuration load.
func validate(opts filter.Options) error {
	c, err := parse(opts)
	if err != nil {
		return err
	}
	if c.SpecFile != "" {
		if _, err := loadSpec(c.SpecFile, c.BasePath); err != nil {
			return fmt.Errorf("spec_file: %w", err)
		}
	}
	return nil
}

// api is the compiled description.
type api struct {
	v        *jsonschema.Validator
	basePath string
	exact    map[string]*pathItem
	templ    []*pathItem // templated paths, longest literal prefix first
	// secured is the number of operations the description asks for a
	// credential on, so an operator can be told when the description
	// carries a control the filter is not being asked to apply.
	secured int
}

type pathItem struct {
	template string
	re       *regexp.Regexp
	params   []string // template parameter names in order
	ops      map[string]*operation
}

type operation struct {
	params   []parameter
	body     *requestBody
	declared map[string]bool // query parameter names
	// security is the credential alternatives the description asks for,
	// any one of which satisfies the operation; anonymous says one of
	// them was the empty object, which is how OpenAPI says the
	// credential is optional.
	security  []requirement
	anonymous bool
}

type parameter struct {
	name, in string
	required bool
	schema   map[string]any
	// style and explode are how the value is spelled on the wire: an
	// array may arrive repeated, comma-separated, pipe-separated or
	// space-separated, and an object may arrive as bracketed names.
	style   string
	explode bool
}

type requestBody struct {
	required bool
	content  map[string]any // media type -> schema
}

// loadSpec reads and compiles a JSON or YAML document from a file.
func loadSpec(path, basePath string) (*api, error) {
	data, err := os.ReadFile(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	return compileSpec(data, basePath)
}

// compileSpec compiles a JSON or YAML document.
func compileSpec(data []byte, basePath string) (*api, error) {
	if len(data) > maxSpecBytes {
		return nil, errors.New("larger than 32 MiB")
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	spec, ok := jsonschema.Jsonify(doc).(map[string]any)
	if !ok {
		return nil, errors.New("not a document")
	}
	ver, _ := spec["openapi"].(string)
	if !strings.HasPrefix(ver, "3.") {
		return nil, fmt.Errorf("openapi version %q is not 3.x", ver)
	}
	a := &api{v: jsonschema.New(spec), exact: map[string]*pathItem{}, basePath: basePath}
	if basePath == "" {
		if servers, _ := spec["servers"].([]any); len(servers) > 0 {
			if s, _ := servers[0].(map[string]any); s != nil {
				if u, _ := s["url"].(string); u != "" {
					if i := strings.Index(u, "://"); i >= 0 {
						u = u[i+3:]
						if j := strings.IndexByte(u, '/'); j >= 0 {
							u = u[j:]
						} else {
							u = ""
						}
					}
					a.basePath = strings.TrimSuffix(u, "/")
				}
			}
		}
	}
	schemes, err := compileSchemes(spec)
	if err != nil {
		return nil, err
	}
	globalSec, globalAnon, err := compileRequirements(spec["security"], schemes, "security")
	if err != nil {
		return nil, err
	}
	paths, _ := spec["paths"].(map[string]any)
	if len(paths) == 0 {
		return nil, errors.New("no paths")
	}
	globalParams := []parameter{}
	for p, node := range paths {
		item, _ := node.(map[string]any)
		if item == nil || !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("path %q is not valid", p)
		}
		pi := &pathItem{template: p, ops: map[string]*operation{}}
		if strings.Contains(p, "{") {
			re, names, err := compileTemplate(p)
			if err != nil {
				return nil, err
			}
			pi.re, pi.params = re, names
		}
		shared := append([]parameter{}, globalParams...)
		if ps, _ := item["parameters"].([]any); ps != nil {
			shared = append(shared, a.parameters(ps)...)
		}
		for method, opNode := range item {
			m := strings.ToUpper(method)
			switch m {
			case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE":
			default:
				continue
			}
			opm, _ := opNode.(map[string]any)
			op := &operation{declared: map[string]bool{}}
			op.params = append(op.params, shared...)
			if ps, _ := opm["parameters"].([]any); ps != nil {
				op.params = append(op.params, a.parameters(ps)...)
			}
			for _, prm := range op.params {
				if prm.in == "query" {
					op.declared[prm.name] = true
				}
			}
			// An operation's own security replaces the global one
			// entirely, and an explicit empty list means this operation
			// needs nothing -- which is different from not saying.
			op.security, op.anonymous = globalSec, globalAnon
			if _, declared := opm["security"]; declared {
				reqs, anon, err := compileRequirements(opm["security"], schemes, m+" "+p)
				if err != nil {
					return nil, err
				}
				op.security, op.anonymous = reqs, anon
			}
			if len(op.security) > 0 && !op.anonymous {
				a.secured++
			}
			if rb := a.v.Resolve(opm["requestBody"]); rb != nil && len(rb.Raw) > 0 {
				req, _ := rb.Raw["required"].(bool)
				body := &requestBody{required: req, content: map[string]any{}}
				if content, _ := rb.Raw["content"].(map[string]any); content != nil {
					for mt, mtNode := range content {
						mtm, _ := mtNode.(map[string]any)
						body.content[strings.ToLower(mt)] = mtm["schema"]
					}
				}
				op.body = body
			}
			pi.ops[m] = op
		}
		if pi.re == nil {
			a.exact[p] = pi
		} else {
			a.templ = append(a.templ, pi)
		}
	}
	// Concrete paths win over templated ones; among templates the one
	// with the longest literal prefix.
	sort.SliceStable(a.templ, func(i, j int) bool {
		return literalPrefix(a.templ[i].template) > literalPrefix(a.templ[j].template)
	})
	return a, nil
}

func literalPrefix(t string) int {
	if i := strings.IndexByte(t, '{'); i >= 0 {
		return i
	}
	return len(t)
}

func compileTemplate(p string) (*regexp.Regexp, []string, error) {
	var b strings.Builder
	var names []string
	b.WriteString("^")
	for len(p) > 0 {
		i := strings.IndexByte(p, '{')
		if i < 0 {
			b.WriteString(regexp.QuoteMeta(p))
			break
		}
		b.WriteString(regexp.QuoteMeta(p[:i]))
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			return nil, nil, fmt.Errorf("path %q: unterminated parameter", p)
		}
		names = append(names, p[i+1:i+j])
		b.WriteString("([^/]+)")
		p = p[i+j+1:]
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return re, names, err
}

func (a *api) parameters(list []any) []parameter {
	out := make([]parameter, 0, len(list))
	for _, node := range list {
		m := a.v.Resolve(node).Raw
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if name == "" || in == "" {
			continue
		}
		req, _ := m["required"].(bool)
		if in == "path" {
			req = true
		}
		schema, _ := m["schema"].(map[string]any)
		if schema == nil {
			if content, _ := m["content"].(map[string]any); content != nil {
				for _, mt := range content {
					if mtm, _ := mt.(map[string]any); mtm != nil {
						schema, _ = mtm["schema"].(map[string]any)
					}
				}
			}
		}
		style, explode := styleOf(m, in)
		out = append(out, parameter{name: name, in: in, required: req, schema: schema, style: style, explode: explode})
	}
	return out
}

// match finds the operation for a method and path.
func (a *api) match(method, path string) (*pathItem, map[string]string, bool) {
	if a.basePath != "" {
		rest, ok := strings.CutPrefix(path, a.basePath)
		if !ok || rest != "" && rest[0] != '/' {
			return nil, nil, false
		}
		path = rest
		if path == "" {
			path = "/"
		}
	}
	if pi, ok := a.exact[path]; ok {
		return pi, nil, true
	}
	for _, pi := range a.templ {
		if m := pi.re.FindStringSubmatch(path); m != nil {
			vals := map[string]string{}
			for i, n := range pi.params {
				vals[n] = m[i+1]
			}
			return pi, vals, true
		}
	}
	_ = method
	return nil, nil, false
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance {
	return &instance{g: g, api: g.current()}
}

// Documented reports whether method and path match a documented
// operation and returns its path template (the API inventory uses it
// to tell shadow endpoints from documented ones).
func (g *guard) Documented(method, path string) (string, bool) {
	a := g.current()
	pi, _, ok := a.match(method, path)
	if !ok {
		return "", false
	}
	m := method
	if m == http.MethodHead {
		if _, has := pi.ops["HEAD"]; !has {
			m = http.MethodGet
		}
	}
	if _, has := pi.ops[m]; !has {
		return "", false
	}
	return a.basePath + pi.template, true
}

// Operations lists every documented method and path template.
func (g *guard) Operations() []apiinv.Operation {
	a := g.current()
	var out []apiinv.Operation
	add := func(pi *pathItem) {
		for m := range pi.ops {
			out = append(out, apiinv.Operation{Method: m, Path: a.basePath + pi.template})
		}
	}
	for _, pi := range a.exact {
		add(pi)
	}
	for _, pi := range a.templ {
		add(pi)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

type instance struct {
	g   *guard
	api *api // the description current when the request began
	// readOnlySeen are the readOnly properties a body carried under
	// read_only: log, reported through End.
	readOnlySeen []string
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	// The cleaned path, as routing sees it: "/api/users/../admin" or
	// "/api//users" must not slip past the description as an unknown path
	// while the upstream router serves the documented operation.
	pi, pathVals, ok := in.api.match(r.Method, netutil.CleanPath(r.URL.Path))
	if !ok {
		if g.cfg.UnknownPaths == "allow" {
			return filter.Continue
		}
		return in.deny(http.StatusNotFound, "unknown_path", nil)
	}
	method := r.Method
	if method == http.MethodHead {
		if _, has := pi.ops["HEAD"]; !has {
			method = http.MethodGet
		}
	}
	op, has := pi.ops[method]
	if !has {
		allowed := make([]string, 0, len(pi.ops))
		for m := range pi.ops {
			allowed = append(allowed, m)
		}
		sort.Strings(allowed)
		v := in.deny(http.StatusMethodNotAllowed, "method", nil)
		v.Headers = map[string]string{"Allow": strings.Join(allowed, ", ")}
		return v
	}
	// The credential the description asks for, before anything else is
	// read: an operation the application forgot to protect is refused
	// here rather than answered there, and a request with nothing to
	// authenticate with is not worth validating a body for.
	if g.cfg.RequireSecurity {
		if want, ok := op.credential(r); !ok {
			v := in.deny(http.StatusUnauthorized, "security", nil)
			v.Attrs = []any{"security_schemes", describe(want)}
			if ch := challenge(want); ch != "" {
				v.Headers = map[string]string{"WWW-Authenticate": ch}
			}
			return v
		}
	}
	rep := &jsonschema.Report{}
	query := r.URL.Query()
	for _, p := range op.params {
		// Every value a parameter carries is judged, not only the first.
		// A repeated query parameter is read differently by everything
		// behind the proxy — PHP and Rails take the last value, ASP.NET
		// joins them with commas, Spring binds an array — so
		// "?limit=10&limit=999" used to reach the application with a
		// value nothing had type-checked, range-checked or
		// pattern-checked, while the whole query was forwarded
		// untouched. The proxy's own routes[].policy already judges
		// every value; these two parsers disagreed about what the value
		// of a parameter is.
		switch p.in {
		case "path", "query", "header", "cookie":
		default:
			continue
		}
		vals, present := in.values(p, r, query, pathVals)
		where := p.in + "." + p.name
		if !present {
			if p.required {
				rep.Add(where, "is required")
			}
			continue
		}
		if p.schema != nil {
			for _, val := range vals {
				in.api.v.Validate(p.schema, val, where, rep, 0)
			}
		}
	}
	if g.cfg.StrictQuery {
		// A deepObject parameter's values arrive under names that are not
		// its name -- filter[from], filter[to] -- so the prefixes count
		// as declared, or strict_query would refuse the very shape the
		// description asked for.
		prefixes := deepPrefixes(op)
		for name := range query {
			if op.declared[name] || hasAnyPrefix(name, prefixes) {
				continue
			}
			rep.Add("query."+name, "is not a parameter of this operation")
		}
	}
	if op.body != nil && (g.cfg.ValidateBody == nil || *g.cfg.ValidateBody) {
		if v := in.checkBody(r, op.body, rep); v != nil {
			return *v
		}
	}
	if len(rep.Issues) > 0 {
		return in.deny(http.StatusBadRequest, "schema", rep.Issues)
	}
	return filter.Continue
}

// checkBody validates the request body; it returns a verdict for
// problems that are not schema issues (size, media type).
func (in *instance) checkBody(r *http.Request, body *requestBody, rep *jsonschema.Report) *filter.Verdict {
	g := in.g
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	if !hasBody {
		if body.required {
			rep.Add("body", "is required")
		}
		return nil
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	schema, ok := body.content[ct]
	if !ok {
		// A wildcard such as application/* or */*.
		for mt, s := range body.content {
			if strings.HasSuffix(mt, "/*") && strings.HasPrefix(ct, strings.TrimSuffix(mt, "*")) || mt == "*/*" {
				schema, ok = s, true
				break
			}
		}
	}
	if !ok {
		v := in.deny(http.StatusUnsupportedMediaType, "media_type", nil)
		return &v
	}
	if !isJSON(ct) && !isForm(ct) {
		// Everything else is somebody else's filter: a multipart upload
		// is upload_guard's, and an opaque media type has no schema to
		// check it against.
		return nil
	}
	if r.ContentLength > g.cfg.MaxBodyBytes {
		v := in.deny(http.StatusRequestEntityTooLarge, "body_size", nil)
		return &v
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, g.cfg.MaxBodyBytes+1))
	if err != nil {
		v := in.deny(http.StatusBadRequest, "body_read", nil)
		return &v
	}
	if int64(len(data)) > g.cfg.MaxBodyBytes {
		v := in.deny(http.StatusRequestEntityTooLarge, "body_size", nil)
		return &v
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if schema == nil {
		return nil
	}
	var value any
	if isForm(ct) {
		// A form carries strings, so each field is coerced by what the
		// schema says it is -- the same treatment the query parameters
		// get, and for the same reason.
		form, ok := formValue(data, schema, in.api.v)
		if !ok {
			rep.Add("body", "is not a readable form")
			return nil
		}
		value = form
	} else {
		v, err := jsonschema.Decode(data)
		if err != nil {
			rep.Add("body", "%s", err.Error())
			return nil
		}
		value = v
	}
	in.api.v.Validate(schema, value, "body", rep, 0)
	if g.cfg.ReadOnly != "allow" {
		ro := &jsonschema.Report{}
		visits := 0
		in.api.readOnly(schema, value, "body", ro, &visits, 0)
		switch {
		case len(ro.Issues) == 0:
		case g.cfg.ReadOnly == "deny":
			v := in.deny(http.StatusBadRequest, "read_only", ro.Issues)
			return &v
		default:
			// log: the request goes on and the access log says what was
			// sent, which is how an operator finds out whether deny
			// would break their clients before turning it on.
			for _, iss := range ro.Issues {
				in.readOnlySeen = append(in.readOnlySeen, iss.Path)
			}
		}
	}
	return nil
}

func (in *instance) deny(status int, detail string, issues []jsonschema.Issue) filter.Verdict {
	msg := map[string]any{"error": "request does not match the API description", "reason": detail}
	if len(issues) > 0 {
		msg["details"] = issues
	}
	body, _ := json.Marshal(msg)
	resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
	v := filter.Verdict{Deny: true, Status: status, Reason: in.g.name, Detail: detail, Response: resp}
	if len(issues) > 0 {
		v.Detail = detail + ":" + issues[0].Path
	}
	return v
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if len(in.readOnlySeen) == 0 {
		return nil
	}
	return []any{"openapi_read_only", strings.Join(in.readOnlySeen, ",")}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "openapi",
		Description: "request validation against an OpenAPI 3 description: paths, methods, parameters, media types and JSON bodies",
		BuffersBody: true,
		Validate:    validate,
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			cfg, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return newGuard(name, cfg, env)
		},
	})
}
