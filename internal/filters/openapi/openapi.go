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
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/jsonschema"
)

// Config is the options schema.
type Config struct {
	SpecFile     string `json:"spec_file"`
	BasePath     string `json:"base_path"`
	UnknownPaths string `json:"unknown_paths"`
	StrictQuery  bool   `json:"strict_query"`
	ValidateBody *bool  `json:"validate_body"`
	MaxBodyBytes int64  `json:"max_body_bytes"`
}

const (
	defaultMaxBody = 1 << 20
	maxSpecBytes   = 32 << 20
)

func parse(opts filter.Options) (*Config, *api, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, nil, err
	}
	var errs []error
	if c.SpecFile == "" || !strings.HasPrefix(c.SpecFile, "/") {
		errs = append(errs, errors.New("spec_file: an absolute path is required"))
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
		return nil, nil, errors.Join(errs...)
	}
	a, err := loadSpec(c.SpecFile, c.BasePath)
	if err != nil {
		return nil, nil, fmt.Errorf("spec_file: %w", err)
	}
	return &c, a, nil
}

// api is the compiled description.
type api struct {
	v        *jsonschema.Validator
	basePath string
	exact    map[string]*pathItem
	templ    []*pathItem // templated paths, longest literal prefix first
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
}

type parameter struct {
	name, in string
	required bool
	schema   map[string]any
}

type requestBody struct {
	required bool
	content  map[string]any // media type -> schema
}

// loadSpec reads and compiles a JSON or YAML document.
func loadSpec(path, basePath string) (*api, error) {
	data, err := os.ReadFile(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
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
		out = append(out, parameter{name: name, in: in, required: req, schema: schema})
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

type guard struct {
	name string
	cfg  *Config
	api  *api
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance { return &instance{g: g} }

type instance struct {
	g *guard
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	pi, pathVals, ok := g.api.match(r.Method, r.URL.Path)
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
	rep := &jsonschema.Report{}
	query := r.URL.Query()
	for _, p := range op.params {
		var raw string
		var present bool
		switch p.in {
		case "path":
			raw, present = pathVals[p.name]
		case "query":
			vals, has := query[p.name]
			present = has
			if has {
				raw = vals[0]
				if p.schema != nil && jsonschema.TypeAllows(p.schema["type"], "array") && len(vals) > 1 {
					raw = strings.Join(vals, ",")
				}
			}
		case "header":
			raw = r.Header.Get(p.name)
			present = raw != ""
		case "cookie":
			if c, err := r.Cookie(p.name); err == nil {
				raw, present = c.Value, true
			}
		default:
			continue
		}
		where := p.in + "." + p.name
		if !present {
			if p.required {
				rep.Add(where, "is required")
			}
			continue
		}
		if p.schema != nil {
			g.api.v.Validate(p.schema, jsonschema.Coerce(p.schema, raw), where, rep, 0)
		}
	}
	if g.cfg.StrictQuery {
		for name := range query {
			if !op.declared[name] {
				rep.Add("query."+name, "is not a parameter of this operation")
			}
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
	if !strings.HasSuffix(ct, "json") && !strings.HasSuffix(ct, "+json") {
		return nil // only JSON bodies are inspected
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
	value, err := jsonschema.Decode(data)
	if err != nil {
		rep.Add("body", "%s", err.Error())
		return nil
	}
	g.api.v.Validate(schema, value, "body", rep, 0)
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

func (in *instance) End() []any { return nil }

func init() {
	filter.Register(filter.Kind{
		Name:        "openapi",
		Description: "request validation against an OpenAPI 3 description: paths, methods, parameters, media types and JSON bodies",
		Validate: func(opts filter.Options) error {
			_, _, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			cfg, a, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return &guard{name: name, cfg: cfg, api: a}, nil
		},
	})
}
