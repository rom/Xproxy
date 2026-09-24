// Package graphql is a built-in filter kind that bounds GraphQL requests
// before they reach the API: query depth, a complexity estimate that
// multiplies nested list arguments, alias count, batch size, query size
// and introspection. Requests are parsed with a small tolerant parser;
// nothing is executed.
//
//	filters:
//	  - name: gql
//	    kind: graphql
//	    options:
//	      max_depth: 10            # nesting of selection sets; default 10
//	      max_complexity: 1000     # fields weighted by list arguments; default 1000
//	      max_aliases: 30          # default 30
//	      max_batch: 1             # operations per request; default 1
//	      max_query_bytes: 65536   # default 64 KiB
//	      introspection: false     # refuse __schema and __type; default true (allowed)
//	      list_args: [first, last, limit]   # arguments that multiply a field's cost
//	      max_list: 1000           # cap for one multiplier
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/netutil"
)

// Config is the options schema.
type Config struct {
	MaxDepth      int      `json:"max_depth"`
	MaxComplexity int      `json:"max_complexity"`
	MaxAliases    int      `json:"max_aliases"`
	MaxBatch      int      `json:"max_batch"`
	MaxQueryBytes int64    `json:"max_query_bytes"`
	Introspection *bool    `json:"introspection"`
	ListArgs      []string `json:"list_args"`
	MaxList       int      `json:"max_list"`
	// MaxDirectives bounds the directives in the query text: a field
	// carrying a thousand @include directives is a thousand evaluations
	// the server does before it resolves anything.
	MaxDirectives int `json:"max_directives"`
	// MaxRootFields bounds an operation's top-level selection, which is
	// the breadth a depth bound says nothing about.
	MaxRootFields int `json:"max_root_fields"`
	// Mutations and Subscriptions are allow (default) or deny: what an
	// operation does, rather than how much it costs.
	Mutations     string `json:"mutations"`
	Subscriptions string `json:"subscriptions"`
	// AllowOperations, when set, is the only operation names that may
	// run. It implies require_operation_name, since an anonymous
	// operation is not on any list.
	AllowOperations []string `json:"allow_operations"`
	// RequireOperationName refuses an operation with no name.
	RequireOperationName bool `json:"require_operation_name"`
	// Persisted is allow (default) or deny: what to do with a request
	// that carries no query text, whose cost nothing here can judge.
	Persisted        string `json:"persisted"`
	listArgs         map[string]bool
	allowedOperation map[string]bool
}

func parse(opts filter.Options) (*Config, error) {
	c := Config{MaxDepth: 10, MaxComplexity: 1000, MaxAliases: 30, MaxBatch: 1, MaxQueryBytes: 64 << 10, MaxList: 1000,
		MaxDirectives: 100, MaxRootFields: 20}
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	check := func(name string, v, lo, hi int) {
		if v < lo || v > hi {
			errs = append(errs, fmt.Errorf("%s: must be between %d and %d", name, lo, hi))
		}
	}
	check("max_depth", c.MaxDepth, 1, 1000)
	check("max_complexity", c.MaxComplexity, 1, 100_000_000)
	check("max_aliases", c.MaxAliases, 0, 100_000)
	check("max_batch", c.MaxBatch, 1, 1000)
	check("max_list", c.MaxList, 1, 1_000_000)
	check("max_directives", c.MaxDirectives, 0, 1_000_000)
	check("max_root_fields", c.MaxRootFields, 1, 100_000)
	for name, v := range map[string]*string{"mutations": &c.Mutations, "subscriptions": &c.Subscriptions} {
		switch *v {
		case "":
			*v = "allow"
		case "allow", "deny":
		default:
			errs = append(errs, fmt.Errorf("%s: must be allow or deny", name))
		}
	}
	switch c.Persisted {
	case "":
		c.Persisted = "allow"
	case "allow", "deny":
	default:
		errs = append(errs, errors.New("persisted: must be allow or deny"))
	}
	if len(c.AllowOperations) > 0 {
		c.allowedOperation = make(map[string]bool, len(c.AllowOperations))
		for _, n := range c.AllowOperations {
			if !nameOK(n) {
				errs = append(errs, fmt.Errorf("allow_operations: %q is not a GraphQL name", n))
			}
			c.allowedOperation[n] = true
		}
		// A list of names that only applies to named operations is a
		// list an anonymous operation walks past.
		c.RequireOperationName = true
	}
	if c.MaxQueryBytes < 256 || c.MaxQueryBytes > 16<<20 {
		errs = append(errs, errors.New("max_query_bytes: must be between 256 and 16777216"))
	}
	if len(c.ListArgs) == 0 {
		c.ListArgs = []string{"first", "last", "limit"}
	}
	c.listArgs = map[string]bool{}
	for _, a := range c.ListArgs {
		if !nameOK(a) {
			errs = append(errs, fmt.Errorf("list_args: %q is not a GraphQL name", a))
		}
		c.listArgs[a] = true
	}
	return &c, errors.Join(errs...)
}

func nameOK(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

type guard struct {
	name string
	cfg  *Config
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance { return &instance{g: g} }

type instance struct {
	g *guard
}

// payload is one JSON request body. Variables are read because a
// pagination argument given as a variable is a real number the server
// will use, and scoring it as the cap when the request says 10 refuses
// queries that cost nothing.
type payload struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
	// Extensions carries the persisted-query hash when there is one; it
	// is read only to tell "no query" from "a query I cannot see".
	Extensions map[string]any `json:"extensions"`
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	// asked is one query with the two things needed to judge it: which
	// operation the request selected, and the variables the server will
	// substitute.
	type asked struct {
		query string
		name  string
		vars  map[string]any
	}
	var queries []asked
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("query")
		if q == "" {
			return filter.Continue // not a GraphQL request
		}
		a := asked{query: q, name: r.URL.Query().Get("operationName")}
		if raw := r.URL.Query().Get("variables"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &a.vars)
		}
		queries = []asked{a}
	case http.MethodPost:
		// Media types are case-insensitive to every GraphQL server;
		// matching the raw header would let "Application/JSON" skip the
		// limits.
		mt := netutil.MediaType(r.Header.Get("Content-Type"))
		isJSON := mt == "application/json" || strings.HasSuffix(mt, "+json")
		if !isJSON && mt != "application/graphql" {
			return filter.Continue
		}
		if r.ContentLength > g.cfg.MaxQueryBytes {
			return in.deny("query too large", "size")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, g.cfg.MaxQueryBytes+1))
		if err != nil {
			return in.deny("body unreadable", "body")
		}
		if int64(len(body)) > g.cfg.MaxQueryBytes {
			return in.deny("query too large", "size")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if !isJSON {
			queries = []asked{{query: string(body)}}
			break
		}
		trimmed := bytes.TrimLeft(body, " \t\r\n")
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var ops []payload
			if err := json.Unmarshal(body, &ops); err != nil {
				return in.deny("malformed batch", "json")
			}
			if len(ops) > g.cfg.MaxBatch {
				return in.deny(fmt.Sprintf("batch of %d operations exceeds %d", len(ops), g.cfg.MaxBatch), "batch")
			}
			for _, op := range ops {
				if v := in.unseen(op); v != nil {
					return *v
				}
				queries = append(queries, asked{query: op.Query, name: op.OperationName, vars: op.Variables})
			}
		} else {
			var op payload
			if err := json.Unmarshal(body, &op); err != nil {
				return in.deny("malformed request", "json")
			}
			if v := in.unseen(op); v != nil {
				return *v
			}
			if op.Query == "" {
				return filter.Continue
			}
			queries = []asked{{query: op.Query, name: op.OperationName, vars: op.Variables}}
		}
	default:
		return filter.Continue
	}
	for _, a := range queries {
		if a.query == "" {
			continue
		}
		if int64(len(a.query)) > g.cfg.MaxQueryBytes {
			return in.deny("query too large", "size")
		}
		doc, err := parseDocument(a.query, g.cfg.listArgs)
		if err != nil {
			return in.deny("query does not parse: "+err.Error(), "syntax")
		}
		if doc.directives > g.cfg.MaxDirectives {
			return in.deny(fmt.Sprintf("%d directives exceed %d", doc.directives, g.cfg.MaxDirectives), "directives")
		}
		m := measure(doc, g.cfg, a.name, a.vars)
		if v := in.policy(r, m); v != nil {
			return *v
		}
		switch {
		case m.overflow:
			return in.deny("the query expands too far", "expansion")
		case m.depth > g.cfg.MaxDepth:
			return in.deny(fmt.Sprintf("depth %d exceeds %d", m.depth, g.cfg.MaxDepth), "depth")
		case m.rootFields > g.cfg.MaxRootFields:
			return in.deny(fmt.Sprintf("%d root fields exceed %d", m.rootFields, g.cfg.MaxRootFields), "root_fields")
		case m.complexity > g.cfg.MaxComplexity:
			return in.deny(fmt.Sprintf("complexity %d exceeds %d", m.complexity, g.cfg.MaxComplexity), "complexity")
		case m.aliases > g.cfg.MaxAliases:
			return in.deny(fmt.Sprintf("%d aliases exceed %d", m.aliases, g.cfg.MaxAliases), "aliases")
		case m.introspection && g.cfg.Introspection != nil && !*g.cfg.Introspection:
			return in.deny("introspection is disabled", "introspection")
		}
	}
	return filter.Continue
}

// unseen refuses a request whose query text is not in it -- a persisted
// query the origin looks up by hash -- when the policy says a query this
// filter cannot read must not run.
//
// It is the one shape that walks past every bound here: no text, nothing
// to parse, nothing to measure. Allowing it is the default because
// persisted queries are usually the safest thing a client can send (the
// origin only runs documents it already has), but a deployment that
// reaches its API through this filter and not otherwise should be able to
// say that an unreadable query is not an allowed one.
func (in *instance) unseen(op payload) *filter.Verdict {
	if op.Query != "" || in.g.cfg.Persisted != "deny" {
		return nil
	}
	if len(op.Extensions) == 0 && op.OperationName == "" {
		// Not a GraphQL request at all: an empty object, or JSON that is
		// somebody else's. Nothing to refuse.
		return nil
	}
	v := in.deny("this endpoint does not accept a query it cannot read", "persisted")
	return &v
}

// policy decides what an operation is, rather than how much it costs: a
// mutation is not a query, and the two want different answers.
func (in *instance) policy(r *http.Request, m metrics) *filter.Verdict {
	g := in.g
	// GET is for queries. The GraphQL over HTTP specification says so,
	// and the reason is that a GET is what a link, an image tag, a
	// prefetch and a crawler all produce: a mutation reachable that way
	// is a mutation anybody can fire from another origin, with the
	// browser attaching the cookies. It is refused whatever the policy
	// says, because no configuration makes it safe.
	if r.Method == http.MethodGet && (m.mutations || m.subscriptions) {
		return ptr(in.deny("a mutation or subscription may not arrive by GET", "get_mutation"))
	}
	if m.mutations && g.cfg.Mutations == "deny" {
		return ptr(in.deny("mutations are not accepted here", "mutation"))
	}
	if m.subscriptions && g.cfg.Subscriptions == "deny" {
		return ptr(in.deny("subscriptions are not accepted here", "subscription"))
	}
	if g.cfg.RequireOperationName && m.unnamed > 0 {
		return ptr(in.deny("an operation must be named", "unnamed"))
	}
	if g.cfg.allowedOperation != nil {
		for _, name := range m.names {
			if !g.cfg.allowedOperation[name] {
				return ptr(in.deny("operation "+name+" is not allowed here", "operation"))
			}
		}
	}
	return nil
}

func ptr(v filter.Verdict) *filter.Verdict { return &v }

// deny answers in the shape GraphQL clients understand: 400 with an
// errors array.
func (in *instance) deny(msg, detail string) filter.Verdict {
	body, _ := json.Marshal(map[string]any{"errors": []map[string]any{{"message": msg, "extensions": map[string]string{"code": "REQUEST_REFUSED"}}}})
	resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
	return filter.Verdict{Deny: true, Status: http.StatusBadRequest, Reason: in.g.name, Detail: detail, Response: resp}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any { return nil }

// ---- measurement -------------------------------------------------------

type metrics struct {
	depth, complexity, aliases int
	introspection              bool
	// rootFields is the widest operation's top-level selection, and
	// mutations and subscriptions record what kinds the document asks
	// for: what an operation does is as much a policy question as how
	// much it costs.
	rootFields               int
	mutations, subscriptions bool
	// unnamed counts operations with no name, which an allow list
	// cannot judge.
	unnamed int
	// names are the operation names the document carries.
	names []string
	// visits is spent by walk and bounds the expansion. A fragment that
	// spreads the next one twice doubles the work per level, so a query
	// of a couple of kilobytes expands to a billion visits with no cycle
	// in it and every configured bound respected: the active set stops a
	// fragment referring to itself, not a fragment referred to twice.
	visits int
	// overflow records that the expansion ran out of visits, so the
	// refusal can say so.
	overflow bool
}

// maxVisits bounds the selections one document's expansion may visit.
const maxVisits = 1 << 16

// measure walks the operations with fragments expanded (a fragment cycle
// counts as the depth bound, which fails the request).
//
// When the request named an operation, only that one is measured, because
// only that one runs: a document that carries a client's whole query file
// and selects one of them should be judged by the one it selected. With
// no name every operation is measured, which is the conservative reading
// of "the server will pick".
func measure(doc *document, cfg *Config, want string, vars map[string]any) metrics {
	var m metrics
	frags := map[string]*selection{}
	for _, f := range doc.fragments {
		frags[f.name] = f
	}
	for _, o := range doc.operations {
		if o.name == "" {
			m.unnamed++
		} else {
			m.names = append(m.names, o.name)
		}
		switch o.kind {
		case "mutation":
			m.mutations = true
		case "subscription":
			m.subscriptions = true
		}
		if want != "" && o.name != want {
			continue
		}
		m.rootFields = max(m.rootFields, len(o.sel.fields))
		d, c := walk(o.sel, frags, cfg, 0, 1, map[string]bool{}, &m, vars)
		m.depth = max(m.depth, d)
		m.complexity += c
	}
	return m
}

// walk returns the depth below sel and its complexity, given the product
// of the list multipliers of its ancestors.
func walk(sel *selection, frags map[string]*selection, cfg *Config, level, mult int, active map[string]bool, m *metrics, vars map[string]any) (depth, complexity int) {
	m.visits++
	if m.visits > maxVisits {
		// Past the bound the answer is the same whatever the rest of the
		// document says: refuse it. Reporting the depth bound keeps the
		// verdict one the client can act on.
		m.overflow = true
		return cfg.MaxDepth + 1, 1 << 40
	}
	depth = level
	for _, f := range sel.fields {
		if f.alias != "" {
			m.aliases++
		}
		if f.name == "__schema" || f.name == "__type" {
			m.introspection = true
		}
		if f.name == "__typename" {
			continue
		}
		fm := mult
		if n := f.cost(vars, cfg); n > 0 {
			fm *= min(n, cfg.MaxList)
			if fm > 1<<40 {
				fm = 1 << 40
			}
		}
		complexity += mult
		if f.sub != nil {
			d, c := walk(f.sub, frags, cfg, level+1, fm, active, m, vars)
			depth = max(depth, d)
			complexity += c
		}
	}
	for _, inl := range sel.inline {
		d, c := walk(inl, frags, cfg, level, mult, active, m, vars)
		depth = max(depth, d)
		complexity += c
	}
	for _, name := range sel.spreads {
		if active[name] {
			depth = max(depth, cfg.MaxDepth+1) // a cycle: never finishes
			continue
		}
		f, ok := frags[name]
		if !ok {
			continue
		}
		active[name] = true
		d, c := walk(f, frags, cfg, level, mult, active, m, vars)
		delete(active, name)
		depth = max(depth, d)
		complexity += c
	}
	if complexity > 1<<40 {
		complexity = 1 << 40
	}
	return depth, complexity
}

// ---- parsing -----------------------------------------------------------

type document struct {
	operations []*op
	fragments  []*selection
	// directives counts the directives in the query text. It is the
	// source count rather than the expanded one, because that is the
	// number an operator can look at their own query and predict.
	directives int
}

// op is one operation: what kind it is, what it is called, and what it
// selects. The kind matters because a mutation is not a query -- it
// changes something, and a protocol that lets one arrive by GET lets a
// link change it.
type op struct {
	kind string // query, mutation or subscription
	name string
	sel  *selection
}

// selection is a selection set (of an operation, a field, a fragment or
// an inline fragment).
type selection struct {
	name    string // fragment name
	fields  []*field
	inline  []*selection
	spreads []string
}

type field struct {
	alias, name string
	// listArg is the largest integer literal given to a list argument,
	// and listVars the variables given to one: a variable's value is
	// known only when the request carries it.
	listArg  int
	listVars []string
	sub      *selection
}

// cost is the list multiplier this field claims: the largest literal, and
// for each variable the value the request carries or the cap when it
// carries none.
//
// Reading the variables matters because a client that writes
// `first: $count` and sends 10 is asking for ten things. Scoring that as
// the cap refuses a query that costs nothing, which is how a complexity
// bound gets turned off by the operator it kept annoying. A variable the
// request does not carry -- or carries as something that is not a
// positive integer, or that has a default this filter never sees -- is
// still the worst case.
func (f *field) cost(vars map[string]any, cfg *Config) int {
	n := f.listArg
	for _, name := range f.listVars {
		v, ok := vars[name]
		if !ok {
			return cfg.MaxList
		}
		i, ok := asInt(v)
		if !ok || i < 0 {
			return cfg.MaxList
		}
		n = max(n, i)
	}
	return n
}

// asInt reads a JSON number that is a whole number.
func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		if x != math.Trunc(x) || x > 1<<30 {
			return 0, false
		}
		return int(x), true
	case json.Number:
		i, err := x.Int64()
		if err != nil || i > 1<<30 {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}

type parser struct {
	src        string
	pos        int
	n          int // tokens consumed, bounded
	directives int
	listArgs   map[string]bool
}

var errTooManyTokens = errors.New("query too long to analyse")

const maxTokens = 200000

func parseDocument(src string, listArgs map[string]bool) (*document, error) {
	p := &parser{src: src, listArgs: listArgs}
	doc := &document{}
	for {
		p.skip()
		if p.pos >= len(p.src) {
			break
		}
		if p.peek() == '{' {
			sel, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			// The shorthand form: an anonymous query and nothing else.
			doc.operations = append(doc.operations, &op{kind: "query", sel: sel})
			continue
		}
		word := p.name()
		switch word {
		case "query", "mutation", "subscription":
			o := &op{kind: word}
			p.skip()
			if p.pos < len(p.src) && p.peek() != '{' && p.peek() != '(' && p.peek() != '@' {
				o.name = p.name()
			}
			if err := p.skipParens(); err != nil {
				return nil, err
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sel, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			o.sel = sel
			doc.operations = append(doc.operations, o)
		case "fragment":
			p.skip()
			name := p.name()
			if name == "" {
				return nil, errors.New("fragment without a name")
			}
			p.skip()
			if p.name() != "on" {
				return nil, errors.New("fragment without a type condition")
			}
			p.skip()
			p.name()
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sel, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			sel.name = name
			doc.fragments = append(doc.fragments, sel)
		case "":
			return nil, fmt.Errorf("unexpected %q at %d", string(p.peek()), p.pos)
		default:
			return nil, fmt.Errorf("unexpected %q at %d", word, p.pos)
		}
	}
	if len(doc.operations) == 0 {
		return nil, errors.New("no operation")
	}
	doc.directives = p.directives
	return doc, nil
}

func (p *parser) peek() byte { return p.src[p.pos] }

func (p *parser) tick() error {
	p.n++
	if p.n > maxTokens {
		return errTooManyTokens
	}
	return nil
}

// skip passes whitespace, commas and comments.
func (p *parser) skip() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r', ',', 0xEF:
			p.pos++
		case '#':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

func (p *parser) name() string {
	p.skip()
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (p.pos > start && c >= '0' && c <= '9') {
			p.pos++
			continue
		}
		break
	}
	return p.src[start:p.pos]
}

func (p *parser) selectionSet() (*selection, error) {
	p.skip()
	if p.pos >= len(p.src) || p.peek() != '{' {
		return nil, fmt.Errorf("expected { at %d", p.pos)
	}
	p.pos++
	sel := &selection{}
	for {
		if err := p.tick(); err != nil {
			return nil, err
		}
		p.skip()
		if p.pos >= len(p.src) {
			return nil, errors.New("unterminated selection set")
		}
		if p.peek() == '}' {
			p.pos++
			return sel, nil
		}
		if strings.HasPrefix(p.src[p.pos:], "...") {
			p.pos += 3
			p.skip()
			word := p.name()
			if word == "on" || word == "" {
				if word == "on" {
					p.skip()
					p.name()
				}
				if err := p.skipDirectives(); err != nil {
					return nil, err
				}
				inl, err := p.selectionSet()
				if err != nil {
					return nil, err
				}
				sel.inline = append(sel.inline, inl)
				continue
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sel.spreads = append(sel.spreads, word)
			continue
		}
		f, err := p.field()
		if err != nil {
			return nil, err
		}
		sel.fields = append(sel.fields, f)
	}
}

func (p *parser) field() (*field, error) {
	name := p.name()
	if name == "" {
		return nil, fmt.Errorf("expected a field name at %d", p.pos)
	}
	f := &field{name: name}
	p.skip()
	if p.pos < len(p.src) && p.peek() == ':' {
		p.pos++
		f.alias = name
		f.name = p.name()
		if f.name == "" {
			return nil, fmt.Errorf("expected a field name after alias at %d", p.pos)
		}
		p.skip()
	}
	if p.pos < len(p.src) && p.peek() == '(' {
		n, vars, err := p.arguments()
		if err != nil {
			return nil, err
		}
		f.listArg, f.listVars = n, vars
	}
	if err := p.skipDirectives(); err != nil {
		return nil, err
	}
	p.skip()
	if p.pos < len(p.src) && p.peek() == '{' {
		sub, err := p.selectionSet()
		if err != nil {
			return nil, err
		}
		f.sub = sub
	}
	return f, nil
}

// arguments consumes (name: value, ...) and returns the largest integer
// literal given to a list argument (0 when none) with the names of the
// variables given to one, whose values the request may or may not carry.
func (p *parser) arguments() (int, []string, error) {
	p.pos++ // (
	largest := 0
	var vars []string
	for {
		if err := p.tick(); err != nil {
			return 0, nil, err
		}
		p.skip()
		if p.pos >= len(p.src) {
			return 0, nil, errors.New("unterminated arguments")
		}
		if p.peek() == ')' {
			p.pos++
			return largest, vars, nil
		}
		name := p.name()
		if name == "" {
			return 0, nil, fmt.Errorf("expected an argument name at %d", p.pos)
		}
		p.skip()
		if p.pos >= len(p.src) || p.peek() != ':' {
			return 0, nil, fmt.Errorf("expected : after %s", name)
		}
		p.pos++
		p.skip()
		start := p.pos
		if err := p.skipValue(); err != nil {
			return 0, nil, err
		}
		if p.listArgs[name] {
			raw := strings.TrimSpace(p.src[start:p.pos])
			if strings.HasPrefix(raw, "$") {
				if len(vars) < 8 {
					vars = append(vars, raw[1:])
				}
			} else if n, err := strconv.Atoi(raw); err == nil && n > largest {
				largest = n
			}
		}
	}
}

// skipValue passes one value: scalars, strings, block strings, variables,
// lists and objects (recursively).
func (p *parser) skipValue() error {
	if err := p.tick(); err != nil {
		return err
	}
	if p.pos >= len(p.src) {
		return errors.New("expected a value")
	}
	switch p.peek() {
	case '"':
		if strings.HasPrefix(p.src[p.pos:], `"""`) {
			end := strings.Index(p.src[p.pos+3:], `"""`)
			if end < 0 {
				return errors.New("unterminated block string")
			}
			p.pos += 3 + end + 3
			return nil
		}
		p.pos++
		for p.pos < len(p.src) {
			switch p.src[p.pos] {
			case '\\':
				p.pos += 2
				continue
			case '"':
				p.pos++
				return nil
			case '\n':
				return errors.New("newline in string")
			}
			p.pos++
		}
		return errors.New("unterminated string")
	case '[':
		p.pos++
		for {
			p.skip()
			if p.pos >= len(p.src) {
				return errors.New("unterminated list")
			}
			if p.peek() == ']' {
				p.pos++
				return nil
			}
			if err := p.skipValue(); err != nil {
				return err
			}
		}
	case '{':
		p.pos++
		for {
			p.skip()
			if p.pos >= len(p.src) {
				return errors.New("unterminated object")
			}
			if p.peek() == '}' {
				p.pos++
				return nil
			}
			if p.name() == "" {
				return fmt.Errorf("expected a field name at %d", p.pos)
			}
			p.skip()
			if p.pos >= len(p.src) || p.peek() != ':' {
				return errors.New("expected : in object value")
			}
			p.pos++
			p.skip()
			if err := p.skipValue(); err != nil {
				return err
			}
		}
	default:
		start := p.pos
		for p.pos < len(p.src) {
			c := p.src[p.pos]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == ')' || c == ']' || c == '}' || c == '@' || c == '#' {
				break
			}
			p.pos++
		}
		if p.pos == start {
			return fmt.Errorf("expected a value at %d", p.pos)
		}
		return nil
	}
}

func (p *parser) skipParens() error {
	p.skip()
	if p.pos < len(p.src) && p.peek() == '(' {
		depth := 0
		for p.pos < len(p.src) {
			if err := p.tick(); err != nil {
				return err
			}
			switch p.peek() {
			case '(':
				depth++
			case ')':
				depth--
			case '"':
				if err := p.skipValue(); err != nil {
					return err
				}
				continue
			}
			p.pos++
			if depth == 0 {
				return nil
			}
		}
		return errors.New("unterminated variable definitions")
	}
	return nil
}

func (p *parser) skipDirectives() error {
	for {
		p.skip()
		if p.pos >= len(p.src) || p.peek() != '@' {
			return nil
		}
		p.pos++
		if p.name() == "" {
			return errors.New("directive without a name")
		}
		p.directives++
		p.skip()
		if p.pos < len(p.src) && p.peek() == '(' {
			if _, _, err := p.arguments(); err != nil {
				return err
			}
		}
	}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "graphql",
		Description: "GraphQL request bounds: depth, complexity, aliases, batch size, query size, introspection",
		BuffersBody: true,
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			cfg, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return &guard{name: name, cfg: cfg}, nil
		},
	})
}
