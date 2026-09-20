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
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/filter"
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
	listArgs      map[string]bool
}

func parse(opts filter.Options) (*Config, error) {
	c := Config{MaxDepth: 10, MaxComplexity: 1000, MaxAliases: 30, MaxBatch: 1, MaxQueryBytes: 64 << 10, MaxList: 1000}
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

// operation is one parsed request.
type operation struct {
	Query         string `json:"query"`
	OperationName string `json:"operationName"`
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	var queries []string
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("query")
		if q == "" {
			return filter.Continue // not a GraphQL request
		}
		queries = []string{q}
	case http.MethodPost:
		// Media types are case-insensitive to every GraphQL server;
		// matching the raw header would let "Application/JSON" skip the
		// limits.
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
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
			queries = []string{string(body)}
			break
		}
		trimmed := bytes.TrimLeft(body, " \t\r\n")
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var ops []operation
			if err := json.Unmarshal(body, &ops); err != nil {
				return in.deny("malformed batch", "json")
			}
			if len(ops) > g.cfg.MaxBatch {
				return in.deny(fmt.Sprintf("batch of %d operations exceeds %d", len(ops), g.cfg.MaxBatch), "batch")
			}
			for _, op := range ops {
				queries = append(queries, op.Query)
			}
		} else {
			var op operation
			if err := json.Unmarshal(body, &op); err != nil {
				return in.deny("malformed request", "json")
			}
			if op.Query == "" {
				return filter.Continue // persisted queries and the like: nothing to bound here
			}
			queries = []string{op.Query}
		}
	default:
		return filter.Continue
	}
	for _, q := range queries {
		if int64(len(q)) > g.cfg.MaxQueryBytes {
			return in.deny("query too large", "size")
		}
		doc, err := parseDocument(q, g.cfg.listArgs)
		if err != nil {
			return in.deny("query does not parse: "+err.Error(), "syntax")
		}
		m := measure(doc, g.cfg)
		switch {
		case m.depth > g.cfg.MaxDepth:
			return in.deny(fmt.Sprintf("depth %d exceeds %d", m.depth, g.cfg.MaxDepth), "depth")
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
}

// measure walks every operation with fragments expanded (a fragment
// cycle counts as the depth bound, which fails the request).
func measure(doc *document, cfg *Config) metrics {
	var m metrics
	frags := map[string]*selection{}
	for _, f := range doc.fragments {
		frags[f.name] = f
	}
	for _, op := range doc.operations {
		d, c := walk(op, frags, cfg, 0, 1, map[string]bool{}, &m)
		m.depth = max(m.depth, d)
		m.complexity += c
	}
	return m
}

// walk returns the depth below sel and its complexity, given the product
// of the list multipliers of its ancestors.
func walk(sel *selection, frags map[string]*selection, cfg *Config, level, mult int, active map[string]bool, m *metrics) (depth, complexity int) {
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
		if f.listArg > 0 {
			fm *= min(f.listArg, cfg.MaxList)
			if fm > 1<<40 {
				fm = 1 << 40
			}
		}
		complexity += mult
		if f.sub != nil {
			d, c := walk(f.sub, frags, cfg, level+1, fm, active, m)
			depth = max(depth, d)
			complexity += c
		}
	}
	for _, inl := range sel.inline {
		d, c := walk(inl, frags, cfg, level, mult, active, m)
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
		d, c := walk(f, frags, cfg, level, mult, active, m)
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
	operations []*selection
	fragments  []*selection
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
	listArg     int
	sub         *selection
}

type parser struct {
	src      string
	pos      int
	n        int // tokens consumed, bounded
	listArgs map[string]bool
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
			doc.operations = append(doc.operations, sel)
			continue
		}
		word := p.name()
		switch word {
		case "query", "mutation", "subscription":
			p.skip()
			if p.pos < len(p.src) && p.peek() != '{' && p.peek() != '(' && p.peek() != '@' {
				p.name() // operation name
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
			doc.operations = append(doc.operations, sel)
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
		n, err := p.arguments()
		if err != nil {
			return nil, err
		}
		f.listArg = n
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
// literal given to a list argument (0 when none; a variable counts as
// the cap, since its value is unknown).
func (p *parser) arguments() (int, error) {
	p.pos++ // (
	largest := 0
	for {
		if err := p.tick(); err != nil {
			return 0, err
		}
		p.skip()
		if p.pos >= len(p.src) {
			return 0, errors.New("unterminated arguments")
		}
		if p.peek() == ')' {
			p.pos++
			return largest, nil
		}
		name := p.name()
		if name == "" {
			return 0, fmt.Errorf("expected an argument name at %d", p.pos)
		}
		p.skip()
		if p.pos >= len(p.src) || p.peek() != ':' {
			return 0, fmt.Errorf("expected : after %s", name)
		}
		p.pos++
		p.skip()
		start := p.pos
		if err := p.skipValue(); err != nil {
			return 0, err
		}
		if p.listArgs[name] {
			raw := strings.TrimSpace(p.src[start:p.pos])
			if strings.HasPrefix(raw, "$") {
				largest = max(largest, 1<<30) // unknown: assume the worst, the cap applies
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
		p.skip()
		if p.pos < len(p.src) && p.peek() == '(' {
			if _, err := p.arguments(); err != nil {
				return err
			}
		}
	}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "graphql",
		Description: "GraphQL request bounds: depth, complexity, aliases, batch size, query size, introspection",
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
