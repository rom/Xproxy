// Package expr is the condition language of routes (routes[].when) and
// header operations (request_headers.when, response_headers.when). An
// expression is parsed once at load, checked for unknown variables,
// functions and arities, and evaluated per request against an Env that
// resolves the same variables as header templates.
//
// Grammar, lowest precedence first:
//
//	expr    := and ( ("||" | "or") and )*
//	and     := not ( ("&&" | "and") not )*
//	not     := ("!" | "not") not | cmp
//	cmp     := term ( ("==" | "!=" | "<" | "<=" | ">" | ">=") term
//	         | "in" list | "not" "in" list | "matches" string )?
//	term    := string | number | "true" | "false" | name | name "(" args ")"
//	         | "(" expr ")"
//	list    := "[" args "]" | "cidr" "(" strings ")"
//
// Strings are single or double quoted with backslash escapes. A bare
// name is a request variable (client_ip, host, path, method, scheme,
// country, ja4, tls_version, hour, weekday...). Values are strings;
// "<", "<=", ">" and ">=" compare numerically when both sides parse as
// numbers and by string otherwise, "==" and "!=" compare as strings.
package expr

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Env resolves variables: name is a bare variable or a function of one
// string argument (header, cookie, query, capture). It is the Resolver
// interface of package tmpl.
type Env interface {
	Resolve(name, arg string) (string, bool)
}

// Expr is a parsed condition.
type Expr struct {
	src  string
	root node
}

// String returns the source text.
func (e *Expr) String() string { return e.src }

// Eval evaluates the condition against env. It cannot fail: a variable
// without a value is the empty string and a comparison of unlike values
// is false.
func (e *Expr) Eval(env Env) bool {
	return truthy(e.root.eval(env))
}

// Parse parses src. vars are the bare variable names accepted and
// captures the group names of the route's regular expressions (accepted
// by capture()).
func Parse(src string, vars map[string]bool, captures ...string) (*Expr, error) {
	if strings.TrimSpace(src) == "" {
		return nil, errors.New("empty expression")
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, vars: vars, captures: captures}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("unexpected %q at %d", p.toks[p.pos].text, p.toks[p.pos].pos)
	}
	return &Expr{src: src, root: root}, nil
}

// MustParse is Parse for validated sources.
func MustParse(src string, vars map[string]bool, captures ...string) *Expr {
	e, err := Parse(src, vars, captures...)
	if err != nil {
		panic(err)
	}
	return e
}

// value is a runtime value: a string (the common case), a boolean, a
// list of strings or a set of prefixes for "in".
type value struct {
	kind kind
	s    string
	b    bool
	list []string
	nets []netip.Prefix
}

type kind int

const (
	kindStr kind = iota
	kindBool
	kindList
	kindNets
)

func str(s string) value   { return value{kind: kindStr, s: s} }
func boolean(b bool) value { return value{kind: kindBool, b: b} }

func truthy(v value) bool {
	switch v.kind {
	case kindBool:
		return v.b
	case kindStr:
		return v.s != "" && v.s != "false" && v.s != "0"
	default:
		return len(v.list) > 0 || len(v.nets) > 0
	}
}

func (v value) text() string {
	switch v.kind {
	case kindBool:
		return strconv.FormatBool(v.b)
	case kindStr:
		return v.s
	}
	return strings.Join(v.list, ",")
}

type node interface {
	eval(env Env) value
}

type literal struct{ v value }

func (l literal) eval(Env) value { return l.v }

type variable struct{ name string }

func (n variable) eval(env Env) value {
	if env == nil {
		return str("")
	}
	s, _ := env.Resolve(n.name, "")
	return str(s)
}

type binary struct {
	op   string
	l, r node
}

func (n binary) eval(env Env) value {
	switch n.op {
	case "||":
		return boolean(truthy(n.l.eval(env)) || truthy(n.r.eval(env)))
	case "&&":
		return boolean(truthy(n.l.eval(env)) && truthy(n.r.eval(env)))
	}
	l, r := n.l.eval(env), n.r.eval(env)
	switch n.op {
	case "==":
		return boolean(equal(l, r))
	case "!=":
		return boolean(!equal(l, r))
	case "<", "<=", ">", ">=":
		return boolean(compare(n.op, l, r))
	case "in":
		return boolean(contains(r, l))
	case "not in":
		return boolean(!contains(r, l))
	}
	return boolean(false)
}

func equal(l, r value) bool {
	if l.kind == kindBool || r.kind == kindBool {
		return truthy(l) == truthy(r)
	}
	return l.text() == r.text()
}

func compare(op string, l, r value) bool {
	var c int
	lf, errL := strconv.ParseFloat(strings.TrimSpace(l.text()), 64)
	rf, errR := strconv.ParseFloat(strings.TrimSpace(r.text()), 64)
	if errL == nil && errR == nil {
		switch {
		case lf < rf:
			c = -1
		case lf > rf:
			c = 1
		}
	} else {
		c = strings.Compare(l.text(), r.text())
	}
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	}
	return c >= 0
}

// contains reports whether set (a list or prefixes) holds v.
func contains(set, v value) bool {
	switch set.kind {
	case kindList:
		for _, s := range set.list {
			if s == v.text() {
				return true
			}
		}
	case kindNets:
		addr, err := netip.ParseAddr(v.text())
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		for _, p := range set.nets {
			if p.Contains(addr) {
				return true
			}
		}
	default:
		return set.text() == v.text()
	}
	return false
}

type not struct{ x node }

func (n not) eval(env Env) value { return boolean(!truthy(n.x.eval(env))) }

type match struct {
	x  node
	re *regexp.Regexp
}

func (n match) eval(env Env) value { return boolean(n.re.MatchString(n.x.eval(env).text())) }

// call is a function application; the resolved functions take an Env
// (header, cookie, query, capture, has_*) or plain values.
type call struct {
	name string
	args []node
}

func (n call) eval(env Env) value {
	arg := func(i int) string { return n.args[i].eval(env).text() }
	resolve := func(name, a string) (string, bool) {
		if env == nil {
			return "", false
		}
		return env.Resolve(name, a)
	}
	switch n.name {
	case "header", "cookie", "query", "capture":
		s, _ := resolve(n.name, arg(0))
		return str(s)
	case "has_header", "has_cookie", "has_query":
		_, ok := resolve(strings.TrimPrefix(n.name, "has_"), arg(0))
		return boolean(ok)
	case "lower":
		return str(strings.ToLower(arg(0)))
	case "upper":
		return str(strings.ToUpper(arg(0)))
	case "trim":
		return str(strings.TrimSpace(arg(0)))
	case "len":
		return str(strconv.Itoa(len(arg(0))))
	case "starts_with":
		return boolean(strings.HasPrefix(arg(0), arg(1)))
	case "ends_with":
		return boolean(strings.HasSuffix(arg(0), arg(1)))
	case "contains":
		return boolean(strings.Contains(arg(0), arg(1)))
	case "matches":
		return boolean(n.args[1].(regexArg).re.MatchString(arg(0)))
	case "cidr":
		return n.args[0].eval(env)
	}
	return str("")
}

// regexArg is the precompiled second argument of matches().
type regexArg struct{ re *regexp.Regexp }

func (r regexArg) eval(Env) value { return str(r.re.String()) }

// functions maps a name to its arity.
var functions = map[string]int{
	"header": 1, "cookie": 1, "query": 1, "capture": 1,
	"has_header": 1, "has_cookie": 1, "has_query": 1,
	"lower": 1, "upper": 1, "trim": 1, "len": 1,
	"starts_with": 2, "ends_with": 2, "contains": 2, "matches": 2,
}

// lexing

type token struct {
	kind tokenKind
	text string
	pos  int
}

type tokenKind int

const (
	tokName tokenKind = iota
	tokString
	tokNumber
	tokPunct
)

func lex(src string) ([]token, error) {
	var toks []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"' || c == '\'':
			s, n, err := lexString(src[i:])
			if err != nil {
				return nil, fmt.Errorf("at %d: %w", i, err)
			}
			toks = append(toks, token{tokString, s, i})
			i += n
		case c >= '0' && c <= '9' || (c == '-' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9'):
			j := i + 1
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.') {
				j++
			}
			toks = append(toks, token{tokNumber, src[i:j], i})
			i = j
		case c == '_' || unicode.IsLetter(rune(c)):
			j := i + 1
			for j < len(src) && (src[j] == '_' || src[j] >= '0' && src[j] <= '9' || unicode.IsLetter(rune(src[j]))) {
				j++
			}
			toks = append(toks, token{tokName, src[i:j], i})
			i = j
		default:
			for _, p := range []string{"==", "!=", "<=", ">=", "&&", "||", "(", ")", "[", "]", ",", "<", ">", "!"} {
				if strings.HasPrefix(src[i:], p) {
					toks = append(toks, token{tokPunct, p, i})
					i += len(p)
					goto next
				}
			}
			return nil, fmt.Errorf("unexpected character %q at %d", c, i)
		next:
		}
	}
	return toks, nil
}

func lexString(s string) (string, int, error) {
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", 0, errors.New("unterminated escape")
			}
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
		case q:
			return b.String(), i + 1, nil
		default:
			b.WriteByte(s[i])
		}
	}
	return "", 0, errors.New("unterminated string")
}

// parsing

type parser struct {
	toks     []token
	pos      int
	vars     map[string]bool
	captures []string
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) accept(kind tokenKind, text string) bool {
	if t := p.peek(); t != nil && t.kind == kind && t.text == text {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expect(kind tokenKind, text string) error {
	if p.accept(kind, text) {
		return nil
	}
	if t := p.peek(); t != nil {
		return fmt.Errorf("expected %q, found %q at %d", text, t.text, t.pos)
	}
	return fmt.Errorf("expected %q at end", text)
}

func (p *parser) parseOr() (node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept(tokPunct, "||") || p.accept(tokName, "or") {
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = binary{"||", l, r}
	}
	return l, nil
}

func (p *parser) parseAnd() (node, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.accept(tokPunct, "&&") || p.accept(tokName, "and") {
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = binary{"&&", l, r}
	}
	return l, nil
}

func (p *parser) parseNot() (node, error) {
	if p.accept(tokPunct, "!") || p.accept(tokName, "not") {
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return not{x}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (node, error) {
	l, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if p.accept(tokPunct, op) {
			r, err := p.parseTerm()
			if err != nil {
				return nil, err
			}
			return binary{op, l, r}, nil
		}
	}
	if p.accept(tokName, "matches") {
		re, err := p.parseRegex()
		if err != nil {
			return nil, err
		}
		return match{l, re}, nil
	}
	if p.accept(tokName, "in") {
		r, err := p.parseList()
		if err != nil {
			return nil, err
		}
		return binary{"in", l, r}, nil
	}
	if t := p.peek(); t != nil && t.kind == tokName && t.text == "not" && p.pos+1 < len(p.toks) && p.toks[p.pos+1].text == "in" {
		p.pos += 2
		r, err := p.parseList()
		if err != nil {
			return nil, err
		}
		return binary{"not in", l, r}, nil
	}
	return l, nil
}

// parseRegex takes the string literal after matches and compiles it.
func (p *parser) parseRegex() (*regexp.Regexp, error) {
	t := p.peek()
	if t == nil || t.kind != tokString {
		return nil, errors.New("matches needs a quoted pattern")
	}
	p.pos++
	re, err := regexp.Compile(t.text)
	if err != nil {
		return nil, fmt.Errorf("pattern at %d: %w", t.pos, err)
	}
	return re, nil
}

// parseList parses the right side of in: a bracketed list of literals
// or cidr(...) with prefixes and addresses.
func (p *parser) parseList() (node, error) {
	if p.accept(tokPunct, "[") {
		var items []string
		for !p.accept(tokPunct, "]") {
			if len(items) > 0 {
				if err := p.expect(tokPunct, ","); err != nil {
					return nil, err
				}
			}
			t := p.peek()
			if t == nil || (t.kind != tokString && t.kind != tokNumber) {
				return nil, errors.New("list items must be quoted strings or numbers")
			}
			p.pos++
			items = append(items, t.text)
		}
		return literal{value{kind: kindList, list: items}}, nil
	}
	if p.accept(tokName, "cidr") {
		if err := p.expect(tokPunct, "("); err != nil {
			return nil, err
		}
		var nets []netip.Prefix
		for !p.accept(tokPunct, ")") {
			if len(nets) > 0 {
				if err := p.expect(tokPunct, ","); err != nil {
					return nil, err
				}
			}
			t := p.peek()
			if t == nil || t.kind != tokString {
				return nil, errors.New("cidr() takes quoted prefixes or addresses")
			}
			p.pos++
			pfx, err := netip.ParsePrefix(t.text)
			if err != nil {
				addr, err2 := netip.ParseAddr(t.text)
				if err2 != nil {
					return nil, fmt.Errorf("cidr(%q): %w", t.text, err)
				}
				pfx = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
			}
			nets = append(nets, pfx.Masked())
		}
		if len(nets) == 0 {
			return nil, errors.New("cidr() needs at least one prefix")
		}
		return literal{value{kind: kindNets, nets: nets}}, nil
	}
	return nil, errors.New("in needs a [list] or cidr(...)")
}

func (p *parser) parseTerm() (node, error) {
	t := p.peek()
	if t == nil {
		return nil, errors.New("unexpected end of expression")
	}
	p.pos++
	switch t.kind {
	case tokString, tokNumber:
		return literal{str(t.text)}, nil
	case tokPunct:
		if t.text == "(" {
			x, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			if err := p.expect(tokPunct, ")"); err != nil {
				return nil, err
			}
			return x, nil
		}
		return nil, fmt.Errorf("unexpected %q at %d", t.text, t.pos)
	}
	switch t.text {
	case "true", "false":
		return literal{boolean(t.text == "true")}, nil
	}
	if p.accept(tokPunct, "(") {
		return p.parseCall(t)
	}
	if !p.vars[t.text] {
		return nil, fmt.Errorf("unknown variable %q at %d", t.text, t.pos)
	}
	return variable{t.text}, nil
}

func (p *parser) parseCall(name *token) (node, error) {
	arity, ok := functions[name.text]
	if !ok {
		return nil, fmt.Errorf("unknown function %q at %d", name.text, name.pos)
	}
	var args []node
	for !p.accept(tokPunct, ")") {
		if len(args) > 0 {
			if err := p.expect(tokPunct, ","); err != nil {
				return nil, err
			}
		}
		if name.text == "matches" && len(args) == 1 {
			re, err := p.parseRegex()
			if err != nil {
				return nil, err
			}
			args = append(args, regexArg{re})
			continue
		}
		a, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		args = append(args, a)
	}
	if len(args) != arity {
		return nil, fmt.Errorf("%s() takes %d argument(s), got %d", name.text, arity, len(args))
	}
	if name.text == "capture" {
		lit, ok := args[0].(literal)
		if !ok {
			return nil, errors.New("capture() takes a quoted group name or number")
		}
		if _, err := strconv.Atoi(lit.v.s); err != nil && !containsString(p.captures, lit.v.s) {
			return nil, fmt.Errorf("capture(%q): no such group", lit.v.s)
		}
	}
	return call{name.text, args}, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
