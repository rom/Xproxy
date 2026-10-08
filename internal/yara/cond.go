package yara

import "strings"

// env is what a condition is evaluated against: the occurrence count of
// every pattern so far, and how many bytes have gone past.
type env struct {
	counts   map[string]int
	filesize int64
}

// expr is a condition.
type expr interface {
	eval(e *env) bool
}

type boolLit bool

func (b boolLit) eval(*env) bool { return bool(b) }

type notExpr struct{ x expr }

func (n notExpr) eval(e *env) bool { return !n.x.eval(e) }

type andExpr struct{ a, b expr }

func (x andExpr) eval(e *env) bool { return x.a.eval(e) && x.b.eval(e) }

type orExpr struct{ a, b expr }

func (x orExpr) eval(e *env) bool { return x.a.eval(e) || x.b.eval(e) }

// stringExpr is "$a": true when the pattern occurred at least once.
type stringExpr struct{ name string }

func (s stringExpr) eval(e *env) bool { return e.counts[s.name] > 0 }

// countExpr is "#a <op> n".
type countExpr struct {
	name string
	op   string
	n    int64
}

func (c countExpr) eval(e *env) bool {
	return compare(int64(e.counts["$"+c.name]), c.op, c.n)
}

// sizeExpr is "filesize <op> n". In a stream filesize is the bytes seen
// so far, which is the only honest answer: there is no end to measure
// against until there is.
type sizeExpr struct {
	op string
	n  int64
}

func (s sizeExpr) eval(e *env) bool { return compare(e.filesize, s.op, s.n) }

// ofExpr is "N of <set>", where N is a count, "any" (1) or "all".
type ofExpr struct {
	n     int64
	all   bool
	items []string
}

func (o ofExpr) eval(e *env) bool {
	got := int64(0)
	for _, name := range o.items {
		if e.counts[name] > 0 {
			got++
		}
	}
	if o.all {
		return got == int64(len(o.items)) && len(o.items) > 0
	}
	return got >= o.n
}

func compare(a int64, op string, b int64) bool {
	switch op {
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	case "==":
		return a == b
	case "!=":
		return a != b
	}
	return false
}

// condition parses a rule's condition.
func (p *parser) condition(r *Rule) (expr, error) {
	e, err := p.orTerm(r)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (p *parser) orTerm(r *Rule) (expr, error) {
	left, err := p.andTerm(r)
	if err != nil {
		return nil, err
	}
	for p.tok.kind == tokIdent && p.tok.text == "or" {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.andTerm(r)
		if err != nil {
			return nil, err
		}
		left = orExpr{left, right}
	}
	return left, nil
}

func (p *parser) andTerm(r *Rule) (expr, error) {
	left, err := p.unary(r)
	if err != nil {
		return nil, err
	}
	for p.tok.kind == tokIdent && p.tok.text == "and" {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.unary(r)
		if err != nil {
			return nil, err
		}
		left = andExpr{left, right}
	}
	return left, nil
}

func (p *parser) unary(r *Rule) (expr, error) {
	if p.tok.kind == tokIdent && p.tok.text == "not" {
		if err := p.advance(); err != nil {
			return nil, err
		}
		x, err := p.unary(r)
		if err != nil {
			return nil, err
		}
		return notExpr{x}, nil
	}
	return p.primary(r)
}

func (p *parser) primary(r *Rule) (expr, error) {
	switch {
	case p.tok.kind == tokPunct && p.tok.text == "(":
		if err := p.advance(); err != nil {
			return nil, err
		}
		x, err := p.orTerm(r)
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return x, nil
	case p.tok.kind == tokIdentifier && strings.HasPrefix(p.tok.text, "$"):
		// Refused before the token is consumed, as the "#" case below
		// does: p.errf reports the line of the current token, so
		// advancing first named the line after the mistake.
		name := p.tok.text
		if strings.Contains(name, "*") {
			return nil, p.errf("%q: a wildcard belongs in a set, as in \"any of (%s)\"", name, name)
		}
		if !hasPattern(r, name) {
			return nil, p.errf("%s is not defined in this rule", name)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return stringExpr{name}, nil
	case p.tok.kind == tokIdentifier && strings.HasPrefix(p.tok.text, "#"):
		name := p.tok.text[1:]
		if !hasPattern(r, "$"+name) {
			return nil, p.errf("#%s: $%s is not defined in this rule", name, name)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		op, n, err := p.comparison()
		if err != nil {
			return nil, err
		}
		return countExpr{name: name, op: op, n: n}, nil
	case p.tok.kind == tokIdentifier:
		return nil, p.errf("%q is not supported: string offsets and lengths have no meaning in a stream", p.tok.text)
	case p.tok.kind == tokIdent:
		return p.identPrimary(r)
	case p.tok.kind == tokNumber:
		n := p.tok.num
		if err := p.advance(); err != nil {
			return nil, err
		}
		return p.numberOf(r, n)
	}
	return nil, p.errf("unexpected %q in a condition", p.tok.text)
}

func (p *parser) identPrimary(r *Rule) (expr, error) {
	word := p.tok.text
	switch word {
	case "true", "false":
		if err := p.advance(); err != nil {
			return nil, err
		}
		return boolLit(word == "true"), nil
	case "filesize":
		if err := p.advance(); err != nil {
			return nil, err
		}
		op, n, err := p.comparison()
		if err != nil {
			return nil, err
		}
		return sizeExpr{op: op, n: n}, nil
	case "any", "all":
		if err := p.advance(); err != nil {
			return nil, err
		}
		return p.ofSet(r, word == "all", 1)
	case "them":
		return nil, p.errf("\"them\" must follow \"of\"")
	case "entrypoint", "for", "at", "in", "matches", "contains":
		return nil, p.errf("%q is not supported; %s", word, Limits)
	}
	return nil, p.errf("%q is not supported in a condition; %s", word, Limits)
}

// ofSet parses the rest of "N of <set>" once the count is known.
func (p *parser) ofSet(r *Rule, all bool, n int64) (expr, error) {
	if p.tok.kind != tokIdent || p.tok.text != "of" {
		return nil, p.errf("expected \"of\", found %q", p.tok.text)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	var items []string
	switch {
	case p.tok.kind == tokIdent && p.tok.text == "them":
		if err := p.advance(); err != nil {
			return nil, err
		}
		for _, pat := range r.Patterns {
			if !pat.Private {
				items = append(items, pat.Name)
			}
		}
	case p.tok.kind == tokPunct && p.tok.text == "(":
		if err := p.advance(); err != nil {
			return nil, err
		}
		for {
			if p.tok.kind != tokIdentifier || !strings.HasPrefix(p.tok.text, "$") {
				return nil, p.errf("expected a string name in the set, found %q", p.tok.text)
			}
			name := p.tok.text
			matched := expand(r, name)
			if len(matched) == 0 {
				return nil, p.errf("%s matches no string in this rule", name)
			}
			items = append(items, matched...)
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.kind == tokPunct && p.tok.text == "," {
				if err := p.advance(); err != nil {
					return nil, err
				}
				continue
			}
			break
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
	default:
		return nil, p.errf("expected \"them\" or a set in parentheses, found %q", p.tok.text)
	}
	if len(items) == 0 {
		return nil, p.errf("the set is empty")
	}
	if !all && n > int64(len(items)) {
		return nil, p.errf("%d of %d strings can never be true", n, len(items))
	}
	return ofExpr{n: n, all: all, items: dedupe(items)}, nil
}

// comparison reads "<op> <number>".
func (p *parser) comparison() (string, int64, error) {
	if p.tok.kind != tokPunct {
		return "", 0, p.errf("expected a comparison, found %q", p.tok.text)
	}
	op := p.tok.text
	switch op {
	case "<", "<=", ">", ">=", "==", "!=":
	default:
		return "", 0, p.errf("%q is not a comparison", op)
	}
	if err := p.advance(); err != nil {
		return "", 0, err
	}
	if p.tok.kind != tokNumber {
		return "", 0, p.errf("expected a number, found %q", p.tok.text)
	}
	n := p.tok.num
	if err := p.advance(); err != nil {
		return "", 0, err
	}
	return op, n, nil
}

func hasPattern(r *Rule, name string) bool {
	for _, p := range r.Patterns {
		if p.Name == name {
			return true
		}
	}
	return false
}

// expand resolves "$a*" to the strings it names.
func expand(r *Rule, name string) []string {
	if !strings.HasSuffix(name, "*") {
		if hasPattern(r, name) {
			return []string{name}
		}
		return nil
	}
	prefix := strings.TrimSuffix(name, "*")
	var out []string
	for _, p := range r.Patterns {
		if strings.HasPrefix(p.Name, prefix) {
			out = append(out, p.Name)
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s) //nolint:gocritic // filtering in place
	}
	return out
}

// numberOf handles "N of ..." where the parser has already read N.
func (p *parser) numberOf(r *Rule, n int64) (expr, error) {
	if n < 0 {
		// The lexer now refuses the literals that could arrive here
		// negative, so this is belt and braces. It stays because the
		// fault it guards is a fail-open: ofExpr asks whether the count
		// is at least n, and a negative n is satisfied before a single
		// byte has gone past.
		return nil, p.errf("a negative count is not a condition")
	}
	return p.ofSet(r, false, n)
}
