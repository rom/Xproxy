package yara

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Rule is one parsed rule.
type Rule struct {
	Name     string
	Tags     []string
	Meta     map[string]string
	Patterns []*Pattern
	Cond     expr
	Global   bool
	Private  bool
	// Width is the overlap in bytes a stream needs so that a match
	// straddling two reads is still found.
	Width int
}

// Rules is a compiled rule set.
type Rules struct {
	rules []*Rule
	width int
}

// Limits states what this implementation supports, so an operator can
// tell before writing rules rather than after.
const Limits = `strings: text (nocase, wide, ascii, fullword, private), hex with ?? and 4? wildcards and [n] or [n-m] jumps, regular expressions (RE2, with i and s flags);
conditions: $a, not, and, or, parentheses, "N of them", "any of them", "all of them", "N of ($a*)", "#a" and "filesize" compared with a number, true, false;
not supported: modules and imports, "at", "in", "for" loops, entrypoint, unbounded jumps, alternation inside a hex string, string offsets and lengths (@a, !a).`

// Compile parses a rule set.
func Compile(src string) (*Rules, error) {
	p := &parser{lex: newLexer(src)}
	if err := p.advance(); err != nil {
		return nil, err
	}
	rs := &Rules{}
	for p.tok.kind != tokEOF {
		r, err := p.rule()
		if err != nil {
			return nil, err
		}
		for _, other := range rs.rules {
			if other.Name == r.Name {
				return nil, fmt.Errorf("rule %q is defined twice", r.Name)
			}
		}
		rs.rules = append(rs.rules, r)
		if r.Width > rs.width {
			rs.width = r.Width
		}
	}
	if len(rs.rules) == 0 {
		return nil, errors.New("no rules")
	}
	return rs, nil
}

// Rules returns the rule names, sorted, for a status view.
func (rs *Rules) Names() []string {
	out := make([]string, 0, len(rs.rules))
	for _, r := range rs.rules {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// Len is the number of rules.
func (rs *Rules) Len() int { return len(rs.rules) }

// Width is the overlap a stream needs between windows.
func (rs *Rules) Width() int { return rs.width }

type parser struct {
	lex *lexer
	tok token
}

func (p *parser) advance() error {
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("line %d: "+format, append([]any{p.tok.line}, args...)...)
}

func (p *parser) expectPunct(s string) error {
	if p.tok.kind != tokPunct || p.tok.text != s {
		return p.errf("expected %q, found %q", s, p.tok.text)
	}
	return p.advance()
}

func (p *parser) rule() (*Rule, error) {
	r := &Rule{Meta: map[string]string{}}
	for p.tok.kind == tokIdent && (p.tok.text == "global" || p.tok.text == "private") {
		if p.tok.text == "global" {
			r.Global = true
		} else {
			r.Private = true
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
	}
	if p.tok.kind != tokIdent {
		return nil, p.errf("expected a rule, found %q", p.tok.text)
	}
	if p.tok.text == "import" || p.tok.text == "include" {
		return nil, p.errf("%s is not supported; this is a self-contained subset of YARA", p.tok.text)
	}
	if p.tok.text != "rule" {
		return nil, p.errf("expected \"rule\", found %q", p.tok.text)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	if p.tok.kind != tokIdent {
		return nil, p.errf("expected a rule name")
	}
	r.Name = p.tok.text
	if err := p.advance(); err != nil {
		return nil, err
	}
	if p.tok.kind == tokPunct && p.tok.text == ":" {
		if err := p.advance(); err != nil {
			return nil, err
		}
		for p.tok.kind == tokIdent {
			r.Tags = append(r.Tags, p.tok.text)
			if err := p.advance(); err != nil {
				return nil, err
			}
		}
		if len(r.Tags) == 0 {
			return nil, p.errf("expected at least one tag after \":\"")
		}
	}
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	for {
		if p.tok.kind == tokPunct && p.tok.text == "}" {
			return nil, p.errf("rule %q has no condition", r.Name)
		}
		if p.tok.kind != tokIdent {
			return nil, p.errf("expected meta, strings or condition, found %q", p.tok.text)
		}
		section := p.tok.text
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		switch section {
		case "meta":
			if err := p.meta(r); err != nil {
				return nil, err
			}
		case "strings":
			if err := p.strings(r); err != nil {
				return nil, err
			}
		case "condition":
			cond, err := p.condition(r)
			if err != nil {
				return nil, err
			}
			r.Cond = cond
			if err := p.expectPunct("}"); err != nil {
				return nil, err
			}
			r.Width = p.width(r)
			return r, nil
		default:
			return nil, p.errf("unknown section %q", section)
		}
	}
}

// width is the overlap this rule needs: the longest pattern, or 0 when
// it has none with a fixed width.
func (p *parser) width(r *Rule) int {
	w := 0
	for _, pat := range r.Patterns {
		if pat.width > w {
			w = pat.width
		}
	}
	return w
}

func (p *parser) meta(r *Rule) error {
	for p.tok.kind == tokIdent && !isSection(p.tok.text) {
		key := p.tok.text
		if err := p.advance(); err != nil {
			return err
		}
		if err := p.expectPunct("="); err != nil {
			return err
		}
		switch p.tok.kind {
		case tokString:
			r.Meta[key] = p.tok.text
		case tokNumber:
			r.Meta[key] = p.tok.text
		case tokIdent:
			if p.tok.text != "true" && p.tok.text != "false" {
				return p.errf("meta value must be a string, a number or a boolean")
			}
			r.Meta[key] = p.tok.text
		default:
			return p.errf("meta value must be a string, a number or a boolean")
		}
		if err := p.advance(); err != nil {
			return err
		}
	}
	return nil
}

func isSection(s string) bool { return s == "meta" || s == "strings" || s == "condition" }

func (p *parser) strings(r *Rule) error {
	for p.tok.kind == tokIdentifier {
		name := p.tok.text
		if !strings.HasPrefix(name, "$") {
			return p.errf("a string is named with $, found %q", name)
		}
		if strings.Contains(name, "*") {
			return p.errf("%q: a wildcard names a set in a condition, not a string", name)
		}
		for _, other := range r.Patterns {
			if other.Name == name {
				return p.errf("%s is defined twice", name)
			}
		}
		if err := p.advance(); err != nil {
			return err
		}
		if err := p.expectPunct("="); err != nil {
			return err
		}
		kind := p.tok.kind
		text := p.tok.text
		if kind == tokPunct && text == "{" {
			hex, err := p.lex.hexString()
			if err != nil {
				return err
			}
			kind, text = tokHex, hex
		} else if kind != tokString && kind != tokRegex {
			return p.errf("expected a string, a regular expression or a hex pattern")
		}
		if err := p.advance(); err != nil {
			return err
		}
		mods := map[string]bool{}
		for p.tok.kind == tokIdent && isModifier(p.tok.text) {
			mods[p.tok.text] = true
			if err := p.advance(); err != nil {
				return err
			}
		}
		if p.tok.kind == tokIdent && !isSection(p.tok.text) {
			return p.errf("%q is not a string modifier this implementation supports", p.tok.text)
		}
		pat, err := compilePattern(name, kind, text, mods)
		if err != nil {
			return p.errf("%s: %v", name, err)
		}
		r.Patterns = append(r.Patterns, pat)
	}
	if len(r.Patterns) == 0 {
		return p.errf("the strings section is empty")
	}
	return nil
}

func isModifier(s string) bool {
	switch s {
	case "nocase", "wide", "ascii", "fullword", "private":
		return true
	case "xor", "base64", "base64wide":
		return false
	}
	return false
}

// LoadFile compiles one rule file.
func LoadFile(path string) (*Rules, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a path from the configuration
	if err != nil {
		return nil, err
	}
	rs, err := Compile(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

// LoadDir compiles every .yar and .yara file in a directory, in name
// order, as one rule set. A file that does not compile fails the load:
// a rule set that silently lost a rule is worse than one that will not
// start.
func LoadDir(dir string) (*Rules, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".yar") || strings.HasSuffix(n, ".yara") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no .yar or .yara files", dir)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n)) //nolint:gosec // a directory from the configuration
		if err != nil {
			return nil, err
		}
		b.Write(raw)
		b.WriteString("\n")
	}
	rs, err := Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return rs, nil
}
