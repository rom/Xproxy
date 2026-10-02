package tacacs

import (
	"fmt"
	"strings"
)

// Command patterns.
//
// The grammar is words, with an optional trailing `...` meaning "and
// anything after". That is the whole of it, and the smallness is the point:
// this is the list that decides whether somebody can reconfigure a core
// router, and a pattern language rich enough to be subtle is a pattern
// language whose author and whose reader disagree.
//
// Matching is word by word and case-insensitively, because a device's
// command line is case-insensitive on every platform that speaks this
// protocol -- `SHOW VERSION` and `show version` are one command, and a
// policy that told them apart would be a policy with a trivial bypass.
//
// Abbreviation is deliberately *not* handled. A Cisco user may type `conf t`
// and the device expands it, but what reaches the TACACS+ server is what the
// device sends, and every platform worth naming sends the expanded form.
// Guessing at expansions here would mean this relay and the device
// disagreeing about what command was run, which is worse than a pattern that
// does not match.

// pattern is one compiled command pattern.
type pattern struct {
	words  []string
	prefix bool
	raw    string
}

// patterns compiles a list.
func patterns(list []string) ([]pattern, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]pattern, 0, len(list))
	for _, s := range list {
		p, err := compilePattern(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func compilePattern(s string) (pattern, error) {
	raw := strings.TrimSpace(s)
	words := strings.Fields(strings.ToLower(raw))
	if len(words) == 0 {
		return pattern{}, fmt.Errorf("%q is empty", s)
	}
	p := pattern{raw: raw}
	for i, w := range words {
		if w != "..." {
			if strings.Contains(w, "...") {
				return pattern{}, fmt.Errorf("%q: \"...\" must stand alone as the last word", s)
			}
			p.words = append(p.words, w)
			continue
		}
		if i != len(words)-1 {
			return pattern{}, fmt.Errorf("%q: \"...\" must be the last word", s)
		}
		p.prefix = true
	}
	if len(p.words) == 0 {
		// A pattern of `...` alone covers every command, which is what an
		// empty list already means. Refusing it is the kinder reading: an
		// operator who wrote it meant something and this is not it.
		return pattern{}, fmt.Errorf("%q: a pattern of only \"...\" covers every command; "+
			"leave the list empty to allow all", s)
	}
	return p, nil
}

// match reports whether a command line matches.
func (p pattern) match(cmd string) bool {
	words := strings.Fields(strings.ToLower(cmd))
	if len(words) < len(p.words) {
		return false
	}
	if !p.prefix && len(words) != len(p.words) {
		return false
	}
	for i, w := range p.words {
		if words[i] != w {
			return false
		}
	}
	return true
}

// matchAny reports whether any pattern matches.
func matchAny(ps []pattern, cmd string) bool {
	for _, p := range ps {
		if p.match(cmd) {
			return true
		}
	}
	return false
}
