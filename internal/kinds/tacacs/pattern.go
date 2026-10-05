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

// match reports whether a command line matches, which is the reading an
// *allow* list is given: exactly these words, unless the pattern said `...`.
// Allowing a command because it begins with an allowed one is the unsafe
// direction -- `show running-config | include password` begins with `show
// running-config` -- so a longer command is not covered here.
func (p pattern) match(cmd string) bool {
	words := strings.Fields(strings.ToLower(cmd))
	if !p.prefix && len(words) != len(p.words) {
		return false
	}
	return p.covers(words)
}

// covers is the word comparison the two readings share.
func (p pattern) covers(words []string) bool {
	if len(words) < len(p.words) {
		return false
	}
	for i, w := range p.words {
		if words[i] != w {
			return false
		}
	}
	return true
}

// reaches reports whether a pattern covers this command or any command that
// begins with it, which is the reading a *deny* list is given.
//
// The asymmetry is deliberate and it is the only place in this file where a
// pattern means two things. A device's command line takes suffixes: a filter
// (`show running-config | include password`), a redirect (`copy
// running-config tftp: ...`), a trailing argument. Under the exact reading a
// deny of `show running-config` misses every one of them -- which is to say it
// misses the spelling an attacker would use and matches only the one an
// operator would -- so a deny pattern covers the command it names and whatever
// follows. Denying more than was asked is the safe direction on a list whose
// purpose is "no router behind this relay accepts this"; allowing more than was
// asked is not, which is why match above stays exact.
func (p pattern) reaches(cmd string) bool {
	return p.covers(strings.Fields(strings.ToLower(cmd)))
}

// matchAny reports whether any pattern matches, for an allow list.
func matchAny(ps []pattern, cmd string) bool {
	for _, p := range ps {
		if p.match(cmd) {
			return true
		}
	}
	return false
}

// reachesAny reports whether any pattern reaches the command, for a deny list.
func reachesAny(ps []pattern, cmd string) bool {
	for _, p := range ps {
		if p.reaches(cmd) {
			return true
		}
	}
	return false
}
