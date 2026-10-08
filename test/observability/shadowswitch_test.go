package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every kind that has an enforcing() reads the listener's own shadow switch, and
// this holds it across all of them at once rather than one test per kind.
//
// `policy: {mode: shadow}` is the estate's spelling of "evaluate and do not
// enforce", documented for every listener. A kind whose enforcing() reads only its
// own monitor_only ignores it silently: the policy is evaluated, the refusal is
// applied, and the operator who asked for a trial gets a door. Four kinds had it
// that way -- postgres, mysql, tds and redis -- each with its own monitor_only and
// no reference to Shadowing anywhere in the package.
//
// It is a source test rather than a behavioural one because the behaviour is per
// protocol and the defect is not: what this adds is that a kind written tomorrow
// cannot quietly leave the switch out.
//
// It now checks two things rather than one, because the enforcement sources were
// folded into config.Enforcement: enforcing() must delegate to that fold rather
// than hand-rolling the combination, and the enforcement() that feeds it must take
// Shadow from the listener. The first half is the new half, and it is the one that
// keeps the precedence the same on every kind -- a hand-rolled enforcing() that
// happened to mention Shadowing() would have passed the old shape while ordering
// the sources differently from its twenty-two siblings.
func TestEveryKindReadsTheListenersOwnShadowSwitch(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "kinds")
	enforcing := regexp.MustCompile(`func \(\w+ \*server\) enforcing\(\) bool \{`)
	enforcement := regexp.MustCompile(`func \(\w+ \*server\) enforcement\(\) config\.Enforcement \{`)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		m := enforcing.FindStringIndex(src)
		if m == nil {
			return nil
		}
		if body, ok := funcBody(src, m[1]-1); !ok || !strings.Contains(body, "enforcement().Enforcing()") {
			t.Errorf("%s: enforcing() does not go through config.Enforcement, so this kind "+
				"combines the enforcement sources its own way; return <recv>.enforcement().Enforcing()", path)
			return nil
		}
		n := enforcement.FindStringIndex(src)
		if n == nil {
			t.Errorf("%s: enforcing() delegates to enforcement() and there is none in this file", path)
			return nil
		}
		body, ok := funcBody(src, n[1]-1)
		if !ok {
			t.Errorf("%s: enforcement() does not parse", path)
			return nil
		}
		if !strings.Contains(body, "Shadowing()") {
			t.Errorf("%s: enforcement() does not read the listener's own shadow "+
				"switch, so policy: {mode: shadow} is evaluated and then enforced "+
				"on this kind; set Shadow from cfg.Shadowing()", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// funcBody returns the text between the brace at open and its match, so a
// one-line body and a multi-line one are read the same way. The old version read
// to the first "\n}" and would have taken the next function's text with it had
// anything in between closed at column zero.
func funcBody(src string, open int) (string, bool) {
	if open < 0 || open >= len(src) || src[open] != '{' {
		return "", false
	}
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], true
			}
		}
	}
	return "", false
}
