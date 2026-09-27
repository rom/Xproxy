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
// So this reads the source of every kind that has an enforcing() and fails on the
// shape: a body that does not mention Shadowing. It is a source test rather than a
// behavioural one because the behaviour is per protocol and the defect is not: the
// two kinds where it is driven over a socket are postgres and redis, and what this
// adds is that a kind written tomorrow cannot quietly leave the switch out.
func TestEveryKindReadsTheListenersOwnShadowSwitch(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "kinds")
	// A one-line enforcing(), or the opening of a multi-line one. modbus writes
	// the long form; both have to mention Shadowing.
	oneLine := regexp.MustCompile(`func \(\w+ \*server\) enforcing\(\) bool \{([^\n]*)\n`)
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
		m := oneLine.FindStringSubmatchIndex(src)
		if m == nil {
			return nil
		}
		body := src[m[2]:m[3]]
		if !strings.Contains(body, "}") {
			// A multi-line body: read to the closing brace at column zero.
			rest := src[m[3]:]
			if end := strings.Index(rest, "\n}"); end >= 0 {
				body += rest[:end]
			}
		}
		if !strings.Contains(body, "Shadowing()") {
			t.Errorf("%s: enforcing() does not read the listener's own shadow "+
				"switch, so policy: {mode: shadow} is evaluated and then enforced "+
				"on this kind; add !cfg.Shadowing() to it", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
