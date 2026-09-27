package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A listener in shadow mode must not count a refusal it did not make, and this
// holds it across every kind at once rather than one test per kind.
//
// internal/proxy keeps two tables, refusals and would-be refusals, and says why
// in its own comment: "Kept apart so a status view cannot add them up." A kind
// that counted a decision in both defeats that in the one way that matters --
// the operator reading the refusal count of a listener under trial is exactly
// the person who must not be told that enforcement is happening when it is not.
//
// Seven kinds had it, and they had it because the counter sat above the branch
// rather than inside it, which is invisible when reading either half alone. So
// this test reads the source of every kind and fails on the shape: a Refuse for
// some reason with a WouldRefuse for the same reason close below it, in the same
// function, means the two are not exclusive.
func TestNoKindCountsARefusalItWouldOnlyHaveMade(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "kinds")
	// A Refuse and the same expression passed to WouldRefuse further down. The
	// reason has to match: the two calls in ntp's request path are about
	// different reasons in exclusive branches, which is correct and must pass.
	refuse := regexp.MustCompile(`\.Refuse\("(\w+)",\s*([^)]+)\)`)
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
		for _, m := range refuse.FindAllStringSubmatchIndex(src, -1) {
			kind := src[m[2]:m[3]]
			reason := strings.TrimSpace(src[m[4]:m[5]])
			// Only a reason held in a variable can be the same decision twice;
			// a literal reason names one specific refusal.
			if strings.HasPrefix(reason, `"`) {
				continue
			}
			rest := src[m[1]:]
			if end := strings.Index(rest, "\n}\n"); end >= 0 {
				rest = rest[:end] // stay inside the function
			}
			at := strings.Index(rest, `.WouldRefuse("`+kind+`", `+reason+`)`)
			if at < 0 {
				continue
			}
			// A return between the two puts them in exclusive branches, which is
			// the correct shape: ntp writes it that way, counting the refusal
			// inside `if enforcing { ... return }` and the would-be refusal after
			// it. Only a Refuse that both paths reach is the defect.
			if strings.Contains(rest[:at], "return") {
				continue
			}
			{
				t.Errorf("%s: Refuse(%s) is above the shadow branch that also "+
					"counts WouldRefuse(%s), so a listener in shadow mode reports "+
					"a refusal it did not make; move the Refuse onto the enforced path",
					path, reason, reason)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
