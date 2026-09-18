package config

import (
	"slices"
	"strings"
	"testing"
)

// FuzzUnifiedDiff checks the line differ: never panics, reports a change
// exactly when the line sequences differ (a trailing newline is not a
// line), and every hunk line of a differing pair comes from one of the
// inputs.
func FuzzUnifiedDiff(f *testing.F) {
	f.Add("a\nb\nc\n", "a\nx\nc\n")
	f.Add("", "a\n")
	f.Add("same\n", "same\n")
	f.Add(strings.Repeat("l\n", 50), strings.Repeat("l\n", 49)+"m\n")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 4096 || len(b) > 4096 {
			return
		}
		out, truncated := unifiedDiff(a, b, "a", "b")
		if truncated {
			t.Fatalf("small inputs truncated (%d and %d bytes)", len(a), len(b))
		}
		changed := strings.Contains(out, "\n@@") // the labels are always printed
		la, lb := strings.Split(strings.TrimSuffix(a, "\n"), "\n"), strings.Split(strings.TrimSuffix(b, "\n"), "\n")
		same := slices.Equal(la, lb)
		if same && changed {
			t.Fatalf("equal line sequences reported as changed:\n%s", out)
		}
		if !same && !changed {
			t.Fatalf("different line sequences reported as equal: %q vs %q", a, b)
		}
		if !changed {
			return
		}
		src := map[string]bool{}
		for _, l := range strings.Split(a, "\n") {
			src[l] = true
		}
		for _, l := range strings.Split(b, "\n") {
			src[l] = true
		}
		for _, l := range strings.Split(out, "\n") {
			if l == "" || strings.HasPrefix(l, "@@") || strings.HasPrefix(l, "---") || strings.HasPrefix(l, "+++") || strings.HasPrefix(l, "...") {
				continue
			}
			if !src[l[1:]] {
				t.Fatalf("hunk line %q not from either input\n%s", l, out)
			}
		}
	})
}
