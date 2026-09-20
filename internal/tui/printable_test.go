package tui

import "testing"

// TestCompactLogLinePrintable: request fields in a security line are
// attacker chosen; DEL and C1 controls (which slog's JSON encoder passes
// through) must not reach the terminal.
func TestCompactLogLinePrintable(t *testing.T) {
	line := `{"time":"2026-09-20T10:11:12Z","msg":"security","action":"deny","reason":"waf","client_ip":"203.0.113.9","method":"GET","host":"h.test","path":"/x` + "\u009b" + `31mred` + "\u007f" + `"}`
	got := compactLogLine(line)
	for _, r := range got {
		if r == 0x9b || r == 0x7f {
			t.Fatalf("control rune reached the output: %q", got)
		}
	}
	if got != "10:11:12 deny waf 203.0.113.9 GET h.test /x31mred" {
		t.Fatalf("line %q", got)
	}
}
