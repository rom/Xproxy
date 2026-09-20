package logging

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// A span is not a log line, so nothing took its client address through
// the redactor: the trace collector held the full address next to a
// trace id the access log also carries.
func TestRedactorClientAddress(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ mode, want string }{
		{"truncate", "203.0.113.0/24"},
		{"keep", "203.0.113.9"},
		{"", "203.0.113.9"},
	} {
		r, err := NewRedactor(&config.Redaction{ClientIP: tc.mode})
		if err != nil {
			t.Fatal(err)
		}
		if got := r.ClientAddress("203.0.113.9"); got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.mode, got, tc.want)
		}
	}
	h, err := NewRedactor(&config.Redaction{ClientIP: "hash", HashSecretFile: filepath.Join(dir, "k")})
	if err != nil {
		t.Fatal(err)
	}
	got := h.ClientAddress("203.0.113.9")
	if !strings.HasPrefix(got, "h:") || got == "203.0.113.9" {
		t.Fatalf("hash mode: %q", got)
	}
	// It is the same pseudonym the log lines carry, so the two stores
	// agree instead of one reversing the other.
	a, _ := h.Attr(slog.String("client_ip", "203.0.113.9"))
	if a.Value.String() != got {
		t.Fatalf("span %q and log %q disagree", got, a.Value.String())
	}
	// A nil redactor (redaction off) changes nothing.
	if got := (*Redactor)(nil).ClientAddress("203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("nil redactor: %q", got)
	}
}
