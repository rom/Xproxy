package logging

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

func TestOpenAndWrite(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Logging{Directory: dir, Level: "info",
		Access: config.LogStream{File: "access.log"}, Error: config.LogStream{File: "error.log"},
		Security: config.LogStream{File: "security.log"}, Audit: config.LogStream{File: "audit.log"}}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.SecurityEvent(context.Background(), "deny", "rate_limit", "client_ip", "1.2.3.4", "ua", "evil\n\"injected\":true")
	l.Error.Debug("hidden")
	l.Error.Info("visible")
	l.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "security.log"))
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not a single JSON line: %q", b)
	}
	if m["action"] != "deny" || m["reason"] != "rate_limit" || m["stream"] != "security" {
		t.Fatalf("fields: %v", m)
	}
	if m["ua"] != "evil\n\"injected\":true" {
		t.Fatalf("ua not preserved verbatim: %v", m["ua"])
	}
	e, _ := os.ReadFile(filepath.Join(dir, "error.log"))
	if strings.Contains(string(e), "hidden") || !strings.Contains(string(e), "visible") {
		t.Fatalf("level filter: %s", e)
	}
	st, _ := os.Stat(filepath.Join(dir, "error.log"))
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestRotate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	w, err := newFileWriter(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("a", 60) + "\n")
	for i := 0; i < 6; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	for _, n := range []string{"x.log", "x.log.1", "x.log.2"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s missing", n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "x.log.3")); err == nil {
		t.Error("x.log.3 should not exist")
	}
}
