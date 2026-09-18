package logging

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

func TestAccessTextFormats(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Logging{Directory: dir, Level: "info",
		Access:   config.LogStream{File: "access.log", Format: "combined"},
		Error:    config.LogStream{File: "error.log"},
		Security: config.LogStream{File: "security.log"},
		Audit:    config.LogStream{File: "audit.log"}}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.Access.Info("request", "client_ip", "203.0.113.9", "method", "GET", "path", "/index.html", "proto", "HTTP/1.1",
		"status", 200, "bytes_out", 2326, "referer", "http://www.example.com/start.html",
		"user_agent", "Mozilla/4.08 \"Win98\"\nX", "oidc_sub", "frank")
	l.Access.Info("request", "client_ip", "203.0.113.10", "method", "HEAD", "path", "/", "proto", "HTTP/2.0", "status", 304, "bytes_out", 0)
	l.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "access.log"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", b)
	}
	re := regexp.MustCompile(`^203\.0\.113\.9 - frank \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "GET /index\.html HTTP/1\.1" 200 2326 "http://www\.example\.com/start\.html" "Mozilla/4\.08 \\"Win98\\"\\nX"$`)
	if !re.MatchString(lines[0]) {
		t.Fatalf("combined line: %s", lines[0])
	}
	if !strings.HasSuffix(lines[1], `"HEAD / HTTP/2.0" 304 - "-" "-"`) || !strings.HasPrefix(lines[1], "203.0.113.10 - - [") {
		t.Fatalf("second line: %s", lines[1])
	}

	// Custom template with a missing field and derived fields.
	dir2 := t.TempDir()
	cfg.Directory = dir2
	cfg.Access = config.LogStream{File: "access.log", Format: "custom", Template: `{time_unix} {route}|{status}|{nope}|{stream}|{request}`}
	l, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.Access.Info("request", "route", "app", "status", 503, "method", "POST", "path", "/x", "proto", "HTTP/1.1")
	l.Close()
	b, _ = os.ReadFile(filepath.Join(dir2, "access.log"))
	line := strings.TrimSpace(string(b))
	if !regexp.MustCompile(`^\d+ app\|503\|-\|access\|POST /x HTTP/1\.1$`).MatchString(line) {
		t.Fatalf("custom line: %s", line)
	}
	for _, bad := range []string{"{", "a {} b", "{a b}", "{x"} {
		if ValidTemplate(bad) == nil {
			t.Errorf("template %q accepted", bad)
		}
	}
	if TemplateFor("json", "") != "" || TemplateFor("common", "") == "" || TemplateFor("custom", "x") != "x" {
		t.Fatal("TemplateFor")
	}
}
