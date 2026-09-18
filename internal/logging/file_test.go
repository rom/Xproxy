package logging

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

func fourStreams(dir string) config.Logging {
	return config.Logging{Directory: dir, Level: "info",
		Access: config.LogStream{File: "access.log"}, Error: config.LogStream{File: "error.log"},
		Security: config.LogStream{File: "security.log"}, Audit: config.LogStream{File: "audit.log"}}
}

func TestReopenAfterRotation(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(fourStreams(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Audit.Info("one")
	p := filepath.Join(dir, "audit.log")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	l.Audit.Info("two") // still goes to the renamed file
	l.Reopen()
	l.Audit.Info("three")
	old, _ := os.ReadFile(p + ".1")
	cur, _ := os.ReadFile(p)
	if !strings.Contains(string(old), "one") || !strings.Contains(string(old), "two") || !strings.Contains(string(cur), "three") || strings.Contains(string(cur), "two") {
		t.Fatalf("old %q new %q", old, cur)
	}
}

func TestInternalRotation(t *testing.T) {
	dir := t.TempDir()
	cfg := fourStreams(dir)
	cfg.Audit.MaxSizeMB = 1
	cfg.Audit.MaxFiles = 2
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	line := strings.Repeat("x", 1000)
	for i := 0; i < 2500; i++ { // ~2.5 MiB: at least two rotations
		l.Audit.Info(line)
	}
	names, _ := filepath.Glob(filepath.Join(dir, "audit.log*"))
	if len(names) < 2 || len(names) > 3 {
		t.Fatalf("archives: %v", names)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.3")); err == nil {
		t.Fatal("more archives than max_files")
	}
}

func TestWriteErrorsCounted(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full not available")
	}
	cfg := config.Logging{Directory: "/dev", Level: "info",
		Access: config.LogStream{File: "full"}, Error: config.LogStream{File: "full"},
		Security: config.LogStream{File: "full"}, Audit: config.LogStream{File: "full"}}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 3; i++ {
		l.SecurityEvent(context.Background(), "deny", "test")
	}
	if got := l.Stats().WriteErrors; got != 3 {
		t.Fatalf("write errors %d", got)
	}
}

func TestDiscardStderrAndLevels(t *testing.T) {
	Discard().Error.Info("nowhere")
	Stderr("warn").Error.Debug("hidden")
	for in, want := range map[string]string{"debug": "DEBUG", "info": "INFO", "warn": "WARN", "error": "ERROR", "": "INFO", "bogus": "INFO"} {
		if got := parseLevel(in).String(); got != want {
			t.Errorf("parseLevel(%q) = %s", in, got)
		}
	}
	w, err := newFileWriter(filepath.Join(t.TempDir(), "x.log"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("write after close succeeded")
	}
	if err := w.Close(); err != nil {
		t.Fatal("second close must be a no-op")
	}
}
