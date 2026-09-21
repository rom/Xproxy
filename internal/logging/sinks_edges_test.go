package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The log is where an operator looks after an incident, so a sink that
// cannot be built has to say so at start-up rather than dropping the
// stream, and a handler wrapper has to keep the redaction rules when
// the caller groups or adds attributes.

func TestSinkConstructionRefusals(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "none")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	siem := map[string]config.SIEM{
		"a ca file that is not there":            {Endpoint: "https://siem.example", CAFile: missing},
		"a ca file with no certificates":         {Endpoint: "https://siem.example", CAFile: notPEM},
		"a client certificate that is not there": {Endpoint: "https://siem.example", CertFile: missing, KeyFile: missing},
		"a client certificate that is not one":   {Endpoint: "https://siem.example", CertFile: notPEM, KeyFile: notPEM},
		"an auth file that is not there":         {Endpoint: "https://siem.example", AuthFile: missing},
		"an auth file that is empty":             {Endpoint: "https://siem.example", AuthFile: empty},
	}
	for name, cfg := range siem {
		cfg.Queue = 8
		cfg.Timeout = config.Duration(2000000000)
		s, err := newSIEMSink(cfg, log)
		if err == nil {
			s.close()
			t.Errorf("siem: %s was accepted", name)
		}
	}
	syslogs := map[string]config.Syslog{
		"a ca file that is not there":            {Network: "tcp+tls", Address: "siem.example:6514", CAFile: missing},
		"a ca file with no certificates":         {Network: "tcp+tls", Address: "siem.example:6514", CAFile: notPEM},
		"a client certificate that is not there": {Network: "tcp+tls", Address: "siem.example:6514", CertFile: missing, KeyFile: missing},
		"a client certificate that is not one":   {Network: "tcp+tls", Address: "siem.example:6514", CertFile: notPEM, KeyFile: notPEM},
	}
	for name, cfg := range syslogs {
		cfg.QueueSize = 8
		s, err := newSyslogSink(cfg)
		if err == nil {
			s.close()
			t.Errorf("syslog: %s was accepted", name)
		}
	}
	// A syslog sink that is configured properly takes a host name from
	// the system when none is given.
	s, err := newSyslogSink(config.Syslog{Network: "udp", Address: "127.0.0.1:514", QueueSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if s.hostname == "" || strings.ContainsAny(s.hostname, " \r\n") {
		t.Errorf("hostname %q", s.hostname)
	}
	s.close()
}

func TestFileWriterOpenFailures(t *testing.T) {
	dir := t.TempDir()
	// A path whose directory does not exist.
	if _, err := newFileWriter(filepath.Join(dir, "nope", "a.log"), 0, 0); err == nil {
		t.Error("a log file in a missing directory was opened")
	}
	// A directory in place of the file.
	if _, err := newFileWriter(dir, 0, 0); err == nil {
		t.Error("a directory was opened as a log file")
	}
	// A file that cannot be written.
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		if _, err := newFileWriter(filepath.Join(ro, "a.log"), 0, 0); err == nil {
			t.Error("a log file in an unwritable directory was opened")
		}
	}
	// A real file: the mode lets the operator's group read it, and the
	// writer refuses to write once closed rather than panicking.
	path := filepath.Join(dir, "a.log")
	w, err := newFileWriter(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("a line\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o007 != 0 {
		t.Errorf("the log file is world accessible: %v", st.Mode().Perm())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("another\n")); err == nil {
		t.Error("a closed writer accepted a line")
	}
	// Closing twice is safe.
	_ = w.Close()
}

// TestHandlerWrappersKeepRedaction covers the wrappers slog calls when
// a caller groups attributes or attaches them to a logger: the rules
// must survive, or a redacted field comes out in the clear under a
// group name.
func TestHandlerWrappersKeepRedaction(t *testing.T) {
	dir := t.TempDir()
	yes, no := true, false
	logs, err := Open(config.Logging{Directory: dir,
		Access:   config.LogStream{Enabled: &no},
		Security: config.LogStream{Enabled: &no},
		Audit:    config.LogStream{Enabled: &no},
		Error:    config.LogStream{Enabled: &yes, File: "error.log", Format: "json"},
		// The streams are listed the way the configuration loader
		// defaults them (internal/config/defaults.go): Open applies the
		// rules to exactly the streams it is given.
		Redaction: &config.Redaction{Enabled: &yes, Streams: []string{"access", "security", "error"}, DropFields: []string{"password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	if logs.Redactor() == nil {
		t.Fatal("no redactor was built")
	}
	base := logs.Error
	// Through a group and through attributes attached to the logger.
	base.With("component", "test").Info("attached", "password", "hunter2")
	base.WithGroup("g").Info("grouped", "password", "hunter2")
	base.With("password", "hunter2").Info("in the logger itself")
	logs.Close()
	data, err := os.ReadFile(filepath.Join(dir, "error.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hunter2") {
		t.Fatalf("a redacted value reached the file:\n%s", data)
	}
	for _, want := range []string{"attached", "grouped", "in the logger itself"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the line %q is missing:\n%s", want, data)
		}
	}
	// A logger with no redaction configured still groups and attaches.
	plain, err := Open(config.Logging{Directory: dir, Access: config.LogStream{Enabled: &no},
		Security: config.LogStream{Enabled: &no}, Audit: config.LogStream{Enabled: &no},
		Error: config.LogStream{Enabled: &yes, File: "plain.log", Format: "json"}})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Redactor() != nil {
		t.Error("a redactor was built without the section")
	}
	plain.Error.WithGroup("g").With("k", "v").Info("hello")
	plain.Close()
	data, err = os.ReadFile(filepath.Join(dir, "plain.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "hello") || !strings.Contains(string(data), "\"g\"") {
		t.Errorf("the grouped line is missing:\n%s", data)
	}
}

// TestMultiHandlerFanOut covers the handler that feeds several sinks:
// one sink failing must not stop the others, and the level filter of
// each is its own.
func TestMultiHandlerFanOut(t *testing.T) {
	var a, b countingHandler
	m := multiHandler{&a, &b}
	ctx := context.Background()
	if !m.Enabled(ctx, slog.LevelInfo) {
		t.Error("a handler that accepts everything did not enable the group")
	}
	rec := slog.NewRecord(nowForTest(), slog.LevelInfo, "hello", 0)
	if err := m.Handle(ctx, rec); err != nil {
		t.Errorf("handle: %v", err)
	}
	if a.n != 1 || b.n != 1 {
		t.Errorf("records: %d and %d", a.n, b.n)
	}
	// A failing sink is reported but the others still receive the line.
	a.err = errNotWritten
	if err := m.Handle(ctx, rec); err == nil {
		t.Error("a failing sink was not reported")
	}
	if b.n != 2 {
		t.Errorf("the second sink received %d records", b.n)
	}
	// WithAttrs and WithGroup wrap every handler.
	if len(m.WithAttrs([]slog.Attr{slog.String("k", "v")}).(multiHandler)) != 2 {
		t.Error("WithAttrs lost a handler")
	}
	if len(m.WithGroup("g").(multiHandler)) != 2 {
		t.Error("WithGroup lost a handler")
	}
	// A group of no handlers is disabled and handles nothing.
	var none multiHandler
	if none.Enabled(ctx, slog.LevelError) {
		t.Error("an empty group is enabled")
	}
	if err := none.Handle(ctx, rec); err != nil {
		t.Errorf("an empty group: %v", err)
	}
}

type countingHandler struct {
	n   int
	err error
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(context.Context, slog.Record) error {
	h.n++
	return h.err
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

var errNotWritten = errors.New("not written")

func nowForTest() time.Time { return time.Unix(1700000000, 0).UTC() }
