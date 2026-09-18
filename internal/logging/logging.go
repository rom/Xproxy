// Package logging provides the four structured log streams of xproxy:
//
//   - access: one JSON line per request (who, what, result, timing)
//   - error: operational events (start, reload, upstream failures)
//   - security: denies and security actions (rate limit, ban, tarpit, WAF)
//   - audit: management plane actions (who changed what)
//
// Every line is JSON with a stable "ts", "level", "msg" and "stream" set of
// fields. Log injection is prevented by the JSON encoder: attacker
// controlled values such as User-Agent are always encoded as JSON strings.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/rom/xproxy/internal/config"
)

// Logs bundles the four streams.
type Logs struct {
	Access   *slog.Logger
	Error    *slog.Logger
	Security *slog.Logger
	Audit    *slog.Logger

	closers []io.Closer
	mu      sync.Mutex
}

// Open creates the streams described by cfg. Files are created with mode
// 0640 inside cfg.Directory, which must exist and be writable.
func Open(cfg config.Logging) (*Logs, error) {
	level := parseLevel(cfg.Level)
	l := &Logs{}
	open := func(name string, s config.LogStream, lvl slog.Level) (*slog.Logger, error) {
		if !s.IsEnabled() {
			return slog.New(slog.NewJSONHandler(io.Discard, nil)), nil
		}
		var w io.Writer
		path := filepath.Join(cfg.Directory, s.File)
		fw, err := newFileWriter(path, int64(s.MaxSizeMB)<<20, s.MaxFiles)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("open %s log: %w", name, err)
		}
		l.closers = append(l.closers, fw)
		w = fw
		if cfg.Stdout {
			w = io.MultiWriter(fw, os.Stdout)
		}
		h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
		return slog.New(h).With("stream", name), nil
	}
	var err error
	if l.Access, err = open("access", cfg.Access, slog.LevelInfo); err != nil {
		return nil, err
	}
	if l.Error, err = open("error", cfg.Error, level); err != nil {
		return nil, err
	}
	if l.Security, err = open("security", cfg.Security, slog.LevelInfo); err != nil {
		return nil, err
	}
	if l.Audit, err = open("audit", cfg.Audit, slog.LevelInfo); err != nil {
		return nil, err
	}
	return l, nil
}

// Discard returns streams that drop everything. Used by tests and by the
// validate command.
func Discard() *Logs {
	d := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return &Logs{Access: d, Error: d, Security: d, Audit: d}
}

// Stderr returns streams that all write to stderr (used before the config is
// loaded and by the management CLI).
func Stderr(level string) *Logs {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(level)})
	base := slog.New(h)
	return &Logs{
		Access:   base.With("stream", "access"),
		Error:    base.With("stream", "error"),
		Security: base.With("stream", "security"),
		Audit:    base.With("stream", "audit"),
	}
}

// Close flushes and closes all files.
func (l *Logs) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.closers {
		_ = c.Close()
	}
	l.closers = nil
}

// Reopen closes and reopens files, for use after external log rotation.
func (l *Logs) Reopen() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.closers {
		if r, ok := c.(interface{ Reopen() error }); ok {
			_ = r.Reopen()
		}
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// SecurityEvent writes a security log entry. action is what the proxy did
// (deny, tarpit, ban, limit), reason is the rule or limit that fired.
func (l *Logs) SecurityEvent(ctx context.Context, action, reason string, attrs ...any) {
	all := make([]any, 0, len(attrs)+4)
	all = append(all, "action", action, "reason", reason)
	all = append(all, attrs...)
	l.Security.LogAttrs(ctx, slog.LevelWarn, "security", argsToAttrs(all)...)
}

func argsToAttrs(args []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			k = fmt.Sprint(args[i])
		}
		out = append(out, slog.Any(k, args[i+1]))
	}
	return out
}
