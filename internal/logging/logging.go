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
	"sync/atomic"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/otlp"
)

// Logs bundles the four streams.
type Logs struct {
	Access   *slog.Logger
	Error    *slog.Logger
	Security *slog.Logger
	Audit    *slog.Logger

	closers  []io.Closer
	mu       sync.Mutex
	journald *journaldSink
	syslog   *syslogSink
	otlp     *otlpSink
	redactor *Redactor
	// writeErrors counts failed file writes across all streams.
	writeErrors atomic.Uint64
}

// Open creates the streams described by cfg. Files are created with mode
// 0640 inside cfg.Directory, which must exist and be writable. Each stream
// fans out to its configured sinks; redaction, when enabled for the
// stream, runs before every sink.
func Open(cfg config.Logging) (*Logs, error) {
	level := parseLevel(cfg.Level)
	l := &Logs{}
	if cfg.Journald != nil {
		l.journald = newJournaldSink(*cfg.Journald)
	}
	if cfg.Syslog != nil {
		s, err := newSyslogSink(*cfg.Syslog)
		if err != nil {
			return nil, err
		}
		l.syslog = s
	}
	if o := cfg.OTLP; o != nil {
		sink, err := newOTLPSink(otlp.Config{Endpoint: o.Endpoint, Timeout: o.Timeout.D(), Headers: o.Headers, CAFile: o.CAFile,
			ServiceName: o.ServiceName, Attributes: o.Attributes, Compress: o.Compresses(), Version: Version},
			o.Batch, o.Queue, o.Interval.D(), slog.New(slog.NewTextHandler(os.Stderr, nil)))
		if err != nil {
			l.Close()
			return nil, err
		}
		l.otlp = sink
	}
	redacted := map[string]bool{}
	if cfg.Redaction.IsEnabled() {
		r, err := NewRedactor(cfg.Redaction)
		if err != nil {
			l.Close()
			return nil, err
		}
		l.redactor = r
		for _, st := range cfg.Redaction.Streams {
			redacted[st] = true
		}
	}
	open := func(name string, s config.LogStream, lvl slog.Level) (*slog.Logger, error) {
		if !s.IsEnabled() {
			return slog.New(slog.NewJSONHandler(io.Discard, nil)), nil
		}
		var handlers multiHandler
		tmpl := TemplateFor(s.Format, s.Template)
		sinks := s.Sinks
		if len(sinks) == 0 {
			sinks = []string{"file"}
		}
		for _, sink := range sinks {
			switch sink {
			case "file":
				path := filepath.Join(cfg.Directory, s.File)
				fw, err := newFileWriter(path, int64(s.MaxSizeMB)<<20, s.MaxFiles)
				if fw != nil {
					fw.errs = &l.writeErrors
				}
				if err != nil {
					l.Close()
					return nil, fmt.Errorf("open %s log: %w", name, err)
				}
				l.closers = append(l.closers, fw)
				var w io.Writer = fw
				if cfg.Stdout {
					w = io.MultiWriter(fw, os.Stdout)
				}
				if tmpl != "" {
					handlers = append(handlers, newTextHandler(w, nil, tmpl, lvl))
				} else {
					handlers = append(handlers, slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl}))
				}
			case "journald":
				if l.journald != nil {
					if tmpl != "" {
						handlers = append(handlers, newTextHandler(nil, l.journald, tmpl, lvl))
					} else {
						handlers = append(handlers, newLineHandler(l.journald, lvl))
					}
				}
			case "syslog":
				if l.syslog != nil {
					if tmpl != "" {
						handlers = append(handlers, newTextHandler(nil, l.syslog, tmpl, lvl))
					} else {
						handlers = append(handlers, newLineHandler(l.syslog, lvl))
					}
				}
			case "otlp":
				if l.otlp != nil {
					handlers = append(handlers, newLineHandler(l.otlp, lvl))
				}
			}
		}
		if len(handlers) == 0 && cfg.Stdout {
			if tmpl != "" {
				handlers = append(handlers, newTextHandler(os.Stdout, nil, tmpl, lvl))
			} else {
				handlers = append(handlers, slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
			}
		}
		var h slog.Handler = handlers
		if len(handlers) == 1 {
			h = handlers[0]
		}
		if redacted[name] {
			h = WithRedaction(h, l.redactor)
		}
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

// Close flushes and closes all files and sinks.
func (l *Logs) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.closers {
		_ = c.Close()
	}
	l.closers = nil
	if l.syslog != nil {
		l.syslog.close()
		l.syslog = nil
	}
	if l.journald != nil {
		l.journald.close()
		l.journald = nil
	}
	if l.otlp != nil {
		l.otlp.close()
		l.otlp = nil
	}
}

// OTLP returns the log exporter status, or nil when not configured.
func (l *Logs) OTLP() *OTLPStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.otlp == nil {
		return nil
	}
	st := l.otlp.status()
	return &st
}

// SinkStats reports messages dropped and sent by the network sinks.
type SinkStats struct {
	SyslogSent     uint64 `json:"syslog_sent"`
	SyslogDropped  uint64 `json:"syslog_dropped"`
	JournalDropped uint64 `json:"journald_dropped"`
	WriteErrors    uint64 `json:"write_errors"`
	Redaction      bool   `json:"redaction"`
	OTLPSent       uint64 `json:"otlp_sent"`
	OTLPDropped    uint64 `json:"otlp_dropped"`
}

// Stats returns sink counters.
func (l *Logs) Stats() SinkStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	var st SinkStats
	if l.syslog != nil {
		st.SyslogSent = l.syslog.sent.Load()
		st.SyslogDropped = l.syslog.drop.Load()
	}
	if l.journald != nil {
		st.JournalDropped = l.journald.drop.Load()
	}
	st.Redaction = l.redactor != nil
	st.WriteErrors = l.writeErrors.Load()
	if l.otlp != nil {
		st.OTLPSent, st.OTLPDropped = l.otlp.sent.Load(), l.otlp.dropped.Load()
	}
	return st
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

// Version is the service.version resource attribute of the OTLP log
// sink; the daemon sets it at start.
var Version string
