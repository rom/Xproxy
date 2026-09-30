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

	"github.com/rom/xproxy/internal/attack"
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
	siem     *siemSink
	redactor *Redactor
	// writeErrors counts failed file writes across all streams.
	writeErrors atomic.Uint64
	// watcher is told about every security event, for the detections built on
	// the stream of them rather than on one message. It is an interface set by
	// the engine at start rather than a call the kinds make, for the reason the
	// ATT&CK tagging is done here: a kind that had to remember to feed it
	// would be a kind whose next refusal reached no detection at all.
	watcher atomic.Pointer[SecurityWatcher]
}

// A SecurityWatcher is told about each security event as it is written.
//
// It is called on the writing goroutine, with the lock-free part of this
// package, so an implementation has to be quick and must not block: the caller
// is a relay in front of a controller. Nothing it does can change the event,
// which is the point -- the log is the record and a watcher is a reader of it.
type SecurityWatcher interface {
	SecurityEvent(action, reason string, attrs []any)
}

// Watch sets the watcher, replacing any previous one. Passing nil clears it.
func (l *Logs) Watch(w SecurityWatcher) {
	if l == nil {
		return
	}
	if w == nil {
		l.watcher.Store(nil)
		return
	}
	l.watcher.Store(&w)
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
	if s := cfg.SIEM; s != nil {
		sink, err := newSIEMSink(*s, slog.New(slog.NewTextHandler(os.Stderr, nil)))
		if err != nil {
			l.Close()
			return nil, err
		}
		l.siem = sink
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
			case "siem":
				if l.siem != nil {
					handlers = append(handlers, newLineHandler(l.siem, lvl))
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
	if l.siem != nil {
		l.siem.close()
		l.siem = nil
	}
}

// SIEM returns the SIEM sink status, or nil when not configured.
func (l *Logs) SIEM() *SIEMStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.siem == nil {
		return nil
	}
	st := l.siem.status()
	return &st
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
	SIEMSent       uint64 `json:"siem_sent"`
	SIEMDropped    uint64 `json:"siem_dropped"`
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
	if l.siem != nil {
		st.SIEMSent, st.SIEMDropped = l.siem.sent.Load(), l.siem.dropped.Load()
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
//
// Where the reason is one internal/attack maps, the entry also carries
// what it means in MITRE ATT&CK terms: `technique`, `technique_name`,
// `tactic` and `matrix`. It is added here, at the one place every
// security event passes through, rather than by each kind at each call
// site -- a kind that had to remember would be a kind whose next refusal
// reason reached a SIEM as a string nobody can catalogue. A reason with
// no mapping carries no such field, which is deliberate: a technique
// label on protocol hygiene would read in a coverage report as a
// detection this proxy does not have.
//
// `matrix` is `ics`, `enterprise`, or both where the refusal means
// something in each catalogue -- which is the common case on a bastion,
// where one session is the way into a plant and a step through an
// estate.
func (l *Logs) SecurityEvent(ctx context.Context, action, reason string, attrs ...any) {
	all := make([]any, 0, len(attrs)+12)
	all = append(all, "action", action, "reason", reason)
	if ts := attack.OfEvent(reason); len(ts) > 0 {
		all = append(all,
			"technique", attack.IDs(ts),
			"technique_name", attack.Names(ts),
			"tactic", attack.Tactics(ts),
			"matrix", attack.Matrices(ts))
	}
	all = append(all, attrs...)
	l.Security.LogAttrs(ctx, slog.LevelWarn, "security", argsToAttrs(all)...)
	// After the log and not before it: a watcher that panicked or blocked
	// would then have lost the event as well, and the record matters more
	// than the detection built on it.
	if w := l.watcher.Load(); w != nil {
		(*w).SecurityEvent(action, reason, attrs)
	}
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

// Redactor returns the configured redactor, or nil when redaction is
// off. It is for the paths that are not log attributes — the trace
// exporter's client address — and must not be used to bypass the log
// handler, which applies the rules itself.
func (l *Logs) Redactor() *Redactor { return l.redactor }
