package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Access log text formats. JSON is the default; these exist for tools
// that read Apache style lines. Values are escaped the way Apache does
// (quotes, backslashes and control characters as \xHH), so a line stays
// one line whatever a client sends.
const (
	FormatJSON     = "json"
	FormatCommon   = "common"   // %h %l %u %t "%r" %>s %b
	FormatCombined = "combined" // common + "%{Referer}i" "%{User-Agent}i"
	FormatCustom   = "custom"   // a template with {field} placeholders
)

const (
	templateCommon   = `{client_ip} - {user} [{time_clf}] "{request}" {status} {bytes_out_clf}`
	templateCombined = templateCommon + ` "{referer}" "{user_agent}"`
)

// TemplateFor returns the template of a named format ("" for json).
func TemplateFor(format, custom string) string {
	switch format {
	case FormatCommon:
		return templateCommon
	case FormatCombined:
		return templateCombined
	case FormatCustom:
		return custom
	}
	return ""
}

// textHandler renders records through a template. It writes to w or, for
// the journald and syslog sinks, hands the line to sink.
type textHandler struct {
	tmpl   []token
	w      io.Writer
	sink   lineSink
	stream string
	level  slog.Level
	pre    []slog.Attr
	mu     *sync.Mutex
}

type token struct {
	lit   string
	field string
}

// ParseTemplate splits a template into literals and {field} references.
func ParseTemplate(t string) ([]token, error) {
	var out []token
	for len(t) > 0 {
		i := strings.IndexByte(t, '{')
		if i < 0 {
			out = append(out, token{lit: t})
			break
		}
		if i > 0 {
			out = append(out, token{lit: t[:i]})
		}
		j := strings.IndexByte(t[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("unclosed { at offset %d", i)
		}
		name := t[i+1 : i+j]
		if name == "" || strings.ContainsAny(name, " {\"\\") {
			return nil, fmt.Errorf("bad field name %q", name)
		}
		out = append(out, token{field: name})
		t = t[i+j+1:]
	}
	return out, nil
}

// ValidTemplate reports whether t parses.
func ValidTemplate(t string) error {
	_, err := ParseTemplate(t)
	return err
}

func newTextHandler(w io.Writer, sink lineSink, template string, level slog.Level) *textHandler {
	tmpl, _ := ParseTemplate(template) // validated
	return &textHandler{tmpl: tmpl, w: w, sink: sink, level: level, mu: &sync.Mutex{}}
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.pre = append(append([]slog.Attr(nil), h.pre...), attrs...)
	for _, a := range attrs {
		if a.Key == "stream" {
			nh.stream = a.Value.String()
		}
	}
	return &nh
}

func (h *textHandler) WithGroup(string) slog.Handler { return h }

func (h *textHandler) Handle(_ context.Context, rec slog.Record) error {
	fields := make(map[string]string, rec.NumAttrs()+len(h.pre)+8)
	add := func(a slog.Attr) {
		if a.Value.Kind() == slog.KindGroup {
			for _, g := range a.Value.Group() {
				fields[a.Key+"."+g.Key] = g.Value.String()
			}
			return
		}
		fields[a.Key] = a.Value.String()
	}
	for _, a := range h.pre {
		add(a)
	}
	rec.Attrs(func(a slog.Attr) bool { add(a); return true })
	fields["msg"] = rec.Message
	fields["level"] = rec.Level.String()
	fields["time_clf"] = rec.Time.Format("02/Jan/2006:15:04:05 -0700")
	fields["time_iso"] = rec.Time.UTC().Format(time.RFC3339Nano)
	fields["time_unix"] = strconv.FormatInt(rec.Time.Unix(), 10)
	if _, ok := fields["request"]; !ok {
		fields["request"] = fields["method"] + " " + fields["path"] + " " + fields["proto"]
	}
	if _, ok := fields["user"]; !ok {
		fields["user"] = "-"
		// The keys the authentication filters actually emit. The old
		// list named three that nothing produces, so %u was "-" for
		// every authenticated request outside the jwt filter.
		for _, k := range []string{"oidc_user", "oidc_sub", "auth_user", "basic_user", "jwt_sub", "jwt_preferred_username", "api_key"} {
			if v, ok := fields[k]; ok && v != "" {
				fields["user"] = v
				break
			}
		}
	}
	if b := fields["bytes_out"]; b == "" || b == "0" {
		fields["bytes_out_clf"] = "-"
	} else {
		fields["bytes_out_clf"] = b
	}
	var buf bytes.Buffer
	for _, tk := range h.tmpl {
		if tk.field == "" {
			buf.WriteString(tk.lit)
			continue
		}
		v, ok := fields[tk.field]
		if !ok || v == "" {
			buf.WriteByte('-')
			continue
		}
		escapeInto(&buf, v)
	}
	if h.sink != nil {
		h.sink.emit(rec.Level, h.stream, buf.Bytes(), rec)
		return nil
	}
	buf.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}

// escapeInto writes v with Apache style escaping: backslash and double
// quote get a backslash, control and non-ASCII bytes become \xHH.
func escapeInto(buf *bytes.Buffer, v string) {
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '"' || c == '\\':
			buf.WriteByte('\\')
			buf.WriteByte(c)
		case c == '\n':
			buf.WriteString(`\n`)
		case c == '\r':
			buf.WriteString(`\r`)
		case c == '\t':
			buf.WriteString(`\t`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(buf, `\x%02x`, c)
		default:
			buf.WriteByte(c)
		}
	}
}
