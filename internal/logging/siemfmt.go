package logging

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// CEF (ArcSight Common Event Format) and LEEF (IBM QRadar Log Event
// Extended Format) renderings of a log record, shared by the syslog sink
// (format cef or leef) and the siem sink. Both put the well known
// attributes into the format's standard keys and keep the remaining
// attributes under their own names, so nothing the JSON line carries is
// lost in translation.

// siemMeta names the product in the CEF and LEEF headers.
type siemMeta struct {
	vendor, product, version, hostname string
}

// cefStandard maps xproxy attributes to CEF extension keys.
var cefStandard = map[string]string{
	"client_ip":  "src",
	"method":     "requestMethod",
	"host":       "dhost",
	"path":       "request",
	"user_agent": "requestClientApplication",
	"referer":    "requestContext",
	"proto":      "app",
	"bytes_in":   "in",
	"bytes_out":  "out",
	"reason":     "reason",
	"action":     "act",
	"msg":        "msg",
}

// cefCustom maps attributes to the numbered custom fields with labels.
var cefCustom = map[string]string{
	"status":      "cn1",
	"duration_ms": "cn2",
	"attempts":    "cn3",
	"request_id":  "cs1",
	"route":       "cs2",
	"upstream":    "cs3",
	"country":     "cs4",
	"ja4":         "cs5",
	"detail":      "cs6",
}

// leefStandard maps attributes to LEEF predefined keys.
var leefStandard = map[string]string{
	"client_ip":  "src",
	"path":       "url",
	"proto":      "proto",
	"user_agent": "userAgent",
	"reason":     "reason",
	"action":     "action",
	"msg":        "msg",
}

// userKeys are the attributes that identify a user, first match wins
// (the same order the access log text formats use).
var userKeys = []string{"oidc_user", "oidc_sub", "auth_user", "jwt_sub", "jwt_preferred_username", "api_key"}

// event is the record flattened for the formatters.
type event struct {
	stream string
	level  slog.Level
	time   time.Time
	msg    string
	keys   []string
	vals   map[string]string
	status int
	action string
}

func flatten(stream string, level slog.Level, rec slog.Record) *event {
	e := &event{stream: stream, level: level, time: rec.Time, msg: rec.Message, vals: map[string]string{}}
	rec.Attrs(func(a slog.Attr) bool {
		e.add("", a)
		return true
	})
	if s, ok := e.vals["status"]; ok {
		e.status, _ = strconv.Atoi(s)
	}
	e.action = e.vals["action"]
	return e
}

func (e *event) add(prefix string, a slog.Attr) {
	key := prefix + a.Key
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			e.add(key+".", g)
		}
		return
	}
	if key == "stream" {
		return
	}
	if _, dup := e.vals[key]; !dup {
		e.keys = append(e.keys, key)
	}
	e.vals[key] = a.Value.String()
}

// user returns the identified user, "" when none.
func (e *event) user() string {
	for _, k := range userKeys {
		if v := e.vals[k]; v != "" {
			return v
		}
	}
	return ""
}

// severity is the 0 to 10 scale both formats use.
func (e *event) severity() int {
	switch e.stream {
	case "access":
		switch {
		case e.status >= 500:
			return 5
		case e.status >= 400:
			return 3
		}
		return 1
	case "security":
		if e.action == "ban" {
			return 8
		}
		return 7
	case "audit":
		return 3
	}
	switch {
	case e.level >= slog.LevelError:
		return 6
	case e.level >= slog.LevelWarn:
		return 4
	}
	return 2
}

// id is the event class: the stream, refined by the action.
func (e *event) id() string {
	switch e.stream {
	case "security", "audit":
		if e.action != "" {
			return e.stream + ":" + e.action
		}
	}
	return e.stream
}

// name is the human readable event name.
func (e *event) name() string {
	switch e.stream {
	case "access":
		return "HTTP request"
	case "security":
		if e.action != "" {
			if r := e.vals["reason"]; r != "" {
				return e.action + " " + r
			}
			return e.action
		}
	case "audit":
		if e.action != "" {
			return "management " + e.action
		}
	}
	return e.msg
}

func cefHeader(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func cefValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.NewReplacer("\r\n", "\\n", "\r", "\\n", "\n", "\\n").Replace(s)
	return escapeControls(s)
}

// escapeControls replaces the bytes that have no business in a log
// record with a printable form. A newline is already handled by the
// callers (it would forge a whole extra event); what is left is the
// rest of C0 and DEL, which carry an escape sequence into an operator's
// terminal or a collector's console, and NUL, which truncates the
// record in collectors that treat it as a string terminator.
func escapeControls(s string) string {
	need := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, "\\x%02x", c)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// cefLine renders the record as CEF:0.
func cefLine(m siemMeta, stream string, level slog.Level, rec slog.Record) []byte {
	e := flatten(stream, level, rec)
	var b bytes.Buffer
	b.WriteString("CEF:0|")
	b.WriteString(cefHeader(m.vendor))
	b.WriteByte('|')
	b.WriteString(cefHeader(m.product))
	b.WriteByte('|')
	b.WriteString(cefHeader(m.version))
	b.WriteByte('|')
	b.WriteString(cefHeader(e.id()))
	b.WriteByte('|')
	b.WriteString(cefHeader(e.name()))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(e.severity()))
	b.WriteByte('|')
	ext := func(k, v string) {
		if v == "" {
			return
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cefValue(v))
		b.WriteByte(' ')
	}
	ext("rt", strconv.FormatInt(e.time.UnixMilli(), 10))
	ext("dvchost", m.hostname)
	ext("cat", stream)
	switch e.stream {
	case "access":
		if e.status >= 400 {
			ext("outcome", "failure")
		} else {
			ext("outcome", "success")
		}
	case "security":
		ext("outcome", "failure")
	}
	if u := e.user(); u != "" {
		ext("suser", u)
	}
	if ep := e.vals["endpoint"]; ep != "" {
		if h, p, err := net.SplitHostPort(ep); err == nil {
			ext("dst", h)
			ext("dpt", p)
		} else {
			ext("dst", ep)
		}
	}
	for _, k := range e.keys {
		v := e.vals[k]
		if k == "endpoint" {
			continue
		}
		if std, ok := cefStandard[k]; ok {
			ext(std, v)
			continue
		}
		if c, ok := cefCustom[k]; ok {
			ext(c, v)
			ext(c+"Label", k)
			continue
		}
		ext(k, v)
	}
	return bytes.TrimRight(b.Bytes(), " ")
}

// reservedLEEF are the keys the LEEF renderer writes itself, which an
// attribute of the same name must not overwrite.
var reservedLEEF = map[string]bool{
	"devTime": true, "devTimeFormat": true, "sev": true, "cat": true,
	"name": true, "src": true, "dst": true, "dstPort": true, "srcPort": true,
	"usrName": true, "identHostName": true, "proto": true,
}

func leefValue(s string) string {
	return escapeControls(strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(s))
}

// leefLine renders the record as LEEF:2.0 with a tab delimiter.
func leefLine(m siemMeta, stream string, level slog.Level, rec slog.Record) []byte {
	e := flatten(stream, level, rec)
	var b bytes.Buffer
	b.WriteString("LEEF:2.0|")
	b.WriteString(cefHeader(m.vendor))
	b.WriteByte('|')
	b.WriteString(cefHeader(m.product))
	b.WriteByte('|')
	b.WriteString(cefHeader(m.version))
	b.WriteByte('|')
	b.WriteString(cefHeader(e.id()))
	b.WriteString("|x09|")
	first := true
	kv := func(k, v string) {
		if v == "" {
			return
		}
		if !first {
			b.WriteByte('\t')
		}
		first = false
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(leefValue(v))
	}
	kv("devTime", e.time.UTC().Format("Jan 02 2006 15:04:05.000"))
	kv("devTimeFormat", "MMM dd yyyy HH:mm:ss.SSS")
	kv("sev", strconv.Itoa(e.severity()))
	kv("cat", stream)
	kv("identHostName", m.hostname)
	if u := e.user(); u != "" {
		kv("usrName", u)
	}
	if ep := e.vals["endpoint"]; ep != "" {
		if h, p, err := net.SplitHostPort(ep); err == nil {
			kv("dst", h)
			kv("dstPort", p)
		} else {
			kv("dst", ep)
		}
	}
	if e.stream != "access" {
		kv("name", e.name())
	}
	for _, k := range e.keys {
		if k == "endpoint" {
			continue
		}
		if std, ok := leefStandard[k]; ok {
			kv(std, e.vals[k])
			continue
		}
		// An attribute named like a field the renderer already wrote
		// would appear twice, and a parser building a key to value map
		// keeps the last one: a DNS query name arrives in an attribute
		// called "name", so a client could choose the event name its
		// own block is filed under and hide it behind a benign label.
		if reservedLEEF[k] {
			kv("xproxy_"+k, e.vals[k])
			continue
		}
		kv(k, e.vals[k])
	}
	return b.Bytes()
}
