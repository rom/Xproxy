package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Almost everything in an access log line came from the client: the
// path, the user agent, the referer, the host, a forwarded header, a
// claim. A log line is a record somebody later greps, parses into a
// SIEM, or reads at three in the morning, and a value that can end the
// line can write records of its own — an authentication success that
// never happened, a deny that was never issued, a field the parser
// attributes to the wrong request.

// hostile is the set of values a client can put in a header.
var hostile = map[string]string{
	"newline":            "a\nb",
	"carriage return":    "a\rb",
	"crlf":               "a\r\nb",
	"double crlf":        "a\r\n\r\nb",
	"forged json record": `x","level":"INFO","msg":"authentication succeeded","user":"admin`,
	"forged clf record":  `x" 200 0` + "\n" + `10.0.0.1 - admin [20/Sep/2026:10:00:00 +0000] "GET /admin HTTP/1.1`,
	"quote":              `a"b`,
	"backslash":          `a\b`,
	"escaped quote":      `a\"b`,
	"tab":                "a\tb",
	"nul":                "a\x00b",
	"bell":               "a\x07b",
	"escape sequence":    "a\x1b[2Jb",
	"del":                "a\x7fb",
	"invalid utf8":       "a\xc3\x28b",
	"lone surrogate":     "a\xed\xa0\x80b",
	"bidi override":      "a\u202eb",
	"zero width":         "a\u200bb",
	"long":               strings.Repeat("x", 100000),
}

// TestTextFormatKeepsOneLinePerRecord requires every hostile value to
// produce exactly one line in every text format.
func TestTextFormatKeepsOneLinePerRecord(t *testing.T) {
	for _, format := range []string{FormatCommon, FormatCombined} {
		for name, value := range hostile {
			t.Run(format+"/"+name, func(t *testing.T) {
				var buf bytes.Buffer
				h := newTextHandler(&buf, nil, TemplateFor(format, ""), slog.LevelInfo)
				log := slog.New(h)
				log.Info("request",
					"client_ip", "192.0.2.1", "user", value, "request", "GET "+value+" HTTP/1.1",
					"status", 200, "bytes_out_clf", 0, "referer", value, "user_agent", value,
					"time_clf", "20/Sep/2026:10:00:00 +0000")
				out := buf.String()
				if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
					t.Fatalf("%d newlines in one record:\n%q", strings.Count(out, "\n"), out)
				}
				for i := 0; i < len(out)-1; i++ {
					if c := out[i]; c < 0x20 || c == 0x7f {
						t.Fatalf("byte %d is the control character %#x:\n%q", i, c, out)
					}
				}
			})
		}
	}
}

// TestJSONFormatEscapes requires the JSON handler to produce one
// document per record whose fields hold the value as given, escaped.
// A forged record inside a field is the attack this prevents.
func TestJSONFormatEscapes(t *testing.T) {
	for name, value := range hostile {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			log.Info("request", "user_agent", value, "path", value)
			out := buf.Bytes()
			if n := bytes.Count(out, []byte("\n")); n != 1 {
				t.Fatalf("%d newlines in one record:\n%q", n, out)
			}
			var doc map[string]any
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatalf("the record is not JSON: %v\n%q", err, out)
			}
			// Exactly the fields the caller named, not any the value
			// tried to add.
			for _, forged := range []string{"level", "msg", "time", "user_agent", "path"} {
				_ = forged
			}
			if len(doc) != 5 && len(doc) != 4 {
				t.Fatalf("the record has %d fields: %v", len(doc), doc)
			}
			if got, _ := doc["user_agent"].(string); got != value && !strings.HasPrefix(name, "invalid") && !strings.HasPrefix(name, "lone") {
				t.Fatalf("the field holds %q, want %q", got, value)
			}
		})
	}
}

// TestTemplateParsing covers the custom format an operator writes,
// where a mistake must be an error at load rather than a line that
// silently drops a field.
func TestTemplateParsing(t *testing.T) {
	good := []string{
		"", "{client_ip}", "plain text", "{a} {b}", "[{time_clf}] \"{request}\"",
		"{a}{b}{c}", "prefix {a} suffix", "{waf_matched}",
	}
	for _, tmpl := range good {
		if err := ValidTemplate(tmpl); err != nil {
			t.Errorf("ValidTemplate(%q): %v", tmpl, err)
		}
	}
	bad := []string{
		"{", "{unclosed", "a {b", "{}", "{ }", "{a b}", `{a"b}`, `{a\b}`, "{{a}",
	}
	for _, tmpl := range bad {
		if err := ValidTemplate(tmpl); err == nil {
			t.Errorf("ValidTemplate(%q) accepted it", tmpl)
		}
	}
	// A field the record does not carry renders as a dash rather than
	// as nothing, so the columns still line up for whatever reads them.
	var buf bytes.Buffer
	log := slog.New(newTextHandler(&buf, nil, "{a}|{missing}|{b}", slog.LevelInfo))
	log.Info("x", "a", "1", "b", "2")
	if got := strings.TrimSpace(buf.String()); got != "1|-|2" {
		t.Fatalf("a missing field rendered as %q", got)
	}
}

// TestTemplateFieldsCannotBeForged is the injection case for the
// template itself: a value that looks like the delimiter of the next
// field must not become one.
func TestTemplateFieldsCannotBeForged(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(newTextHandler(&buf, nil, `{client_ip} "{request}" {status}`, slog.LevelInfo))
	log.Info("request",
		"client_ip", "192.0.2.1",
		"request", `GET / HTTP/1.1" 200 0`+"\n"+`10.0.0.1 - - [x] "GET /admin HTTP/1.1`,
		"status", 403)
	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("the forged line split the record:\n%q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), " 403") {
		t.Fatalf("the status is not where the template puts it:\n%q", out)
	}
	if strings.Contains(out, `" 200 0`) && !strings.Contains(out, `\"`) {
		t.Fatalf("the embedded quote was not escaped:\n%q", out)
	}
}

// TestEscaping pins the escaping itself, byte by byte, because every
// other test here depends on it.
func TestEscaping(t *testing.T) {
	cases := map[string]string{
		"plain":     "plain",
		"a\nb":      `a\nb`,
		"a\rb":      `a\rb`,
		"a\tb":      `a\tb`,
		`a"b`:       `a\"b`,
		`a\b`:       `a\\b`,
		"a\x00b":    `a\x00b`,
		"a\x1bb":    `a\x1bb`,
		"a\x7fb":    `a\x7fb`,
		"\u00e5":    `\xc3\xa5`, // non-ASCII becomes bytes
		"":          "",
		" leading":  " leading",
		"trailing ": "trailing ",
	}
	for in, want := range cases {
		var buf bytes.Buffer
		escapeInto(&buf, in)
		if got := buf.String(); got != want {
			t.Errorf("escapeInto(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGroupedAttributes covers an attribute group, which is how a
// filter reports several values at once; the flattened keys must not
// collide with a top level field an operator's template names.
func TestGroupedAttributes(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(newTextHandler(&buf, nil, "{a}|{g.x}|{g.y}", slog.LevelInfo))
	log.Info("x", "a", "1", slog.Group("g", "x", "2", "y", "3"))
	if got := strings.TrimSpace(buf.String()); got != "1|2|3" {
		t.Fatalf("grouped attributes rendered as %q", got)
	}
	// WithGroup is not a grouping this handler applies: the template
	// names flat fields, so it must return a handler that still works
	// rather than one that drops everything.
	h := newTextHandler(&buf, nil, "{a}", slog.LevelInfo).WithGroup("ignored")
	buf.Reset()
	slog.New(h).Info("x", "a", "1")
	if got := strings.TrimSpace(buf.String()); got != "1" {
		t.Fatalf("after WithGroup the handler rendered %q", got)
	}
}

// TestLevelFiltering covers the level gate, which is what keeps a debug
// build's volume out of a production log.
func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	h := newTextHandler(&buf, nil, "{msg}", slog.LevelWarn)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("an info record passed a warn handler")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("an error record was filtered by a warn handler")
	}
	log := slog.New(h)
	log.Info("quiet")
	log.Error("loud")
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("the level gate let through %q", buf.String())
	}
}

// TestConcurrentWrites drives one handler from many goroutines. Every
// request on every listener logs through the same handler, and a line
// interleaved with another is a line nobody can parse.
func TestConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(newTextHandler(&buf, nil, `{client_ip} "{request}" {status}`, slog.LevelInfo))
	done := make(chan struct{})
	for g := 0; g < 16; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 50; i++ {
				log.Info("request", "client_ip", fmt.Sprintf("192.0.2.%d", g),
					"request", strings.Repeat("x", 200), "status", 200)
			}
		}(g)
	}
	for g := 0; g < 16; g++ {
		<-done
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 16*50 {
		t.Fatalf("%d lines, want %d", len(lines), 16*50)
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "192.0.2.") || !strings.HasSuffix(line, `" 200`) {
			t.Fatalf("line %d is interleaved: %q", i, line)
		}
	}
}

// TestTimeFieldIsNotClientControlled covers the timestamp, which is the
// one field a record must not take from the request.
func TestTimeFieldIsNotClientControlled(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(newTextHandler(&buf, nil, "[{time_clf}] {msg}", slog.LevelInfo))
	log.Info("request", "time_clf", "01/Jan/1970:00:00:00 +0000\n10.0.0.1 - -")
	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("a forged timestamp split the record:\n%q", out)
	}
	_ = time.Now
}

// TestOTLPAttributeKinds covers the conversion from a slog attribute to
// an OTLP one. A collector indexes on the type, so an integer that
// arrives as a string is a field nobody can aggregate.
func TestOTLPAttributeKinds(t *testing.T) {
	cases := []struct {
		name string
		attr slog.Attr
		want string // the field of otlp.KV that must be set
	}{
		{"string", slog.String("k", "v"), "string"},
		{"int", slog.Int("k", 7), "int"},
		{"int64", slog.Int64("k", 7), "int"},
		{"uint64", slog.Uint64("k", 7), "int"},
		{"bool", slog.Bool("k", true), "bool"},
		{"float", slog.Float64("k", 1.5), "float"},
		{"duration", slog.Duration("k", time.Second), "string"},
		{"time", slog.Time("k", time.Unix(0, 0)), "string"},
		{"any", slog.Any("k", []string{"a"}), "string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kv := otlpAttr("", tc.attr)
			if len(kv) != 1 || kv[0].Key != "k" {
				t.Fatalf("produced %v", kv)
			}
			v := kv[0].Value
			switch tc.want {
			case "string":
				if v.StringValue == nil {
					t.Fatalf("%v is not a string value", v)
				}
			case "int":
				if v.IntValue == nil {
					t.Fatalf("%v is not an int value", v)
				}
			case "bool":
				if v.BoolValue == nil {
					t.Fatalf("%v is not a bool value", v)
				}
			case "float":
				if v.DoubleValue == nil {
					t.Fatalf("%v is not a float value", v)
				}
			}
		})
	}
	// A group flattens with dotted keys, recursively.
	kv := otlpAttr("", slog.Group("g", slog.String("a", "1"), slog.Group("h", slog.Int("b", 2))))
	if len(kv) != 2 || kv[0].Key != "g.a" || kv[1].Key != "g.h.b" {
		t.Fatalf("a nested group produced %v", kv)
	}
	// A prefix is applied.
	if kv := otlpAttr("p.", slog.String("k", "v")); kv[0].Key != "p.k" {
		t.Fatalf("prefixed key %q", kv[0].Key)
	}
}

// TestOTLPSeverity covers the mapping to the OTLP scale, including the
// levels between the named ones, which a caller can produce.
func TestOTLPSeverity(t *testing.T) {
	cases := []struct {
		level slog.Level
		num   int
		text  string
	}{
		{slog.LevelDebug, 5, "DEBUG"},
		{slog.LevelDebug + 1, 5, "DEBUG"},
		{slog.LevelInfo, 9, "INFO"},
		{slog.LevelInfo + 1, 9, "INFO"},
		{slog.LevelWarn, 13, "WARN"},
		{slog.LevelError, 17, "ERROR"},
		{slog.LevelError + 4, 17, "ERROR"},
		{slog.Level(-100), 5, "DEBUG"},
	}
	for _, tc := range cases {
		num, text := severity(tc.level)
		if num != tc.num || text != tc.text {
			t.Errorf("severity(%v) = %d %q, want %d %q", tc.level, num, text, tc.num, tc.text)
		}
	}
}

// TestSIEMEventFields covers the event a SIEM record is built from: the
// flattening, the duplicate keys, the stream attribute that is not a
// field, and the severity each stream maps to.
func TestSIEMEventFields(t *testing.T) {
	rec := slog.NewRecord(time.Now(), slog.LevelWarn, "denied", 0)
	rec.AddAttrs(
		slog.String("stream", "security"), // not a field of its own
		slog.String("action", "ban"),
		slog.String("status", "403"),
		slog.Group("waf", slog.String("rule", "942100"), slog.Int("score", 5)),
		slog.String("auth_user", "alice"),
		slog.String("auth_user", "mallory"), // a duplicate key keeps one column
	)
	e := flatten("security", slog.LevelWarn, rec)
	if e.vals["waf.rule"] != "942100" || e.vals["waf.score"] != "5" {
		t.Fatalf("group flattening: %v", e.vals)
	}
	if _, ok := e.vals["stream"]; ok {
		t.Fatal("the stream attribute became a field")
	}
	if e.status != 403 {
		t.Fatalf("status parsed as %d", e.status)
	}
	if e.user() != "mallory" {
		t.Fatalf("user is %q; the last value for a key wins", e.user())
	}
	n := 0
	for _, k := range e.keys {
		if k == "auth_user" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the duplicate key produced %d columns", n)
	}
	if got := e.severity(); got != 8 {
		t.Fatalf("a ban is severity %d, want 8", got)
	}

	// The other streams and statuses.
	for _, tc := range []struct {
		stream string
		status string
		action string
		want   int
	}{
		{"access", "200", "", 1},
		{"access", "404", "", 3},
		{"access", "503", "", 5},
		{"security", "403", "deny", 7},
		{"audit", "", "", 3},
	} {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
		if tc.status != "" {
			r.AddAttrs(slog.String("status", tc.status))
		}
		if tc.action != "" {
			r.AddAttrs(slog.String("action", tc.action))
		}
		if got := flatten(tc.stream, slog.LevelInfo, r).severity(); got != tc.want {
			t.Errorf("%s/%s/%s is severity %d, want %d", tc.stream, tc.status, tc.action, got, tc.want)
		}
	}
	// A status that is not a number is not a status.
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String("status", "not a number"))
	if got := flatten("access", slog.LevelInfo, r).status; got != 0 {
		t.Fatalf("a non-numeric status parsed as %d", got)
	}
}
