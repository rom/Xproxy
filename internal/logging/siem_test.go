package logging

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func accessRecord() slog.Record {
	rec := slog.NewRecord(time.Date(2026, 9, 19, 7, 15, 0, 123000000, time.UTC), slog.LevelInfo, "request", 0)
	rec.AddAttrs(slog.String("request_id", "r1"), slog.String("client_ip", "203.0.113.9"), slog.String("method", "GET"),
		slog.String("host", "www.example.com"), slog.String("path", "/a=b|c"), slog.Int("status", 404), slog.Int64("bytes_out", 512),
		slog.Float64("duration_ms", 1.5), slog.String("endpoint", "10.0.0.5:8080"), slog.String("user_agent", "curl/8\nnext"),
		slog.String("jwt_sub", "alice"), slog.String("route", "web"))
	return rec
}

func TestCEFAndLEEF(t *testing.T) {
	m := siemMeta{vendor: "Sysctl", product: "Xproxy", version: "1.3", hostname: "edge1"}
	cef := string(cefLine(m, "access", slog.LevelInfo, accessRecord()))
	if !strings.HasPrefix(cef, "CEF:0|Sysctl|Xproxy|1.3|access|HTTP request|3|") {
		t.Fatalf("cef header: %s", cef)
	}
	for _, want := range []string{"rt=1789802100123", "dvchost=edge1", "outcome=failure", "suser=alice", "dst=10.0.0.5 dpt=8080",
		"src=203.0.113.9", "requestMethod=GET", "dhost=www.example.com", `request=/a\=b|c`, "cn1=404 cn1Label=status",
		"out=512", "cs1=r1 cs1Label=request_id", "cs2=web cs2Label=route", `requestClientApplication=curl/8\nnext`, "cn2=1.5 cn2Label=duration_ms"} {
		if !strings.Contains(cef, want) {
			t.Errorf("cef missing %q in %s", want, cef)
		}
	}
	if strings.Contains(cef, "endpoint=") || strings.Contains(cef, "\n") {
		t.Fatalf("cef: %s", cef)
	}
	leef := string(leefLine(m, "access", slog.LevelInfo, accessRecord()))
	if !strings.HasPrefix(leef, "LEEF:2.0|Sysctl|Xproxy|1.3|access|x09|devTime=Sep 19 2026 07:15:00.123\tdevTimeFormat=MMM dd yyyy HH:mm:ss.SSS\tsev=3\tcat=access\tidentHostName=edge1\tusrName=alice\tdst=10.0.0.5\tdstPort=8080\t") {
		t.Fatalf("leef: %q", leef)
	}
	for _, want := range []string{"src=203.0.113.9", "url=/a=b|c", "status=404", "userAgent=curl/8 next", "method=GET"} {
		if !strings.Contains(leef, want) {
			t.Errorf("leef missing %q in %q", want, leef)
		}
	}

	// Security and audit events: id and name come from the action.
	sec := slog.NewRecord(time.Now(), slog.LevelWarn, "security", 0)
	sec.AddAttrs(slog.String("action", "ban"), slog.String("reason", "waf"), slog.String("client_ip", "203.0.113.9"), slog.String("detail", "5 in 1m"))
	cef = string(cefLine(m, "security", slog.LevelWarn, sec))
	if !strings.Contains(cef, "|security:ban|ban waf|8|") || !strings.Contains(cef, "act=ban reason=waf") || !strings.Contains(cef, "cs6=5 in 1m cs6Label=detail") {
		t.Fatalf("security cef: %s", cef)
	}
	aud := slog.NewRecord(time.Now(), slog.LevelInfo, "management action", 0)
	aud.AddAttrs(slog.String("action", "reload"), slog.Int("peer_uid", 0))
	leef = string(leefLine(m, "audit", slog.LevelInfo, aud))
	if !strings.Contains(leef, "|audit:reload|x09|") || !strings.Contains(leef, "\tname=management reload\t") || !strings.Contains(leef, "action=reload\tpeer_uid=0") {
		t.Fatalf("audit leef: %q", leef)
	}
	errRec := slog.NewRecord(time.Now(), slog.LevelError, "upstream | failed", 0)
	cef = string(cefLine(m, "error", slog.LevelError, errRec))
	if !strings.Contains(cef, `|error|upstream \| failed|6|`) {
		t.Fatalf("error cef: %s", cef)
	}
}

type siemCollector struct {
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
	status  int
}

func (c *siemCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		rd = gz
	}
	body, _ := io.ReadAll(rd)
	c.mu.Lock()
	c.bodies = append(c.bodies, string(body))
	c.headers = append(c.headers, r.Header.Clone())
	status := c.status
	c.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
	}
}

func (c *siemCollector) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.bodies)
		c.mu.Unlock()
		if got >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

func siemConfig(dir, endpoint, format string, compress bool) config.Logging {
	return config.Logging{Directory: dir, Level: "info",
		Access:   config.LogStream{File: "access.log", Sinks: []string{"siem"}},
		Error:    config.LogStream{File: "error.log"},
		Security: config.LogStream{File: "security.log", Sinks: []string{"file", "siem"}},
		Audit:    config.LogStream{File: "audit.log"},
		SIEM: &config.SIEM{Endpoint: endpoint, AllowHTTP: true, Format: format, Timeout: config.Duration(2 * time.Second), Compress: &compress,
			Batch: 10, Interval: config.Duration(50 * time.Millisecond), Queue: 100, Vendor: "Sysctl", Product: "Xproxy", Hostname: "edge1"}}
}

func TestSIEMSinkFormats(t *testing.T) {
	for _, tc := range []struct {
		format, contentType string
		compress            bool
		check               func(t *testing.T, body string)
	}{
		{"json", "application/x-ndjson", true, func(t *testing.T, body string) {
			lines := strings.Split(strings.TrimSpace(body), "\n")
			if len(lines) != 2 || !strings.Contains(lines[0], `"stream":"access"`) || !strings.Contains(lines[1], `"reason":"waf"`) {
				t.Fatalf("ndjson: %q", body)
			}
		}},
		{"hec", "application/json", false, func(t *testing.T, body string) {
			dec := json.NewDecoder(strings.NewReader(body))
			var first map[string]any
			if err := dec.Decode(&first); err != nil {
				t.Fatal(err)
			}
			if first["host"] != "edge1" || first["source"] != "xproxy" || first["sourcetype"] != "xproxy:access" || first["event"].(map[string]any)["status"].(float64) != 200 {
				t.Fatalf("hec: %v", first)
			}
			if _, ok := first["time"].(string); !ok {
				t.Fatalf("hec time: %v", first)
			}
		}},
		{"cef", "text/plain; charset=utf-8", false, func(t *testing.T, body string) {
			if !strings.HasPrefix(body, "CEF:0|Sysctl|Xproxy|") || !strings.Contains(body, "\nCEF:0|Sysctl|Xproxy|") || !strings.Contains(body, "|security:deny|deny waf|7|") {
				t.Fatalf("cef: %q", body)
			}
		}},
		{"leef", "text/plain; charset=utf-8", false, func(t *testing.T, body string) {
			if !strings.HasPrefix(body, "LEEF:2.0|Sysctl|Xproxy|") || !strings.Contains(body, "|security:deny|x09|") {
				t.Fatalf("leef: %q", body)
			}
		}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			col := &siemCollector{}
			srv := httptest.NewServer(col)
			defer srv.Close()
			cfg := siemConfig(t.TempDir(), srv.URL, tc.format, tc.compress)
			auth := filepath.Join(t.TempDir(), "auth")
			if err := os.WriteFile(auth, []byte("Splunk secret-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.SIEM.AuthFile = auth
			cfg.SIEM.Headers = map[string]string{"X-Index": "edge"}
			l, err := Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			l.Access.Info("request", "client_ip", "203.0.113.9", "status", 200)
			l.Security.Warn("security", "action", "deny", "reason", "waf")
			l.Audit.Info("not exported")
			bodies := col.wait(t, 1)
			deadline := time.Now().Add(2 * time.Second)
			for l.Stats().SIEMSent < 2 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			st := l.Stats()
			l.Close()
			if len(bodies) != 1 {
				t.Fatalf("pushes = %d", len(bodies))
			}
			h := col.headers[0]
			if h.Get("Authorization") != "Splunk secret-token" || h.Get("X-Index") != "edge" || h.Get("Content-Type") != tc.contentType {
				t.Fatalf("headers: %v", h)
			}
			if (h.Get("Content-Encoding") == "gzip") != tc.compress {
				t.Fatalf("encoding: %v", h)
			}
			tc.check(t, bodies[0])
			if st.SIEMSent != 2 || st.SIEMDropped != 0 {
				t.Fatalf("stats %+v", st)
			}
		})
	}
}

func TestSIEMSinkFailuresAndStatus(t *testing.T) {
	col := &siemCollector{status: 503}
	srv := httptest.NewServer(col)
	defer srv.Close()
	l, err := Open(siemConfig(t.TempDir(), srv.URL, "json", false))
	if err != nil {
		t.Fatal(err)
	}
	l.Access.Info("request", "status", 200)
	col.wait(t, 1)
	deadline := time.Now().Add(2 * time.Second)
	for l.Stats().SIEMDropped == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := l.SIEM()
	if st == nil || st.Failed != 1 || st.Dropped != 1 || !strings.Contains(st.LastError, "503") || st.Format != "json" {
		t.Fatalf("status %+v", st)
	}
	l.Close()
	if Discard().SIEM() != nil {
		t.Fatal("status without a sink")
	}
	cfg := siemConfig(t.TempDir(), srv.URL, "json", false)
	cfg.SIEM.AuthFile = filepath.Join(t.TempDir(), "missing")
	if _, err := Open(cfg); err == nil {
		t.Fatal("missing auth file accepted")
	}
	cfg = siemConfig(t.TempDir(), srv.URL, "json", false)
	cfg.SIEM.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := Open(cfg); err == nil {
		t.Fatal("missing ca file accepted")
	}
}

func TestSIEMSinkMemoryLimits(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)

	// An individual encoded record is rejected before it can be retained.
	s := &siemSink{cfg: config.SIEM{Format: "json"}, queue: make(chan []byte, 300), log: log}
	s.emit(slog.LevelInfo, "access", make([]byte, maxSIEMRecordBytes+1), rec)
	if len(s.queue) != 0 || s.dropped.Load() != 1 || s.queuedBytes.Load() != 0 {
		t.Fatalf("oversized record retained: queued=%d dropped=%d bytes=%d", len(s.queue), s.dropped.Load(), s.queuedBytes.Load())
	}

	// Record count alone cannot admit more than the aggregate byte budget.
	record := make([]byte, maxSIEMRecordBytes)
	for range maxSIEMQueueBytes/maxSIEMRecordBytes + 1 {
		s.emit(slog.LevelInfo, "access", record, rec)
	}
	if got := s.queuedBytes.Load(); got != maxSIEMQueueBytes {
		t.Fatalf("queued bytes = %d, want %d", got, maxSIEMQueueBytes)
	}
	if len(s.queue) != maxSIEMQueueBytes/maxSIEMRecordBytes || s.dropped.Load() != 2 {
		t.Fatalf("memory budget not enforced: queued=%d dropped=%d", len(s.queue), s.dropped.Load())
	}

	// A full count-bounded channel rolls its byte reservation back.
	s = &siemSink{cfg: config.SIEM{Format: "json"}, queue: make(chan []byte, 1), log: log}
	s.emit(slog.LevelInfo, "access", []byte("first"), rec)
	s.emit(slog.LevelInfo, "access", []byte("second"), rec)
	if got := s.queuedBytes.Load(); got != int64(len("first")) {
		t.Fatalf("queued bytes after full channel = %d", got)
	}
}

func TestSyslogCEF(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	l, err := Open(syslogCfg(t.TempDir(), "udp", pc.LocalAddr().String(), "cef"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Security.Warn("security", "action", "deny", "reason", "acl", "client_ip", "203.0.113.9")
	buf := make([]byte, 9000)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	if !strings.HasPrefix(msg, "<156>1 ") || !strings.Contains(msg, " security - CEF:0|Sysctl|Xproxy|") || !strings.Contains(msg, "|security:deny|deny acl|7|") || !strings.Contains(msg, "src=203.0.113.9") {
		t.Fatalf("syslog cef: %q", msg)
	}
	if bytes.Contains(buf[:n], []byte(`"stream"`)) {
		t.Fatalf("json leaked into cef: %q", msg)
	}
}
