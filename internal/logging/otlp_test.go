package logging

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func TestOTLPSink(t *testing.T) {
	var mu sync.Mutex
	var docs []map[string]any
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		if json.Unmarshal(body, &doc) != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		docs = append(docs, doc)
		mu.Unlock()
	}))
	t.Cleanup(collector.Close)
	off := false
	dir := t.TempDir()
	cfg := config.Logging{Directory: dir, Level: "info",
		Access:   config.LogStream{File: "access.log", Sinks: []string{"file", "otlp"}},
		Error:    config.LogStream{File: "error.log"},
		Security: config.LogStream{File: "security.log", Sinks: []string{"otlp"}},
		Audit:    config.LogStream{File: "audit.log"},
		OTLP: &config.OTLPExport{Endpoint: collector.URL, AllowHTTP: true, Timeout: config.Duration(2 * time.Second), ServiceName: "edge",
			Compress: &off, Batch: 10, Interval: config.Duration(50 * time.Millisecond), Queue: 100}}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.Access.Info("request", "client_ip", "203.0.113.9", "status", 200, "trace_id", "4bf92f3577b34da6a3ce929d0e0e4736", "span_id", "00f067aa0ba902b7", "ok", true)
	l.Security.Warn("deny", "reason", "waf")
	l.Audit.Info("not exported")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(docs)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(docs) == 0 {
		t.Fatal("nothing exported")
	}
	var records []map[string]any
	for _, d := range docs {
		rl := d["resourceLogs"].([]any)[0].(map[string]any)
		for _, r := range rl["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any) {
			records = append(records, r.(map[string]any))
		}
	}
	if len(records) != 2 {
		t.Fatalf("records %v", records)
	}
	acc := records[0]
	if acc["body"].(map[string]any)["stringValue"] != "request" || acc["severityNumber"].(float64) != 9 || acc["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" || acc["spanId"] != "00f067aa0ba902b7" {
		t.Fatalf("access record %v", acc)
	}
	attrs := map[string]map[string]any{}
	for _, a := range acc["attributes"].([]any) {
		kv := a.(map[string]any)
		attrs[kv["key"].(string)] = kv["value"].(map[string]any)
	}
	if attrs["xproxy.stream"]["stringValue"] != "access" || attrs["status"]["intValue"] != "200" || attrs["ok"]["boolValue"] != true || attrs["client_ip"]["stringValue"] != "203.0.113.9" {
		t.Fatalf("attributes %v", attrs)
	}
	if sec := records[1]; sec["severityText"] != "WARN" || sec["severityNumber"].(float64) != 13 {
		t.Fatalf("security record %v", sec)
	}
	if st := l.OTLP(); st != nil { // closed: status is gone
		t.Fatalf("status after close %+v", st)
	}
}
