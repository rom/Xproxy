package waf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCRSPlugins loads a plugin directory with one plugin as loose files
// and one as a checked out repository, with a data file referenced from a
// rule.
func TestCRSPlugins(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "deny-agent-config.conf"), "SecAction \"id:9500000,phase:1,pass,t:none,nolog,setvar:tx.deny_agent_enabled=1\"\n")
	write(t, filepath.Join(dir, "deny-agent-before.conf"), "SecRule REQUEST_HEADERS:User-Agent \"@pmFromFile deny-agents.data\" \"id:9500100,phase:1,deny,status:403,log,msg:'denied agent',tag:'attack-plugin'\"\n")
	write(t, filepath.Join(dir, "deny-agents.data"), "evilbot\n")
	write(t, filepath.Join(dir, "after-plugin", "plugins", "after-plugin-after.conf"), "SecRule REQUEST_HEADERS:X-After \"@streq yes\" \"id:9501100,phase:1,deny,status:418,log,msg:'after rule'\"\n")
	write(t, filepath.Join(dir, "after-plugin", "README.md"), "not a rule\n")

	cfg := wafConfig(nil)
	cfg.Profiles[0].CRS.PluginsDir = dir
	e, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	ps := e.Profiles()
	if len(ps) != 1 || strings.Join(ps[0].Plugins, ",") != "after-plugin,deny-agent" {
		t.Fatalf("plugins = %+v", ps)
	}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("User-Agent", "evilbot/1.0")
	v, _ := run(t, e, ModeBlock, r)
	if !v.Deny || v.Status != 403 {
		t.Fatalf("plugin before rule: %+v", v)
	}
	r = httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("X-After", "yes")
	v, _ = run(t, e, ModeBlock, r)
	if !v.Deny || v.Status != 418 {
		t.Fatalf("plugin after rule: %+v", v)
	}
	r = httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	if v, _ = run(t, e, ModeBlock, r); v.Deny {
		t.Fatalf("clean request denied: %+v", v)
	}

	// Selecting plugins by name.
	cfg.Profiles[0].CRS.Plugins = []string{"deny-agent"}
	e, err = New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Profiles()[0].Plugins; len(got) != 1 || got[0] != "deny-agent" {
		t.Fatalf("selected plugins = %v", got)
	}
	r = httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("X-After", "yes")
	if v, _ = run(t, e, ModeBlock, r); v.Deny {
		t.Fatalf("unselected plugin still active: %+v", v)
	}
	cfg.Profiles[0].CRS.Plugins = []string{"missing"}
	if _, err = New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog); err == nil || !strings.Contains(err.Error(), "no plugin") {
		t.Fatalf("missing plugin: %v", err)
	}
	cfg.Profiles[0].CRS.Plugins = nil
	cfg.Profiles[0].CRS.PluginsDir = t.TempDir()
	if _, err = New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog); err == nil {
		t.Fatal("empty plugin directory accepted")
	}
}

const orderSchema = `{
  "type": "object",
  "required": ["sku", "quantity"],
  "additionalProperties": false,
  "properties": {
    "sku": {"type": "string", "pattern": "^[A-Z]{3}-[0-9]{4}$"},
    "quantity": {"type": "integer", "minimum": 1, "maximum": 100},
    "note": {"type": "string", "maxLength": 20}
  }
}`

func schemaConfig(t *testing.T) *config.WAF {
	t.Helper()
	file := filepath.Join(t.TempDir(), "order.json")
	write(t, file, orderSchema)
	cfg := wafConfig(nil)
	cfg.Profiles[0].JSONSchemas = []config.WAFJSONSchema{{Name: "order", Paths: []string{"/api/orders"}, Methods: []string{"POST", "PUT"}, SchemaFile: file}}
	cfg.Profiles[0].Directives = "SecAction \"id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH'\"\n"
	return cfg
}

func jsonPost(path, body string) *http.Request {
	r := httptest.NewRequest("POST", "http://example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestJSONSchemaBlock(t *testing.T) {
	st := NewStats()
	e, err := New(schemaConfig(t), Need{"default": {ModeBlock: true, ModeDetect: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Profiles()[0].Schemas; len(got) != 1 || got[0] != "order" {
		t.Fatalf("schemas = %v", got)
	}
	// A valid body passes and is replayed to the upstream.
	r := jsonPost("/api/orders", `{"sku":"ABC-1234","quantity":2}`)
	f, _ := e.Filter("default", ModeBlock)
	inst := f.Begin(context.Background(), info())
	if v := inst.Request(r); v.Deny {
		t.Fatalf("valid body denied: %+v", v)
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != `{"sku":"ABC-1234","quantity":2}` {
		t.Fatalf("body not replayed: %q", body)
	}
	inst.End()

	// Violations are denied with a JSON problem body.
	v, attrs := run(t, e, ModeBlock, jsonPost("/api/orders", `{"sku":"abc","quantity":0,"extra":1}`))
	if !v.Deny || v.Status != 400 || v.Reason != "waf" || !strings.HasPrefix(v.Detail, "json_schema:order:") {
		t.Fatalf("violation: %+v", v)
	}
	if v.Response == nil {
		t.Fatal("no problem response")
	}
	var problem map[string]any
	if err := json.NewDecoder(v.Response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if details, _ := problem["details"].([]any); len(details) != 3 {
		t.Fatalf("details = %v", problem)
	}
	if !hasAttr(attrs, "waf_schema") {
		t.Fatalf("attrs = %v", attrs)
	}
	// Malformed JSON, and a body over the limit.
	if v, _ := run(t, e, ModeBlock, jsonPost("/api/orders", `{"sku":`)); !v.Deny || v.Status != 400 {
		t.Fatalf("malformed: %+v", v)
	}
	if v, _ := run(t, e, ModeBlock, jsonPost("/api/orders", `{"note":"`+strings.Repeat("x", 5000)+`"}`)); !v.Deny || v.Status != 413 {
		t.Fatalf("oversize: %+v", v)
	}
	// Other paths, methods and media types are not checked.
	if v, _ := run(t, e, ModeBlock, jsonPost("/api/other", `{"sku":"abc"}`)); v.Deny {
		t.Fatalf("other path denied: %+v", v)
	}
	r = httptest.NewRequest("PATCH", "http://example.com/api/orders", strings.NewReader(`{"sku":"abc"}`))
	r.Header.Set("Content-Type", "application/json")
	if v, _ := run(t, e, ModeBlock, r); v.Deny {
		t.Fatalf("other method denied: %+v", v)
	}
	r = httptest.NewRequest("POST", "http://example.com/api/orders", strings.NewReader("sku=abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v, _ := run(t, e, ModeBlock, r); v.Deny {
		t.Fatalf("form body denied: %+v", v)
	}
	// Detect mode records the violation and lets the request through.
	v, attrs = run(t, e, ModeDetect, jsonPost("/api/orders", `{"sku":"abc","quantity":0}`))
	if v.Deny {
		t.Fatalf("detect mode denied: %+v", v)
	}
	if !hasAttr(attrs, "waf_schema") || !hasAttr(attrs, "waf_detected") {
		t.Fatalf("detect attrs = %v", attrs)
	}
	if rep := st.Report(10, nil); rep.SchemaViolations != 3 {
		t.Fatalf("schema violations = %d", rep.SchemaViolations)
	}
}

func TestJSONSchemaRequired(t *testing.T) {
	cfg := schemaConfig(t)
	cfg.Profiles[0].JSONSchemas[0].Required = true
	e, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := run(t, e, ModeBlock, httptest.NewRequest("POST", "http://example.com/api/orders", nil)); !v.Deny || v.Status != 400 {
		t.Fatalf("missing body: %+v", v)
	}
	r := httptest.NewRequest("POST", "http://example.com/api/orders", strings.NewReader("sku=abc"))
	r.Header.Set("Content-Type", "text/plain")
	if v, _ := run(t, e, ModeBlock, r); !v.Deny || v.Status != 415 {
		t.Fatalf("wrong media type: %+v", v)
	}
	cfg.Profiles[0].JSONSchemas[0].SchemaFile = filepath.Join(t.TempDir(), "missing.json")
	if _, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog); err == nil {
		t.Fatal("missing schema file accepted")
	}
}

func anomalyConfigFor(action string) *config.WAFAnomaly {
	return &config.WAFAnomaly{Enabled: true, Window: config.Duration(time.Minute), MinRequests: 10, Threshold: 4, Action: action, MaxClients: 1000}
}

// drive sends one window of traffic: n normal clients with a few paths
// and no matches, and one scanner client with many paths and errors.
func drive(t *testing.T, e *Engine, st *Stats, now time.Time, scanner bool) {
	t.Helper()
	f, err := e.Filter("default", ModeBlock)
	if err != nil {
		t.Fatal(err)
	}
	st.now = func() time.Time { return now }
	for c := 0; c < 12; c++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(c + 1)})
		for i := 0; i < 20; i++ {
			path := []string{"/", "/about", "/cart"}[i%3]
			r := httptest.NewRequest("GET", "http://example.com"+path, nil)
			in := &filter.Info{RequestID: "r", ClientIP: ip, Route: "r", Host: "example.com", Path: path}
			inst := f.Begin(context.Background(), in)
			inst.Request(r)
			inst.Response(&http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody})
			inst.End()
		}
	}
	if scanner {
		ip := netip.MustParseAddr("203.0.113.99")
		for i := 0; i < 60; i++ {
			path := "/admin/" + strings.Repeat("x", i%40)
			r := httptest.NewRequest("GET", "http://example.com"+path, nil)
			in := &filter.Info{RequestID: "r", ClientIP: ip, Route: "r", Host: "example.com", Path: path}
			inst := f.Begin(context.Background(), in)
			inst.Request(r)
			inst.Response(&http.Response{StatusCode: 404, Header: http.Header{}, Body: http.NoBody})
			inst.End()
		}
	}
}

func TestAnomalyDetection(t *testing.T) {
	st := NewStats()
	cfg := wafConfig(nil)
	cfg.Anomaly = anomalyConfigFor("block")
	e, err := New(cfg, Need{"default": {ModeBlock: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.anomaly.windowStart.Store(start.UnixNano())
	// Window 1: normal traffic builds the baseline.
	drive(t, e, st, start, false)
	// Window 2: the scanner appears; scored at the end of the window.
	drive(t, e, st, start.Add(time.Minute), true)
	// Window 3 starts: the roll happens on the first observation.
	drive(t, e, st, start.Add(2*time.Minute), false)
	rep := st.Report(10, nil).Anomaly
	if rep == nil || !rep.Enabled || rep.Windows != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Flagged != 1 || len(rep.Top) != 1 || rep.Top[0].Client != "203.0.113.99" {
		t.Fatalf("flagged = %+v", rep)
	}
	if rep.Top[0].Score < 4 || rep.Top[0].Feature == "" {
		t.Fatalf("flag = %+v", rep.Top[0])
	}
	if len(rep.Baseline) != anomalyFeatures {
		t.Fatalf("baseline = %+v", rep.Baseline)
	}
	// Requests of the flagged client are denied with the anomaly reason.
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	in := info()
	in.ClientIP = netip.MustParseAddr("203.0.113.99")
	v := runInfo(t, e, ModeBlock, r, in)
	if !v.Deny || v.Status != 403 || v.Reason != "waf_anomaly" || !hasAttr(v.Attrs, "waf_anomaly_score") {
		t.Fatalf("flagged client: %+v", v)
	}
	if v := runInfo(t, e, ModeBlock, httptest.NewRequest("GET", "http://example.com/", nil), info()); v.Deny {
		t.Fatalf("normal client denied: %+v", v)
	}
	if rep := st.Report(10, nil).Anomaly; rep.Acted != 1 {
		t.Fatalf("acted = %d", rep.Acted)
	}
	// Challenge and log actions.
	cfg.Anomaly.Action = "challenge"
	st.Configure(nil, cfg.Anomaly)
	if v := runInfo(t, e, ModeBlock, httptest.NewRequest("GET", "http://example.com/", nil), in); !v.Deny || !v.Challenge {
		t.Fatalf("challenge: %+v", v)
	}
	cfg.Anomaly.Action = "log"
	st.Configure(nil, cfg.Anomaly)
	f, _ := e.Filter("default", ModeBlock)
	inst := f.Begin(context.Background(), in)
	if v := inst.Request(httptest.NewRequest("GET", "http://example.com/", nil)); v.Deny {
		t.Fatalf("log action denied: %+v", v)
	}
	if attrs := inst.End(); !hasAttr(attrs, "waf_anomaly") {
		t.Fatalf("log attrs = %v", attrs)
	}
	// The flag expires when the client stays away.
	st.now = func() time.Time { return start.Add(10 * time.Minute) }
	if st.anomaly.lookup("203.0.113.99") != nil {
		t.Fatal("flag did not expire")
	}
	if rep := st.Report(10, nil).Anomaly; rep.Flagged != 0 {
		t.Fatalf("flagged after expiry = %d", rep.Flagged)
	}
	// Reset clears everything; a disabled detector reports so.
	st.Reset()
	if rep := st.Report(10, nil).Anomaly; rep.Windows != 0 || rep.FlaggedTotal != 0 {
		t.Fatalf("after reset = %+v", rep)
	}
	st.Configure(nil, nil)
	if rep := st.Report(10, nil).Anomaly; rep.Enabled {
		t.Fatal("disabled detector reports enabled")
	}
}

func TestAnomalyTrackerBound(t *testing.T) {
	st := NewStats()
	c := anomalyConfigFor("log")
	c.MaxClients = 100
	st.Configure(nil, c)
	now := time.Now()
	for i := 0; i < 150; i++ {
		st.anomaly.observe("client-"+strings.Repeat("a", i%50)+string(rune('a'+i/50)), "/", false, false, now)
	}
	rep := st.anomaly.report()
	if rep.Clients != 100 || rep.Dropped == 0 {
		t.Fatalf("clients %d dropped %d", rep.Clients, rep.Dropped)
	}
}
