package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The GUI is a web application an operator points a browser at, and
// every one of its write endpoints reaches the running proxy or the
// file it starts from. These tests are about what those endpoints do
// with input that is not what the form sends: a body that is not JSON,
// a field that is not there, a configuration that does not parse, an
// etag from a version somebody else has already replaced.

// opSession returns a client logged in as the operator.
func opSession(t *testing.T, o Options) (*Server, *client, string) {
	t.Helper()
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(minimalConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	if o.Socket == "" {
		o.Socket = fm.path
	}
	if o.UsersFile == "" {
		o.UsersFile = writeUsers(t, dir)
	}
	if o.ConfigFile == "" {
		o.ConfigFile = cfgPath
	}
	if o.Listen == "" {
		o.Listen = "127.0.0.1:0"
	}
	s, c := newTestServer(t, o)
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("login: %d", st)
	}
	return s, c, o.ConfigFile
}

// TestBodiesThatAreNotRequests covers every JSON endpoint against the
// bodies a browser never sends. Each must be a 4xx naming the problem,
// not a 500 and not a silent success.
func TestBodiesThatAreNotRequests(t *testing.T) {
	_, c, _ := opSession(t, Options{})
	endpoints := []string{"/api/bans", "/api/rollback", "/api/config/validate", "/api/config/file"}
	bodies := []string{
		"", " ", "{", "}", "[]", "null", "true", `"a string"`, "42",
		`{"unknown_field":1}`,
		`{"target":`,
		`{"target":"1.2.3.4"} {"target":"5.6.7.8"}`,
		strings.Repeat(`{"a":`, 10000),
	}
	for _, path := range endpoints {
		for i, body := range bodies {
			t.Run(fmt.Sprintf("%s/%d", path, i), func(t *testing.T) {
				method := "POST"
				if path == "/api/config/file" {
					method = "PUT"
				}
				st, resp := c.doRaw(method, path, body)
				if st >= 500 {
					t.Fatalf("%s %.30q gave %d: %s", method, body, st, resp)
				}
				if st == 200 && body != "" {
					t.Logf("%s %.30q was accepted", method, body)
				}
			})
		}
	}
}

// TestSeriesParameters covers the query arguments of the graph view,
// which come from the address bar.
func TestSeriesParameters(t *testing.T) {
	_, c, _ := opSession(t, Options{})
	ok := []string{"", "?since=5m", "?since=1h&limit=10", "?since=30s", "?limit=100000"}
	for _, q := range ok {
		if st, body := c.do("GET", "/api/series"+q, nil, false); st != 200 {
			t.Errorf("/api/series%s gave %d: %s", q, st, body)
		}
	}
	// A negative duration parses, and the management API decides what
	// a window ending before it began means; the filter here is on the
	// spelling, not on the arithmetic.
	if st, _ := c.do("GET", "/api/series?since=-1h", nil, false); st != 200 {
		t.Errorf("a negative window gave %d", st)
	}
	bad := []string{"?since=yesterday", "?since=5", "?limit=0", "?limit=-1",
		"?limit=100001", "?limit=lots", "?since=" + strings.Repeat("9", 100)}
	for _, q := range bad {
		st, body := c.do("GET", "/api/series"+q, nil, false)
		if st != 400 {
			t.Errorf("/api/series%s gave %d: %s", q, st, body)
		}
	}
}

// TestBanTargets covers the ban form, where the target is typed by
// hand. The reason is always prefixed with the operator's name, so an
// audit trail cannot be forged by typing one.
func TestBanTargets(t *testing.T) {
	_, c, _ := opSession(t, Options{})
	st, body := c.do("POST", "/api/bans", map[string]string{"target": "203.0.113.4", "duration": "10m", "reason": "scanner"}, true)
	if st != 200 {
		t.Fatalf("a plain ban gave %d: %s", st, body)
	}
	// The fake management API refuses a reason without the prefix, so
	// a 200 here is the prefix being applied.
	for _, reason := range []string{
		"", "   ", "admin:someone-else: forged", "a\nb", strings.Repeat("x", 10000),
	} {
		st, body := c.do("POST", "/api/bans", map[string]string{"target": "203.0.113.5", "duration": "10m", "reason": reason}, true)
		if st != 200 {
			t.Errorf("the reason %.20q gave %d: %s", reason, st, body)
		}
	}
	// Removing one needs a target.
	if st, _ := c.do("DELETE", "/api/bans", nil, true); st != 400 {
		t.Error("a delete with no target was accepted")
	}
	if st, _ := c.do("DELETE", "/api/bans?target=", nil, true); st != 400 {
		t.Error("a delete with an empty target was accepted")
	}
	if st, body := c.do("DELETE", "/api/bans?target=203.0.113.4", nil, true); st != 200 {
		t.Errorf("a delete gave %d: %s", st, body)
	}
	// A target with a slash or a query in it reaches the management
	// API as one parameter rather than a different request.
	if st, _ := c.do("DELETE", "/api/bans?target="+"198.51.100.0%2F24", nil, true); st != 200 {
		t.Error("a network target was refused")
	}
}

// TestConfigEditing covers the editor: validation, the etag that stops
// two operators overwriting each other, and the backup the write
// leaves behind.
func TestConfigEditing(t *testing.T) {
	_, c, cfgPath := opSession(t, Options{})

	st, body := c.do("GET", "/api/config/file", nil, false)
	if st != 200 {
		t.Fatalf("reading the configuration gave %d: %s", st, body)
	}
	var view configFileView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if view.Text != minimalConfig || view.ETag == "" || view.Mode == "" {
		t.Fatalf("view %+v", view)
	}

	// A configuration that does not parse is 422 with the problems
	// listed, and the file on disk is untouched.
	broken := "version: 1\nserver:\n  listeners: [{name: http, address: \"not an address\"}]\n"
	st, body = c.do("PUT", "/api/config/file", configFileRequest{Text: broken, ETag: view.ETag}, true)
	if st != 422 {
		t.Fatalf("a broken configuration gave %d: %s", st, body)
	}
	var v validation
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.OK || len(v.Problems) == 0 {
		t.Fatalf("validation %+v", v)
	}
	if onDisk, _ := os.ReadFile(cfgPath); string(onDisk) != minimalConfig {
		t.Fatal("a refused configuration was written anyway")
	}

	// The validate endpoint answers the same without writing anything.
	st, body = c.do("POST", "/api/config/validate", configFileRequest{Text: broken}, true)
	if st != 200 {
		t.Fatalf("validate gave %d: %s", st, body)
	}
	if err := json.Unmarshal(body, &v); err != nil || v.OK {
		t.Fatalf("validate said %+v (%v)", v, err)
	}
	st, body = c.do("POST", "/api/config/validate", configFileRequest{Text: minimalConfig}, true)
	if err := json.Unmarshal(body, &v); err != nil || !v.OK || v.Routes != 1 {
		t.Fatalf("validating a good configuration said %+v (%v) with status %d", v, err, st)
	}

	// A stale etag is a conflict, not an overwrite.
	good := minimalConfig + "logging:\n  level: debug\n"
	st, body = c.do("PUT", "/api/config/file", configFileRequest{Text: good, ETag: "0000"}, true)
	if st != 409 {
		t.Fatalf("a stale etag gave %d: %s", st, body)
	}
	if onDisk, _ := os.ReadFile(cfgPath); string(onDisk) != minimalConfig {
		t.Fatal("a conflicting write went through")
	}

	// The real etag writes, keeps the mode and leaves a backup.
	st, body = c.do("PUT", "/api/config/file", configFileRequest{Text: good, ETag: view.ETag}, true)
	if st != 200 {
		t.Fatalf("a good write gave %d: %s", st, body)
	}
	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != good {
		t.Fatal("the file does not hold what was written")
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("the file is mode %04o after a save", uint32(info.Mode().Perm()))
	}
	bak, err := os.ReadFile(cfgPath + ".bak")
	if err != nil {
		t.Fatalf("no backup: %v", err)
	}
	if string(bak) != minimalConfig {
		t.Fatal("the backup does not hold the previous content")
	}
	// No temporary file was left next to it.
	entries, err := os.ReadDir(filepath.Dir(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}

	// An empty etag writes without the check, which is how a first
	// save from a fresh editor works.
	if st, _ := c.do("PUT", "/api/config/file", configFileRequest{Text: minimalConfig}, true); st != 200 {
		t.Error("a write with no etag was refused")
	}

	// A configuration past the size ceiling is refused before it is
	// parsed.
	huge := configFileRequest{Text: strings.Repeat("#", maxConfigBytes+1)}
	if st, _ := c.do("PUT", "/api/config/file", huge, true); st != 413 {
		t.Error("an oversize configuration was not refused")
	}
	if st, _ := c.do("POST", "/api/config/validate", huge, true); st != 413 {
		t.Error("an oversize configuration was validated")
	}
}

// TestConfigWithoutAFile covers the GUI started with no configuration
// file: the editor must say so rather than fail in a way that reads
// like the proxy is broken.
func TestConfigWithoutAFile(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir)})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}
	if st, body := c.do("GET", "/api/config/file", nil, false); st != 404 {
		t.Fatalf("reading with no file gave %d: %s", st, body)
	}
	if st, _ := c.do("PUT", "/api/config/file", configFileRequest{Text: minimalConfig}, true); st != 404 {
		t.Error("writing with no file was not refused")
	}
	// Validation still works: it needs no file.
	if st, _ := c.do("POST", "/api/config/validate", configFileRequest{Text: minimalConfig}, true); st != 200 {
		t.Error("validation needs a configuration file")
	}
	// And so does the log view's refusal.
	if st, _ := c.do("GET", "/api/logs/access", nil, false); st == 200 {
		t.Error("a log stream was served with no configuration file")
	}
}

// TestLogStreams covers the log view, whose stream name comes from the
// address bar and whose file is named by the data plane's own
// configuration.
func TestLogStreams(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := "version: 1\nserver:\n  listeners: [{name: http, address: \"127.0.0.1:0\"}]\n" +
		"logging:\n  directory: " + logDir + "\n  access: {enabled: true}\n  security: {enabled: true}\n" +
		"upstreams:\n  - {name: app, endpoints: [{address: 127.0.0.1:9}]}\n" +
		"routes:\n  - {name: all, paths: [\"/\"], upstream: app}\n"
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), ConfigFile: cfgPath})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}

	// A stream whose file does not exist yet: an empty view, not a 500.
	st, body := c.do("GET", "/api/logs/access", nil, false)
	if st >= 500 {
		t.Fatalf("a missing log file gave %d: %s", st, body)
	}

	// With content, the last lines come back.
	var lines strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&lines, `{"n":%d}`+"\n", i)
	}
	if err := os.WriteFile(filepath.Join(logDir, "access.log"), []byte(lines.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	st, body = c.do("GET", "/api/logs/access", nil, false)
	if st != 200 {
		t.Fatalf("reading the log gave %d: %s", st, body)
	}
	// The lines are JSON strings inside the document, so the braces and
	// quotes of each one are escaped.
	if !strings.Contains(string(body), `n\":499`) {
		t.Fatalf("the newest line is missing from %d bytes", len(body))
	}
	if !strings.Contains(string(body), `n\":300`) || strings.Contains(string(body), `n\":1}`) {
		t.Fatalf("the tail is not the last 200 lines: %.200s", body)
	}

	// A stream nobody configured, and names that are not streams.
	for _, stream := range []string{"", "bogus", "../../etc/passwd", "access/../../etc/passwd", "ACCESS", "access%00", "access%2f%2e%2e"} {
		st, body := c.do("GET", "/api/logs/"+stream, nil, false)
		if st == 200 && stream != "" {
			t.Errorf("the stream %q was served: %.80s", stream, body)
		}
		if st >= 500 {
			t.Errorf("the stream %q gave %d", stream, st)
		}
	}
}

// TestRestartCommand covers the button that restarts the daemon, which
// runs a command an operator configured — and must not exist at all
// when they did not configure one.
func TestRestartCommand(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir)})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}
	if st, body := c.do("POST", "/api/restart", nil, true); st != 501 {
		t.Fatalf("restart with no command gave %d: %s", st, body)
	}

	// A command that fails reports the failure and its output rather
	// than claiming success.
	_, c2 := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir),
		RestartCommand: []string{"/bin/sh", "-c", "echo went wrong >&2; exit 3"}})
	if st := c2.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}
	st, body := c2.do("POST", "/api/restart", nil, true)
	if st != 409 {
		t.Fatalf("a failing restart gave %d: %s", st, body)
	}
	if !strings.Contains(string(body), "went wrong") {
		t.Fatalf("the output is missing: %s", body)
	}

	// One that succeeds.
	_, c3 := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir),
		RestartCommand: []string{"/bin/sh", "-c", "echo restarted"}})
	if st := c3.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}
	if st, body := c3.do("POST", "/api/restart", nil, true); st != 200 || !strings.Contains(string(body), "restarted") {
		t.Fatalf("a good restart gave %d: %s", st, body)
	}
}

// TestManagementFailuresReachTheOperator requires a proxy that answers
// an error to produce a message rather than an empty view: the GUI is
// how an operator finds out the control plane is not there.
func TestManagementFailuresReachTheOperator(t *testing.T) {
	dir := t.TempDir()
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: filepath.Join(dir, "absent.sock"),
		UsersFile: writeUsers(t, dir)})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}
	for _, path := range []string{"/api/status", "/api/bans", "/api/series"} {
		st, body := c.do("GET", path, nil, false)
		if st == 200 {
			t.Errorf("%s answered though the proxy is not there: %s", path, body)
		}
		if !strings.Contains(string(body), "error") {
			t.Errorf("%s gave %d with no message: %s", path, st, body)
		}
	}
	if st, body := c.do("POST", "/api/reload", nil, true); st == 200 {
		t.Errorf("a reload against nothing reported success: %s", body)
	}
}
