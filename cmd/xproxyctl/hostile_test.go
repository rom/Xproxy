package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMgmt answers every management path with bytes a test chose, so
// the control tool meets a daemon that is broken, a version it does not
// know, or an answer somebody tampered with on the way.
type fakeMgmt struct {
	path  string
	body  atomic.Value // []byte
	code  atomic.Int32
	hangs atomic.Bool
}

func startFakeMgmt(t *testing.T) *fakeMgmt {
	t.Helper()
	dir := t.TempDir()
	f := &fakeMgmt{path: filepath.Join(dir, "m.sock")}
	f.body.Store([]byte("{}"))
	f.code.Store(200)
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if f.hangs.Load() {
				hj, ok := w.(http.Hijacker)
				if ok {
					conn, _, err := hj.Hijack()
					if err == nil {
						_ = conn.Close()
						return
					}
				}
			}
			w.WriteHeader(int(f.code.Load()))
			_, _ = w.Write(f.body.Load().([]byte))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeMgmt) answer(code int, body string) {
	f.code.Store(int32(code)) //nolint:gosec // test status
	f.body.Store([]byte(body))
}

// readOnlyCommands are the subcommands that only read from the daemon,
// so they can be pointed at a hostile answer without changing anything.
var readOnlyCommands = []string{
	"status", "stats", "upstreams", "quotas", "waf", "sandbox", "tls", "telemetry",
	"acme", "cache", "geoip", "otlp", "ingress", "dns", "maintenance", "accounts",
	"botscore", "api", "patches", "honeypot", "filters", "icap", "metrics", "series",
	"fleet", "cluster", "bans", "config",
}

// TestHostileManagementAnswers points every reading command at a daemon
// whose answers are rubbish. The tool must report an error or print an
// empty view — never panic, never hang, never print a success line for
// an answer it could not read.
func TestHostileManagementAnswers(t *testing.T) {
	f := startFakeMgmt(t)
	answers := []struct {
		name string
		code int
		body string
	}{
		{"empty", 200, ""},
		{"not json", 200, "<html>the wrong daemon</html>"},
		{"a truncated document", 200, `{"version":"1.4","listeners":{`},
		{"a json array", 200, `[1,2,3]`},
		{"a json string", 200, `"status"`},
		{"json null", 200, `null`},
		{"every field the wrong type", 200, `{"version":1,"pid":"x","generation":[],"listeners":"none","stats":42,"routes":{},"upstreams":null}`},
		{"a deeply nested document", 200, strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200)},
		{"a huge document", 200, `{"version":"` + strings.Repeat("v", 1<<20) + `"}`},
		{"NaN and Infinity", 200, `{"stats":{"uptime_seconds":NaN}}`},
		{"a negative uptime", 200, `{"version":"x","pid":-1,"generation":-5,"stats":{"uptime_seconds":-99}}`},
		{"duplicate keys", 200, `{"version":"a","version":"b"}`},
		{"http 500", 500, `{"error":"broken"}`},
		{"http 404", 404, ``},
		{"http 401", 401, `unauthorized`},
		{"a redirect", 302, ``},
	}
	for _, a := range answers {
		f.answer(a.code, a.body)
		for _, cmd := range readOnlyCommands {
			args := []string{cmd}
			if cmd == "series" {
				args = append(args, "-since", "1m")
			}
			code, out, errOut := runCmd(t, f.path, "", args...)
			if code != 0 && code != 1 {
				t.Errorf("%s with %s: exit %d\n%s%s", cmd, a.name, code, out, errOut)
			}
			if code == 1 && !strings.Contains(errOut, "error:") {
				t.Errorf("%s with %s: exit 1 without an error line: %q", cmd, a.name, errOut)
			}
			if code == 0 && strings.Contains(out, "panic") {
				t.Errorf("%s with %s printed a panic", cmd, a.name)
			}
		}
		// The same answers as JSON output, which takes a different path
		// through most commands.
		for _, cmd := range []string{"status", "stats", "upstreams", "quotas", "bans", "waf", "sandbox", "tls"} {
			if code, _, errOut := runCmd(t, f.path, "", "-json", cmd); code != 0 && code != 1 {
				t.Errorf("-json %s with %s: exit %d %q", cmd, a.name, code, errOut)
			}
		}
	}
}

// TestDaemonThatHangsUp covers the socket going away mid-answer, which
// is what a restart during a command looks like.
func TestDaemonThatHangsUp(t *testing.T) {
	f := startFakeMgmt(t)
	f.hangs.Store(true)
	for _, cmd := range []string{"status", "bans", "waf", "metrics"} {
		code, _, errOut := runCmd(t, f.path, "", cmd)
		if code != 1 || !strings.Contains(errOut, "error:") {
			t.Errorf("%s against a daemon that hung up: exit %d %q", cmd, code, errOut)
		}
	}
	// A path that is not a socket at all, and one that does not exist.
	dir := t.TempDir()
	plain := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(plain, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sock := range []string{plain, filepath.Join(dir, "missing.sock"), dir, ""} {
		if code, _, errOut := runCmd(t, sock, "", "status"); code != 1 || !strings.Contains(errOut, "error:") {
			t.Errorf("socket %q: exit %d %q", sock, code, errOut)
		}
	}
}

// TestBadArgumentsForEverySubcommand walks the command table with flags
// and arguments nobody meant. Every one must be a usage error or a
// clean failure, and the usage text must name the command.
func TestBadArgumentsForEverySubcommand(t *testing.T) {
	sock, cfgPath := harness(t)
	// A file argument goes into a temporary directory: some of these
	// subcommands write the file they are given, and a test must not
	// leave one in the working tree.
	scratch := filepath.Join(t.TempDir(), "arg")
	for _, c := range commandTable {
		for _, extra := range [][]string{
			{"-no-such-flag"},
			{"-top", "not-a-number"},
			{"--", scratch},
		} {
			args := append([]string{c.name}, extra...)
			code, out, errOut := runCmd(t, sock, cfgPath, args...)
			if code != 0 && code != 1 && code != 2 {
				t.Errorf("%v: exit %d\n%s%s", args, code, out, errOut)
			}
			if strings.Contains(out, "panic:") || strings.Contains(errOut, "panic:") {
				t.Errorf("%v panicked", args)
			}
		}
	}
	// A subcommand of a subcommand that does not exist: the ones that
	// take a subcommand say so.
	for _, args := range [][]string{
		{"waf", "nonsense"},
		{"api", "nonsense"},
		{"maintenance", "nonsense"},
		{"completion", "nonsense"},
		{"apikey", "nonsense"},
	} {
		code, _, errOut := runCmd(t, sock, cfgPath, args...)
		if code != 2 || !strings.Contains(errOut, "usage") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
	// tail names the stream rather than printing a usage line.
	if code, _, errOut := runCmd(t, sock, cfgPath, "tail", "nonsense"); code != 2 || !strings.Contains(errOut, "unknown stream") {
		t.Errorf("tail nonsense: exit %d, stderr %q", code, errOut)
	}
	// The commands that take no subcommand ignore a stray word rather
	// than refusing it. That is the current contract; it is recorded
	// here so a change to it is a deliberate one.
	for _, args := range [][]string{{"fleet", "nonsense"}, {"status", "nonsense"}, {"stats", "nonsense"}} {
		if code, _, errOut := runCmd(t, sock, cfgPath, args...); code != 0 {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}

// TestGlobalFlagRejections covers the flags every command shares.
func TestGlobalFlagRejections(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{"-unknown", "status"},
		{"-json=maybe", "status"},
		{"-socket"},
		{"-h"},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d\n%s%s", args, code, out.String(), errOut.String())
		}
	}
	// No arguments at all prints the usage, on standard error.
	out.Reset()
	errOut.Reset()
	if code := run(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
		t.Errorf("no arguments: exit %d, stderr %q", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("usage went to standard output: %q", out.String())
	}
}

// TestValidateHostileConfigurations covers the one command that reads a
// file rather than the daemon.
func TestValidateHostileConfigurations(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bad := map[string]string{
		"empty.yaml":     "",
		"rubbish.yaml":   "\x00\x01\x02 not yaml",
		"list.yaml":      "- a\n- b\n",
		"scalar.yaml":    "just a string\n",
		"unknown.yaml":   "version: 1\nnonsense: true\n",
		"anchors.yaml":   "version: 1\na: &a [1,1,1,1,1,1,1,1,1]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n",
		"tabs.yaml":      "version: 1\nserver:\n\tlisteners: []\n",
		"truncated.yaml": "version: 1\nserver:\n  listeners:\n    - {name: main,",
	}
	for name, body := range bad {
		p := write(name, body)
		code, out, errOut := runCmd(t, "", p, "validate")
		if code != 1 {
			t.Errorf("%s: exit %d\n%s%s", name, code, out, errOut)
		}
		if !strings.Contains(errOut, "error:") {
			t.Errorf("%s: no error line: %q", name, errOut)
		}
	}
	// A directory, a missing file and a file that cannot be read.
	for _, p := range []string{dir, filepath.Join(dir, "nope.yaml")} {
		if code, _, errOut := runCmd(t, "", p, "validate"); code != 1 || !strings.Contains(errOut, "error:") {
			t.Errorf("%s: exit %d %q", p, code, errOut)
		}
	}
}

// TestTailHostileInput covers the log follower: the streams it knows,
// the ones it does not, and a file it cannot open.
func TestTailHostileInput(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	cfg := "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n" +
		"logging:\n  directory: " + logDir + "\n  access: {enabled: true}\n" +
		"upstreams:\n  - {name: u, endpoints: [{address: 127.0.0.1:1}]}\n" +
		"routes:\n  - {name: r, upstream: u}\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	// Streams that are not streams.
	for _, stream := range []string{"", "bogus", "ACCESS", "../../etc/passwd", "access\x00"} {
		out.Reset()
		errOut.Reset()
		if code := tail(cfgPath, stream, &out, &errOut); code != 2 {
			t.Errorf("stream %q: exit %d %q", stream, code, errOut.String())
		}
	}
	// A configuration that cannot be read.
	out.Reset()
	errOut.Reset()
	if code := tail(filepath.Join(dir, "nope.yaml"), "access", &out, &errOut); code != 1 {
		t.Errorf("a missing configuration: exit %d", code)
	}
	// A stream whose file is not there.
	out.Reset()
	errOut.Reset()
	if code := tail(cfgPath, "access", &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "error:") {
		t.Errorf("a missing log file: exit %d %q", code, errOut.String())
	}

	// A real follow: lines appended after it starts are printed, and a
	// rotation is followed. The follower only returns on error, so the
	// test ends it by removing the file and rotating onto nothing.
	logFile := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logFile, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	var tailErr bytes.Buffer
	go func() { done <- tail(cfgPath, "access", pw, &tailErr) }()
	lines := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				lines <- string(buf[:n])
			}
			if err != nil {
				close(lines)
				return
			}
		}
	}()
	appendTo := func(path, s string) {
		t.Helper()
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.WriteString(fh, s)
		_ = fh.Close()
	}
	// The follower seeks to the end when it opens, so a line written
	// before it got there would be missed: write until it is seen.
	wait := func(write func(), want string) {
		t.Helper()
		deadline := time.After(30 * time.Second)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		write()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("the follower stopped before %q: %s", want, tailErr.String())
				}
				if strings.Contains(l, want) {
					return
				}
			case <-tick.C:
				write()
			case <-deadline:
				t.Fatalf("%q never arrived: %s", want, tailErr.String())
			}
		}
	}
	wait(func() { appendTo(logFile, "first\n") }, "first")
	// Rotate: the old file moves aside and a new one takes the name.
	if err := os.Rename(logFile, logFile+".1"); err != nil {
		t.Fatal(err)
	}
	wait(func() { appendTo(logFile, "after-rotation\n") }, "after-rotation")
	// Now make the follow fail: the name is rotated away and a directory
	// takes its place, so the reopen finds something it cannot read. The
	// follower returns an error rather than spinning on it.
	if err := os.Rename(logFile, logFile+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logFile, 0o750); err != nil {
		t.Fatal(err)
	}
	go func() {
		// Drain whatever the follower writes on its way out, so it is
		// never blocked on the pipe.
		for range lines {
		}
	}()
	select {
	case code := <-done:
		if code == 0 {
			t.Error("the follower returned success")
		}
		if !strings.Contains(tailErr.String(), "error:") {
			t.Errorf("the follower stopped without an error line: %q", tailErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Error("the follower did not return")
	}
	_ = pw.Close()
	_ = pr.Close()
}

// TestHtpasswdHostileInput covers the one command that writes a
// credential file.
func TestHtpasswdHostileInput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "users")
	var out, errOut bytes.Buffer
	run1 := func(path, name, pw string) int {
		out.Reset()
		errOut.Reset()
		return htpasswd(path, name, strings.NewReader(pw), &out, &errOut)
	}
	// Names the file format cannot hold.
	for _, name := range []string{"", "a:b", "a\nb", "a\rb", "a:b:c"} {
		if code := run1(file, name, "a long enough password\n"); code != 2 {
			t.Errorf("the name %q gave exit %d", name, code)
		}
	}
	// Passwords the hash refuses.
	for _, pw := range []string{"", "\n", "short\n", strings.Repeat("p", 2000) + "\n"} {
		if code := run1(file, "alice", pw); code == 0 {
			t.Errorf("the password %.10q was accepted", pw)
		}
	}
	// A name that is legal but unusual, and a password with the bytes a
	// shell would have mangled.
	for _, tc := range []struct{ name, pw string }{
		{"alice@example.com", "correct horse battery"},
		{"a.b-c_d", "éàü a password"},
		{"UPPER", "tabs\tand spaces   "},
		{strings.Repeat("n", 64), "another long password"},
	} {
		if code := run1(file, tc.name, tc.pw+"\n"); code != 0 {
			t.Errorf("%q: exit %d: %s", tc.name, code, errOut.String())
		}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\n"); n != 4 {
		t.Errorf("the file has %d lines:\n%s", n, data)
	}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		// One colon separates the name from the hash; the hash's own
		// fields are separated by $, so a name can never be confused
		// with a hash.
		if strings.Count(line, ":") != 1 || !strings.Contains(line, ":pbkdf2-sha256$") {
			t.Errorf("line %q does not have the expected shape", line)
		}
	}
	// Comments and unrelated lines in an existing file are kept.
	mixed := filepath.Join(dir, "mixed")
	if err := os.WriteFile(mixed, []byte("# a comment\n\nbob:pbkdf2-sha256$1000$AA$AA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run1(mixed, "alice", "a long enough password\n"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	data, _ = os.ReadFile(mixed)
	if !strings.Contains(string(data), "# a comment") || !strings.Contains(string(data), "bob:") {
		t.Errorf("the existing file was not preserved:\n%s", data)
	}
	// A path that cannot be written.
	if code := run1(filepath.Join(dir, "nope", "users"), "alice", "a long enough password\n"); code == 0 {
		t.Error("a write into a missing directory succeeded")
	}
	if code := run1(dir, "alice", "a long enough password\n"); code == 0 {
		t.Error("a directory was written as a users file")
	}
	// A stdin that fails before a newline.
	out.Reset()
	errOut.Reset()
	if code := htpasswd(file, "alice", &failingReader{}, &out, &errOut); code != 1 {
		t.Errorf("a failing stdin gave exit %d", code)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("stdin broke") }

// TestOutputIsMachineReadable pins the promise -json makes: whatever
// the daemon answered, the tool either prints one JSON document or
// fails; it never prints half a document with a table around it.
func TestOutputIsMachineReadable(t *testing.T) {
	sock, cfgPath := harness(t)
	for _, cmd := range []string{"status", "stats", "upstreams", "quotas", "bans", "sandbox", "waf", "tls", "filters", "config"} {
		code, out, errOut := runCmd(t, sock, cfgPath, "-json", cmd)
		if code != 0 {
			continue // an unconfigured subsystem is allowed to fail
		}
		trimmed := strings.TrimSpace(out)
		if trimmed == "" {
			continue
		}
		if cmd == "config" || cmd == "metrics" {
			continue // these are documents of their own format
		}
		var v any
		if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
			t.Errorf("-json %s did not print one JSON document: %v\n%.200s", cmd, err, trimmed)
		}
		if errOut != "" {
			t.Errorf("-json %s wrote to standard error: %q", cmd, errOut)
		}
	}
}

// hostileText is what an attacker would like an operator's terminal to
// receive: a title change, a screen clear, a cursor move, a carriage
// return that overwrites the line it is on, and a backspace.
const hostileText = "evil\x1b]0;pwned\x07\x1b[2J\x1b[1;1H\rADMIN OK\x08\x08"

// TestNothingPrintsTerminalControls points the tool at a daemon whose
// answers carry terminal escapes in every string field. The values in
// these tables come off the network, so an operator running a command
// must not be handing their terminal to whoever supplied them.
func TestNothingPrintsTerminalControls(t *testing.T) {
	f := startFakeMgmt(t)
	now := time.Now()
	stamp := now.Format(time.RFC3339Nano)
	// One document per shape the commands decode. Each carries the
	// hostile text wherever a string can go.
	docs := map[string]string{
		"/v1/status": `{"version":"` + jsonHostile + `","pid":1,"generation":2,"routes":1,"upstreams":1,
			"listeners":{"` + jsonHostile + `":"` + jsonHostile + `"},
			"stats":{"uptime_seconds":10,"requests":5,"denials":{"` + jsonHostile + `":3}}}`,
		"/v1/upstreams": `{"` + jsonHostile + `":[{"address":"` + jsonHostile + `","weight":1,"healthy":true,"discovered":true}]}`,
		"/v1/pools":     `{"` + jsonHostile + `":{"slow_start":"` + jsonHostile + `","discovery":{"type":"dns","name":"` + jsonHostile + `","interval":"30s","last_error":"` + jsonHostile + `"}}}`,
		"/v1/bans":      `[{"target":"` + jsonHostile + `","reason":"` + jsonHostile + `","kind":"ip","expires":"` + stamp + `","hits":2}]`,
		"/v1/cluster": `{"node_id":"` + jsonHostile + `","listen":"` + jsonHostile + `","peers":[{"node_id":"` + jsonHostile + `",
			"address":"` + jsonHostile + `","connected":false,"last_error":"` + jsonHostile + `"}]}`,
		"/v1/fleet": `{"enabled":true,"controller":"` + jsonHostile + `","node_id":"` + jsonHostile + `","dir":"` + jsonHostile + `",
			"interval":"1m","last_error":"` + jsonHostile + `","applied":{"digest":"` + jsonHostile + `","ok":false,"at":"` + stamp + `","error":"` + jsonHostile + `"}}`,
		"/v1/acme":     `[{"domains":["` + jsonHostile + `"],"status":"` + jsonHostile + `","error":"` + jsonHostile + `","not_after":"` + stamp + `"}]`,
		"/v1/icap":     `[{"name":"` + jsonHostile + `","url":"` + jsonHostile + `","last_error":"` + jsonHostile + `"}]`,
		"/v1/filters":  `{"filters":[{"name":"` + jsonHostile + `","kind":"` + jsonHostile + `","routes":["` + jsonHostile + `"]}]}`,
		"/v1/patches":  `[{"id":"` + jsonHostile + `","description":"` + jsonHostile + `","enabled":true,"hits":1}]`,
		"/v1/tls":      `{"` + jsonHostile + `":[{"names":["` + jsonHostile + `"],"issuer":"` + jsonHostile + `","not_after":"` + stamp + `","ocsp":{"status":"` + jsonHostile + `","error":"` + jsonHostile + `"},"ct":{"embedded":1,"verified":0,"ok":false,"error":"` + jsonHostile + `"}}]}`,
		"/v1/honeypot": `{"enabled":true,"hits":[{"ip":"` + jsonHostile + `","path":"` + jsonHostile + `","user_agent":"` + jsonHostile + `","at":"` + stamp + `"}]}`,
		"/v1/waf":      `{"enabled":true,"profiles":[{"name":"` + jsonHostile + `","mode":"` + jsonHostile + `","rules":1}]}`,
		"/v1/config":   "version: 1\n# " + jsonHostileRaw + "\n",
		"/metrics":     "xproxy_requests_total{route=\"" + jsonHostileRaw + "\"} 1\n",
	}
	for path, body := range docs {
		f.answer(200, body)
		for _, cmd := range readOnlyCommands {
			args := []string{cmd}
			if cmd == "series" {
				args = append(args, "-since", "1m")
			}
			code, out, errOut := runCmd(t, f.path, "", args...)
			if code != 0 && code != 1 {
				t.Fatalf("%s with %s: exit %d", cmd, path, code)
			}
			for _, where := range []struct {
				name string
				text string
			}{{"stdout", out}, {"stderr", errOut}} {
				if i := strings.IndexFunc(where.text, isTerminalControl); i >= 0 {
					t.Errorf("%s (%s answer) put %q in %s at %d", cmd, path, where.text[i:min(i+8, len(where.text))], where.name, i)
				}
			}
		}
	}
}

// isTerminalControl reports the bytes a terminal acts on. Newline and
// tab are layout, not control.
func isTerminalControl(r rune) bool {
	return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f
}

// jsonHostile is hostileText as a JSON string body, and jsonHostileRaw
// is the same bytes for documents that are not JSON.
var (
	jsonHostileRaw = hostileText
	jsonHostile    = strings.NewReplacer(
		"\x1b", `\u001b`, "\x07", `\u0007`, "\r", `\r`, "\x08", `\b`, `"`, `\"`,
	).Replace(hostileText)
)

// TestTerminalSafeWriter covers the filter itself: one byte in, one
// byte out, so a table's columns still line up, and nothing a terminal
// acts on survives.
func TestTerminalSafeWriter(t *testing.T) {
	var buf bytes.Buffer
	w := terminalSafe{&buf}
	in := make([]byte, 0, 256)
	for i := 0; i < 256; i++ {
		in = append(in, byte(i))
	}
	n, err := w.Write(in)
	if err != nil || n != len(in) {
		t.Fatalf("write: %d %v", n, err)
	}
	got := buf.Bytes()
	if len(got) != len(in) {
		t.Fatalf("%d bytes in, %d out", len(in), len(got))
	}
	for i := range got {
		switch {
		case in[i] == '\n' || in[i] == '\t':
			if got[i] != in[i] {
				t.Errorf("byte %#x was changed to %#x", in[i], got[i])
			}
		case in[i] < 0x20 || in[i] == 0x7f:
			if got[i] != '?' {
				t.Errorf("byte %#x came through as %#x", in[i], got[i])
			}
		default:
			if got[i] != in[i] {
				t.Errorf("byte %#x was changed to %#x", in[i], got[i])
			}
		}
	}
	// UTF-8 text survives whole.
	buf.Reset()
	const text = "hällö 你好 \U0001f600"
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if buf.String() != text {
		t.Errorf("UTF-8 text came back as %q", buf.String())
	}
	// A write split across an escape sequence is still filtered.
	buf.Reset()
	_, _ = w.Write([]byte("a\x1b"))
	_, _ = w.Write([]byte("[2Jb"))
	if buf.String() != "a?[2Jb" {
		t.Errorf("a split escape came back as %q", buf.String())
	}
}
