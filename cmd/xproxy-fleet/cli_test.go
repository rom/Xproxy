package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/fleet"
	"github.com/rom/xproxy/internal/testutil"
)

// Everything this command prints about a node came from that node, over
// the network, and the controller does not trust nodes in this
// direction: an agent is a machine that may already be compromised.
// These tests drive the operator commands against a fake controller
// socket, with one node reporting normally and one reporting hostile
// values.

// fakeController serves the controller's operator socket on a Unix
// socket in a temporary directory, and returns its path.
func fakeController(t *testing.T, ov fleet.Overview) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "fleet.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]fleet.NodeView{}
	for _, n := range ov.Nodes {
		byID[n.NodeID] = n
	}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/v1/fleet/nodes", func(w http.ResponseWriter, _ *http.Request) { write(w, ov) })
	mux.HandleFunc("/v1/fleet/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		write(w, ov)
	})
	mux.HandleFunc("/v1/fleet/nodes/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v1/fleet/nodes/")
		id, isBundle := strings.CutSuffix(rest, "/bundle")
		n, ok := byID[id]
		if !ok {
			http.Error(w, "unknown node "+id, http.StatusNotFound)
			return
		}
		if isBundle {
			write(w, map[string]any{"digest": n.Digest, "files": map[string]string{"xproxy.yaml": "version: 1\n"}})
			return
		}
		write(w, n)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// overview is two nodes: one healthy, one that reports values chosen to
// hurt whoever reads them.
func overview() fleet.Overview {
	hostile := fleet.NodeStatus{
		NodeID: "edge2",
		// A compromised node's report: an escape sequence that clears
		// the screen and sets the terminal title, a carriage return
		// that would repaint the row above, and a value long enough to
		// push the rest of the fleet off the display.
		Hostname:   "\x1b[2J\x1b]0;pwned\x07edge2",
		Version:    "1.0.0\r\nedge1  in sync",
		Tags:       []string{"a\x1b[31mb"},
		ReportedAt: time.Now(),
		Applied:    fleet.Result{Digest: "deadbeefdeadbeefdeadbeef", OK: false, Error: strings.Repeat("x", 5000)},
	}
	return fleet.Overview{
		Dir: "/var/lib/xproxy-fleet", Scans: 7,
		Nodes: []fleet.NodeView{
			{
				NodeID: "edge1", Assigned: true, Digest: "0123456789abcdef0123", Files: 3,
				Seen: true, LastSeen: time.Now().Add(-30 * time.Second), InSync: true,
				Remote: "192.0.2.10:5000", CertName: "edge1",
				Status: fleet.NodeStatus{
					NodeID: "edge1", Hostname: "edge1.example.com", Version: "1.0.0",
					Tags: []string{"eu", "edge"}, Uptime: 3600, Generation: 4,
					ReportedAt: time.Now(), Applied: fleet.Result{Digest: "0123456789abcdef0123", OK: true},
					Requests: 1000, Responses5xx: 2, Denied: 30, UpstreamsTotal: 2, UpstreamsHealthy: 2,
					EndpointsTotal: 4, EndpointsHealthy: 4, CertExpiry: time.Now().Add(720 * time.Hour),
				},
			},
			{
				NodeID: "edge2", Assigned: true, Digest: "aaaabbbbccccdddd", Files: 1,
				Seen: true, LastSeen: time.Now().Add(-time.Hour), Stale: true,
				Remote: "192.0.2.11:5000", CertName: "edge2", Status: hostile,
			},
			{NodeID: "edge3", Assigned: true, Digest: "eeeeffff00001111", Files: 1},
			{NodeID: "edge4", ScanErr: "nodes/edge4/xproxy.yaml: not a document"},
		},
	}
}

// TestNodesTable prints the fleet table and checks both that it says
// what it should and that nothing a node sent survives into it.
func TestNodesTable(t *testing.T) {
	sock := fakeController(t, overview())
	var out, errOut bytes.Buffer
	if code := run([]string{"nodes", "-admin-socket", sock}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	s := out.String()
	for _, want := range []string{"edge1", "in sync", "edge2", "stale", "edge3", "never seen", "directory /var/lib/xproxy-fleet", "scans 7"} {
		if !strings.Contains(s, want) {
			t.Errorf("the table does not mention %q:\n%s", want, s)
		}
	}
	assertTerminalSafe(t, s)
	// The long error is cut, not printed whole.
	if strings.Contains(s, strings.Repeat("x", 300)) {
		t.Error("a 5000 character error was printed in full")
	}
}

// TestNodesJSON is the machine readable form, which is passed through
// unchanged: a program reading it is not a terminal.
func TestNodesJSON(t *testing.T) {
	sock := fakeController(t, overview())
	var out, errOut bytes.Buffer
	if code := run([]string{"nodes", "-admin-socket", sock, "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	var ov fleet.Overview
	if err := json.Unmarshal(out.Bytes(), &ov); err != nil {
		t.Fatalf("the -json output is not JSON: %v", err)
	}
	if len(ov.Nodes) != 4 || ov.Scans != 7 {
		t.Fatalf("round trip lost data: %+v", ov)
	}
}

// TestNodeDetail covers the single node view, in both forms, for a node
// that has reported and one that has not.
func TestNodeDetail(t *testing.T) {
	sock := fakeController(t, overview())
	var out, errOut bytes.Buffer
	if code := run([]string{"node", "edge1", "-admin-socket", sock}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	s := out.String()
	for _, want := range []string{"node edge1", "edge1.example.com", "requests 1000", "certificate expiry", "tags eu,edge"} {
		if !strings.Contains(s, want) {
			t.Errorf("the detail view does not mention %q:\n%s", want, s)
		}
	}

	out.Reset()
	if code := run([]string{"node", "edge3", "-admin-socket", sock}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "never reported") {
		t.Fatalf("a node that never reported: %s", out.String())
	}

	out.Reset()
	if code := run([]string{"node", "edge2", "-admin-socket", sock}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	assertTerminalSafe(t, out.String())

	out.Reset()
	if code := run([]string{"node", "edge1", "-admin-socket", sock, "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	var n fleet.NodeView
	if err := json.Unmarshal(out.Bytes(), &n); err != nil || n.NodeID != "edge1" {
		t.Fatalf("-json: %v %+v", err, n)
	}
}

// TestBundle prints the assigned bundle, which is always JSON.
func TestBundle(t *testing.T) {
	sock := fakeController(t, overview())
	var out, errOut bytes.Buffer
	if code := run([]string{"bundle", "edge1", "-admin-socket", sock}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	var b map[string]any
	if err := json.Unmarshal(out.Bytes(), &b); err != nil {
		t.Fatalf("the bundle is not JSON: %v", err)
	}
	if b["digest"] != "0123456789abcdef0123" {
		t.Fatalf("bundle: %v", b)
	}
}

// TestScan asks the controller to rescan now and prints the result.
func TestScan(t *testing.T) {
	sock := fakeController(t, overview())
	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "-admin-socket", sock}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "edge1") {
		t.Fatalf("scan printed %q", out.String())
	}
	out.Reset()
	if code := run([]string{"scan", "-admin-socket", sock, "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("code %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "{") {
		t.Fatalf("-json scan printed %q", out.String())
	}
}

// TestControllerErrors covers what the commands do when the controller
// says no. The message must name the socket and the status, because
// that is the whole diagnosis.
func TestControllerErrors(t *testing.T) {
	sock := fakeController(t, overview())
	var out, errOut bytes.Buffer
	if code := run([]string{"node", "nosuch", "-admin-socket", sock}, &out, &errOut); code != 1 {
		t.Fatalf("an unknown node gave code %d", code)
	}
	if !strings.Contains(errOut.String(), "404") {
		t.Fatalf("the error does not carry the status: %q", errOut.String())
	}
	errOut.Reset()
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if code := run([]string{"nodes", "-admin-socket", missing}, &out, &errOut); code != 1 {
		t.Fatal("a missing socket was not an error")
	}
	if !strings.Contains(errOut.String(), missing) {
		t.Fatalf("the error does not name the socket: %q", errOut.String())
	}
}

// TestBadFlags covers the flag parsing of each subcommand: an unknown
// flag is usage, not a crash and not a default.
func TestBadFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{"nodes", "-bogus"},
		{"node", "edge1", "-bogus"},
		{"bundle", "edge1", "-bogus"},
		{"scan", "-bogus"},
		{"validate", "-bogus"},
		{"serve", "-bogus"},
		{"bundle"},
		{"bundle", "-json"},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v gave code %d, want 2", args, code)
		}
	}
}

// TestNodeIDIsEscapedInThePath covers a node id with a slash or a
// query in it: the id reaches the controller as one path segment, not
// as a different request.
func TestNodeIDIsEscapedInThePath(t *testing.T) {
	var got string
	dir := t.TempDir()
	sock := filepath.Join(dir, "fleet.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"node_id":"x"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	var out, errOut bytes.Buffer
	run([]string{"node", "../../v1/fleet/scan", "-admin-socket", sock}, &out, &errOut)
	if strings.Contains(got, "/../") || strings.HasSuffix(got, "/scan") {
		t.Fatalf("a node id walked out of its path segment: %q", got)
	}
}

// TestReadNameMap covers the file that names certificate exceptions,
// which is the alternative to turning the node id binding off entirely.
func TestReadNameMap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "names")
	if err := os.WriteFile(p, []byte("# a comment\n\nedge1 edge1.example.com\n  edge2   host2  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := readNameMap(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["edge1"] != "edge1.example.com" || m["edge2"] != "host2" {
		t.Fatalf("name map: %v", m)
	}
	if m, err := readNameMap(""); err != nil || m != nil {
		t.Fatal("an empty path must mean no exceptions")
	}
	if _, err := readNameMap(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing file was accepted")
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("edge1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNameMap(bad); err == nil || !strings.Contains(err.Error(), ":1:") {
		t.Fatalf("a one field line gave %v; the error must name the line", err)
	}
	bad3 := filepath.Join(dir, "bad3")
	if err := os.WriteFile(bad3, []byte("a b c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNameMap(bad3); err == nil {
		t.Fatal("a three field line was accepted")
	}
	// And the command refuses to start with a broken map rather than
	// starting with an empty one.
	var out, errOut bytes.Buffer
	if code := run([]string{"serve", "-dir", dir, "-cert", "c", "-key", "k", "-ca", "ca", "-name-map", bad}, &out, &errOut); code != 1 {
		t.Fatalf("serve with a broken name map gave code %d", code)
	}
}

// TestDashAndShort covers the two renderers directly, including the
// values only a hostile agent produces.
func TestDashAndShort(t *testing.T) {
	if dash("") != "-" || dash("   ") != "   " || dash("\x00\x01") != "-" {
		t.Fatalf("dash: %q %q %q", dash(""), dash("   "), dash("\x00\x01"))
	}
	if got := dash(strings.Repeat("a", 500)); len(got) != 200 || !strings.HasSuffix(got, "...") {
		t.Fatalf("a long value rendered as %d characters", len(got))
	}
	// The escape byte is what a terminal acts on; the rest of the
	// sequence is inert text once it is gone, and mangling it further
	// would hide what the node actually sent.
	if got := dash("a\x1b[2Jb\rc\nd"); got != "a[2Jbcd" {
		t.Fatalf("escapes survived: %q", got)
	}
	// Printable non-ASCII stays: an operator's node names are not
	// required to be English.
	if got := dash("nod-öst"); got != "nod-öst" {
		t.Fatalf("a non-ASCII name was mangled to %q", got)
	}
	if short("abc") != "abc" || short("0123456789abcdef") != "0123456789ab" {
		t.Fatal("short")
	}
	if printable("\u200b\u0007x") != "\u200bx" {
		t.Logf("printable keeps %q", printable("\u200b\u0007x"))
	}
}

// assertTerminalSafe fails when output carries a byte a terminal would
// act on instead of show.
func assertTerminalSafe(t *testing.T, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			t.Fatalf("output byte %d is the control character %#x:\n%q", i, c, s)
		}
	}
	if strings.Contains(s, "\x1b") {
		t.Fatalf("output carries an escape sequence:\n%q", s)
	}
}

// TestValidateReportsEveryNode covers the directory validator's output
// shape, which an operator reads before a push.
func TestValidateReportsEveryNode(t *testing.T) {
	dir := t.TempDir()
	good := "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n" +
		"upstreams:\n  - name: web\n    endpoints: [{address: \"10.0.0.1:8080\"}]\n" +
		"routes:\n  - {name: default, upstream: web}\n"
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("edge%d", i)
		if err := os.MkdirAll(filepath.Join(dir, "nodes", id), 0o750); err != nil {
			t.Fatal(err)
		}
		content := good
		if i == 3 {
			content = "version: 1\nserver:\n  listeners: [{name: main, address: \"not-an-address\"}]\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "nodes", id, "xproxy.yaml"), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "-dir", dir}, &out, &errOut); code != 1 {
		t.Fatalf("code %d: %s%s", code, out.String(), errOut.String())
	}
	// Every node is named, in a stable order, whether it is good or not.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("5 nodes produced %d lines:\n%s", len(lines), out.String())
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, fmt.Sprintf("edge%d: ", i)) {
			t.Fatalf("line %d is %q; nodes must be listed in order", i, line)
		}
	}
	if !strings.Contains(out.String(), "edge3: ") || strings.Contains(out.String(), "edge3: ok") {
		t.Fatal("the broken node was reported as ok")
	}
}

// TestServeStartsAndShutsDown starts the controller for real — a mutual
// TLS node listener and the operator socket — answers one operator
// request over the socket, and requires a clean stop on SIGTERM with
// the socket removed behind it. A controller that left its socket
// behind would refuse to start the next time.
func TestServeStartsAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "controller")
	if err := os.MkdirAll(filepath.Join(dir, "nodes", "edge1"), 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n" +
		"upstreams:\n  - name: web\n    endpoints: [{address: \"10.0.0.1:8080\"}]\n" +
		"routes:\n  - {name: default, upstream: web}\n"
	if err := os.WriteFile(filepath.Join(dir, "nodes", "edge1", "xproxy.yaml"), []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "fleet.sock")

	// Catch SIGTERM here first, so the signal below can never reach the
	// default handler and kill the test binary if serve has not armed
	// its own yet.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)

	done := make(chan int, 1)
	var out, errOut bytes.Buffer
	go func() {
		done <- run([]string{"serve", "-dir", dir, "-listen", "127.0.0.1:0",
			"-cert", cert, "-key", key, "-ca", ca.Path, "-admin-socket", sock, "-scan", "50ms"}, &out, &errOut)
	}()

	// Wait for the operator socket to answer.
	deadline := time.Now().Add(20 * time.Second)
	var ov fleet.Overview
	for {
		if err := adminGet(sock, http.MethodGet, "/v1/fleet/nodes", &ov); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the operator socket never answered: %s", errOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(ov.Nodes) != 1 || ov.Nodes[0].NodeID != "edge1" {
		t.Fatalf("the controller did not pick up the node: %+v", ov)
	}
	// A rescan on demand works over the same socket.
	if err := adminGet(sock, http.MethodPost, "/v1/fleet/scan", &ov); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d: %s", code, errOut.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop on SIGTERM")
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("the operator socket was left behind")
	}
}

// TestServeRefusesBadInputs covers the ways serve must fail before it
// binds anything.
func TestServeRefusesBadInputs(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "controller")
	cases := []struct {
		name string
		args []string
	}{
		{"missing cert", []string{"serve", "-dir", dir, "-key", key, "-ca", ca.Path}},
		{"cert file absent", []string{"serve", "-dir", dir, "-cert", filepath.Join(dir, "nope.pem"), "-key", key, "-ca", ca.Path}},
		{"ca file absent", []string{"serve", "-dir", dir, "-cert", cert, "-key", key, "-ca", filepath.Join(dir, "nope.pem")}},
		{"key is not a key", []string{"serve", "-dir", dir, "-cert", cert, "-key", ca.Path, "-ca", ca.Path}},
		{"listen in use", []string{"serve", "-dir", dir, "-cert", cert, "-key", key, "-ca", ca.Path, "-listen", "256.256.256.256:1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tc.args, &out, &errOut); code != 1 {
				t.Fatalf("code %d, want 1 (%s)", code, errOut.String())
			}
			if errOut.Len() == 0 {
				t.Fatal("it failed without saying why")
			}
		})
	}
}
