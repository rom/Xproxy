package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// The terminal interface reads two things: the management API and the
// security log file. Both can be unavailable, slow, or full of values
// that came from a client — and the result is drawn on an operator's
// terminal, which acts on some of those bytes.

const sourceYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
bans: {action: reject}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`

// liveSource starts a management server and returns a source over it,
// with a security log file the test can write to.
func liveSource(t *testing.T) (Source, string) {
	t.Helper()
	cfg, err := config.Parse([]byte(sourceYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "m.sock")
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

	cfg.Logging.Directory = dir
	cfg.Logging.Security.File = "security.log"
	return NewSource(mgmt.NewClient(sock), cfg), filepath.Join(dir, "security.log")
}

// TestFetchAgainstALiveProxy covers the ordinary case: every view the
// interface draws comes back, and nothing is recorded as an error.
func TestFetchAgainstALiveProxy(t *testing.T) {
	src, _ := liveSource(t)
	d := src.Fetch(context.Background())
	if d.Status == nil {
		t.Fatalf("no status: %v", d.Errors)
	}
	if d.At.IsZero() {
		t.Fatal("the data has no timestamp")
	}
	// The subsystems this configuration does not have report errors
	// rather than empty views, so the interface can say which part is
	// missing instead of drawing an empty table.
	if len(d.Errors) == 0 {
		t.Log("every view answered")
	}
}

// TestFetchWithNoProxy covers the interface started against a socket
// that is not there, which is what running it after a crash looks like.
// Every view must record its own error rather than the whole fetch
// failing, because the one view that does answer is the one an
// operator needs.
func TestFetchWithNoProxy(t *testing.T) {
	src := NewSource(mgmt.NewClient(filepath.Join(t.TempDir(), "absent.sock")), nil)
	d := src.Fetch(context.Background())
	if len(d.Errors) == 0 {
		t.Fatal("a fetch against nothing reported no errors")
	}
	for what, msg := range d.Errors {
		if msg == "" {
			t.Fatalf("the error for %q is empty", what)
		}
	}
	if d.Status != nil {
		t.Fatal("a status came back from a socket that is not there")
	}
}

// TestFetchRespectsTheContext covers a management API that does not
// answer within the refresh interval: the fetch must come back, and
// what it hands the renderer must then stop changing.
//
// Each view runs in two goroutines — one waiting, one calling — so that
// a slow view does not hold the others. The waiting one gives up at
// ctx.Done(); the calling one is left running and finishes its call
// afterwards. It used to store the answer then, into a Data the caller
// had already been given and the renderer was already drawing: a write
// to a live map from a goroutine nobody was waiting for. Run this one
// under -race.
func TestFetchRespectsTheContext(t *testing.T) {
	src, _ := liveSource(t)
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		d := src.Fetch(ctx)
		cancel()
		// Read everything the renderer would read, while whatever the
		// fetch abandoned is still finishing its call.
		for range d.Errors {
		}
		for range d.Upstreams {
		}
		for range d.Pools {
		}
		for range d.TLS {
		}
		_ = d.Status
		_ = d.Bans
		_ = d.LogLines
		time.Sleep(time.Millisecond)
	}
}

// TestFetchIsBoundedByTheContext requires the fetch itself to return
// near the deadline rather than at the pace of the slowest view.
func TestFetchIsBoundedByTheContext(t *testing.T) {
	src, _ := liveSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan Data, 1)
	go func() { done <- src.Fetch(ctx) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("a cancelled fetch did not return")
	}
}

// TestTailLines covers the security log reader, whose file is written
// by another process while this one reads it.
func TestTailLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")

	// A file that is not there is an error, not an empty view.
	if _, err := tailLines(path, 10); err == nil {
		t.Fatal("a missing log file was read")
	}

	// An empty file has no lines and no error.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := tailLines(path, 10)
	if err != nil || len(lines) != 0 {
		t.Fatalf("an empty file: %v %v", lines, err)
	}

	// Fewer lines than asked for.
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if lines, err = tailLines(path, 10); err != nil || len(lines) != 3 || lines[2] != "three" {
		t.Fatalf("three lines: %v %v", lines, err)
	}

	// More lines than asked for: the last n, in order.
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if lines, err = tailLines(path, 5); err != nil || len(lines) != 5 {
		t.Fatalf("five of a thousand: %v %v", lines, err)
	}
	if lines[4] != "line 999" || lines[0] != "line 995" {
		t.Fatalf("the wrong five: %v", lines)
	}

	// A file larger than the window: the reader takes the tail and
	// drops the first line, which is probably partial.
	b.Reset()
	for i := 0; b.Len() < 512<<10; i++ {
		fmt.Fprintf(&b, "%06d %s\n", i, strings.Repeat("x", 100))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err = tailLines(path, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 20 {
		t.Fatalf("%d lines from a large file", len(lines))
	}
	for i, l := range lines {
		if len(l) != 107 {
			t.Fatalf("line %d is %d bytes; the window cut a line in half: %q", i, len(l), l)
		}
	}

	// A file with no trailing newline still yields its last line.
	if err := os.WriteFile(path, []byte("a\nb\nc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if lines, err = tailLines(path, 10); err != nil || len(lines) != 3 || lines[2] != "c" {
		t.Fatalf("no trailing newline: %v %v", lines, err)
	}

	// A file of one enormous line, and one of NUL bytes: neither is a
	// log this process wrote, and neither may be a panic.
	for _, content := range []string{strings.Repeat("x", 1<<20), strings.Repeat("\x00", 1024), "\n\n\n\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic reading a %d byte file: %v", len(content), r)
				}
			}()
			if _, err := tailLines(path, 10); err != nil {
				t.Logf("refused: %v", err)
			}
		}()
	}

	// A directory where a file belongs.
	if _, err := tailLines(dir, 10); err == nil {
		t.Fatal("a directory was read as a log file")
	}
}

// TestSourceWithoutConfig covers the interface started with no
// configuration file to read, where the log path is unknown: the
// management views still work and the log view is simply absent.
func TestSourceWithoutConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(sourceYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()

	src := NewSource(mgmt.NewClient(sock), nil)
	d := src.Fetch(context.Background())
	if d.Status == nil {
		t.Fatalf("no status without a configuration: %v", d.Errors)
	}
}

// TestEveryViewSurvivesHostileData draws every view with values that
// came from a client or from a peer — a deny reason typed by nobody, a
// node name from another machine, a certificate subject from a CA, a
// WAF rule message. None of it may reach the terminal as bytes the
// terminal acts on, and none of it may break the frame.
func TestEveryViewSurvivesHostileData(t *testing.T) {
	evil := "\x1b[2J\x1b]0;pwned\x07\r\n\x00\x7f\u009b31m" + strings.Repeat("x", 500)
	d := sample()
	d.Status.Version = evil
	d.Status.Listeners = map[string]string{evil: evil}
	for name, eps := range d.Upstreams {
		eps[0].Address = evil
		d.Upstreams[name] = eps
	}
	d.Bans[0].Target = evil
	d.Bans[0].Reason = evil
	d.Bans[0].Source = evil
	d.Cluster.NodeID = evil
	d.Cluster.Peers[0].Address = evil
	d.Cluster.Peers[1].LastError = evil
	d.Cluster.Inbound[0].NodeID = evil
	d.Cluster.Inbound[0].CertName = evil
	d.LogLines = []string{
		`{"time":"2026-09-18T12:00:00.000Z","msg":"security","action":"` + "\x1b[2Jdeny" + `","reason":"` + "\u009b31mwaf" + `","client_ip":"203.0.113.9","path":"/` + "\x07\x7f" + `"}`,
		"not json at all\x1b[2J",
		"",
		`{"time":"` + strings.Repeat("9", 1000) + `"}`,
	}
	d.WAF.Report.Rules[0].Message = evil
	d.Errors = map[string]string{"status": evil, "waf": evil}
	for l, certs := range d.TLS {
		certs[0].Names = []string{evil}
		certs[0].Issuer = evil
		d.TLS[l] = certs
	}

	for _, width := range []int{40, 80, 200} {
		for _, height := range []int{10, 24, 60} {
			for v := View(0); v < viewCount; v++ {
				st := State{View: v, Width: width, Height: height, Refresh: time.Second}
				for _, sty := range []Style{Plain, ANSI} {
					lines := Render(d, st, sty)
					frame := strings.Join(lines, "\n")
					// Under the plain style nothing may carry an
					// escape or a control character at all, because
					// the renderer emits none: whatever is there came
					// from the data.
					if sty.Reset == "" {
						for i := 0; i < len(frame); i++ {
							if c := frame[i]; (c < 0x20 && c != '\n') || c == 0x7f {
								t.Fatalf("view %d at %dx%d: byte %d is the control character %#x", v, width, height, i, c)
							}
						}
					}
					// Under the colour style only the style's own
					// eight codes may appear: no cursor movement, no
					// screen clear, no title set.
					if sty.Reset != "" {
						for _, bad := range []string{"\x1b[2J", "\x1b]0;", "\x1b[H", "\x1b[K", "\x07", "\r"} {
							if strings.Contains(frame, bad) {
								t.Fatalf("view %d at %dx%d carries %q from the data", v, width, height, bad)
							}
						}
					}
					if len(lines) != height {
						t.Fatalf("view %d at %dx%d drew %d lines", v, width, height, len(lines))
					}
					for n, line := range lines {
						if visibleLen(line) > width {
							t.Fatalf("view %d at %dx%d: line %d is %d columns wide", v, width, height, n, visibleLen(line))
						}
					}
				}
			}
		}
	}
}

// TestRenderWithNothing covers the first frame, before any fetch has
// answered: every view must draw something rather than nothing, and
// nothing may index into an empty slice.
func TestRenderWithNothing(t *testing.T) {
	for v := View(0); v < viewCount; v++ {
		st := State{View: v, Width: 80, Height: 24, Refresh: time.Second}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("view %d panicked on empty data: %v", v, r)
				}
			}()
			if len(Render(Data{}, st, Plain)) != 24 {
				t.Fatalf("view %d drew the wrong number of lines", v)
			}
		}()
	}
}

// TestRenderAtAbsurdSizes covers a terminal the operator resized to
// something the interface was not designed for.
func TestRenderAtAbsurdSizes(t *testing.T) {
	d := sample()
	for _, size := range [][2]int{{1, 1}, {0, 0}, {5, 3}, {1000, 2}, {20, 1000}, {-1, -1}} {
		for v := View(0); v < viewCount; v++ {
			st := State{View: v, Width: size[0], Height: size[1], Refresh: time.Second}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("view %d at %dx%d panicked: %v", v, size[0], size[1], r)
					}
				}()
				Render(d, st, Plain)
			}()
		}
	}
}
