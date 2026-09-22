package tcp_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/tcp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

const testRules = `
rule secret_marker : exfiltration {
  meta:
    description = "a marker that must not leave"
  strings:
    $a = "TOP-SECRET-MARKER"
  condition:
    $a
}

rule pe_header : malware {
  strings:
    $mz = { 4D 5A 90 00 }
  condition:
    $mz
}
`

func rulesFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(p, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// echoServer answers whatever it is sent, and can also speak first.
func echoServer(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if greeting != "" {
					_, _ = io.WriteString(c, greeting)
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func yaraListener(t *testing.T, backend, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        default: echo
        idle_timeout: 5s
        yara:
          rules_file: %s
%s
logging: {access: {enabled: false}}
upstreams:
  - name: echo
    endpoints: [{address: %s}]
`, rulesFile(t), extra, backend)
	s := proxytest.Start(t, yaml)
	return s, proxytest.Addr(t, s, "l4")
}

// TestYARAClosesOnMatch: a stream carrying what a rule names is cut,
// and the bytes after the match never reach the upstream.
func TestYARAClosesOnMatch(t *testing.T) {
	backend := echoServer(t, "")
	s, addr := yaraListener(t, backend, "")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "hello TOP-SECRET-MARKER goodbye"); err != nil {
		t.Fatal(err)
	}
	// The connection is closed rather than echoed back.
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("the stream continued: %q", buf[:n])
	}
	if sn := s.Stats(); sn.YARAMatches == 0 {
		t.Fatal("the match was not counted")
	}
}

// A stream with nothing a rule names goes through unchanged.
func TestYARAPassesClean(t *testing.T) {
	backend := echoServer(t, "")
	s, addr := yaraListener(t, backend, "")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "nothing to see here"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "nothing to see here" {
		t.Fatalf("clean stream: %q %v", buf[:n], err)
	}
	if sn := s.Stats(); sn.YARAMatches != 0 {
		t.Fatal("a clean stream matched")
	}
	if sn := s.Stats(); sn.YARAScanned == 0 {
		t.Fatal("nothing was scanned")
	}
}

// The upstream direction is scanned too: what comes back is as much a
// stream as what goes out.
func TestYARAScansUpstream(t *testing.T) {
	backend := echoServer(t, "here is a \x4d\x5a\x90\x00 header\n")
	s, addr := yaraListener(t, backend, "")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// A layer 4 listener reads the client's first bytes before it dials
	// the upstream, so the client speaks first even here.
	if _, err := io.WriteString(c, "hello\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	// Either the greeting is cut short or the connection is closed;
	// what must not happen is the stream carrying on afterwards.
	_, _ = c.Read(buf)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c, "still here?"); err == nil {
		if n, err := c.Read(buf); err == nil && n > 0 {
			t.Fatalf("the stream continued after a match: %q", buf[:n])
		}
	}
	if sn := s.Stats(); sn.YARAMatches == 0 {
		t.Fatal("the upstream direction was not scanned")
	}
}

// With action: log the match is recorded and the bytes go on.
func TestYARALogOnly(t *testing.T) {
	backend := echoServer(t, "")
	s, addr := yaraListener(t, backend, "          action: log")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := "carrying TOP-SECRET-MARKER along"
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := io.ReadAtLeast(c, buf, len(msg))
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("log mode should forward: %q %v", buf[:n], err)
	}
	if sn := s.Stats(); sn.YARAMatches == 0 {
		t.Fatal("the match was not counted")
	}
}

// Scanning one direction only is a real halving of the work, so it has
// to actually skip the other.
func TestYARAOneDirection(t *testing.T) {
	backend := echoServer(t, "a \x4d\x5a\x90\x00 header\n")
	s, addr := yaraListener(t, backend, "          directions: [client]")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "hello\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("the greeting should arrive: %v", err)
	}
	if sn := s.Stats(); sn.YARAMatches != 0 {
		t.Fatal("the upstream direction was scanned although it was not listed")
	}
}

// A rule set that does not compile fails the listener rather than
// starting without it.
func TestYARABadRulesFail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yar")
	if err := os.WriteFile(p, []byte("rule r { condition: pe.entry_point > 0 }"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        default: echo
        yara: {rules_file: %s}
logging: {access: {enabled: false}}
upstreams:
  - name: echo
    endpoints: [{address: "127.0.0.1:1"}]
`, p)
	if _, err := config.Parse([]byte(yaml)); err == nil {
		t.Fatal("a rule set using a module should not load")
	}
}
