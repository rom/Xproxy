package mysql

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A pcapng capture of a relayed session, end to end through the real listener.
//
// The capture subsystem has its own tests for the file format and for the rule
// selectors. What these check is the wiring: that this kind opens a tap at all,
// that it opens it early enough to hold a session it refuses, and that the
// statement an operator is looking for is in the file rather than the handshake
// around it.

const captureMyYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: mysql
      mysql:
%s
logging: {access: {enabled: false}}
capture:
  enabled: true
  start_active: true
  directory: %s
  bodies: true
  max_body_bytes: 4096
  rules:
%s
upstreams:
  - {name: my, endpoints: [{address: %q}]}
`

func captureRelay(t *testing.T, section, rules, serverAddr string) (*proxy.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	s := proxytest.Start(t, fmt.Sprintf(captureMyYAML, section, dir, rules, serverAddr))
	return s, proxytest.Addr(t, s, "db"), dir
}

// recorded waits for the proxy to finish writing n sessions and returns the
// capture directory's bytes.
//
// The whole file rather than the reassembled streams: a payload sits in the
// packet block verbatim, so a search over the file finds it, and the framing is
// internal/capture's to test rather than this kind's.
func recorded(t *testing.T, s *proxy.Server, dir string, n uint64) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := s.CaptureStatus()
		if st.Captured+st.Skipped >= n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d sessions were recorded: %+v", st.Captured+st.Skipped, n, st)
		}
		time.Sleep(time.Millisecond)
	}
	s.Capture().Flush()
	var out strings.Builder
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out.Write(b)
	}
	return out.String()
}

// The session an operator asked for: the statements that passed, the login that
// sent them, and the listener and protocol that name the file's contents without
// an access log beside it.
func TestACapturedSessionHoldsTheStatementsAndTheLogin(t *testing.T) {
	srv := startFake(t, &fakeServer{})
	s, addr, dir := captureRelay(t, base, "    - {name: db, kinds: [mysql]}\n", srv.addr())
	cl := dial(t, addr, "report", "sales", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("login refused: %s", msg)
	}
	if msg := cl.send(t, wire.ComQuery, "SELECT total FROM invoices"); msg != "" {
		t.Fatalf("the query was refused: %s", msg)
	}
	_ = cl.c.Close()

	out := recorded(t, s, dir, 1)
	for _, want := range []string{
		"SELECT total FROM invoices", // what the client ran
		"kind=mysql", "listener=db",  // which listener wrote it
		"user=report", // and who was logged in
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the capture does not hold %q", want)
		}
	}
}

// The capture an operator reaches for most often is `denied: true`, and a session
// refused by the concurrency bound is the hardest case: it is turned away before
// anything is dialled, so there is no upstream address and no byte of protocol.
// It still has to be written, and writing it must not take the connection's
// goroutine down with it.
func TestARefusedSessionIsCapturedThoughItNeverDialled(t *testing.T) {
	srv := startFake(t, &fakeServer{})
	section := base + "        max_sessions: 1\n"
	s, addr, dir := captureRelay(t, section, "    - {name: refused, kinds: [mysql], denied: true}\n", srv.addr())

	// The first session holds the only slot, and is not captured: the rule wants
	// refusals.
	held := dial(t, addr, "report", "", wire.CapDeprecateEOF)
	if msg := held.ready(t); msg != "" {
		t.Fatalf("the first login was refused: %s", msg)
	}
	// The second is refused at the gate.
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	_ = second.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("the session over the bound was served")
	}

	out := recorded(t, s, dir, 1)
	if !strings.Contains(out, "denied=too_many_sessions") {
		t.Errorf("the capture does not name the refusal:\n%q", lastBytes(out))
	}
	// And the session that was served is not in a file the rule did not ask for.
	if strings.Contains(out, "user=report") {
		t.Error("the capture holds a session the rule did not select")
	}
}

// lastBytes is the tail of a capture file, for a failure message.
func lastBytes(s string) string {
	if len(s) > 512 {
		return s[len(s)-512:]
	}
	return s
}
