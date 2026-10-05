package tcp_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// A session in the middle of being relayed, while its listener is rebuilt.
//
// This is the claim a hot reload makes, on the kind where it is easiest to
// break: the listener's settings change, so the listener is rebuilt, and the
// connection that was already open goes on relaying in both directions as
// though nothing had happened. It works because the accept socket belongs to
// the engine rather than to a generation -- the new generation opens a front on
// the same socket, and the old one keeps serving what it had accepted until it
// ends.
//
// A connection opened after the switch is the new generation's, which the byte
// bound here makes visible: the old listener had no bound and the new one
// refuses past 4 KiB, so the two connections are told different things by the
// same port at the same moment.
func TestASessionSurvivesItsListenerBeingRebuilt(t *testing.T) {
	ln := sinkEcho(t) // echoes, so both directions are testable
	tpl := `
version: 1
server:
  shutdown_timeout: 30s
  listeners:
    - name: l4
      address: %q
      kind: tcp
      tcp:
        default: backend
        idle_timeout: 30s
%s
logging: {access: {enabled: false}}
upstreams:
  - name: backend
    endpoints: [{address: %s}]
`
	s, addr := boundedRelay(t, ln.Addr().String(), "        idle_timeout: 30s")

	// A session, and one round trip through it before the reload.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	roundTrip := func(what string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.WriteString(c, what); err != nil {
			t.Fatalf("writing %q: %v", what, err)
		}
		got := make([]byte, len(what))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("reading the echo of %q: %v", what, err)
		}
		if string(got) != what {
			t.Fatalf("echo = %q, want %q", got, what)
		}
	}
	roundTrip("before-the-reload")

	// The address stays as the file writes it: a reload matches a listener
	// by what its configuration says, and "the same listener" is the one
	// whose name and address did not change.
	cfg, err := config.Parse([]byte(fmt.Sprintf(tpl, "127.0.0.1:0",
		"        max_bytes_in: 4096", ln.Addr().String())))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := s.Addrs()["l4"]; got != addr {
		t.Fatalf("the socket moved: %s -> %s", addr, got)
	}

	// The session that was open before the switch is still relaying.
	roundTrip("after-the-reload")

	// A connection opened after the switch is served too, on the same
	// port, by the generation that now holds the front.
	fresh, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("a connection after the reload: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	_ = fresh.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(fresh, "the new generation"); err != nil {
		t.Fatalf("writing on a new connection: %v", err)
	}
	got := make([]byte, len("the new generation"))
	if _, err := io.ReadFull(fresh, got); err != nil {
		t.Fatalf("the new connection did not relay: %v", err)
	}

	// And the session from before the switch is still relaying, which is
	// the whole claim: a reload rebuilt this listener and the connection
	// it had accepted never noticed.
	roundTrip(strings.Repeat("z", 8192))
	if st := s.Stats(); st.Reloads != 1 || st.ReloadFailures != 0 {
		t.Fatalf("reload counters: %+v", st)
	}
}
