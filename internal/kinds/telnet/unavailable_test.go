package telnet_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// What happens when the session cannot be had: the client is banned, the
// equipment is not answering, or the gateway is going down with somebody
// still inside.
//
// None of these is an error the operator of a telnet bastion can be left to
// infer. A banned client must not reach the equipment at all; a target that
// is not answering must be said in words rather than as a socket that closes,
// because the alternative is an engineer who concludes the plant is down; and
// a shutdown must end rather than wait on a session nobody is watching.

// telnetTo is a gateway whose upstream is whatever address it is given,
// including one nothing is listening on.
func telnetTo(t *testing.T, target string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %q}]
`, target))
	return s, s.Addrs()["legacy"]
}

// TestEquipmentThatIsNotAnsweringIsSaidInWords: the engineer is told the
// target is unavailable. A bastion that closed the connection instead would
// have them reporting the plant down.
func TestEquipmentThatIsNotAnsweringIsSaidInWords(t *testing.T) {
	// A port that was bound and released, so nothing is listening on it and
	// nothing else in this suite has it either.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := ln.Addr().String()
	_ = ln.Close()

	_, addr := telnetTo(t, gone)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("nothing was said about the unavailable target: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "unavailable") {
		t.Errorf("the client was told %q", buf[:n])
	}
}

// TestABannedClientNeverReachesTheEquipment: the ladder is ahead of the
// equipment. An address that has been turned away often enough is refused on
// the ban rather than on what it asked for -- and on another listener of the
// same estate, because the ladder is the estate's and not one listener's.
func TestABannedClientNeverReachesTheEquipment(t *testing.T) {
	tg := startTarget(t)
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
    - name: bait
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
        allow_clients: [10.0.0.0/8]
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %s}]
bans:
  action: reject
  state_file: %s
  triggers: [{name: knock, reasons: [telnet_denied], threshold: 1, window: 1m, duration: 1h}]
`, tg.addr(), filepath.Join(t.TempDir(), "bans.state")))

	knock := func(addr string) {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 64)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}
	// Off the list on the second listener: that refusal is what puts the
	// address on the ladder.
	knock(s.Addrs()["bait"])
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().BansActive == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the refusal never reached the ban ladder")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// And now the listener that would have admitted it turns it away.
	knock(s.Addrs()["legacy"])
	deadline = time.Now().Add(10 * time.Second)
	for s.Stats().Refusals["telnet"]["banned"] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the ban was not counted: %v", s.Stats().Refusals["telnet"])
		}
		time.Sleep(5 * time.Millisecond)
	}
	if seen := tg.seen(); len(seen) != 0 {
		t.Errorf("the equipment was dialled anyway: %q", seen)
	}
}

// TestShutdownEndsEvenWithSomebodyInside: a shutdown whose grace is already
// spent closes the sessions it was not given time for instead of waiting on
// an engineer who has gone to lunch.
func TestShutdownEndsEvenWithSomebodyInside(t *testing.T) {
	tg := startTarget(t)
	s, addr := telnetTo(t, tg.addr())
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 256)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("the session never started: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already past
	done := make(chan struct{})
	go func() {
		_ = s.Shutdown(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the shutdown waited on the open session")
	}
	// The session is gone, which is what the closing was for.
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}
