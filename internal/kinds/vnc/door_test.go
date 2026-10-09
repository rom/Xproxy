package vnc_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/rfb"
)

// The two bounds that end a session without anything on the wire being
// wrong: the ban a refusal earned, applied before the next connection
// is read at all, and the session bound an operator set.

// A refusal is observed by the ban ladder, and the ban is applied at
// the door: the next connection from that address is dropped without
// a version being offered, which is the point of a ban rather than a
// refusal -- the second attempt costs the gateway nothing.
func TestARefusalEarnsABanAndTheBanIsAppliedAtTheDoor(t *testing.T) {
	tg := startTarget(t, &target{})
	s, addr := gatewayWithTop(t, tg, "        security_types: [none]", `bans:
  action: reject
  triggers: [{name: desktops, reasons: [vnc_denied], threshold: 1, window: 1m, duration: 1h}]`)

	// A client that picks a type it was not offered is refused, and
	// that refusal is what the ladder hears.
	first := dial(t, addr)
	first.version(rfb.V38)
	first.offered()
	first.write([]byte{rfb.SecVNCAuth})
	if ok, _ := first.result(); ok {
		t.Fatal("a type that was not offered was accepted")
	}
	waitFor(t, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["vnc"]["security_not_offered"] > 0 ||
			s.Stats().VNCRefused > 0
	})

	// The next connection from the same address gets nothing: no
	// version, no list, no reply.
	again, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	_ = again.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := io.ReadFull(again, make([]byte, 12)); err == nil {
		t.Errorf("a banned address was offered a version: %d octets", n)
	}
	if n := s.Stats().VNCRejected; n == 0 {
		t.Error("the banned connection was not counted as rejected")
	}
}

// A session bound ends a session that is otherwise behaving: an
// operator who set one is saying how long a desktop may be held, and a
// bound that only applied to idle sessions would not say that.
func TestTheSessionBoundEndsASessionThatIsStillRunning(t *testing.T) {
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [none]\n        session_timeout: 1s")
	cl := dial(t, addr)
	if si := cl.open(true); si.Name == "" {
		t.Fatal("the session never opened")
	}
	// The stream is running, so nothing here is idle; what ends it is
	// the bound.
	_ = cl.c.SetReadDeadline(time.Now().Add(20 * time.Second))
	start := time.Now()
	if _, err := io.Copy(io.Discard, cl.c); err != nil {
		t.Fatalf("the session ended with %v rather than being closed", err)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("the session bound took %s to end the session", took)
	}
}
