package proxy

import (
	"net"
	"os"
	"strconv"
	"testing"
)

// TestSameAddress: the reload matches a listener to its socket by
// address, so the wildcard forms of one port have to compare equal --
// a listener renamed from ":8080" to "[::]:8080" must keep its socket
// rather than rebind a port it still holds.
func TestSameAddress(t *testing.T) {
	same := [][2]string{
		{"127.0.0.1:8080", "127.0.0.1:8080"},
		{":8080", "0.0.0.0:8080"},
		{"0.0.0.0:8080", "[::]:8080"},
		{":8080", "[::]:8080"},
	}
	for _, p := range same {
		if !sameAddress(p[0], p[1]) || !sameAddress(p[1], p[0]) {
			t.Errorf("%q and %q were not the same address", p[0], p[1])
		}
	}
	differ := [][2]string{
		{"127.0.0.1:8080", "127.0.0.1:8081"},
		{"127.0.0.1:8080", "127.0.0.2:8080"},
		{"127.0.0.1:8080", "[::1]:8080"},
		{":8080", "127.0.0.1:8080"},
		{"not an address", "127.0.0.1:8080"},
		{"127.0.0.1:8080", ""},
		{"", ""},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, p := range differ {
		if sameAddress(p[0], p[1]) {
			t.Errorf("%q and %q were treated as the same address", p[0], p[1])
		}
	}
}

func TestActivatedListenersRefusesBadEnvironment(t *testing.T) {
	// Without the variables there is no activation and no error: the
	// proxy binds its own sockets.
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	a, err := activatedListeners()
	if err != nil || len(a.streams) != 0 || len(a.packets) != 0 {
		t.Fatalf("an unactivated process got %v, %v", a, err)
	}
	// A set meant for another process is ignored: inheriting a stranger's
	// descriptors would serve traffic on sockets nobody meant for us.
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
	t.Setenv("LISTEN_FDS", "2")
	if a, err := activatedListeners(); err != nil || len(a.streams) != 0 {
		t.Errorf("another process's set gave %v, %v", a, err)
	}
	t.Setenv("LISTEN_PID", "not-a-pid")
	if a, err := activatedListeners(); err != nil || len(a.streams) != 0 {
		t.Errorf("an unparseable pid gave %v, %v", a, err)
	}
	// A count that is not a number, negative, or larger than any
	// plausible unit is an error rather than a loop over stray
	// descriptors.
	// Each call that gets as far as reading the count also consumes the
	// variables, so they are set again for every case.
	for _, n := range []string{"many", "-1", "1025", "99999999999999999999"} {
		t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		t.Setenv("LISTEN_FDS", n)
		if _, err := activatedListeners(); err == nil {
			t.Errorf("LISTEN_FDS=%q was accepted", n)
		}
	}
	// A valid set consumes the variables so a child process does not
	// inherit them and try to adopt the same descriptors.
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "0")
	if _, err := activatedListeners(); err != nil {
		t.Fatalf("an empty set: %v", err)
	}
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" {
		t.Error("the activation variables were left in the environment")
	}
}

func TestListenerForPrefersActivatedSockets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Named sockets are matched by name and consumed, so a second
	// listener of the same name binds its own rather than sharing one.
	a := &activated{streams: map[string]net.Listener{"main": ln}, packets: map[string]net.PacketConn{"main-udp": pc}}
	got, adopted, err := listenerFor(a, "main", "127.0.0.1:0", 0)
	if err != nil || !adopted || got != ln {
		t.Fatalf("named listener = %v, %v, %v", got, adopted, err)
	}
	if len(a.streams) != 0 {
		t.Error("the activated listener was not consumed")
	}
	gotPC, act, err := packetFor(a, "main", "127.0.0.1:0")
	if err != nil || !act || gotPC != pc {
		t.Fatalf("named packet socket = %v, %v, %v", gotPC, act, err)
	}
	if len(a.packets) != 0 {
		t.Error("the activated packet socket was not consumed")
	}

	// A socket named by its address is matched by address, and a wildcard
	// bind is the same address as an explicit one on the same port.
	addr := ln.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	a2 := &activated{streams: map[string]net.Listener{"[::]:" + port: ln}, packets: map[string]net.PacketConn{"0.0.0.0:" + port: pc}}
	if got, act, err := listenerFor(a2, "other", ":"+port, 0); err != nil || !act || got != ln {
		t.Errorf("address match = %v, %v, %v", got, act, err)
	}
	if got, act, err := packetFor(a2, "other", "0.0.0.0:"+port); err != nil || !act || got != pc {
		t.Errorf("packet address match = %v, %v, %v", got, act, err)
	}

	// Nothing to adopt: a socket is bound, and the caller is told it is
	// not an activated one so it closes it on shutdown.
	empty := &activated{streams: map[string]net.Listener{}, packets: map[string]net.PacketConn{}}
	fresh, act, err := listenerFor(empty, "main", "127.0.0.1:0", 0)
	if err != nil || act {
		t.Fatalf("a fresh listener = %v, %v", act, err)
	}
	_ = fresh.Close()
	freshPC, act, err := packetFor(empty, "main", "127.0.0.1:0")
	if err != nil || act {
		t.Fatalf("a fresh packet socket = %v, %v", act, err)
	}
	_ = freshPC.Close()
	// An address nothing can bind is an error, not a silent no-listener.
	if _, _, err := listenerFor(empty, "main", "203.0.113.200:80", 0); err == nil {
		t.Error("an unbindable address was accepted")
	}
	if _, _, err := packetFor(empty, "main", "203.0.113.200:80"); err == nil {
		t.Error("an unbindable datagram address was accepted")
	}
}
