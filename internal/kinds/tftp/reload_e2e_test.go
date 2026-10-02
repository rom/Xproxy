package tftp

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// A reload of a datagram listener, which until the sockets were handed from
// one generation to the next could not happen at all.
//
// A UDP socket cannot be bound twice, so a rebuilt listener that opened its
// own failed with "address already in use" -- about a port this process was
// itself holding -- and the reload failed with it. Every datagram kind was in
// that position: tftp, ntp, dhcp, dhcpv6, bacnet, coap, and the datagram side
// of syslog and snmp. The three the engine knew bound UDP were refused up
// front with "restart required" instead, which is the same hole with a better
// error.
//
// So this is the test that the hole is closed: the policy changes, the reload
// succeeds, the address does not move, what was allowed before is still
// allowed, and what the new policy allows is allowed now.
func TestADatagramListenerReloadsOnItsOwnSocket(t *testing.T) {
	file := content(600)
	srv := startFileServer(t, &fileServer{file: file})
	readOnly := "        upstream: servers\n        default_action: allow\n        operations: [read]\n"
	both := "        upstream: servers\n        default_action: allow\n        operations: [read, write]\n"
	s, addr := tftpRelay(t, readOnly, srv.addr())

	// A read is this listener's business and a write is not.
	if got, errp := dial(t, addr).read("boot.img"); errp != nil || !bytes.Equal(got, file) {
		t.Fatalf("a read before the reload: %d bytes, err %v", len(got), errp)
	}
	if errp := dial(t, addr).write("new.img", content(64)); errp == nil {
		t.Fatal("a write was relayed under operations: [read]")
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf(tftpYAML, both, "", srv.addr())))
	if err != nil {
		t.Fatal(err)
	}
	// The listener keeps its name and the address its file gives, which is
	// how an operator's edit arrives: the policy changed and nothing else.
	if err := s.Reload(cfg); err != nil {
		t.Fatalf("reload of a tftp listener: %v", err)
	}
	if got := s.Addrs()["boot"]; got != addr {
		t.Fatalf("the socket moved: %s -> %s", addr, got)
	}

	// The same socket, the new policy: the read still works and the write
	// is now the listener's business.
	if got, errp := dial(t, addr).read("boot.img"); errp != nil || !bytes.Equal(got, file) {
		t.Fatalf("a read after the reload: %d bytes, err %v", len(got), errp)
	}
	before := len(srv.seen())
	if errp := dial(t, addr).write("new.img", content(64)); errp != nil {
		t.Fatalf("a write under operations: [read, write]: %v", errp)
	}
	got := srv.seen()
	if len(got) <= before || got[len(got)-1].Filename != "new.img" {
		t.Fatalf("the server saw %+v, want the write at the end", got)
	}
	if st := s.Stats(); st.Reloads != 1 || st.ReloadFailures != 0 {
		t.Fatalf("reload counters: %+v", st)
	}
}
