package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// This listener is the one that needs the same port on both transports:
// RFC 1035 §4.2 puts DNS on 53 over UDP and over TCP, and a resolver that
// answered on one of them would work until an answer did not fit.
//
// So the engine opens the datagram socket on the port the accept socket
// was given, and on a listener configured with port 0 that port is the
// kernel's choice from the TCP side alone -- it can be a port something
// else holds on the UDP side, and there is no way to ask for one free in
// both. A listener whose port the file left open is then bound again
// somewhere else, which is what this pair of tests is about: the port the
// file *does* name is never moved, and a port 0 listener comes up.
//
// What is not here is the collision itself. It needs the kernel to hand
// out one particular port out of thousands while the test holds it on the
// other transport, and there is no way to ask for that; the retry's own
// decision is tested in internal/proxy, where every branch of it is
// driven directly.

// A port the file names whose datagram side is taken fails, with the
// reason it failed and nothing left bound behind it. The listener is
// never quietly moved somewhere else: it would then answer nothing on the
// port the clients are configured with. (That the retry does not even
// consider a port the file names is asserted in internal/proxy, where the
// decision is driven directly; here it could not be told apart from
// eight attempts at the same port.)
func TestAPortWhoseDatagramSideIsTakenIsReported(t *testing.T) {
	// Run the whole scenario on a fresh port until one attempt can be checked
	// without a sibling in the way.
	//
	// The check that matters -- nothing was left bound behind the failure --
	// can only be made by binding the port again, and the port is an ephemeral
	// one while this suite runs its packages in parallel. So a failed re-bind
	// means either the engine leaked the socket or another test in another
	// package happens to hold that port, and those two are indistinguishable
	// in one attempt. They are not indistinguishable across three: a leaked
	// socket is held for the life of this process, so an engine that leaks
	// fails every attempt, while a coincidence on one particular ephemeral
	// port out of three is not something to build a test failure on.
	//
	// This was a timeout before, first of two seconds and then of thirty, and a
	// full run of the suite exceeded both -- failing a test about a leak on a
	// machine that had none. Waiting longer was never going to be the answer,
	// because how long a sibling holds a port is not this test's to bound.
	const attempts = 3
	var last error
	for i := range attempts {
		leaked, err := datagramSideTaken(t)
		if err != nil {
			t.Fatal(err)
		}
		if !leaked {
			return
		}
		last = fmt.Errorf("attempt %d: the accept socket was not free again", i+1)
	}
	t.Errorf("the accept socket was left behind on %d ports in a row, so the engine "+
		"kept it: %v", attempts, last)
}

// datagramSideTaken runs the scenario once: hold a port on UDP, ask the engine
// to listen on it, and say whether the accept socket was still taken
// afterwards. Every assertion that does not depend on an ephemeral port is made
// here, once per attempt.
func datagramSideTaken(t *testing.T) (bool, error) {
	t.Helper()
	// The UDP side of a port whose TCP side is free.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false, err
	}
	defer func() { _ = pc.Close() }()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		return false, err
	}
	err = start(t, "127.0.0.1:"+port)
	if err == nil {
		t.Fatal("the listener came up on a port its datagram socket could not have")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("the failure was reported as %v", err)
	}
	// Nothing was left half-bound behind the failure: the datagram port is
	// still the socket above's. This one does not race -- the port is held by
	// this test for the whole attempt, so anything else holding it would be the
	// engine.
	if extra, err := net.ListenPacket("udp", "127.0.0.1:"+port); err == nil {
		_ = extra.Close()
		t.Error("the datagram port came free, so the engine had taken it")
	}
	// And the accept socket. A moment's grace for the kernel to finish the
	// close the engine has already asked for, then the answer.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err == nil {
			_ = ln.Close()
			return false, nil
		}
		if time.Now().After(deadline) {
			return true, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// And a listener that left the port to the kernel comes up with both
// sockets on one port.
func TestAPortZeroListenerGetsBothSockets(t *testing.T) {
	if err := start(t, "127.0.0.1:0"); err != nil {
		t.Fatalf("the listener did not come up: %v", err)
	}
}

// start runs one dns listener at an address and shuts it down again,
// returning what came up or the failure that stopped it.
func start(t *testing.T, address string) error {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: resolver
      address: "%s"
      kind: dns
      dns:
        upstreams: ["127.0.0.1:53"]
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - {name: r, upstream: app}
`, address)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	return nil
}
