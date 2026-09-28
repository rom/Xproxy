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
	// The UDP side of a port whose TCP side is free.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	err = start(t, "127.0.0.1:"+port)
	if err == nil {
		t.Fatal("the listener came up on a port its datagram socket could not have")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("the failure was reported as %v", err)
	}
	// Nothing was left half-bound behind the failure: the datagram port
	// is still the socket above's, and the accept socket is closed.
	if extra, err := net.ListenPacket("udp", "127.0.0.1:"+port); err == nil {
		_ = extra.Close()
		t.Error("the datagram port came free, so the engine had taken it")
	}
	// The accept socket is free again. Bounded rather than immediate,
	// because the port is an ephemeral one and this suite runs packages in
	// parallel: another test taking it for a moment is indistinguishable
	// from a leak in one attempt, and it happens. A socket this process
	// leaked is held for the life of the process, so it fails every
	// attempt and the test still says so.
	//
	// The bound is generous for that reason. It was two seconds and a full
	// run of the suite exceeded it -- a sibling package had the port for
	// longer than that -- which failed a test about a leak on a machine that
	// had none. Half a minute costs nothing in the passing case, where the
	// first attempt succeeds, and a real leak still fails every one of them.
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err == nil {
			_ = ln.Close()
			break
		}
		last = err
		if time.Now().After(deadline) {
			t.Errorf("the accept socket was left behind: %v", last)
			break
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
