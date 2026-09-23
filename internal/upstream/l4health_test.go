package upstream

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// waitHealthy waits for an endpoint to reach a state, or says what it
// was instead. Probes run on their own goroutine on their own interval,
// so this is the only honest way to assert on one.
func waitHealthy(t *testing.T, e *Endpoint, want bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.Healthy() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: healthy=%v, want %v", what, e.Healthy(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func l4HealthCheck(kind string) *config.HealthCheck {
	return &config.HealthCheck{Type: kind, Path: config.DefaultHealthCheckPath,
		Interval: config.Duration(50 * time.Millisecond), Timeout: config.Duration(30 * time.Millisecond),
		HealthyThreshold: 1, UnhealthyThreshold: 1, MaxConcurrent: 4}
}

// A tcp check proves something accepted and nothing more, which is the
// honest limit of a probe for a protocol the proxy does not speak. The
// endpoint goes unhealthy when the listener closes.
func TestTCPConnectProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	c := testCfg("round_robin", ln.Addr().String())
	c.HealthCheck = l4HealthCheck("tcp")
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	e := p.endpoints()[0]
	waitHealthy(t, e, true, "a listening port")
	_ = ln.Close()
	waitHealthy(t, e, false, "a closed port")
}

// A udp check has to prove more than a tcp one, because a UDP socket
// accepts nothing: a datagram to a dead port may produce an ICMP
// unreachable the sender is never told about, may be filtered on the
// path, and says nothing about a process that is bound but wedged. So
// the probe asks a question and silence is the failure.
func TestUDPProbeNeedsAnAnswer(t *testing.T) {
	var answer atomic.Pointer[string]
	set := func(s string) { answer.Store(&s) }
	set("PONG v1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) != "PING" { // the probe's own question
				continue
			}
			if a := *answer.Load(); a != "" {
				_, _ = pc.WriteTo([]byte(a), addr)
			}
		}
	}()
	c := testCfg("round_robin", pc.LocalAddr().String())
	hc := l4HealthCheck("udp")
	hc.Send = "PING"
	hc.Expect = "PONG"
	c.HealthCheck = hc
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	e := p.endpoints()[0]
	waitHealthy(t, e, true, "an answering service")
	// A bound but wedged service: the socket is still open, so nothing
	// at the network layer has changed, and the check must still notice.
	set("")
	waitHealthy(t, e, false, "a service that stopped answering")
	// An answer that is not the expected one is no better than silence.
	set("ERROR: starting up")
	time.Sleep(200 * time.Millisecond)
	if e.Healthy() {
		t.Fatal("an answer without the expected text was accepted")
	}
	set("PONG v2")
	waitHealthy(t, e, true, "the expected answer again")
}

// A hex probe and a hex expectation, for the services whose smallest
// question is not text. The payload here is the shape of a DNS query
// header rather than a string.
func TestUDPProbeInHex(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			// Answer with the same transaction id and the response bit.
			_, _ = pc.WriteTo([]byte{buf[0], buf[1], 0x81, 0x80}, addr)
		}
	}()
	c := testCfg("round_robin", pc.LocalAddr().String())
	hc := l4HealthCheck("udp")
	hc.SendHex = "abcd0100000100000000000000"
	hc.ExpectHex = "abcd8180"
	c.HealthCheck = hc
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	waitHealthy(t, p.endpoints()[0], true, "a hex probe answered in hex")
}

// Any answer at all is accepted where nothing is expected of it, which
// is still much more than silence proves.
func TestUDPProbeWithNoExpectation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte("anything at all"), addr)
		}
	}()
	c := testCfg("round_robin", pc.LocalAddr().String())
	hc := l4HealthCheck("udp")
	hc.Send = "?"
	c.HealthCheck = hc
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	waitHealthy(t, p.endpoints()[0], true, "any answer")
}

// A port nobody is bound to is unhealthy. It is the case a connect probe
// would be enough for and a UDP one has to work for anyway.
func TestUDPProbeOnADeadPort(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:1")
	hc := l4HealthCheck("udp")
	hc.Send = "PING"
	c.HealthCheck = hc
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	waitHealthy(t, p.endpoints()[0], false, "a port with nothing bound")
}
