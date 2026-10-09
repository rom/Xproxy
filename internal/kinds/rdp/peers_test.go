package rdp

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rdp"
)

// A peer that is not there, or is there and says nothing an RDP
// implementation would say. The negotiation and the conference
// sequence are the two stretches where this gateway is reading one end
// and writing the other, and a failure in either must end the session
// rather than carry on with half a negotiation -- which on this
// protocol would mean relaying a connection whose security was never
// agreed.

// peer returns a connection whose far end reads everything and answers
// nothing, and a function that drops the far end. Not net.Pipe: that
// is synchronous, so an unread write there blocks for ever instead of
// failing.
func peer(t *testing.T) (ours net.Conn, drop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		done <- c
		_, _ = io.Copy(io.Discard, c)
	}()
	ours, err = net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	far := <-done
	if far == nil {
		t.Fatal("the far end never arrived")
	}
	t.Cleanup(func() { _ = far.Close(); _ = ours.Close() })
	return ours, func() {
		_ = far.Close()
		_ = ours.SetReadDeadline(time.Now().Add(-time.Second))
	}
}

// babble returns a connection whose far end answers everything with
// the same octet. Every read then succeeds and nothing it returns is a
// PDU.
func babble(t *testing.T, fill byte) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		go func() { _, _ = io.Copy(io.Discard, c) }()
		noise := make([]byte, 4096)
		for i := range noise {
			noise[i] = fill
		}
		for {
			if _, err := c.Write(noise); err != nil {
				return
			}
		}
	}()
	ours, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ours.Close() })
	_ = ours.SetDeadline(time.Now().Add(10 * time.Second))
	return ours
}

// negotiating is a session on a listener that offers TLS and the
// legacy protocol and uses TLS towards the desktop.
func negotiating(t *testing.T) *session {
	t.Helper()
	srv := &server{engine: engine(t), cfg: config.Listener{Name: "desks"},
		v: &config.RDPListener{}, devices: map[uint32]bool{}, channels: map[string]bool{},
		upstreamProtocol: rdp.ProtocolSSL,
		upTLS:            &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // the handshake never completes here
	}
	srv.offered = protocolBit(rdp.ProtocolSSL) | protocolBit(rdp.ProtocolRDP)
	return &session{t: srv, ip: netip.MustParseAddr("192.0.2.9"), target: "desk7.lab.test:3389",
		channelName: map[uint16]string{}, inert: map[uint16]bool{}, dynamic: newDynamicState()}
}

func legs() []struct {
	name string
	run  func(*session) string
	toUp bool
} {
	return []struct {
		name string
		run  func(*session) string
		toUp bool
	}{
		{name: "the client's negotiation", run: (*session).clientNegotiate},
		{name: "the desktop's negotiation", run: (*session).upstreamNegotiate, toUp: true},
		{name: "the conference sequence", run: (*session).conference},
	}
}

func TestEveryStretchEndsWhenThePeerIsAlreadyGone(t *testing.T) {
	for _, c := range legs() {
		t.Run(c.name, func(t *testing.T) {
			se := negotiating(t)
			conn, drop := peer(t)
			drop()
			_ = conn.Close()
			// Both legs are the dead one: the conference sequence
			// reads the client and writes the desktop, so either
			// failing has to end it.
			se.client, se.up = conn, conn
			if reason := c.run(se); reason == "" {
				t.Error("the stretch reported success against a peer that is not there")
			}
		})
	}
}

func TestEveryStretchEndsWhenThePeerAnswersNothing(t *testing.T) {
	for _, c := range legs() {
		t.Run(c.name, func(t *testing.T) {
			se := negotiating(t)
			conn, drop := peer(t)
			se.client, se.up = conn, conn
			done := make(chan string, 1)
			go func() { done <- c.run(se) }()
			time.Sleep(20 * time.Millisecond)
			drop()
			select {
			case reason := <-done:
				if reason == "" {
					t.Error("the stretch reported success against a peer that said nothing")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the stretch is still waiting on a peer that has gone")
			}
		})
	}
}

func TestEveryStretchEndsWhenThePeerAnswersNonsense(t *testing.T) {
	for _, fill := range []byte{0x00, 0xff} {
		for _, c := range legs() {
			t.Run(c.name+filler(fill), func(t *testing.T) {
				se := negotiating(t)
				conn := babble(t, fill)
				se.client, se.up = conn, conn
				done := make(chan string, 1)
				go func() { done <- c.run(se) }()
				select {
				case reason := <-done:
					if reason == "" {
						t.Error("the stretch took nonsense for a negotiation")
					}
				case <-time.After(20 * time.Second):
					t.Fatal("the stretch is still reading nonsense")
				}
			})
		}
	}
}

func filler(b byte) string {
	const digits = "0123456789abcdef"
	return ", answered 0x" + string([]byte{digits[b>>4], digits[b&0xf]})
}

// A client asking for a protocol this listener does not offer is told
// which way to come back, rather than being dropped: the failure code
// is what a client acts on.
func TestAClientAskingForAProtocolThisListenerDoesNotOfferIsToldWhich(t *testing.T) {
	// The code depends on whether TLS is on the listener's own list,
	// because that is what tells the client whether coming back with
	// TLS would work. A listener that lists it but has no certificate
	// still cannot complete it.
	for _, c := range []struct {
		name    string
		offered uint32
		ask     uint32
		want    uint32
	}{
		{
			name:    "a listener that lists TLS but has no certificate",
			offered: protocolBit(rdp.ProtocolSSL), ask: rdp.ProtocolHybrid,
			want: rdp.FailSSLRequiredByServer,
		},
		{
			name:    "and one that does not list it at all",
			offered: 0, ask: rdp.ProtocolHybrid,
			want: rdp.FailSSLNotAllowedByServer,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			se := negotiating(t)
			se.t.offered = c.offered
			client, far := net.Pipe()
			se.client = client
			req, err := rdp.ConnectionRequest{HasNegotiation: true, Protocols: c.ask}.Encode()
			if err != nil {
				t.Fatal(err)
			}
			answer := make(chan []byte, 1)
			go func() {
				if _, werr := far.Write(req); werr != nil {
					answer <- nil
					return
				}
				buf := make([]byte, 64)
				n, _ := far.Read(buf)
				answer <- buf[:n]
			}()
			if reason := se.clientNegotiate(); reason != "no_protocol" {
				t.Fatalf("an unofferable protocol ended %q, want no_protocol", reason)
			}
			select {
			case got := <-answer:
				pdu, err := rdp.ReadPDU(bytes.NewReader(got))
				if err != nil {
					t.Fatalf("the refusal was not a PDU: %v", err)
				}
				cc, err := rdp.ParseConnectionConfirm(pdu.Body)
				if err != nil {
					t.Fatalf("the refusal was not a connection confirm: %v", err)
				}
				if cc.Failure != c.want {
					t.Errorf("the client was told %#x, want %#x", cc.Failure, c.want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the client was never answered")
			}
			_ = far.Close()
		})
	}
}
