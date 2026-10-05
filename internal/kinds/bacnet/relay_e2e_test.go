package bacnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// device is a fake building controller. What it records is the assertion
// that matters on a security relay: not what the client was told, but what
// reached the plant.
type device struct {
	pc net.PacketConn

	mu  sync.Mutex
	got [][]byte
	// answers, when set, replaces the reply the device would send.
	answers func(raw []byte) []byte
	// extra is how many unsolicited I-Am datagrams the device sends back
	// for each message it receives, which is what a discovery broadcast
	// does to an estate.
	extra int
	// mute answers nothing: a device that is reachable and not talking.
	mute bool
}

func startDevice(t *testing.T, d *device) *device {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go d.serve()
	return d
}

func (d *device) addr() string { return d.pc.LocalAddr().String() }

func (d *device) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := d.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		d.mu.Lock()
		d.got = append(d.got, raw)
		answers, extra, mute := d.answers, d.extra, d.mute
		d.mu.Unlock()
		if mute {
			continue
		}
		if answers != nil {
			if out := answers(raw); out != nil {
				_, _ = d.pc.WriteTo(out, from)
			}
			continue
		}
		if out := d.reply(raw); out != nil {
			_, _ = d.pc.WriteTo(out, from)
		}
		for i := 0; i < extra; i++ {
			_, _ = d.pc.WriteTo(iAm(uint32(9+i)), from)
		}
	}
}

// reply answers a confirmed request the way a device does: a simple
// acknowledgement for a write, a complex one carrying a value for a read.
func (d *device) reply(raw []byte) []byte {
	v, err := wire.ParseBVLC(raw)
	if err != nil || !v.Function.CarriesNPDU() {
		return nil
	}
	n, err := wire.ParseNPDU(v.Payload)
	if err != nil || n.NetworkMessage {
		return nil
	}
	a, err := wire.ParseAPDU(n.APDU)
	if err != nil || a.Type != wire.PDUConfirmedRequest {
		return nil
	}
	if a.Service.Writes() {
		return bvlcWrap(wire.FuncOriginalUnicast, []byte{0x01, 0x00, 0x20, a.InvokeID, a.Service.Choice})
	}
	// A complex acknowledgement with a real value: object, property, then a
	// constructed value holding one real number.
	body := []byte{0x01, 0x00, 0x30, a.InvokeID, a.Service.Choice}
	body = append(body, 0x0C, 0x00, 0x00, 0x00, 0x0C) // context 0: the object
	body = append(body, 0x19, 0x55)                   // context 1: present-value
	body = append(body, 0x3E, 0x44, 0x41, 0xA8, 0x00, 0x00, 0x3F)
	return bvlcWrap(wire.FuncOriginalUnicast, body)
}

func (d *device) seen() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.got))
	copy(out, d.got)
	return out
}

// parsed reads what the device received, which is what a test asserts
// against.
func (d *device) parsed(t *testing.T) []wire.APDU {
	t.Helper()
	raws := d.seen()
	out := make([]wire.APDU, 0, len(raws))
	for _, raw := range raws {
		v, err := wire.ParseBVLC(raw)
		if err != nil || !v.Function.CarriesNPDU() {
			continue
		}
		n, err := wire.ParseNPDU(v.Payload)
		if err != nil || n.NetworkMessage {
			continue
		}
		a, err := wire.ParseAPDU(n.APDU)
		if err != nil {
			// A relay that forwarded something a device cannot parse is a
			// relay that has broken the message it was inspecting.
			t.Fatalf("the device received a message it could not parse: %v", err)
		}
		out = append(out, a)
	}
	return out
}

// waitFor waits until the device has seen n messages, so a test does not
// race the relay's own goroutines.
func (d *device) waitFor(t *testing.T, n int, what string) [][]byte {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if got := d.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the device saw %d messages, want %d", what, len(d.seen()), n)
	return nil
}

// nothingReached fails if the device received anything at all. This is the
// assertion a refusal test needs: a relay that refuses the client and
// forwards the request anyway has refused nothing.
//
// It waits for the relay to count the refusal before it looks rather than
// sleeping for a fixed time first. An absence asserted after a sleep is an
// absence asserted wherever that sleep happened to land in the relay's work,
// and on a loaded machine it can land before the relay has read the datagram
// at all -- so the test would pass whether the message was refused or
// forwarded, which is a test that cannot fail. Every path that returns
// without forwarding counts its reason first, so once the count has moved the
// decision is made and the empty device is the real answer.
func (d *device) nothingReached(t *testing.T, s *proxy.Server) {
	t.Helper()
	refused := func() uint64 {
		var n uint64
		for _, c := range s.Stats().Refusals["bacnet"] {
			n += c
		}
		return n
	}
	for deadline := time.Now().Add(3 * time.Second); refused() == 0; {
		if time.Now().After(deadline) {
			t.Fatalf("the relay counted no refusal: %v", s.Stats().Refusals["bacnet"])
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := d.seen(); len(got) != 0 {
		t.Fatalf("%d messages reached the device through a refusal", len(got))
	}
}

// waitRefusal waits for one named refusal reason to be counted. It is the
// positive half of an absence: a test that wants to say "and this did not go
// through" waits for the refusal that stopped it and then looks, rather than
// looking after a fixed wait and hoping the relay was finished.
func waitRefusal(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; {
		if s.Stats().Refusals["bacnet"][reason] > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay counted no %s refusal: %v", reason, s.Stats().Refusals["bacnet"])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func bvlcWrap(fn wire.Function, payload []byte) []byte {
	out := append([]byte{0x81, byte(fn), 0, 0}, payload...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// iAm is a device announcing itself, which is what a Who-Is is answered
// with -- by every device that heard it.
func iAm(instance uint32) []byte {
	body := []byte{0x01, 0x00, 0x10, wire.IAm}
	body = append(body, 0xC4)
	body = append(body, (wire.ObjectID{Type: wire.DeviceObject, Instance: instance}).Encode()...)
	body = append(body, 0x22, 0x05, 0xC4, 0x91, 0x00, 0x21, 0x0F)
	return bvlcWrap(wire.FuncOriginalUnicast, body)
}

// The client side: a workstation that sends a datagram and reads whatever
// comes back, or nothing.
type client struct{ c net.Conn }

func dialClient(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{c: c}
}

func (cl *client) send(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := cl.c.Write(raw); err != nil {
		t.Fatal(err)
	}
}

// answer reads one reply, or reports that none came. A refusal that is a
// rejection and a refusal that is silence are different things to a client,
// so a test has to be able to tell them apart.
func (cl *client) answer(t *testing.T, within time.Duration) (wire.APDU, bool) {
	t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 4096)
	n, err := cl.c.Read(buf)
	if err != nil {
		return wire.APDU{}, false
	}
	v, err := wire.ParseBVLC(buf[:n])
	if err != nil {
		t.Fatalf("the relay sent a client something that is not a message: %v", err)
	}
	np, err := wire.ParseNPDU(v.Payload)
	if err != nil {
		t.Fatalf("the relay sent a client a broken network header: %v", err)
	}
	a, err := wire.ParseAPDU(np.APDU)
	if err != nil {
		t.Fatalf("the relay sent a client a broken application message: %v", err)
	}
	return a, true
}

// countAnswers reads until nothing more comes, which is how the
// amplification bound is measured.
func (cl *client) countAnswers(t *testing.T, within time.Duration) int {
	t.Helper()
	n := 0
	for deadline := time.Now().Add(within); time.Now().Before(deadline); {
		_ = cl.c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 4096)
		if _, err := cl.c.Read(buf); err != nil {
			break
		}
		n++
	}
	return n
}

const bacnetYAML = `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: bacnet
      bacnet:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: devices, endpoints: [{address: %q}]}
`

func bacnetServer(t *testing.T, section, deviceAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(bacnetYAML, section, deviceAddr))
	return s, proxytest.Addr(t, s, "plant")
}

// base is a listener that carries reads and refuses everything else, which
// is what an unconfigured one does.
const base = `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow`

// A read goes through, and the answer comes back to the client that asked.
func TestAReadReachesTheDeviceAndTheAnswerComesBack(t *testing.T) {
	d := startDevice(t, &device{})
	_, addr := bacnetServer(t, base, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, readReq(1, wire.ObjectID{Type: wire.AnalogInput, Instance: 12}, wire.PropPresentValue))
	d.waitFor(t, 1, "a read")
	got := d.parsed(t)
	if len(got) != 1 || got[0].Service.Name() != "readProperty" {
		t.Fatalf("the device saw %+v", got)
	}
	a, ok := cl.answer(t, 3*time.Second)
	if !ok {
		t.Fatal("no answer came back")
	}
	if a.Type != wire.PDUComplexACK {
		t.Fatalf("the client got a %s", a.Type)
	}
	// The identifier the client used is the one it gets back, whatever the
	// relay used towards the device.
	if a.InvokeID != 1 {
		t.Fatalf("the answer carries invoke identifier %d, and the client used 1", a.InvokeID)
	}
}

// Two clients using the same invoke identifier towards the same device must
// each get their own answer. Without the translation they are
// indistinguishable on the way back, and one client's answer is delivered
// to the other -- which on a building means a workstation being told a
// value it did not ask for.
func TestTwoClientsWithTheSameInvokeIdentifierEachGetTheirOwnAnswer(t *testing.T) {
	var held [][]byte
	var mu sync.Mutex
	d := startDevice(t, &device{})
	d.mu.Lock()
	d.answers = func(raw []byte) []byte {
		// Hold the first request and answer both at once, so the two are
		// certainly outstanding together.
		mu.Lock()
		held = append(held, raw)
		n := len(held)
		mu.Unlock()
		if n < 2 {
			return nil
		}
		return d.reply(raw)
	}
	d.mu.Unlock()
	_, addr := bacnetServer(t, base, d.addr())
	one, two := dialClient(t, addr), dialClient(t, addr)
	one.send(t, readReq(7, wire.ObjectID{Type: wire.AnalogInput, Instance: 1}, wire.PropPresentValue))
	two.send(t, readReq(7, wire.ObjectID{Type: wire.AnalogInput, Instance: 2}, wire.PropPresentValue))
	raws := d.waitFor(t, 2, "two reads")
	// The relay must have given the device two different identifiers, or
	// there is nothing to translate back.
	ids := map[uint8]bool{}
	for _, raw := range raws {
		v, _ := wire.ParseBVLC(raw)
		n, _ := wire.ParseNPDU(v.Payload)
		a, err := wire.ParseAPDU(n.APDU)
		if err != nil {
			t.Fatal(err)
		}
		ids[a.InvokeID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("the device saw invoke identifiers %v: two clients were not separated", ids)
	}
	// The second client's answer is the one the device sends, and it has to
	// carry the identifier that client used.
	a, ok := two.answer(t, 3*time.Second)
	if !ok {
		t.Fatal("the second client got no answer")
	}
	if a.InvokeID != 7 {
		t.Fatalf("the answer carries %d, and the client used 7", a.InvokeID)
	}
}

// A write is refused by default. This is the whole point of the listener:
// an unconfigured relay in front of a building carries reads and does not
// carry changes.
func TestAWriteIsRefusedByTheDefaultServiceList(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, writeReq(1, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 0))
	if a, ok := cl.answer(t, 2*time.Second); !ok {
		t.Fatal("a refused client was told nothing: a reject was expected")
	} else if a.Type != wire.PDUReject {
		t.Fatalf("the client got a %s, want a reject", a.Type)
	}
	d.nothingReached(t, s)
}

// And a write the configuration allows does reach the plant, because a
// relay that refused everything would not be deployable.
func TestAnAllowedWriteReachesThePlant(t *testing.T) {
	d := startDevice(t, &device{})
	_, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [readProperty, writeProperty]
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, writeReq(1, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 10))
	d.waitFor(t, 1, "a write")
	if got := d.parsed(t); len(got) != 1 || got[0].Service.Name() != "writeProperty" {
		t.Fatalf("the device saw %+v", got)
	}
	if a, ok := cl.answer(t, 3*time.Second); !ok || a.Type != wire.PDUSimpleACK {
		t.Fatalf("the write was not acknowledged: %v %v", a.Type, ok)
	}
}

// The priority ladder. A write at priority 1 takes a piece of plant away
// from the management system, the schedules and the operator, and holds it
// until whoever wrote it relinquishes it.
func TestAWriteAtLifeSafetyPriorityIsRefused(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [writeProperty]
        max_command_priority: 8
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, writeReq(1, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 1))
	if a, ok := cl.answer(t, 2*time.Second); !ok || a.Type != wire.PDUReject {
		t.Fatalf("a write at priority 1 was not rejected: %v %v", a.Type, ok)
	}
	d.nothingReached(t, s)
}

// A write at a priority the bound allows goes through, so the bound is a
// bound and not a ban.
func TestAWriteAtAnOrdinaryPriorityIsCarried(t *testing.T) {
	d := startDevice(t, &device{})
	_, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [writeProperty]
        max_command_priority: 8
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, writeReq(1, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 10))
	d.waitFor(t, 1, "a write at priority 10")
}

// out-of-service is how a sensor is made to lie: the point is cut loose
// from the physical world and every graphics page in the estate then
// reports whatever was written as the truth.
func TestAWriteToOutOfServiceIsRefused(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [writeProperty]
        objects: [analog-input]
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, writeReq(1, wire.ObjectID{Type: wire.AnalogInput, Instance: 5}, wire.PropOutOfService, 0))
	if a, ok := cl.answer(t, 2*time.Second); !ok || a.Type != wire.PDUReject {
		t.Fatalf("a write to out-of-service was not rejected: %v %v", a.Type, ok)
	}
	d.nothingReached(t, s)
}

// The BBMD registration: one unauthenticated datagram that asks to be sent
// every broadcast on a network the sender is not on.
func TestAForeignDeviceRegistrationIsRefused(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, base, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, bvlcWrap(wire.FuncRegisterForeignDevice, []byte{0x01, 0x2C}))
	d.nothingReached(t, s)
}

// A discovery broadcast is bounded in the answers it brings back. This is
// the protocol's amplifier: one Who-Is, an I-Am from every device that
// hears it.
func TestABroadcastsAnswersAreBounded(t *testing.T) {
	d := startDevice(t, &device{extra: 12})
	_, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        allow_broadcast: true
        max_broadcast_replies: 3
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, whoIs())
	d.waitFor(t, 1, "a who-Is")
	if n := cl.countAnswers(t, 2*time.Second); n > 3 {
		t.Fatalf("the client got %d answers to one broadcast, and the bound is 3", n)
	}
}

// An answer nobody asked for is not delivered. On a datagram protocol that
// is the shape of an answer-spoofing attempt: a reply to a question the
// client did ask, from somewhere else, arriving first.
func TestAnUnsolicitedReplyIsNotDelivered(t *testing.T) {
	d := startDevice(t, &device{})
	d.mu.Lock()
	d.answers = func(raw []byte) []byte {
		// The right shape, the wrong invoke identifier.
		return bvlcWrap(wire.FuncOriginalUnicast, []byte{0x01, 0x00, 0x20, 0xFE, wire.WriteProperty})
	}
	d.mu.Unlock()
	_, addr := bacnetServer(t, base, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, readReq(1, wire.ObjectID{Type: wire.AnalogInput, Instance: 1}, wire.PropPresentValue))
	d.waitFor(t, 1, "a read")
	if _, ok := cl.answer(t, time.Second); ok {
		t.Fatal("an answer with an invoke identifier nobody used was delivered to the client")
	}
}

// A client that may not send here at all is refused before anything inside
// its datagram is read.
func TestAClientOutsideTheListIsRefusedWithoutReadingItsRequest(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [192.0.2.0/24]
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, readReq(1, wire.ObjectID{Type: wire.AnalogInput, Instance: 1}, wire.PropPresentValue))
	d.nothingReached(t, s)
	if _, ok := cl.answer(t, 500*time.Millisecond); ok {
		t.Fatal("a client outside the list was answered")
	}
}

// A datagram that is not a BACnet message never reaches the plant.
func TestSomethingElseOnThePortDoesNotReachTheDevice(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, base, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, []byte{0x16, 0x03, 0x01, 0x00, 0x2A})
	cl.send(t, []byte{0x81, 0x0A, 0xFF, 0xFF, 0x01, 0x00})
	d.nothingReached(t, s)
}

// An object rule the relay cannot apply is a refusal rather than a pass. A
// listener with rules about objects cannot decide about a request whose
// object it did not find, and letting it through would be deciding by the
// gap in a table.
func TestARequestWhoseObjectCannotBeFoundIsRefusedWhenObjectRulesExist(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [createObject, readProperty]
        objects: [analog-value]
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	// createObject names its object inside a choice, which no fixed
	// position describes.
	body := []byte{0x01, 0x00, 0x00, 0x05, 0x01, wire.CreateObject, 0x0E, 0x09, 0x02, 0x0F}
	cl.send(t, bvlcWrap(wire.FuncOriginalUnicast, body))
	if a, ok := cl.answer(t, 2*time.Second); !ok || a.Type != wire.PDUReject {
		t.Fatalf("a request with an unlocatable object was not rejected: %v %v", a.Type, ok)
	}
	d.nothingReached(t, s)
}

// A relay in shadow mode records what it would have refused and forwards
// the request -- except for the bounds, which are never shadowed.
func TestShadowModeCarriesAPolicyRefusalAndStillHoldsTheBounds(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [readProperty]
        default_action: allow
      policy: {mode: shadow}`, d.addr())
	cl := dialClient(t, addr)
	// A service the policy refuses: carried, because it is a policy choice.
	cl.send(t, writeReq(1, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 10))
	d.waitFor(t, 1, "a write in monitor mode")
	// A write at life safety priority: refused anyway, because a bound in
	// shadow mode is a bound that is not there.
	cl.send(t, writeReq(2, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 1))
	// Waited for rather than slept past: the refusal is counted on the path
	// that returns without forwarding, so the count moving is the relay
	// saying it has decided. A sleep here would let the second write be
	// counted as absent before the relay had read it.
	waitRefusal(t, s, "command_priority_too_high")
	if got := d.seen(); len(got) != 1 {
		t.Fatalf("the device saw %d messages: a bound was shadowed", len(got))
	}
}

// A Who-Is addressed to network 65535 asks every router in the estate to
// repeat it on every network it serves. That is the protocol's amplifier
// with the volume turned up, and no routing at all is carried unless the
// configuration names the networks it should reach.
func TestAGlobalBroadcastIsRefused(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        allow_broadcast: true
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, globalWhoIs())
	d.nothingReached(t, s)
}

// And a routed broadcast to a network the configuration names does go.
func TestARoutedRequestToANamedNetworkIsCarried(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        networks: [5]
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	body := []byte{0x01, 0x24, 0x00, 0x05, 0x01, 0x22, 0xFF, 0x00, 0x05, 0x01, wire.ReadProperty}
	body = append(body, 0x0C)
	body = append(body, (wire.ObjectID{Type: wire.AnalogInput, Instance: 1}).Encode()...)
	body = append(body, 0x19, byte(wire.PropPresentValue))
	cl.send(t, bvlcWrap(wire.FuncOriginalUnicast, body))
	d.waitFor(t, 1, "a routed read")
	// And a network the configuration does not name is refused. Only the low
	// octet of DNET is rewritten: the octet after it is the destination
	// address length, and writing a 9 there would move every field behind it,
	// so the relay would be refusing a message it could not parse rather than
	// a well formed request to network 9 -- which is what this test is about.
	body[3] = 0x09
	cl.send(t, bvlcWrap(wire.FuncOriginalUnicast, body))
	// The refusal, not a pause, is what says the relay has finished with the
	// second request: a sleep ends wherever it ends, and the device being
	// empty at that moment would mean nothing about what happens next.
	waitRefusal(t, s, "network_not_allowed")
	if got := d.seen(); len(got) != 1 {
		t.Fatalf("the device saw %d messages: a request to an unnamed network was carried", len(got))
	}
}

// The builders. Each one is a whole datagram, so what the tests send is
// what a workstation would send.

func readReq(invoke uint8, o wire.ObjectID, p wire.PropertyID) []byte {
	body := []byte{0x01, 0x04, 0x00, 0x05, invoke, wire.ReadProperty}
	body = append(body, 0x0C)
	body = append(body, o.Encode()...)
	body = append(body, 0x19, byte(p))
	return bvlcWrap(wire.FuncOriginalUnicast, body)
}

// writeReq writes a real number to a property, at a priority when one is
// given: priority 0 means the request carries none, which the standard
// makes the lowest there is.
func writeReq(invoke uint8, o wire.ObjectID, p wire.PropertyID, prio uint8) []byte {
	body := []byte{0x01, 0x04, 0x00, 0x05, invoke, wire.WriteProperty}
	body = append(body, 0x0C)
	body = append(body, o.Encode()...)
	body = append(body, 0x19, byte(p))
	body = append(body, 0x3E, 0x44, 0x41, 0xA8, 0x00, 0x00, 0x3F)
	if prio > 0 {
		body = append(body, 0x49, prio)
	}
	return bvlcWrap(wire.FuncOriginalUnicast, body)
}

// whoIs is a discovery broadcast on the local network. It carries no
// destination field: a Who-Is addressed to network 65535 asks every router
// in the internetwork to repeat it, which this relay refuses -- see
// TestAGlobalBroadcastIsRefused.
func whoIs() []byte {
	return bvlcWrap(wire.FuncOriginalBroadcast, []byte{0x01, 0x00, 0x10, wire.WhoIs})
}

// globalWhoIs is the same discovery addressed to network 65535.
func globalWhoIs() []byte {
	return bvlcWrap(wire.FuncOriginalBroadcast, []byte{0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, wire.WhoIs})
}

// A table read the configuration allows gets its answer back. The link
// layer carries no identifier to pair one by, so a relay that expected no
// answer would forward the question and drop the reply -- which reads to an
// operator as a BBMD that does not respond.
func TestALinkLayerRequestGetsItsOneAnswerBack(t *testing.T) {
	d := startDevice(t, &device{})
	d.mu.Lock()
	d.answers = func(raw []byte) []byte {
		// A BVLC-Result saying the operation succeeded.
		return bvlcWrap(wire.FuncResult, []byte{0x00, 0x00})
	}
	d.mu.Unlock()
	_, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        allow_bbmd: true
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, bvlcWrap(wire.FuncReadBDT, nil))
	d.waitFor(t, 1, "a distribution table read")
	if n := cl.countAnswers(t, time.Second); n != 1 {
		t.Fatalf("the client got %d answers to a table read, want 1", n)
	}
}

// The service list applies to the building's side too. A device -- or
// something on the plant network wearing a device's address -- that
// broadcasts a timeSynchronization at a client network is setting the clock
// on every host that listens, and that service is not on the default list
// in either direction.
func TestAnUnconfirmedRequestFromTheBuildingIsCheckedAgainstTheServiceList(t *testing.T) {
	d := startDevice(t, &device{})
	d.mu.Lock()
	d.answers = func(raw []byte) []byte {
		// A time synchronisation broadcast, sent back as if unprompted.
		body := []byte{0x01, 0x00, 0x10, wire.TimeSynchronization,
			0xA4, 126, 3, 2, 1, 0xB4, 10, 30, 0, 0}
		return bvlcWrap(wire.FuncOriginalBroadcast, body)
	}
	d.mu.Unlock()
	_, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        allow_broadcast: true
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, whoIs())
	d.waitFor(t, 1, "a who-Is")
	if n := cl.countAnswers(t, time.Second); n != 0 {
		t.Fatalf("the client was sent %d clock-setting broadcasts", n)
	}
	// And an i-Am, which is on the default list, does come back.
	d.mu.Lock()
	d.answers = func(raw []byte) []byte { return iAm(9) }
	d.mu.Unlock()
	cl2 := dialClient(t, addr)
	cl2.send(t, whoIs())
	if n := cl2.countAnswers(t, 2*time.Second); n == 0 {
		t.Fatal("an i-Am did not come back")
	}
}

// A segmented exchange runs in both directions. The reply's segments carry
// the identifier this relay chose and the client's acknowledgements carry
// the one the client chose, so both have to be translated -- a relay that
// translated only the reply would have every segmented download stall after
// its first window, which on a building is a trend log that never arrives.
func TestASegmentedExchangeIsTranslatedInBothDirections(t *testing.T) {
	var mine uint8
	var haveMine bool
	var mu sync.Mutex
	var acks int
	d := startDevice(t, &device{})
	d.mu.Lock()
	d.answers = func(raw []byte) []byte {
		v, err := wire.ParseBVLC(raw)
		if err != nil {
			return nil
		}
		n, err := wire.ParseNPDU(v.Payload)
		if err != nil {
			return nil
		}
		a, err := wire.ParseAPDU(n.APDU)
		if err != nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		switch a.Type {
		case wire.PDUConfirmedRequest:
			mine, haveMine = a.InvokeID, true
			// The first segment of a complex acknowledgement, more to come.
			return bvlcWrap(wire.FuncOriginalUnicast,
				[]byte{0x01, 0x00, 0x3C, a.InvokeID, 0x00, 0x01, wire.ReadRange, 0x0C, 0, 0, 0, 1})
		case wire.PDUSegmentACK:
			// The acknowledgement has to name the identifier the relay
			// gave the device, not the one the client used.
			if !haveMine || a.InvokeID != mine {
				return nil
			}
			acks++
			// The last segment.
			return bvlcWrap(wire.FuncOriginalUnicast,
				[]byte{0x01, 0x00, 0x30, a.InvokeID, wire.ReadRange, 0x0C, 0, 0, 0, 1})
		}
		return nil
	}
	d.mu.Unlock()
	_, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        services: [readRange]
        default_action: allow`, d.addr())
	cl := dialClient(t, addr)
	// A segmented request for a range, invoke identifier 42.
	body := []byte{0x01, 0x04, 0x02, 0x05, 42, wire.ReadRange, 0x0C}
	body = append(body, (wire.ObjectID{Type: wire.TrendLog, Instance: 1}).Encode()...)
	body = append(body, 0x19, 0x83)
	cl.send(t, bvlcWrap(wire.FuncOriginalUnicast, body))
	first, ok := cl.answer(t, 3*time.Second)
	if !ok {
		t.Fatal("no first segment")
	}
	if !first.Segmented || !first.MoreFollows || first.InvokeID != 42 {
		t.Fatalf("first segment %+v, want segmented with the client's identifier", first)
	}
	// The client acknowledges the segment, naming its own identifier.
	cl.send(t, bvlcWrap(wire.FuncOriginalUnicast, []byte{0x01, 0x00, 0x40, 42, 0x00, 0x01}))
	last, ok := cl.answer(t, 3*time.Second)
	if !ok {
		mu.Lock()
		got := acks
		mu.Unlock()
		t.Fatalf("no last segment: the device accepted %d acknowledgements", got)
	}
	if last.Segmented || last.InvokeID != 42 {
		t.Fatalf("last segment %+v", last)
	}
}

// An acknowledgement for an exchange that does not exist is not forwarded.
// On a datagram protocol that is either a client whose request has timed out
// or a stranger interfering with somebody else's transfer.
func TestAnAcknowledgementForNoExchangeIsNotForwarded(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetServer(t, base, d.addr())
	cl := dialClient(t, addr)
	cl.send(t, bvlcWrap(wire.FuncOriginalUnicast, []byte{0x01, 0x00, 0x40, 99, 0x00, 0x01}))
	d.nothingReached(t, s)
}

// A listener shut down at the moment it starts, two hundred times, under
// the race detector. The obvious way to write this is a WaitGroup whose Add
// runs in Serve and whose Wait runs in Shutdown, and that is wrong in a way
// no warning reports: the reader goroutine either is or is not waited for
// depending on the scheduler, so Shutdown returns while it is still reading
// a socket the process is about to close.
//
// The server is built by hand rather than through the engine because the
// engine's own lifecycle is what this test is trying to get out of the way.
// Nothing here sends a datagram, so the only fields touched are the socket
// and the group -- which is exactly the pair the race is between.
func TestServeAndShutdownDoNotRaceOnStartup(t *testing.T) {
	for i := 0; i < 200; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p, err := compile(&config.BACnetListener{Upstream: "devices"})
		if err != nil {
			t.Fatal(err)
		}
		s := &server{name: "plant", pc: pc, policy: p,
			pend: newPending(16, 4, time.Second), timeout: time.Second, window: time.Second}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serve()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.shutdown(ctx)
		cancel()
		wg.Wait()
		// And Serve after a Shutdown starts nothing rather than adding to a
		// group nobody will wait on again.
		s.serve()
	}
}

// Shadow mode carries a policy choice and still refuses the link layer.
//
// docs/CONFIG.md names foreign-device registration among what a shadowed
// `bacnet` listener still refuses, and the reason is that there is no undoing
// one: a registration forwarded so that it could be written down puts the
// sender inside the building's whole broadcast domain for the life of the lease.
// The same holds for a Secure-BVLL wrapper, whose contents the relay has not
// read -- shadow mode never applies to a message the code could not read.
func TestShadowModeStillRefusesTheLinkLayer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		datagram []byte
		reason   string
	}{
		{"foreign device registration", bvlcWrap(wire.FuncRegisterForeignDevice, []byte{0x01, 0x2C}), "bbmd_not_allowed"},
		{"read broadcast distribution table", bvlcWrap(wire.FuncReadBDT, nil), "bbmd_not_allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := startDevice(t, &device{})
			s, addr := bacnetServer(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
      policy: {mode: shadow}`, d.addr())
			cl := dialClient(t, addr)
			cl.send(t, tc.datagram)
			waitRefusal(t, s, tc.reason)
			if got := d.seen(); len(got) != 0 {
				t.Fatalf("%d messages reached the building through a shadowed hard refusal", len(got))
			}
			// Counted as a refusal, not as a would-be one: the listener did
			// refuse it, and a status view that said otherwise would be
			// reporting enforcement that did happen as enforcement that did not.
			if n := s.Stats().WouldRefusals["bacnet"][tc.reason]; n != 0 {
				t.Errorf("counted %d would-be refusals for a bound that held", n)
			}
		})
	}
}
