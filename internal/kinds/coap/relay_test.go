package coap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// fakeDevice is the thing at the far end. It records every message that reached
// it, which is the assertion that matters on a security relay: not what the
// client was told, but what got through to the equipment.
type fakeDevice struct {
	pc net.PacketConn

	mu    sync.Mutex
	got   []*wire.Message
	relay net.Addr
	// reply builds the answer. Nil answers 2.05 Content with a small payload.
	reply  func(*wire.Message) *wire.Message
	silent bool
}

func startDevice(t *testing.T, d *fakeDevice) *fakeDevice {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no loopback here: %v", err)
	}
	d.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go d.serve()
	return d
}

func (d *fakeDevice) addr() string { return d.pc.LocalAddr().String() }

func (d *fakeDevice) serve() {
	buf := make([]byte, wire.MaxMessage+1)
	for {
		n, from, err := d.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		m, err := wire.Parse(buf[:n])
		if err != nil {
			continue
		}
		d.mu.Lock()
		d.got = append(d.got, m)
		d.relay = from
		silent, build := d.silent, d.reply
		d.mu.Unlock()
		if silent {
			continue
		}
		out := content(m, []byte("21.5"))
		if build != nil {
			out = build(m)
		}
		if out == nil {
			continue
		}
		raw, err := wire.Encode(out)
		if err != nil {
			continue
		}
		_, _ = d.pc.WriteTo(raw, from)
	}
}

func (d *fakeDevice) seen() []*wire.Message {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*wire.Message, len(d.got))
	copy(out, d.got)
	return out
}

func (d *fakeDevice) await(t *testing.T, n int, what string) []*wire.Message {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := d.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the device saw %d messages", what, len(d.seen()))
	return nil
}

func (d *fakeDevice) relayAddr() net.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.relay
}

// content is the ordinary answer: a piggybacked 2.05 with a payload.
func content(req *wire.Message, payload []byte) *wire.Message {
	out := wire.Answer(req, wire.Content, req.MessageID)
	out.Set(wire.OptionContentFormat, nil) // text/plain
	out.Payload = payload
	return out
}

const coapYAML = `
version: 1
server:
  listeners:
    - name: segment
      address: "127.0.0.1:0"
      kind: coap
%s
      coap:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: devices, endpoints: [{address: %q}]}
`

// base is the section every test starts from: the pool, and a rule that permits
// the telemetry subtree so that the default deny does not refuse everything.
const base = "        upstream: devices\n" +
	"        rules:\n" +
	"          - name: telemetry\n" +
	"            action: allow\n" +
	"            paths: [\"/3303/...\"]\n"

func relayFor(t *testing.T, section, device string) (*proxy.Server, string) {
	t.Helper()
	return relayWith(t, section, "", device)
}

func relayWith(t *testing.T, section, extra, device string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(coapYAML, extra, section, device))
	return s, proxytest.Addr(t, s, "segment")
}

// client is a device on the segment.
type client struct {
	t    *testing.T
	conn *net.UDPConn
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp4", nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{t: t, conn: c}
}

func (c *client) send(m *wire.Message) {
	c.t.Helper()
	raw, err := wire.Encode(m)
	if err != nil {
		c.t.Fatal(err)
	}
	c.raw(raw)
}

func (c *client) raw(b []byte) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *client) read(d time.Duration) (*wire.Message, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return wire.Parse(buf[:n])
}

func (c *client) ask(m *wire.Message) *wire.Message {
	c.t.Helper()
	c.send(m)
	got, err := c.read(5 * time.Second)
	if err != nil {
		c.t.Fatalf("no answer: %v", err)
	}
	return got
}

func (c *client) expectSilence(what string) {
	c.t.Helper()
	if m, err := c.read(400 * time.Millisecond); err == nil {
		c.t.Fatalf("%s: answered with %s", what, m.Code)
	}
}

// get builds a request for a path.
func get(mid uint16, token byte, segs ...string) *wire.Message {
	return req(wire.GET, mid, token, segs...)
}

func req(code wire.Code, mid uint16, token byte, segs ...string) *wire.Message {
	m := &wire.Message{Type: wire.Confirmable, Code: code, MessageID: mid,
		Token: []byte{token, 0x5a}}
	for _, s := range segs {
		m.Add(wire.OptionURIPath, []byte(s))
	}
	return m
}

// until waits for a counter to move, which is how a refusal that answers nothing
// is observed.
func until(t *testing.T, s *proxy.Server, what string, f func(proxy.Snapshot) bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if f(s.Stats()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: refusals %+v", what, s.Stats().Refusals["coap"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func refused(reason string) func(proxy.Snapshot) bool {
	return func(st proxy.Snapshot) bool { return st.Refusals["coap"][reason] > 0 }
}

// The floor: a request a rule permits reaches the device, and the device's answer
// reaches the client.
func TestARequestARulePermitsIsRelayed(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	_, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	got := c.ask(get(0x1001, 1, "3303", "0", "5700"))
	if got.Code != wire.Content {
		t.Fatalf("the client got %s", got.Code)
	}
	if string(got.Payload) != "21.5" {
		t.Errorf("payload %q", got.Payload)
	}
	// And the device saw the request as the client sent it: the relay forwards
	// the datagram rather than rebuilding it.
	seen := up.await(t, 1, "the request")[0]
	if seen.Code != wire.GET || seen.Path() != "/3303/0/5700" {
		t.Errorf("the device saw %s %s", seen.Code, seen.Path())
	}
	if string(seen.Token) != string([]byte{1, 0x5a}) {
		t.Errorf("token %x", seen.Token)
	}
}

// A path no rule covers is refused, and the refusal is answered rather than
// dropped -- which is the difference between one refused request and five.
func TestAPathNoRuleCoversIsRefusedAndAnswered(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	got := c.ask(req(wire.PUT, 0x1002, 2, "3311", "0", "5850"))
	if got.Code != wire.Forbidden {
		t.Fatalf("the client got %s, wanted 4.03", got.Code)
	}
	// A piggybacked answer: the acknowledgement carries the response, with the
	// request's own message identifier and token.
	if got.Type != wire.Acknowledgement || got.MessageID != 0x1002 {
		t.Errorf("type %s id %#x", got.Type, got.MessageID)
	}
	if string(got.Token) != string([]byte{2, 0x5a}) {
		t.Errorf("token %x, wanted the request's", got.Token)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the refused request reached the device")
	}
	until(t, s, "the refusal", refused("default_deny"))
	if s.Stats().CoAPRefusalsAnswered == 0 {
		t.Error("the refusal was not counted as answered")
	}
}

// answer_refusals: false drops instead, which the validator warns about and which
// this test is here to make visible.
func TestARefusalCanBeDroppedInstead(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        answer_refusals: false\n", up.addr())
	c := dial(t, addr)
	c.send(req(wire.PUT, 0x1003, 3, "3311", "0", "5850"))
	c.expectSilence("a refusal with answering off")
	until(t, s, "the refusal", refused("default_deny"))
	if s.Stats().CoAPRefusalsAnswered != 0 {
		t.Error("something was answered")
	}
}

// The option pair that turns the device into a forward proxy, refused by either
// spelling and with the code the standard gives.
func TestProxyingIsRefusedByEitherOption(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*wire.Message)
	}{
		{"proxy_uri", func(m *wire.Message) {
			m.Set(wire.OptionProxyURI, []byte("coap://192.0.2.1/admin"))
		}},
		{"proxy_scheme", func(m *wire.Message) {
			m.Set(wire.OptionProxyScheme, []byte("http"))
			m.Set(wire.OptionURIHost, []byte("elsewhere.example"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startDevice(t, &fakeDevice{})
			s, addr := relayFor(t, base, up.addr())
			c := dial(t, addr)
			m := get(0x1100, 4, "3303", "0", "5700")
			tc.set(m)
			got := c.ask(m)
			if got.Code != wire.ProxyingNotSupported {
				t.Fatalf("the client got %s, wanted 5.05", got.Code)
			}
			if len(up.seen()) != 0 {
				t.Fatal("the request reached the device")
			}
			until(t, s, "the refusal", refused("proxying_not_allowed"))
			if s.Stats().CoAPProxyRefused == 0 {
				t.Error("nothing was counted as a proxying refusal")
			}
		})
	}
}

// What RFC 7252 says a proxy does with an option it cannot name, which is the one
// place the standard hands a relay the answer instead of a judgement call.
func TestAnUnknownOptionGetsTheCodeTheStandardGives(t *testing.T) {
	for _, tc := range []struct {
		name   string
		number uint16
		want   wire.Code
		reason string
	}{
		{"a critical option nobody registered", 1001, wire.BadOption, "unknown_critical_option"},
		{"an unsafe one", 1002, wire.BadGateway, "unknown_unsafe_option"},
		// Both bits set, and the unsafe answer wins: 5.02 says "this hop will
		// not forward your request" where 4.02 says "your request named
		// something I do not support".
		{"both at once", 1003, wire.BadGateway, "unknown_unsafe_option"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startDevice(t, &fakeDevice{})
			s, addr := relayFor(t, base, up.addr())
			c := dial(t, addr)
			m := get(0x1200, 5, "3303", "0", "5700")
			m.Set(tc.number, []byte("x"))
			if got := c.ask(m); got.Code != tc.want {
				t.Fatalf("the client got %s, wanted %s", got.Code, tc.want)
			}
			if len(up.seen()) != 0 {
				t.Fatal("the request reached the device")
			}
			until(t, s, "the refusal", refused(tc.reason))
		})
	}
	// An elective, safe-to-forward option nobody registered travels, because
	// that is what the standard says a proxy does with one.
	up := startDevice(t, &fakeDevice{})
	_, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	m := get(0x1201, 6, "3303", "0", "5700")
	m.Set(1000, []byte("elective and safe"))
	if got := c.ask(m); got.Code != wire.Content {
		t.Fatalf("the client got %s", got.Code)
	}
	seen := up.await(t, 1, "the request")[0]
	if v, ok := seen.Get(1000); !ok || string(v) != "elective and safe" {
		t.Errorf("the option did not reach the device: %q %v", v, ok)
	}
}

// A path whose segments would not mean what the joined path looks like. This is
// the case that says the path policy is not decorative: one segment containing a
// separator renders as several, so a rule about /3303 would otherwise be
// satisfied by a request that reaches /3311.
func TestAPathThatWouldLieIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	m := &wire.Message{Type: wire.Confirmable, Code: wire.PUT, MessageID: 0x1300,
		Token: []byte{7}}
	m.Add(wire.OptionURIPath, []byte("3303/../3311/0/5850"))
	got := c.ask(m)
	if got.Code != wire.BadRequest {
		t.Fatalf("the client got %s, wanted 4.00", got.Code)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the request reached the device")
	}
	until(t, s, "the refusal", refused("suspicious_path"))
}

// A method outside the list, with the code the standard gives for it.
func TestAMethodOutsideTheListIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        methods: [get]\n", up.addr())
	c := dial(t, addr)
	if got := c.ask(req(wire.PUT, 0x1400, 8, "3303", "0", "5700")); got.Code != wire.MethodNotAllowed {
		t.Fatalf("the client got %s, wanted 4.05", got.Code)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the request reached the device")
	}
	until(t, s, "the refusal", refused("method_not_allowed"))
	// And a get on the same path is carried, so the list is what decided.
	if got := c.ask(get(0x1401, 9, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("a get was refused: %s", got.Code)
	}
}

// An answer from an address that is not a device. Pinned to two loopback
// addresses because allow_servers decides on the sender's address, and shadow
// mode, because this refusal is one a listener being trialled still enforces.
func TestAnAnswerFromSomewhereElseIsDropped(t *testing.T) {
	if pc, err := net.ListenPacket("udp4", "127.0.0.2:0"); err != nil {
		t.Skipf("no second loopback address here: %v", err)
	} else {
		_ = pc.Close()
	}
	rogue := &fakeDevice{silent: true}
	up := startDevice(t, &fakeDevice{silent: true})
	pc, err := net.ListenPacket("udp4", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	rogue.pc = pc
	t.Cleanup(func() { _ = pc.Close() })

	s, addr := relayWith(t, base, "      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)
	c.send(get(0x1500, 10, "3303", "0", "5700"))
	asked := up.await(t, 1, "the request")[0]

	// The real device stays silent, so the only answer that could reach the
	// client is the rogue's -- aimed straight at the socket the relay is
	// waiting on, which is the strongest thing a rogue can do.
	raw, err := wire.Encode(content(asked, []byte("0.0")))
	if err != nil {
		t.Fatal(err)
	}
	target := up.relayAddr()
	if target == nil {
		t.Fatal("the relay's device socket is not known")
	}
	if _, err := rogue.pc.WriteTo(raw, target); err != nil {
		t.Fatal(err)
	}
	c.expectSilence("an answer from an address that is not a device")
	until(t, s, "the rogue answer", func(st proxy.Snapshot) bool {
		return st.CoAPRogueDevice > 0
	})
	if s.Stats().CoAPWouldDeny > 0 {
		t.Error("the rogue answer was only recorded as a would-be refusal")
	}
}

// The amplification factor, which is the check a per-datagram bound cannot make:
// the answer is unremarkable on its own and is a large multiple of the question.
func TestAnAmplifiedAnswerIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		return content(m, []byte(strings.Repeat("x", 800)))
	}})
	s, addr := relayFor(t, base+"        amplification_factor: 4\n", up.addr())
	c := dial(t, addr)
	c.send(get(0x1600, 11, "3303", "0", "5700"))
	c.expectSilence("an answer eighty times the question")
	until(t, s, "the refusal", refused("amplified"))
	if s.Stats().CoAPAmplified == 0 {
		t.Error("nothing was counted as amplified")
	}

	// And the same listener carries a proportionate answer, so the factor is
	// what decided rather than the size alone.
	small := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		return content(m, []byte("21.5"))
	}})
	_, addr2 := relayFor(t, base+"        amplification_factor: 4\n", small.addr())
	if got := dial(t, addr2).ask(get(0x1601, 12, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("a proportionate answer was refused: %s", got.Code)
	}
}

// A block-wise transfer whose declared total is past the bound, refused at the
// first block rather than the sixty-four thousandth.
func TestADeclaredTransferPastTheBoundIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        max_transfer_bytes: 4096\n", up.addr())
	c := dial(t, addr)

	m := req(wire.PUT, 0x1700, 13, "3303", "0", "5700")
	m.Set(wire.OptionBlock1, []byte{0x08}) // block zero of sixteen, more to come
	m.Set(wire.OptionSize1, []byte{0x10, 0x00, 0x00})
	m.Payload = []byte("first")
	if got := c.ask(m); got.Code != wire.RequestEntityTooLarge {
		t.Fatalf("the client got %s, wanted 4.13", got.Code)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the transfer reached the device")
	}
	until(t, s, "the refusal", refused("transfer_too_large"))
}

// A block larger than the bound, which is a separate decision from the total.
func TestABlockPastTheBoundIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        max_block_bytes: 64\n", up.addr())
	c := dial(t, addr)
	m := get(0x1800, 14, "3303", "0", "5700")
	m.Set(wire.OptionBlock2, []byte{0x06}) // block zero of a kilobyte
	if got := c.ask(m); got.Code != wire.RequestEntityTooLarge {
		t.Fatalf("the client got %s", got.Code)
	}
	until(t, s, "the refusal", refused("block_too_large"))
	if len(up.seen()) != 0 {
		t.Fatal("the request reached the device")
	}
}

// Observe: a registration is carried, the notifications that follow are delivered
// to the client that asked, and the registrations are bounded.
func TestObserveIsCarriedAndBounded(t *testing.T) {
	up := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		out := content(m, []byte("21.5"))
		out.Set(wire.OptionObserve, []byte{1})
		return out
	}})
	_, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	m := get(0x1900, 15, "3303", "0", "5700")
	m.Set(wire.OptionObserve, nil) // register
	got := c.ask(m)
	if got.Code != wire.Content {
		t.Fatalf("the registration was refused: %s", got.Code)
	}
	if _, ok := got.Observe(); !ok {
		t.Error("the answer carried no observe option")
	}
	// A second notification for the same token reaches the same client, because
	// an observed registration outlives its first answer.
	asked := up.await(t, 1, "the registration")[0]
	note := &wire.Message{Type: wire.NonConfirmable, Code: wire.Content,
		MessageID: 0x2a, Token: append([]byte(nil), asked.Token...)}
	note.Set(wire.OptionObserve, []byte{2})
	note.Payload = []byte("21.6")
	raw, err := wire.Encode(note)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := up.pc.WriteTo(raw, up.relayAddr()); err != nil {
		t.Fatal(err)
	}
	second, err := c.read(5 * time.Second)
	if err != nil {
		t.Fatalf("the notification did not arrive: %v", err)
	}
	if string(second.Payload) != "21.6" {
		t.Errorf("the notification carried %q", second.Payload)
	}
}

// The registration bound, which exists because a registration has no timeout.
func TestTooManyObserversIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{silent: true})
	s, addr := relayFor(t, base+"        max_observers: 1\n", up.addr())

	first := dial(t, addr)
	m := get(0x1a00, 16, "3303", "0", "5700")
	m.Set(wire.OptionObserve, nil)
	first.send(m)
	up.await(t, 1, "the first registration")

	second := dial(t, addr)
	m2 := get(0x1a01, 17, "3303", "0", "5700")
	m2.Set(wire.OptionObserve, nil)
	if got := second.ask(m2); got.Code != wire.ServiceUnavailable {
		t.Fatalf("the client got %s, wanted 5.03", got.Code)
	}
	until(t, s, "the refusal", refused("too_many_observers"))
	if n := len(up.seen()); n != 1 {
		t.Errorf("the device saw %d registrations", n)
	}
}

// Discovery: the resource whose purpose is to list every other resource.
func TestDiscoveryCanBeRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, "        upstream: devices\n"+
		"        allow_discovery: false\n"+
		"        rules:\n          - {name: all, action: allow}\n", up.addr())
	c := dial(t, addr)
	if got := c.ask(get(0x1b00, 18, ".well-known", "core")); got.Code != wire.Forbidden {
		t.Fatalf("the client got %s", got.Code)
	}
	until(t, s, "the refusal", refused("discovery_not_allowed"))
	if len(up.seen()) != 0 {
		t.Fatal("the discovery request reached the device")
	}
}

// An answer nobody asked for, which on this protocol is either a device answering
// a request that has expired or something aiming answers at the relay.
func TestAnUnsolicitedAnswerIsDropped(t *testing.T) {
	up := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		out := content(m, []byte("21.5"))
		// A token nobody sent.
		out.Token = []byte{0xff, 0xfe}
		return out
	}})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	c.send(get(0x1c00, 19, "3303", "0", "5700"))
	c.expectSilence("an answer whose token nobody sent")
	until(t, s, "the refusal", func(st proxy.Snapshot) bool {
		return st.CoAPUnsolicited > 0
	})
}

// require_token, which closes the degenerate case of clients that send none: the
// token is the only thing pairing an answer with its question.
func TestATokenlessRequestCanBeRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        require_token: true\n", up.addr())
	c := dial(t, addr)
	m := get(0x1d00, 20, "3303", "0", "5700")
	m.Token = nil
	if got := c.ask(m); got.Code != wire.BadRequest {
		t.Fatalf("the client got %s", got.Code)
	}
	until(t, s, "the refusal", refused("no_token"))
	if len(up.seen()) != 0 {
		t.Fatal("the request reached the device")
	}
}

// A message past the bound is refused before anything reads it, and there is
// nothing to answer with: a message this relay would not parse is one whose token
// it has not read.
func TestAnOversizeMessageIsRefusedUnread(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        max_message_bytes: 64\n", up.addr())
	c := dial(t, addr)
	m := req(wire.PUT, 0x1e00, 21, "3303", "0", "5700")
	m.Payload = []byte(strings.Repeat("x", 200))
	c.send(m)
	c.expectSilence("a message past the bound")
	until(t, s, "the refusal", refused("message_too_large"))
	if s.Stats().CoAPOversize == 0 {
		t.Error("nothing was counted as oversize")
	}
	if len(up.seen()) != 0 {
		t.Fatal("the message reached the device")
	}
}

// An option twice where the standard has no meaning for a second one, and the
// path, which is built out of repetition and must not be refused for it.
func TestARepeatedOptionIsRefusedAndAPathIsNot(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	m := get(0x1f00, 22, "3303", "0", "5700")
	m.Add(wire.OptionAccept, []byte{50})
	m.Add(wire.OptionAccept, []byte{60})
	if got := c.ask(m); got.Code != wire.BadOption {
		t.Fatalf("the client got %s", got.Code)
	}
	until(t, s, "the refusal", refused("repeated_option"))

	// Four path segments and two query parts are ordinary.
	ok := get(0x1f01, 23, "3303", "0", "5700")
	ok.Add(wire.OptionURIQuery, []byte("unit=c"))
	ok.Add(wire.OptionURIQuery, []byte("fresh=1"))
	if got := c.ask(ok); got.Code != wire.Content {
		t.Fatalf("a path and a query were refused: %s", got.Code)
	}
}

// RFC 8323's signalling belongs to the stream transports. Over UDP it is a code
// nothing should send, and it is refused hard so a listener being trialled does
// not forward it.
func TestSignallingOverDatagramIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayWith(t, base, "      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)
	m := &wire.Message{Type: wire.Confirmable, Code: wire.CSM, MessageID: 0x2000,
		Token: []byte{24}}
	c.send(m)
	c.expectSilence("a signalling code over UDP")
	until(t, s, "the refusal", refused("signalling_over_datagram"))
	if len(up.seen()) != 0 {
		t.Fatal("the signalling message reached the device")
	}
}

// Shadow mode carries what the policy would have refused, and does not carry a
// hard refusal -- which is the whole point of the flag.
func TestShadowModeCarriesAPolicyRefusalAndNotABound(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayWith(t, base+"        max_payload_bytes: 8\n",
		"      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)

	// A path no rule covers: an opinion, so it is carried and written down.
	if got := c.ask(req(wire.PUT, 0x2100, 25, "3311", "0", "5850")); got.Code != wire.Content {
		t.Fatalf("shadow mode did not carry a policy refusal: %s", got.Code)
	}
	if s.Stats().CoAPWouldDeny == 0 {
		t.Error("nothing was recorded as a would-be refusal")
	}
	if s.Stats().Refusals["coap"]["default_deny"] > 0 {
		t.Error("a would-be refusal was counted as a refusal")
	}

	// A payload past the bound: not an opinion, so it is refused anyway.
	big := req(wire.PUT, 0x2101, 26, "3303", "0", "5700")
	big.Payload = []byte(strings.Repeat("x", 64))
	if got := c.ask(big); got.Code != wire.RequestEntityTooLarge {
		t.Fatalf("shadow mode carried a bound: %s", got.Code)
	}
	until(t, s, "the bound", refused("payload_too_large"))
}

// The rate limit, keyed on the source address because that is the only key this
// protocol offers in NoSec.
func TestTheRateLimitHolds(t *testing.T) {
	up := startDevice(t, &fakeDevice{silent: true})
	s, addr := relayFor(t, base+"        rate_limit: 1\n        rate_burst: 1\n", up.addr())
	c := dial(t, addr)
	for i := 0; i < 20; i++ {
		c.send(get(uint16(0x2200+i), byte(i), "3303", "0", "5700")) //nolint:gosec // i < 20
	}
	until(t, s, "the rate limit", refused("rate_limited"))
	if n := len(up.seen()); n > 5 {
		t.Errorf("%d of twenty requests got through a limit of one a second", n)
	}
}

// A rule on the paths selects as well as decides, so a rule about one subtree does
// not decide about another -- and the rule that matched is the one in the logs.
func TestARuleOnPathsSelectsAndDecides(t *testing.T) {
	section := "        upstream: devices\n" +
		"        rules:\n" +
		"          - name: telemetry\n" +
		"            action: allow\n" +
		"            methods: [get]\n" +
		"            paths: [\"/3303/...\"]\n" +
		"          - name: lighting\n" +
		"            action: allow\n" +
		"            methods: [put]\n" +
		"            paths: [\"/3311/0/5850\"]\n"
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, section, up.addr())
	c := dial(t, addr)

	// The telemetry rule permits the read.
	if got := c.ask(get(0x2300, 30, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("a permitted read was refused: %s", got.Code)
	}
	// The lighting rule permits exactly one path, and a sibling is not it.
	if got := c.ask(req(wire.PUT, 0x2301, 31, "3311", "0", "5850")); got.Code != wire.Content {
		t.Fatalf("a permitted write was refused: %s", got.Code)
	}
	if got := c.ask(req(wire.PUT, 0x2302, 32, "3311", "0", "5851")); got.Code != wire.Forbidden {
		t.Fatalf("a write outside the rule was allowed: %s", got.Code)
	}
	// And a write to the telemetry subtree matches no rule, because that rule
	// covers reads: a method the rule does not name does not select it.
	if got := c.ask(req(wire.PUT, 0x2303, 33, "3303", "0", "5700")); got.Code != wire.Forbidden {
		t.Fatalf("a write to the read subtree was allowed: %s", got.Code)
	}
	until(t, s, "the refusal", refused("default_deny"))
}

// A rule outside its window does not decide, so the default does.
func TestARulesWindowHolds(t *testing.T) {
	section := "        upstream: devices\n" +
		"        rules:\n" +
		"          - name: maintenance\n" +
		"            action: allow\n" +
		"            paths: [\"/3311/...\"]\n" +
		"            schedule: {from: \"02:00\", to: \"03:00\"}\n"
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, section, up.addr())
	c := dial(t, addr)
	// Unless the suite is run in that one hour of UTC, the rule is out of force
	// and the default refuses. The window is checked directly in the policy
	// tests; this is the end-to-end half.
	now := time.Now().UTC().Hour()
	got := c.ask(req(wire.PUT, 0x2400, 34, "3311", "0", "5850"))
	if now == 2 {
		if got.Code != wire.Content {
			t.Fatalf("inside the window the write was refused: %s", got.Code)
		}
		return
	}
	if got.Code != wire.Forbidden {
		t.Fatalf("outside the window the write was allowed: %s", got.Code)
	}
	until(t, s, "the refusal", refused("default_deny"))
	if len(up.seen()) != 0 {
		t.Fatal("the write reached the device")
	}
}

// The content format a payload declares, in both directions.
func TestTheContentFormatIsChecked(t *testing.T) {
	// The device answers in CBOR, because the list applies in both directions:
	// an answer declaring a format the estate does not carry is refused too, and
	// a device replying text/plain here would be refused for that rather than
	// for what this test is about.
	up := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		out := wire.Answer(m, wire.Content, m.MessageID)
		out.Set(wire.OptionContentFormat, []byte{60})
		out.Payload = []byte{0xa0}
		return out
	}})
	s, addr := relayFor(t, base+"        content_formats: [application/cbor]\n", up.addr())
	c := dial(t, addr)

	m := req(wire.PUT, 0x2500, 35, "3303", "0", "5700")
	m.Set(wire.OptionContentFormat, []byte{50}) // application/json
	m.Payload = []byte(`{"v":1}`)
	if got := c.ask(m); got.Code != wire.UnsupportedContentFormat {
		t.Fatalf("the client got %s, wanted 4.15", got.Code)
	}
	until(t, s, "the refusal", refused("content_format_not_allowed"))

	ok := req(wire.PUT, 0x2501, 36, "3303", "0", "5700")
	ok.Set(wire.OptionContentFormat, []byte{60}) // application/cbor
	ok.Payload = []byte{0xa0}
	if got := c.ask(ok); got.Code != wire.Content {
		t.Fatalf("a listed format was refused: %s", got.Code)
	}

	// The other direction: a device answering in a format the estate does not
	// carry is refused as well, which is the half that catches a device that has
	// been reflashed.
	odd := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		out := wire.Answer(m, wire.Content, m.MessageID)
		out.Set(wire.OptionContentFormat, []byte{41}) // application/xml
		out.Payload = []byte("<v>1</v>")
		return out
	}})
	s2, addr2 := relayFor(t, base+"        content_formats: [application/cbor]\n", odd.addr())
	c2 := dial(t, addr2)
	c2.send(get(0x2502, 37, "3303", "0", "5700"))
	c2.expectSilence("an answer in a format the estate does not carry")
	until(t, s2, "the refusal", refused("content_format_not_allowed"))
}

// A method arriving from the device side, which is either a confused device or
// something bouncing requests off the relay.
func TestARequestFromTheDeviceSideIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		// A GET back at the relay, carrying the token so it pairs.
		out := &wire.Message{Type: wire.NonConfirmable, Code: wire.GET,
			MessageID: 0x99, Token: append([]byte(nil), m.Token...)}
		out.Add(wire.OptionURIPath, []byte("3303"))
		return out
	}})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	c.send(get(0x2600, 37, "3303", "0", "5700"))
	c.expectSilence("a request from the device side")
	until(t, s, "the refusal", refused("request_from_server_side"))
}

// A client outside the address list, which in NoSec is the only thing a rule can
// name about a client.
func TestAClientOutsideTheListIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+"        deny_clients: [\"127.0.0.0/8\"]\n", up.addr())
	c := dial(t, addr)
	c.send(get(0x2700, 38, "3303", "0", "5700"))
	c.expectSilence("a client on a denied network")
	until(t, s, "the refusal", refused("client_not_allowed"))
	if len(up.seen()) != 0 {
		t.Fatal("a denied client reached the device")
	}
}

// A bare reset from a client travels. It is how a device says "stop sending me
// that", so a relay that swallowed one would leave a notification running that
// the client asked to end.
func TestAResetTravels(t *testing.T) {
	up := startDevice(t, &fakeDevice{silent: true})
	_, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	c.send(wire.ResetFor(0x2800))
	seen := up.await(t, 1, "the reset")[0]
	if seen.Type != wire.Reset || !seen.Code.IsEmpty() {
		t.Errorf("the device saw %s %s", seen.Type, seen.Code)
	}
}

// The pending table is the pairing, so when it is full the request is refused
// rather than the pairing made unreliable.
func TestAFullPendingTableRefusesTheRequest(t *testing.T) {
	up := startDevice(t, &fakeDevice{silent: true})
	s, addr := relayFor(t, base+"        max_pending: 1\n        request_timeout: 30s\n",
		up.addr())
	first := dial(t, addr)
	first.send(get(0x2900, 40, "3303", "0", "5700"))
	up.await(t, 1, "the first request")

	second := dial(t, addr)
	if got := second.ask(get(0x2901, 41, "3303", "0", "5700")); got.Code != wire.ServiceUnavailable {
		t.Fatalf("the client got %s, wanted 5.03", got.Code)
	}
	until(t, s, "the refusal", refused("too_many_pending"))
	if n := len(up.seen()); n != 1 {
		t.Errorf("the device saw %d requests", n)
	}
}

// A non-confirmable request gets a non-confirmable refusal with an identifier of
// the relay's own, and still the request's token.
func TestANonConfirmableRefusalIsNonConfirmable(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	_, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	m := req(wire.PUT, 0x2a00, 42, "3311", "0", "5850")
	m.Type = wire.NonConfirmable
	got := c.ask(m)
	if got.Type != wire.NonConfirmable {
		t.Errorf("the refusal came back as %s", got.Type)
	}
	if got.Code != wire.Forbidden {
		t.Errorf("code %s", got.Code)
	}
	if string(got.Token) != string(m.Token) {
		t.Errorf("token %x, wanted the request's %x", got.Token, m.Token)
	}
	if got.MessageID == m.MessageID {
		t.Error("the answer reused the request's message identifier, which only an acknowledgement does")
	}
}

// itoa via the shared helper, so the test file and the kind agree on the
// rendering used in a refusal's detail.
func TestByteCountReads(t *testing.T) {
	if got := byteCount(1500); got != "1500 octets" {
		t.Errorf("byteCount rendered %q", got)
	}
	if got := tokenHex([]byte{0x0a, 0xff}); got != "0aff" {
		t.Errorf("tokenHex rendered %q", got)
	}
	if got := binary.BigEndian.Uint16([]byte{0x01, 0x02}); got != 0x0102 {
		t.Errorf("the test file's own helper: %d", got)
	}
}

// The listener's own switches, on a listener with default_action: allow and no
// rules -- which is the only configuration where they are the thing deciding.
//
// This matters because a rule carries its own copy of several of them, so a test
// that always went through a rule would be testing the rule and leaving the
// listener's switch untested. An estate that writes default_action: allow is
// relying on exactly these.
func TestTheListenersOwnSwitchesDecideWhenNoRuleDoes(t *testing.T) {
	open := "        upstream: devices\n        default_action: allow\n"

	t.Run("proxying", func(t *testing.T) {
		up := startDevice(t, &fakeDevice{})
		s, addr := relayFor(t, open, up.addr())
		m := get(0x3000, 50, "3303", "0", "5700")
		m.Set(wire.OptionProxyURI, []byte("coap://192.0.2.1/admin"))
		if got := dial(t, addr).ask(m); got.Code != wire.ProxyingNotSupported {
			t.Fatalf("the client got %s", got.Code)
		}
		until(t, s, "the refusal", refused("proxying_not_allowed"))
		if len(up.seen()) != 0 {
			t.Fatal("the request reached the device")
		}
	})

	t.Run("the path list", func(t *testing.T) {
		up := startDevice(t, &fakeDevice{})
		s, addr := relayFor(t, open+"        allow_paths: [\"/3303/...\"]\n", up.addr())
		c := dial(t, addr)
		if got := c.ask(get(0x3001, 51, "3303", "0", "5700")); got.Code != wire.Content {
			t.Fatalf("a listed path was refused: %s", got.Code)
		}
		if got := c.ask(get(0x3002, 52, "3311", "0", "5850")); got.Code != wire.Forbidden {
			t.Fatalf("a path outside the list was allowed: %s", got.Code)
		}
		until(t, s, "the refusal", refused("path_not_allowed"))
	})

	t.Run("observe", func(t *testing.T) {
		up := startDevice(t, &fakeDevice{})
		s, addr := relayFor(t, open+"        allow_observe: false\n", up.addr())
		m := get(0x3003, 53, "3303", "0", "5700")
		m.Set(wire.OptionObserve, nil)
		if got := dial(t, addr).ask(m); got.Code != wire.BadOption {
			t.Fatalf("the client got %s", got.Code)
		}
		until(t, s, "the refusal", refused("observe_not_allowed"))
		if len(up.seen()) != 0 {
			t.Fatal("the registration reached the device")
		}
	})

	t.Run("the message types", func(t *testing.T) {
		up := startDevice(t, &fakeDevice{})
		s, addr := relayFor(t, open+"        message_types: [con]\n", up.addr())
		c := dial(t, addr)
		non := get(0x3004, 54, "3303", "0", "5700")
		non.Type = wire.NonConfirmable
		c.send(non)
		// Nothing to answer: the type the client used is the thing refused, so
		// the refusal has no type to answer in.
		c.expectSilence("a non-confirmable request where only con is allowed")
		until(t, s, "the refusal", refused("message_type_not_allowed"))
		if len(up.seen()) != 0 {
			t.Fatal("the request reached the device")
		}
		// And a confirmable one on the same path is carried.
		if got := c.ask(get(0x3005, 55, "3303", "0", "5700")); got.Code != wire.Content {
			t.Fatalf("a confirmable request was refused: %s", got.Code)
		}
	})
}

// A response arriving on the *client* side, which is what a device answering
// directly into the segment looks like from here -- or something aiming answers at
// the relay. Refused hard, so a listener being trialled does not forward it to a
// device as though a client had asked something.
func TestAResponseFromTheClientSideIsRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayWith(t, base, "      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)
	m := &wire.Message{Type: wire.NonConfirmable, Code: wire.Content,
		MessageID: 0x3100, Token: []byte{56}}
	m.Payload = []byte("99.9")
	c.send(m)
	c.expectSilence("a response from the client side")
	until(t, s, "the refusal", refused("response_from_client_side"))
	if len(up.seen()) != 0 {
		t.Fatal("a response was relayed to a device as a request")
	}
}

// A suspicious path is refused in shadow mode too. It is not an opinion an
// operator can try out: carrying a path whose rendering does not mean what it looks
// like is the harm, because the relay's own decision was about a different path
// than the device will act on.
func TestShadowModeStillRefusesAPathThatWouldLie(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayWith(t, base, "      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)
	m := &wire.Message{Type: wire.Confirmable, Code: wire.PUT, MessageID: 0x3200,
		Token: []byte{57}}
	m.Add(wire.OptionURIPath, []byte("3303/../3311/0/5850"))
	if got := c.ask(m); got.Code != wire.BadRequest {
		t.Fatalf("shadow mode carried a path that would lie: %s", got.Code)
	}
	until(t, s, "the refusal", refused("suspicious_path"))
	if len(up.seen()) != 0 {
		t.Fatal("the request reached the device")
	}
}

// An observed registration outlives the request timeout, which is the point of
// observing: the notifications arrive minutes apart and each one is another answer
// to the same request. A sweep that dropped registrations would deliver the first
// notification and silently lose the rest.
func TestAnObservedRegistrationOutlivesTheRequestTimeout(t *testing.T) {
	up := startDevice(t, &fakeDevice{reply: func(m *wire.Message) *wire.Message {
		out := content(m, []byte("21.5"))
		out.Set(wire.OptionObserve, []byte{1})
		return out
	}})
	_, addr := relayFor(t, base+"        request_timeout: 1s\n", up.addr())
	c := dial(t, addr)

	m := get(0x3300, 58, "3303", "0", "5700")
	m.Set(wire.OptionObserve, nil)
	if got := c.ask(m); got.Code != wire.Content {
		t.Fatalf("the registration was refused: %s", got.Code)
	}
	asked := up.await(t, 1, "the registration")[0]

	// Past the timeout by enough that the sweeper has run over it more than once.
	time.Sleep(2500 * time.Millisecond)

	note := &wire.Message{Type: wire.NonConfirmable, Code: wire.Content,
		MessageID: 0x2b, Token: append([]byte(nil), asked.Token...)}
	note.Set(wire.OptionObserve, []byte{9})
	note.Payload = []byte("22.1")
	raw, err := wire.Encode(note)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := up.pc.WriteTo(raw, up.relayAddr()); err != nil {
		t.Fatal(err)
	}
	got, err := c.read(5 * time.Second)
	if err != nil {
		t.Fatalf("the notification after the timeout did not arrive: %v", err)
	}
	if string(got.Payload) != "22.1" {
		t.Errorf("the notification carried %q", got.Payload)
	}
}
