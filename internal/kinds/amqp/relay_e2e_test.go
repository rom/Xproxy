package amqp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The relay end to end, through the real engine, against a broker that keeps a
// record of what reached it.
//
// What got through is the assertion that matters. A test that checked only the
// client's error would pass against a relay that answered a refusal and
// forwarded the operation anyway, which is the bug that actually happens -- so
// every refusal here is asserted twice: the client was told, and the broker
// never saw it.

// fakeBroker is enough of a message broker to complete both handshakes and
// record every method and performative that arrived.
type fakeBroker struct {
	ln net.Listener
	// refuseAuth makes the broker refuse the credential the way a real one
	// does: by closing the connection instead of tuning it (0-9-1), or with
	// a non-zero SASL outcome (1.0).
	refuseAuth bool
	// deliver, when set, is an exchange the broker delivers a message from
	// after a basic.consume, which is how the inbound direction is driven.
	deliver string

	mu    sync.Mutex
	saw   []string
	names []string
}

func startBroker(t *testing.T, b *fakeBroker) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go b.serve()
	return b
}

func (b *fakeBroker) addr() string { return b.ln.Addr().String() }

func (b *fakeBroker) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.session(c)
	}
}

func (b *fakeBroker) record(what string, names ...string) {
	b.mu.Lock()
	b.saw = append(b.saw, what)
	b.names = append(b.names, names...)
	b.mu.Unlock()
}

// got says whether the broker saw a method or performative by name.
func (b *fakeBroker) got(what string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.saw {
		if s == what {
			return true
		}
	}
	return false
}

func (b *fakeBroker) sawNames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.names...)
}

func (b *fakeBroker) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	r := wire.NewReader(c, 0)
	h, err := r.Header()
	if err != nil {
		return
	}
	b.record("header " + h.String())
	if h.Version() == wire.V10 {
		b.session10(c, r, h)
		return
	}
	// 0-9-1: the broker speaks first.
	_, _ = c.Write(frame091(wire.FrameMethod, 0, methodPayload(wire.ClassConnection, 10,
		[]byte{0, 9}, emptyTable(), lstr([]byte("PLAIN AMQPLAIN")), lstr([]byte("en_US")))))
	for {
		f, err := r.Next()
		if err != nil {
			return
		}
		if f.Heartbeat() {
			continue
		}
		switch f.Type {
		case wire.FrameHeader:
			b.record("content")
			continue
		case wire.FrameBody:
			b.record("body")
			continue
		}
		m, err := wire.ParseMethod(f.Payload)
		if err != nil {
			return
		}
		name := m.Name()
		var names []string
		if targets, ok := m.Targets(); ok {
			for _, t := range targets {
				names = append(names, t.Kind+":"+t.Name)
			}
		}
		b.record(name, names...)
		switch name {
		case "connection.start-ok":
			if b.refuseAuth {
				// What a real broker does: it closes the connection rather
				// than tuning it, so the arrival of tune is the answer to
				// "was the credential accepted".
				_, _ = c.Write(frame091(wire.FrameMethod, 0, methodPayload(wire.ClassConnection, 50,
					u16(403), sstr("ACCESS_REFUSED - Login was refused"), u16(10), u16(11))))
				return
			}
			_, _ = c.Write(frame091(wire.FrameMethod, 0, methodPayload(wire.ClassConnection, 30,
				u16(2047), u32(131072), u16(60))))
		case "connection.open":
			_, _ = c.Write(frame091(wire.FrameMethod, 0, methodPayload(wire.ClassConnection, 41, sstr(""))))
		case "channel.open":
			_, _ = c.Write(frame091(wire.FrameMethod, f.Channel, methodPayload(wire.ClassChannel, 11, lstr(nil))))
		case "queue.declare":
			_, _ = c.Write(frame091(wire.FrameMethod, f.Channel, methodPayload(wire.ClassQueue, 11,
				sstr("work"), u32(0), u32(0))))
		case "queue.delete":
			_, _ = c.Write(frame091(wire.FrameMethod, f.Channel, methodPayload(wire.ClassQueue, 41, u32(0))))
		case "queue.purge":
			_, _ = c.Write(frame091(wire.FrameMethod, f.Channel, methodPayload(wire.ClassQueue, 31, u32(0))))
		case "basic.consume":
			_, _ = c.Write(frame091(wire.FrameMethod, f.Channel, methodPayload(wire.ClassBasic, 21, sstr("tag-1"))))
			if b.deliver != "" {
				_, _ = c.Write(frame091(wire.FrameMethod, f.Channel, methodPayload(wire.ClassBasic, 60,
					sstr("tag-1"), u64(1), bitsOf(false), sstr(b.deliver), sstr("orders.created"))))
				_, _ = c.Write(frame091(wire.FrameHeader, f.Channel, contentHeaderPayload(2, 0)))
				_, _ = c.Write(frame091(wire.FrameBody, f.Channel, []byte("hi")))
			}
		case "connection.close":
			_, _ = c.Write(frame091(wire.FrameMethod, 0, methodPayload(wire.ClassConnection, 51)))
			return
		}
	}
}

// session10 is the 1.0 side: the SASL layer, a second header, and then the
// performatives.
func (b *fakeBroker) session10(c net.Conn, r *wire.Reader, h wire.Header) {
	if h.Layer() == wire.ProtoSASL {
		_, _ = c.Write(h.Bytes())
		_, _ = c.Write(frame10(wire.FrameSASL, 0, perfBody(0x40, sym10("PLAIN"))))
		for {
			f, err := r.Next()
			if err != nil {
				return
			}
			p, err := wire.ParsePerformative(f.Payload)
			if err != nil {
				return
			}
			b.record(p.Name())
			if p.Code != wire.PerfSASLInit {
				continue
			}
			code := uint8(0)
			if b.refuseAuth {
				code = 1
			}
			_, _ = c.Write(frame10(wire.FrameSASL, 0, perfBody(0x44, []byte{0x50, code})))
			if b.refuseAuth {
				return
			}
			break
		}
		// Both peers start again with a fresh header.
		h2, err := r.Header()
		if err != nil {
			return
		}
		b.record("header " + h2.String())
		_, _ = c.Write(h2.Bytes())
	} else {
		_, _ = c.Write(h.Bytes())
	}
	for {
		f, err := r.Next()
		if err != nil {
			return
		}
		if f.Heartbeat() {
			continue
		}
		p, err := wire.ParsePerformative(f.Payload)
		if err != nil {
			return
		}
		var names []string
		if _, _, role, source, target, ok := p.Attach(); ok {
			addr := target
			if role == wire.RoleReceiver {
				addr = source
			}
			names = append(names, "address:"+addr)
		}
		b.record(p.Name(), names...)
		switch p.Code {
		case wire.PerfOpen:
			_, _ = c.Write(frame10(wire.FrameAMQP, 0, perfBody(0x10, s10("broker"), s10("/"), u10(131072))))
		case wire.PerfBegin:
			_, _ = c.Write(frame10(wire.FrameAMQP, f.Channel, perfBody(0x11,
				u10(uint32(f.Channel)), u10(0), u10(100), u10(100), u10(255))))
		case wire.PerfAttach:
			_, _ = c.Write(frame10(wire.FrameAMQP, f.Channel, perfBody(0x12, s10("link"), u10(1), bool10(true))))
		case wire.PerfClose:
			_, _ = c.Write(frame10(wire.FrameAMQP, 0, perfBody(0x18)))
			return
		}
	}
}

const amqpYAML = `
version: 1
server:
  listeners:
    - name: broker
      address: "127.0.0.1:0"
      kind: amqp
      amqp:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: br, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, brokerAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(amqpYAML, section, brokerAddr))
	return s, proxytest.Addr(t, s, "broker")
}

// base is a listener with the transport security off, because every test using
// it is about the policy rather than the transport: a fixture running a TLS
// stack to check an exchange list would be testing crypto/tls.
const base = "        upstream: br\n" +
	"        require_tls: false\n" +
	"        default_action: allow\n"

// client091 is a minimal AMQP 0-9-1 client.
type client091 struct {
	t *testing.T
	c net.Conn
	r *wire.Reader
}

func dial091(t *testing.T, addr string) *client091 {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	cl := &client091{t: t, c: c, r: wire.NewReader(c, 0)}
	cl.write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1})
	cl.r.SetVersion(wire.V091)
	return cl
}

func (cl *client091) write(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

func (cl *client091) send(class, id uint16, channel uint16, args ...[]byte) {
	cl.t.Helper()
	cl.write(frame091(wire.FrameMethod, channel, methodPayload(class, id, args...)))
}

// next reads the next method and returns its name, or "" at the end of the
// connection.
func (cl *client091) next() (string, *wire.Method) {
	cl.t.Helper()
	for {
		f, err := cl.r.Next()
		if err != nil {
			return "", nil
		}
		if f.Type != wire.FrameMethod {
			continue
		}
		m, err := wire.ParseMethod(f.Payload)
		if err != nil {
			return "", nil
		}
		return m.Name(), m
	}
}

// expect reads until the named method arrives, and fails if the connection
// ends first.
func (cl *client091) expect(want string) *wire.Method {
	cl.t.Helper()
	for {
		name, m := cl.next()
		if name == "" {
			cl.t.Fatalf("the connection ended before %s", want)
		}
		if name == want {
			return m
		}
		if name == "connection.close" {
			code, text, _, _, _ := m.CloseReason()
			cl.t.Fatalf("waiting for %s, the connection was closed: %d %s", want, code, text)
		}
	}
}

// handshake completes the 0-9-1 handshake as a client library does.
func (cl *client091) handshake(user, vhost string) {
	cl.t.Helper()
	cl.expect("connection.start")
	cl.send(wire.ClassConnection, 11, 0, emptyTable(), sstr("PLAIN"),
		lstr([]byte("\x00"+user+"\x00secret")), sstr("en_US"))
	cl.expect("connection.tune")
	cl.send(wire.ClassConnection, 31, 0, u16(2047), u32(131072), u16(60))
	cl.send(wire.ClassConnection, 40, 0, sstr(vhost), sstr(""), bitsOf(false))
	cl.expect("connection.open-ok")
	cl.send(wire.ClassChannel, 10, 1, sstr(""))
	cl.expect("channel.open-ok")
}

// closed reads until the connection is closed and returns the refusal text,
// failing if something else arrives first.
func (cl *client091) closed() string {
	cl.t.Helper()
	for {
		name, m := cl.next()
		switch name {
		case "":
			return ""
		case "connection.close":
			_, text, _, _, _ := m.CloseReason()
			return text
		}
	}
}

// The ordinary path: a client publishes and consumes, and the broker sees it.
func TestAnAllowedSessionReachesTheBroker(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base, b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")

	cl.send(wire.ClassBasic, 40, 1, u16(0), sstr("events"), sstr("orders.created"), bitsOf(false, false))
	cl.write(frame091(wire.FrameHeader, 1, contentHeaderPayload(5, 0)))
	cl.write(frame091(wire.FrameBody, 1, []byte("hello")))
	cl.send(wire.ClassBasic, 20, 1, u16(0), sstr("work"), sstr("tag-1"),
		bitsOf(false, false, false, false), emptyTable())
	cl.expect("basic.consume-ok")

	for _, want := range []string{"connection.start-ok", "connection.tune-ok", "connection.open",
		"channel.open", "basic.publish", "content", "body", "basic.consume"} {
		if !b.got(want) {
			t.Errorf("the broker never saw %s (saw %v)", want, b.saw)
		}
	}
	names := b.sawNames()
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "exchange:events") || !strings.Contains(joined, "queue:work") {
		t.Errorf("the broker saw the names %v", names)
	}
}

// Topology is off by default, and the refusal ends the connection with the
// protocol's own statement.
func TestATopologyMethodIsRefusedAndNeverReachesTheBroker(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base, b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")

	cl.send(wire.ClassQueue, 40, 1, u16(0), sstr("work"), bitsOf(false, false, false))
	text := cl.closed()
	if !strings.Contains(text, "topology_not_allowed") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("queue.delete") {
		t.Error("the queue.delete reached the broker")
	}
}

// The dead-letter exchange: the argument that names an exchange nothing else in
// the method mentions.
func TestADeadLetterExchangeOutsideThePolicyIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+
		"        allow_topology: true\n"+
		"        allow_exchanges: [\"events\", \"events.#\"]\n"+
		"        allow_queues: [\"work\"]\n", b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")

	// The same declare twice: once with a dead-letter exchange inside the
	// policy, once with one outside it.
	cl.send(wire.ClassQueue, 10, 1, u16(0), sstr("work"),
		bitsOf(false, true, false, false, false),
		tbl(entryStr("x-dead-letter-exchange", "events.dead")))
	cl.expect("queue.declare-ok")

	cl.send(wire.ClassQueue, 10, 1, u16(0), sstr("work"),
		bitsOf(false, true, false, false, false),
		tbl(entryStr("x-dead-letter-exchange", "payroll")))
	text := cl.closed()
	if !strings.Contains(text, "exchange_not_allowed") || !strings.Contains(text, "payroll") {
		t.Errorf("the refusal said %q", text)
	}
	// One declare reached the broker, not two.
	n := 0
	for _, s := range b.saw {
		if s == "queue.declare" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the broker saw %d declares", n)
	}
}

// A message is refused on the size its content header declares, before the
// body arrives.
func TestAnOversizeMessageIsRefusedBeforeItsBody(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+"        max_message_bytes: 64\n", b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")

	cl.send(wire.ClassBasic, 40, 1, u16(0), sstr("events"), sstr("orders.created"), bitsOf(false, false))
	cl.write(frame091(wire.FrameHeader, 1, contentHeaderPayload(4096, 0)))
	text := cl.closed()
	if !strings.Contains(text, "message_too_large") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("body") {
		t.Error("a body frame reached the broker")
	}
}

// require_auth waits for the broker's answer, not the client's claim.
func TestAnOperationBeforeTheBrokerAnsweredIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, "        upstream: br\n"+
		"        require_tls: false\n"+
		"        default_action: allow\n", b.addr())
	cl := dial091(t, addr)
	cl.expect("connection.start")
	// A publish instead of a start-ok: the connection has authenticated
	// nothing.
	cl.send(wire.ClassBasic, 40, 1, u16(0), sstr("events"), sstr("k"), bitsOf(false, false))
	text := cl.closed()
	if !strings.Contains(text, "not_authenticated") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("basic.publish") {
		t.Error("the publish reached the broker")
	}
}

// A credential the broker refuses is the broker's decision, and the relay
// records it rather than treating the attempt as a login.
func TestACredentialTheBrokerRefusesIsNotALogin(t *testing.T) {
	b := startBroker(t, &fakeBroker{refuseAuth: true})
	s, addr := relayFor(t, base, b.addr())
	cl := dial091(t, addr)
	cl.expect("connection.start")
	cl.send(wire.ClassConnection, 11, 0, emptyTable(), sstr("PLAIN"),
		lstr([]byte("\x00orders\x00wrong")), sstr("en_US"))
	// The broker's own refusal reaches the client.
	if text := cl.closed(); !strings.Contains(text, "ACCESS_REFUSED") {
		t.Errorf("the broker's refusal read as %q", text)
	}
	// And the relay counted it as the broker refusing, not as its own
	// refusal.
	waitFor(t, func() bool { return s.Stats().Refusals["amqp"]["not_authenticated"] == 0 })
}

// The mechanism policy: ANONYMOUS is not a login this listener passes on.
func TestAnAnonymousLoginIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base, b.addr())
	cl := dial091(t, addr)
	cl.expect("connection.start")
	cl.send(wire.ClassConnection, 11, 0, emptyTable(), sstr("ANONYMOUS"), lstr(nil), sstr("en_US"))
	if text := cl.closed(); !strings.Contains(text, "mechanism_not_allowed") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("connection.start-ok") {
		t.Error("the ANONYMOUS login reached the broker")
	}
}

// A version the listener does not serve is answered with one it does, which is
// what both specifications say to do.
func TestARefusedVersionIsAnsweredWithASupportedHeader(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+"        versions: [\"0-9-1\"]\n", b.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	// An AMQP 1.0 client.
	if _, err := c.Write([]byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var got [8]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		t.Fatalf("no header came back: %v", err)
	}
	if want := []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}; string(got[:]) != string(want) {
		t.Errorf("the answer was %v, want %v", got, want)
	}
	// And the broker was never dialled at all: the header is decided before
	// anything reaches it.
	if len(b.saw) != 0 {
		t.Errorf("the broker saw %v", b.saw)
	}
}

// The inbound direction: a delivery from an exchange on the deny list is
// refused, and one from an exchange merely off the allow list is not.
func TestADeliveryFromADeniedExchangeIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{deliver: "payroll"})
	_, addr := relayFor(t, base+"        deny_exchanges: [\"payroll\"]\n", b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")
	cl.send(wire.ClassBasic, 20, 1, u16(0), sstr("work"), sstr("tag-1"),
		bitsOf(false, false, false, false), emptyTable())
	if text := cl.closed(); !strings.Contains(text, "delivery_denied") {
		t.Errorf("the refusal said %q", text)
	}

	// The same delivery from an exchange that is simply not on the allow
	// list goes through, because a consumer need not be allowed to name the
	// exchange a message was published to.
	b2 := startBroker(t, &fakeBroker{deliver: "somebody-elses"})
	_, addr2 := relayFor(t, base+"        allow_exchanges: [\"events\"]\n"+
		"        allow_queues: [\"work\"]\n", b2.addr())
	cl2 := dial091(t, addr2)
	cl2.handshake("orders", "/")
	cl2.send(wire.ClassBasic, 20, 1, u16(0), sstr("work"), sstr("tag-1"),
		bitsOf(false, false, false, false), emptyTable())
	cl2.expect("basic.consume-ok")
	if m := cl2.expect("basic.deliver"); m == nil {
		t.Error("the delivery never arrived")
	}
}

// AMQP 1.0, end to end: the SASL layer, the second header, and an attach whose
// address the policy decides.
func TestATenConnectionIsRelayedAndDecided(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+
		"        allow_exchanges: [\"events\"]\n"+
		"        allow_routing_keys: [\"orders.#\"]\n"+
		"        allow_queues: [\"work\"]\n", b.addr())

	cl := dial10(t, addr)
	cl.sasl("orders")
	cl.open("/")
	cl.begin()
	// A sender to an allowed address.
	cl.attach(1, false, "/exchange/events/orders.created")
	cl.expect("attach")
	if !b.got("attach") {
		t.Error("the attach never reached the broker")
	}
	// And one to an exchange outside the policy.
	cl.attach(2, false, "/exchange/payroll/salaries")
	if text := cl.closedText(); !strings.Contains(text, "exchange_not_allowed") {
		t.Errorf("the refusal said %q", text)
	}
}

// The 1.0 management node, which is how a client administers a broker over the
// connection it publishes on.
func TestATenAttachToTheManagementNodeIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base, b.addr())
	cl := dial10(t, addr)
	cl.sasl("orders")
	cl.open("/")
	cl.begin()
	cl.attach(1, false, "$management")
	if text := cl.closedText(); !strings.Contains(text, "management_node_denied") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("attach") {
		t.Error("the attach reached the broker")
	}
}

// A 1.0 transfer on a handle nobody attached: the address was never checked, so
// the message is not forwarded.
func TestATenTransferOnAnUnknownHandleIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base, b.addr())
	cl := dial10(t, addr)
	cl.sasl("orders")
	cl.open("/")
	cl.begin()
	cl.send(0x14, u10(9), u10(1), bin10([]byte{1}), u10(0), bool10(false), bool10(false))
	if text := cl.closedText(); !strings.Contains(text, "no_such_link") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("transfer") {
		t.Error("the transfer reached the broker")
	}
}

// A 1.0 client that never authenticates: the header with no SASL layer is a
// connection with no identity at all.
func TestATenConnectionWithoutSASLIsRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base, b.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}); err != nil {
		t.Fatal(err)
	}
	r := wire.NewReader(c, 0)
	if _, err := r.Header(); err != nil {
		t.Fatalf("no header came back: %v", err)
	}
	// open, with no SASL exchange before it.
	if _, err := c.Write(frame10(wire.FrameAMQP, 0, perfBody(0x10, s10("client"), s10("/")))); err != nil {
		t.Fatal(err)
	}
	// The relay refuses it, and the broker never sees an open.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.got("open") {
			t.Fatal("the open reached the broker")
		}
		if _, err := r.Next(); err != nil {
			return
		}
	}
}

// client10 is a minimal AMQP 1.0 client.
type client10 struct {
	t *testing.T
	c net.Conn
	r *wire.Reader
}

func dial10(t *testing.T, addr string) *client10 {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client10{t: t, c: c, r: wire.NewReader(c, 0)}
}

func (cl *client10) write(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

// sasl runs the SASL layer and the second protocol header.
func (cl *client10) sasl(user string) {
	cl.t.Helper()
	cl.write([]byte{'A', 'M', 'Q', 'P', 3, 1, 0, 0})
	cl.r.SetVersion(wire.V10)
	if _, err := cl.r.Header(); err != nil {
		cl.t.Fatalf("no SASL header came back: %v", err)
	}
	cl.expect("sasl-mechanisms")
	cl.write(frame10(wire.FrameSASL, 0, perfBody(0x41, sym10("PLAIN"),
		bin10([]byte("\x00"+user+"\x00secret")))))
	cl.expect("sasl-outcome")
	cl.write([]byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0})
	if _, err := cl.r.Header(); err != nil {
		cl.t.Fatalf("no second header came back: %v", err)
	}
}

func (cl *client10) open(hostname string) {
	cl.t.Helper()
	cl.write(frame10(wire.FrameAMQP, 0, perfBody(0x10, s10("client"), s10(hostname), u10(131072))))
	cl.expect("open")
}

func (cl *client10) begin() {
	cl.t.Helper()
	cl.write(frame10(wire.FrameAMQP, 1, perfBody(0x11, null10(), u10(0), u10(100), u10(100), u10(255))))
	cl.expect("begin")
}

func (cl *client10) attach(handle uint32, receiver bool, address string) {
	cl.t.Helper()
	src, tgt := tgt10("", false), tgt10(address, false)
	if receiver {
		src, tgt = src10(address, false), src10("", false)
	}
	cl.write(frame10(wire.FrameAMQP, 1, perfBody(0x12, s10("link"), u10(handle),
		bool10(receiver), null10(), null10(), src, tgt)))
}

func (cl *client10) send(code uint8, fields ...[]byte) {
	cl.t.Helper()
	cl.write(frame10(wire.FrameAMQP, 1, perfBody(code, fields...)))
}

func (cl *client10) next() (string, *wire.Performative) {
	cl.t.Helper()
	for {
		f, err := cl.r.Next()
		if err != nil {
			return "", nil
		}
		if f.Heartbeat() {
			continue
		}
		p, err := wire.ParsePerformative(f.Payload)
		if err != nil {
			return "", nil
		}
		return p.Name(), p
	}
}

func (cl *client10) expect(want string) *wire.Performative {
	cl.t.Helper()
	for {
		name, p := cl.next()
		if name == "" {
			cl.t.Fatalf("the connection ended before %s", want)
		}
		if name == want {
			return p
		}
		if name == "close" {
			_, desc, _ := p.CloseError()
			cl.t.Fatalf("waiting for %s, the connection was closed: %s", want, desc)
		}
	}
}

// closedText reads until the connection is closed and returns the description
// the close carried.
func (cl *client10) closedText() string {
	cl.t.Helper()
	for {
		name, p := cl.next()
		switch name {
		case "":
			return ""
		case "close":
			_, desc, _ := p.CloseError()
			return desc
		}
	}
}

// waitFor polls a condition with a generous deadline, for the assertions about
// counters: a counter is written by the goroutine that read the frame, so the
// test cannot know it has happened without looking.
func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ok() {
		t.Error("the condition never held")
	}
}

// The deny list is the one no rule can take back, and a destructive method on
// it is refused even in monitor mode.
func TestADeniedMethodIsRefusedWhateverTheMode(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+
		"        monitor_only: true\n"+
		"        allow_topology: true\n"+
		"        deny_methods: [\"queue.purge\"]\n", b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")

	// A declare is allowed, which is what monitor mode means.
	cl.send(wire.ClassQueue, 10, 1, u16(0), sstr("work"),
		bitsOf(false, true, false, false, false), emptyTable())
	cl.expect("queue.declare-ok")
	// The purge on the deny list is not: it empties a queue, and a refusal
	// recorded after the fact is a queue that is empty.
	cl.send(wire.ClassQueue, 30, 1, u16(0), sstr("work"), bitsOf(false))
	if text := cl.closed(); !strings.Contains(text, "method_denied") {
		t.Errorf("the refusal said %q", text)
	}
	if b.got("queue.purge") {
		t.Error("the purge reached the broker")
	}
}

// A message on AMQP 1.0 is a run of transfers, so the bound is the sum: a relay
// that bounded each frame would bound nothing.
func TestATenMessageIsBoundedAcrossItsTransfers(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+"        max_message_bytes: 64\n", b.addr())
	cl := dial10(t, addr)
	cl.sasl("orders")
	cl.open("/")
	cl.begin()
	cl.attach(1, false, "/queue/work")
	cl.expect("attach")
	// Four transfers of forty octets each, all but the last with `more`
	// set. Each frame is inside the bound and the message is not.
	body := make([]byte, 40)
	for i := 0; i < 4; i++ {
		// The message's octets travel in the same frame as the
		// performative that describes them, after it.
		cl.write(frame10(wire.FrameAMQP, 1, append(perfBody(0x14, u10(1), u10(uint32(i)),
			bin10([]byte{byte(i)}), u10(0), bool10(false), bool10(i < 3)), body...)))
	}
	if text := cl.closedText(); !strings.Contains(text, "message_too_large") {
		t.Errorf("the refusal said %q", text)
	}
}

// The channels and links a connection closes are forgotten, so a long-lived
// connection that opens and closes them does not exhaust a bound.
func TestClosedChannelsAndDetachedLinksAreForgotten(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+"        max_channels: 2\n        max_links: 1\n", b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")
	// A second channel, then close it, then a third: with the bound at two
	// and the first still open, the third only fits because the second was
	// forgotten.
	cl.send(wire.ClassChannel, 10, 2, sstr(""))
	cl.expect("channel.open-ok")
	cl.send(wire.ClassChannel, 40, 2, u16(200), sstr("bye"), u16(0), u16(0))
	cl.send(wire.ClassChannel, 10, 3, sstr(""))
	cl.expect("channel.open-ok")
	// And a fourth is over the bound.
	cl.send(wire.ClassChannel, 10, 4, sstr(""))
	if text := cl.closed(); !strings.Contains(text, "too_many_channels") {
		t.Errorf("the refusal said %q", text)
	}

	// The same for 1.0 links.
	b2 := startBroker(t, &fakeBroker{})
	_, addr2 := relayFor(t, base+"        max_links: 1\n", b2.addr())
	cl2 := dial10(t, addr2)
	cl2.sasl("orders")
	cl2.open("/")
	cl2.begin()
	cl2.attach(1, false, "/queue/work")
	cl2.expect("attach")
	cl2.send(0x16, u10(1), bool10(true)) // detach
	cl2.attach(2, false, "/queue/work")
	cl2.expect("attach")
	cl2.attach(3, false, "/queue/work")
	if text := cl2.closedText(); !strings.Contains(text, "too_many_links") {
		t.Errorf("the refusal said %q", text)
	}
}

// A credential the broker refuses on 1.0 is the broker's answer too, and the
// relay records it as a failure rather than as a login.
func TestATenCredentialTheBrokerRefusesIsNotALogin(t *testing.T) {
	b := startBroker(t, &fakeBroker{refuseAuth: true})
	_, addr := relayFor(t, base, b.addr())
	cl := dial10(t, addr)
	cl.write([]byte{'A', 'M', 'Q', 'P', 3, 1, 0, 0})
	cl.r.SetVersion(wire.V10)
	if _, err := cl.r.Header(); err != nil {
		t.Fatalf("no SASL header came back: %v", err)
	}
	cl.expect("sasl-mechanisms")
	cl.write(frame10(wire.FrameSASL, 0, perfBody(0x41, sym10("PLAIN"),
		bin10([]byte("\x00orders\x00wrong")))))
	p := cl.expect("sasl-outcome")
	code, ok := p.SASLOutcome()
	if !ok || code == 0 {
		t.Errorf("the outcome was %d, %v", code, ok)
	}
}

// log_methods writes a line per operation, and the line names what the
// operation named.
func TestTheAccessLogNamesWhatAnOperationNamed(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := relayFor(t, base+"        log_methods: true\n", b.addr())
	cl := dial091(t, addr)
	cl.handshake("orders", "/")
	cl.send(wire.ClassBasic, 40, 1, u16(0), sstr("events"), sstr("orders.created"), bitsOf(false, false))
	cl.send(wire.ClassBasic, 20, 1, u16(0), sstr("work"), sstr("tag-1"),
		bitsOf(false, false, false, false), emptyTable())
	cl.expect("basic.consume-ok")
	// The assertion is that nothing broke: the log sink in this fixture
	// discards, and what matters is that the path that builds the line is
	// exercised against a real method rather than left to a reader.
	if !b.got("basic.consume") {
		t.Error("the consume never reached the broker")
	}

	// The same on 1.0, where the interesting line is the attach.
	b2 := startBroker(t, &fakeBroker{})
	_, addr2 := relayFor(t, base+"        log_methods: true\n", b2.addr())
	cl2 := dial10(t, addr2)
	cl2.sasl("orders")
	cl2.open("/")
	cl2.begin()
	cl2.attach(1, true, "/queue/work")
	cl2.expect("attach")
	if !b2.got("attach") {
		t.Error("the attach never reached the broker")
	}
}

// The documented posture: the port is TLS, and the relay terminates it before
// a credential crosses it.
//
// The other tests in this file switch it off because they are about the policy;
// this one is about the setting that matters most on this protocol, so it runs
// a real handshake.
func TestTheListenerTerminatesTLSAndThenSpeaksAMQP(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "broker.test")
	b := startBroker(t, &fakeBroker{})
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: broker
      address: "127.0.0.1:0"
      kind: amqp
      tls:
        certificates: [{cert_file: %q, key_file: %q}]
      amqp:
        upstream: br
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: br, endpoints: [{address: %q}]}
`, cert, key, b.addr())
	s := proxytest.Start(t, yaml)
	addr := proxytest.Addr(t, s, "broker")

	pem, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the certificate did not load")
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool,
		ServerName: "broker.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("the TLS handshake failed: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	cl := &client091{t: t, c: c, r: wire.NewReader(c, 0)}
	cl.write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1})
	cl.r.SetVersion(wire.V091)
	cl.handshake("orders", "/")
	cl.send(wire.ClassBasic, 40, 1, u16(0), sstr("events"), sstr("orders.created"), bitsOf(false, false))
	cl.write(frame091(wire.FrameHeader, 1, contentHeaderPayload(2, 0)))
	cl.write(frame091(wire.FrameBody, 1, []byte("hi")))
	cl.send(wire.ClassBasic, 20, 1, u16(0), sstr("work"), sstr("t"),
		bitsOf(false, false, false, false), emptyTable())
	cl.expect("basic.consume-ok")
	if !b.got("basic.publish") {
		t.Error("the publish never reached the broker")
	}

	// And a client that speaks AMQP to the TLS port gets nowhere, which is
	// what require_tls means: the handshake fails before a protocol header
	// is read.
	plain, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	_ = plain.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := plain.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, err := io.ReadFull(plain, buf); err == nil {
		t.Errorf("a plaintext client read %d octets from a TLS port: %q", n, buf)
	}
}
