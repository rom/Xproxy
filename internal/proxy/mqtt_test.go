package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/mqtt"
	"github.com/rom/xproxy/internal/testutil"
)

// fakeBroker records every packet it was sent and answers the ones a
// session needs, so a test can prove what did and did not reach it.
type fakeBroker struct {
	ln net.Listener
	mu sync.Mutex
	// got holds the packets received, in order.
	got []mqtt.Packet
	// garbage answers the first packet with an unparseable one.
	garbage bool
}

func startBroker(t *testing.T, b *fakeBroker) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.session(c)
		}
	}()
	return b
}

func (b *fakeBroker) addr() string { return b.ln.Addr().String() }

func (b *fakeBroker) packets() []mqtt.Packet {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]mqtt.Packet(nil), b.got...)
}

// saw reports whether a packet of this type reached the broker, and the
// first one if so.
func (b *fakeBroker) saw(kind byte) (mqtt.Packet, bool) {
	for _, p := range b.packets() {
		if p.Type == kind {
			return p, true
		}
	}
	return mqtt.Packet{}, false
}

func (b *fakeBroker) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	version := byte(mqtt.V311)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		p, err := mqtt.ReadPacket(c, 1<<20)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.got = append(b.got, p)
		b.mu.Unlock()
		if b.garbage {
			// A remaining length that never terminates: the proxy must
			// refuse it rather than pass it on.
			_, _ = c.Write([]byte{mqtt.CONNACK << 4, 0x80, 0x80, 0x80, 0x80, 0x01})
			return
		}
		var reply mqtt.Packet
		switch p.Type {
		case mqtt.CONNECT:
			if cn, err := mqtt.ParseConnect(p); err == nil {
				version = cn.Version
			}
			body := []byte{0, 0}
			if version >= mqtt.V5 {
				body = append(body, 0)
			}
			reply = mqtt.Packet{Type: mqtt.CONNACK, Body: body}
		case mqtt.SUBSCRIBE:
			s, err := mqtt.ParseSubscribe(p, version)
			if err != nil {
				return
			}
			body := []byte{byte(s.PacketID >> 8), byte(s.PacketID)}
			if version >= mqtt.V5 {
				body = append(body, 0)
			}
			for range s.Filters {
				body = append(body, 0)
			}
			reply = mqtt.Packet{Type: mqtt.SUBACK, Body: body}
		case mqtt.PUBLISH:
			pub, err := mqtt.ParsePublish(p)
			if err != nil {
				return
			}
			if pub.QoS == 0 {
				continue
			}
			kind := byte(mqtt.PUBACK)
			if pub.QoS == 2 {
				kind = mqtt.PUBREC
			}
			body := []byte{byte(pub.PacketID >> 8), byte(pub.PacketID)}
			reply = mqtt.Packet{Type: kind, Body: body}
		case mqtt.PINGREQ:
			reply = mqtt.Packet{Type: mqtt.PINGRESP}
		case mqtt.DISCONNECT:
			return
		default:
			continue
		}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(reply.Encode()); err != nil {
			return
		}
	}
}

// mqttClient is the test's side of a session.
type mqttClient struct {
	t    *testing.T
	conn net.Conn
}

func dialMQTT(t *testing.T, addr string) *mqttClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &mqttClient{t: t, conn: c}
}

func (c *mqttClient) send(p mqtt.Packet) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(p.Encode()); err != nil {
		c.t.Fatalf("write %s: %v", p.Name(), err)
	}
}

func (c *mqttClient) read() (mqtt.Packet, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return mqtt.ReadPacket(c.conn, 1<<20)
}

func (c *mqttClient) expect(kind byte, what string) mqtt.Packet {
	c.t.Helper()
	p, err := c.read()
	if err != nil {
		c.t.Fatalf("%s: %v", what, err)
	}
	if p.Type != kind {
		c.t.Fatalf("%s: got %s, want type %d", what, p.Name(), kind)
	}
	return p
}

// expectClosed checks that the proxy ended the session.
func (c *mqttClient) expectClosed(what string) {
	c.t.Helper()
	for {
		p, err := c.read()
		if err != nil {
			return
		}
		// A v5 DISCONNECT may arrive before the close.
		if p.Type != mqtt.DISCONNECT {
			c.t.Fatalf("%s: session still open, got %s", what, p.Name())
		}
	}
}

func mqttConnect(version byte, clientID, username string) mqtt.Packet {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', version}
	var flags byte = 0x02
	if username != "" {
		flags |= 0x80
	}
	body = append(body, flags, 0, 60)
	if version >= mqtt.V5 {
		body = append(body, 0)
	}
	body = append(body, byte(len(clientID)>>8), byte(len(clientID)))
	body = append(body, clientID...)
	if username != "" {
		body = append(body, byte(len(username)>>8), byte(len(username)))
		body = append(body, username...)
	}
	return mqtt.Packet{Type: mqtt.CONNECT, Body: body}
}

func mqttPublish(topic string, qos byte, id uint16, retain bool, payload string) mqtt.Packet {
	flags := qos << 1
	if retain {
		flags |= 1
	}
	body := append([]byte{byte(len(topic) >> 8), byte(len(topic))}, topic...)
	if qos > 0 {
		body = append(body, byte(id>>8), byte(id))
	}
	body = append(body, payload...)
	return mqtt.Packet{Type: mqtt.PUBLISH, Flags: flags, Body: body}
}

func mqttSubscribe(id uint16, filters ...string) mqtt.Packet {
	body := []byte{byte(id >> 8), byte(id)}
	for _, f := range filters {
		body = append(body, byte(len(f)>>8), byte(len(f)))
		body = append(body, f...)
		body = append(body, 0)
	}
	return mqtt.Packet{Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: body}
}

const mqttYAML = `
version: 1
server:
  listeners:
    - name: iot
      address: "127.0.0.1:0"
      kind: mqtt
      mqtt:
        upstream: broker
        tls_mode: none
%s
logging: {access: {enabled: false}}
upstreams:
  - name: broker
    endpoints: [{address: %s}]
`

func mqttServerFor(t *testing.T, b *fakeBroker, extra string) (*Server, string) {
	t.Helper()
	s, _ := startServer(t, fmt.Sprintf(mqttYAML, extra, b.addr()))
	return s, s.Addrs()["iot"]
}

const mqttTopicPolicy = `        publish_allow: ["devices/+/telemetry"]
        publish_deny: ["devices/+/telemetry/private"]
        subscribe_allow: ["devices/+/commands"]
        subscribe_deny: ["$SYS/#"]`

// TestMQTTRelay walks a session that the policy allows and checks the
// packets reach the broker unchanged.
func TestMQTTRelay(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := mqttServerFor(t, b, mqttTopicPolicy)

	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, "device-1", "device-1"))
	if ack := c.expect(mqtt.CONNACK, "connack"); ack.Body[1] != 0 {
		t.Fatalf("connack code %d", ack.Body[1])
	}
	c.send(mqttSubscribe(1, "devices/1/commands"))
	c.expect(mqtt.SUBACK, "suback")
	c.send(mqttPublish("devices/1/telemetry", 1, 2, false, "21.5C"))
	c.expect(mqtt.PUBACK, "puback")
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")

	pub, ok := b.saw(mqtt.PUBLISH)
	if !ok {
		t.Fatal("the publication did not reach the broker")
	}
	if !bytes.Contains(pub.Body, []byte("21.5C")) {
		t.Fatalf("the payload was rewritten: %q", pub.Body)
	}
	sn := s.stats.snapshot()
	if sn.MQTTSessions != 1 || sn.MQTTPublished != 1 || sn.MQTTSubscribed != 1 {
		t.Fatalf("counters: %+v", struct{ S, P, Sub uint64 }{sn.MQTTSessions, sn.MQTTPublished, sn.MQTTSubscribed})
	}
}

// A publication outside the allow list, or inside the deny list, never
// reaches the broker.
func TestMQTTPublishPolicy(t *testing.T) {
	for _, tc := range []struct{ name, topic string }{
		{"outside the allow list", "devices/1/config"},
		{"inside the deny list", "devices/1/telemetry/private"},
		{"another device", "devices/2/telemetry/private"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := startBroker(t, &fakeBroker{})
			_, addr := mqttServerFor(t, b, mqttTopicPolicy)
			c := dialMQTT(t, addr)
			c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
			c.expect(mqtt.CONNACK, "connack")
			c.send(mqttPublish(tc.topic, 0, 0, false, "x"))
			c.expectClosed("refused publish")
			if _, ok := b.saw(mqtt.PUBLISH); ok {
				t.Fatal("the refused publication reached the broker")
			}
		})
	}
}

// With action: drop the session survives and the client is told, which
// is what keeps a QoS 1 publisher from retrying for ever.
func TestMQTTPublishDrop(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := mqttServerFor(t, b, mqttTopicPolicy+"\n        action: drop")
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	c.expect(mqtt.CONNACK, "connack")
	c.send(mqttPublish("devices/1/config", 1, 9, false, "x"))
	ack := c.expect(mqtt.PUBACK, "puback for the refused publish")
	if len(ack.Body) < 3 || ack.Body[2] != 0x87 {
		t.Fatalf("puback should carry not-authorized: %v", ack.Body)
	}
	// QoS 2 needs the whole exchange answered, or the client is stuck.
	c.send(mqttPublish("devices/1/config", 2, 10, false, "x"))
	c.expect(mqtt.PUBREC, "pubrec for the refused publish")
	c.send(mqtt.Packet{Type: mqtt.PUBREL, Flags: 0x02, Body: []byte{0, 10}})
	c.expect(mqtt.PUBCOMP, "pubcomp for the refused publish")
	// The session still works.
	c.send(mqttPublish("devices/1/telemetry", 1, 11, false, "ok"))
	c.expect(mqtt.PUBACK, "puback for the allowed publish")
	if _, ok := b.saw(mqtt.PUBREL); ok {
		t.Fatal("a PUBREL for a publication the broker never saw was forwarded")
	}
}

// A filter is not a topic: "#" must not pass an allow list of
// "devices/+/commands", and nothing may reach a denied subtree.
func TestMQTTSubscribePolicy(t *testing.T) {
	for _, tc := range []struct{ name, filter string }{
		{"the firehose", "#"},
		{"a wildcard wider than the allowance", "devices/#"},
		{"another subtree", "billing/+/commands"},
		{"the broker's own tree", "$SYS/#"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := startBroker(t, &fakeBroker{})
			_, addr := mqttServerFor(t, b, mqttTopicPolicy)
			c := dialMQTT(t, addr)
			c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
			c.expect(mqtt.CONNACK, "connack")
			c.send(mqttSubscribe(1, tc.filter))
			c.expectClosed("refused subscribe")
			if _, ok := b.saw(mqtt.SUBSCRIBE); ok {
				t.Fatal("the refused subscription reached the broker")
			}
		})
	}
}

// With action: drop a refused SUBSCRIBE is answered with a failure code
// for every filter, and the session continues.
func TestMQTTSubscribeDrop(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := mqttServerFor(t, b, mqttTopicPolicy+"\n        action: drop")
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, "device-1", "device-1"))
	c.expect(mqtt.CONNACK, "connack")
	c.send(mqttSubscribe(3, "devices/1/commands", "#"))
	ack := c.expect(mqtt.SUBACK, "suback")
	if len(ack.Body) != 4 || ack.Body[2] != 0x80 || ack.Body[3] != 0x80 {
		t.Fatalf("every filter should be refused: %v", ack.Body)
	}
	if _, ok := b.saw(mqtt.SUBSCRIBE); ok {
		t.Fatal("a partially refused subscription reached the broker")
	}
	c.send(mqttSubscribe(4, "devices/1/commands"))
	c.expect(mqtt.SUBACK, "suback for the allowed subscription")
}

// The CONNECT checks: version, client id, username and the will, each
// answered with the code its version spells it with.
func TestMQTTConnectPolicy(t *testing.T) {
	cases := []struct {
		name    string
		extra   string
		packet  mqtt.Packet
		wantV5  byte
		want311 byte
	}{
		{"version refused", "        versions: [\"5.0\"]", mqttConnect(mqtt.V311, "d", "u"), 0, 0x01},
		{"no username", "        require_auth: true", mqttConnect(mqtt.V5, "d", ""), 0x87, 0},
		{"empty client id", "        allow_empty_client_id: false", mqttConnect(mqtt.V5, "", "u"), 0x85, 0},
		{"client id too long", "        max_client_id: 4", mqttConnect(mqtt.V5, "much-too-long", "u"), 0x85, 0},
		{"client id pattern", "        client_id_pattern: \"^device-[0-9]+$\"", mqttConnect(mqtt.V5, "intruder", "u"), 0x85, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := startBroker(t, &fakeBroker{})
			_, addr := mqttServerFor(t, b, tc.extra)
			c := dialMQTT(t, addr)
			c.send(tc.packet)
			ack := c.expect(mqtt.CONNACK, "connack")
			want := tc.wantV5
			if tc.want311 != 0 {
				want = tc.want311
			}
			if ack.Body[1] != want {
				t.Fatalf("got code %#x want %#x", ack.Body[1], want)
			}
			if _, ok := b.saw(mqtt.CONNECT); ok {
				t.Fatal("the refused CONNECT reached the broker")
			}
			c.expectClosed("refused connect")
		})
	}
}

// A will is a message the broker publishes for the client after it is
// gone, so it goes through the publish policy like any other.
func TestMQTTWillPolicy(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := mqttServerFor(t, b, mqttTopicPolicy)
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', mqtt.V5, 0x02 | 0x04, 0, 60, 0}
	body = append(body, 0, 1, 'd') // client id
	body = append(body, 0)         // will properties
	body = append(body, 0, 5, 'a', 'd', 'm', 'i', 'n')
	body = append(body, 0, 1, 'x') // will payload
	c := dialMQTT(t, addr)
	c.send(mqtt.Packet{Type: mqtt.CONNECT, Body: body})
	ack := c.expect(mqtt.CONNACK, "connack")
	if ack.Body[1] != 0x87 {
		t.Fatalf("a will outside the policy should be refused: %#x", ack.Body[1])
	}
	if _, ok := b.saw(mqtt.CONNECT); ok {
		t.Fatal("the refused CONNECT reached the broker")
	}
}

// A session begins with CONNECT. A first packet of any other type never
// reaches the broker.
func TestMQTTFirstPacket(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := mqttServerFor(t, b, mqttTopicPolicy)
	c := dialMQTT(t, addr)
	c.send(mqttPublish("devices/1/telemetry", 0, 0, false, "x"))
	c.expectClosed("publish before connect")
	if len(b.packets()) != 0 {
		t.Fatal("something reached the broker before CONNECT")
	}
}

// A second CONNECT would take a new identity on a session already
// authorised as another.
func TestMQTTSecondConnect(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := mqttServerFor(t, b, mqttTopicPolicy)
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	c.expect(mqtt.CONNACK, "connack")
	c.send(mqttConnect(mqtt.V5, "device-2", "device-2"))
	c.expectClosed("second connect")
	n := 0
	for _, p := range b.packets() {
		if p.Type == mqtt.CONNECT {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the broker saw %d CONNECT packets", n)
	}
}

// A packet over the bound is refused before its body is read, and the
// session ends: its length is what the next read depends on.
func TestMQTTPacketTooLarge(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := mqttServerFor(t, b, mqttTopicPolicy+"\n        max_packet_size: 2048")
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	c.expect(mqtt.CONNACK, "connack")
	c.send(mqttPublish("devices/1/telemetry", 0, 0, false, string(bytes.Repeat([]byte{'x'}, 4096))))
	c.expectClosed("oversize publish")
	if _, ok := b.saw(mqtt.PUBLISH); ok {
		t.Fatal("the oversize publication reached the broker")
	}
}

// A malformed packet ends the session with nothing forwarded.
func TestMQTTMalformed(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := mqttServerFor(t, b, mqttTopicPolicy)
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	c.expect(mqtt.CONNACK, "connack")
	// A PUBLISH at QoS 3, which no version has.
	c.send(mqtt.Packet{Type: mqtt.PUBLISH, Flags: 0x06, Body: []byte{0, 1, 'a', 0, 1}})
	c.expectClosed("malformed publish")
	if _, ok := b.saw(mqtt.PUBLISH); ok {
		t.Fatal("the malformed packet reached the broker")
	}
	if sn := s.stats.snapshot(); sn.MQTTProtocolErrors == 0 {
		t.Fatal("the violation was not counted")
	}
}

// A broker packet the proxy cannot parse is not passed on: its framing
// is what the client's next read depends on.
func TestMQTTBrokerGarbage(t *testing.T) {
	b := startBroker(t, &fakeBroker{garbage: true})
	s, addr := mqttServerFor(t, b, mqttTopicPolicy)
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	if _, err := c.read(); err == nil {
		t.Fatal("the unparseable packet was passed through")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		// Any close is fine; what matters is that nothing was relayed.
		_ = err
	}
	if sn := s.stats.snapshot(); sn.MQTTProtocolErrors == 0 {
		t.Fatal("the violation was not counted")
	}
}

// A client outside allow_clients never reaches the broker.
func TestMQTTAllowClients(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := mqttServerFor(t, b, "        allow_clients: [\"192.0.2.0/24\"]")
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	c.expectClosed("denied client")
	if len(b.packets()) != 0 {
		t.Fatal("a denied client reached the broker")
	}
	if sn := s.stats.snapshot(); sn.MQTTRejected == 0 {
		t.Fatal("the refusal was not counted")
	}
}

// Implicit TLS on the listener and to the broker, which is the only
// shape MQTT has: there is no in-band upgrade.
func TestMQTTTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "iot.test")
	bcert, bkey := ca.Issue(t, dir, "broker.test")
	pair, err := tls.LoadX509KeyPair(bcert, bkey)
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b.ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = b.ln.Close() })
	go func() {
		for {
			c, err := b.ln.Accept()
			if err != nil {
				return
			}
			go b.session(c)
		}
	}()

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: iot
      address: "127.0.0.1:0"
      kind: mqtt
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      mqtt:
        upstream: broker
        publish_allow: ["devices/+/telemetry"]
        upstream_tls_mode: implicit
        upstream_tls: {server_name: broker.test, ca_file: %s}
logging: {access: {enabled: false}}
upstreams:
  - name: broker
    endpoints: [{address: %s}]
`, cert, key, ca.Path, ln.Addr().String())
	s, _ := startServer(t, yaml)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	conn, err := tls.Dial("tcp", s.Addrs()["iot"], &tls.Config{ServerName: "iot.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	c := &mqttClient{t: t, conn: conn}
	c.send(mqttConnect(mqtt.V5, "device-1", "device-1"))
	c.expect(mqtt.CONNACK, "connack over TLS")
	if _, ok := b.saw(mqtt.CONNECT); !ok {
		t.Fatal("the CONNECT did not reach the broker")
	}
}
