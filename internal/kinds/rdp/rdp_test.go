package rdp_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/rdp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/testutil"
)

// desktop is a Remote Desktop server as far as the gateway is
// concerned: it completes the connection sequence and keeps what
// reached it, so a test can see what the policy let through.
type desktop struct {
	ln *net.Listener
	// protocol is what it selects in the negotiation, and tlsCfg the
	// certificate it presents when that protocol is TLS.
	protocol uint32
	tlsCfg   *tls.Config
	// ioChannel and the identifiers it hands out.
	ioChannel uint16
	// shown is written to the client once the sequence is done.
	shown []byte

	mu sync.Mutex
	// channels is the list the gateway asked for, which is where a
	// refused channel shows up under another name.
	channels []rdp.Channel
	// info is the credential that arrived, and devices the redirection
	// announcement. sawAnnounce tells an announcement of no devices
	// from no announcement at all, which is the difference between a
	// policy that refused everything and one that never ran.
	info        *rdp.ClientInfo
	devices     []rdp.Device
	sawAnnounce bool
	// got is everything that came in on a channel, so a test can check
	// that a refused one carried nothing.
	got map[uint16][]byte
	// push carries payloads for the desktop to send *down* a channel. The
	// dynamic channel extension needs it: the desktop is the side that opens
	// a dynamic channel, so a test about that policy has to drive the
	// desktop-to-client direction rather than the other one.
	push chan pushed
}

// pushed is one payload the desktop sends down a channel.
type pushed struct {
	channel uint16
	payload []byte
}

func startDesktop(t *testing.T, d *desktop) *desktop {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.ln = &ln
	d.ioChannel = 1003
	d.got = map[uint16][]byte{}
	if d.shown == nil {
		d.shown = []byte("DESKTOP-UPDATE")
	}
	if d.push == nil {
		d.push = make(chan pushed, 8)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c)
		}
	}()
	return d
}

func (d *desktop) addr() string { return (*d.ln).Addr().String() }

func (d *desktop) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	pdu, err := rdp.ReadPDU(c)
	if err != nil {
		return
	}
	if _, err := rdp.ParseConnectionRequest(pdu.Body); err != nil {
		return
	}
	out, err := rdp.ConnectionConfirm{Protocol: d.protocol, HasNegotiation: true}.Encode()
	if err != nil {
		return
	}
	if _, err := c.Write(out); err != nil {
		return
	}
	if d.protocol == rdp.ProtocolSSL && d.tlsCfg != nil {
		tc := tls.Server(c, d.tlsCfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		c = tc
	}
	// The conference exchange: read the client's half, answer with an
	// identifier per channel it asked for.
	pdu, err = rdp.ReadPDU(c)
	if err != nil {
		return
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		return
	}
	conn, err := rdp.ParseConnect(payload)
	if err != nil {
		return
	}
	blocks, err := conn.Walk()
	if err != nil {
		return
	}
	var list []rdp.Channel
	for _, b := range blocks {
		if b.Type == rdp.BlockClientNetwork {
			if list, err = rdp.ParseChannels(b.Data); err != nil {
				return
			}
		}
	}
	d.mu.Lock()
	d.channels = list
	d.mu.Unlock()

	sc := rdp.ServerChannels{IOChannel: d.ioChannel}
	for i := range list {
		sc.IDs = append(sc.IDs, uint16(1004+i))
	}
	scData, err := sc.Encode()
	if err != nil {
		return
	}
	resp := buildResponse(scData)
	if _, err := c.Write(resp); err != nil {
		return
	}
	// What the desktop shows travels as a fast path update, which is
	// how a real one sends the screen.
	if _, err := c.Write(fastPath(d.shown)); err != nil {
		return
	}
	// And anything a test asks the desktop to send down a channel.
	if d.push != nil {
		go func() {
			for p := range d.push {
				data := rdp.SendData{Initiator: 1002, Channel: p.channel,
					Priority: 0x70, Payload: p.payload}
				out, err := rdp.DataPDU(data.Encode())
				if err != nil {
					return
				}
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
	// Then whatever the client sends, kept per channel.
	for {
		pdu, err := rdp.ReadPDU(c)
		if err != nil {
			return
		}
		payload, err := rdp.X224Payload(pdu.Body)
		if err != nil {
			continue
		}
		data, ok, err := rdp.ParseSendData(payload)
		if err != nil || !ok {
			continue
		}
		d.mu.Lock()
		d.got[data.Channel] = append(d.got[data.Channel], data.Payload...)
		d.mu.Unlock()
		d.inspect(data)
	}
}

// inspect keeps the two payloads a test asks about.
func (d *desktop) inspect(data rdp.SendData) {
	if data.Channel == d.ioChannel {
		head, rest, err := rdp.ParseSecurityHeader(data.Payload)
		if err != nil || head.Flags&rdp.SecInfoPkt == 0 {
			return
		}
		if info, err := rdp.ParseClientInfo(rest); err == nil {
			d.mu.Lock()
			d.info = info
			d.mu.Unlock()
		}
		return
	}
	chunk, err := rdp.ParseChannelChunk(data.Payload)
	if err != nil || !rdp.IsDeviceAnnounce(chunk.Data) {
		return
	}
	if devices, err := rdp.ParseDeviceAnnounce(chunk.Data); err == nil {
		d.mu.Lock()
		d.devices, d.sawAnnounce = devices, true
		d.mu.Unlock()
	}
}

func (d *desktop) asked() []rdp.Channel {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]rdp.Channel(nil), d.channels...)
}

func (d *desktop) credential() *rdp.ClientInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.info
}

func (d *desktop) redirected() ([]rdp.Device, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]rdp.Device(nil), d.devices...), d.sawAnnounce
}

func (d *desktop) seen(channel uint16) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.got[channel]...)
}

// buildResponse assembles the desktop's half of the conference
// exchange around a server network block.
func buildResponse(scData []byte) []byte {
	block := func(typ uint16, data []byte) []byte {
		head := make([]byte, 4)
		binary.LittleEndian.PutUint16(head[0:2], typ)
		binary.LittleEndian.PutUint16(head[2:4], uint16(len(data)+4))
		return append(head, data...)
	}
	blocks := append(block(rdp.BlockServerCore, []byte{0x04, 0x00, 0x08, 0x00}),
		block(rdp.BlockServerNetwork, scData)...)
	blocks = append(blocks, block(rdp.BlockServerSecurity, make([]byte, 8))...)

	inner := []byte{0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00}
	inner = append(inner, []byte("Duca")...)
	inner = append(inner, perLen(len(blocks))...)
	inner = append(inner, blocks...)
	gcc := append([]byte{0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01}, perLen(len(inner))...)
	gcc = append(gcc, inner...)

	var body []byte
	field := func(tag byte, content []byte) {
		body = append(body, tag)
		body = append(body, berLen(len(content))...)
		body = append(body, content...)
	}
	field(0x0A, []byte{0x00})
	field(0x02, []byte{0x00})
	field(0x30, bytes.Repeat([]byte{0x02, 0x01, 0x02}, 8))
	field(0x04, gcc)

	out := append([]byte{0x7F, 0x66}, berLen(len(body))...)
	out = append(out, body...)
	pdu, err := rdp.DataPDU(out)
	if err != nil {
		panic(err)
	}
	return pdu
}

func perLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{byte(0x80 | n>>8), byte(n)}
}

func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// gateway starts a server with one rdp listener in front of d.
func gateway(t *testing.T, d *desktop, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desks
      address: "127.0.0.1:0"
      kind: rdp
      rdp:
        upstream: farm
%s
logging: {access: {enabled: false}}
upstreams:
  - name: farm
    endpoints: [{address: %s}]
`, extra, d.addr())
	s := proxytest.Start(t, yaml)
	return s, proxytest.Addr(t, s, "desks")
}

// certs writes a certificate for the listener and returns the paths
// and a pool that trusts it. The desktop presents the same one, since
// what is being tested is the policy rather than a public key
// infrastructure.
func certs(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "gate.test")
	pem, err := os.ReadFile(cert) //nolint:gosec // the test wrote this path
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the test certificate did not parse")
	}
	return cert, key, pool
}

// serverTLS builds what the desktop presents.
func serverTLS(t *testing.T, cert, key string) *tls.Config {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
}

// client is enough of a Remote Desktop client to drive the gateway.
type client struct {
	t  *testing.T
	c  net.Conn
	io uint16
	// ids are the identifiers the gateway passed back, in the order
	// the channels were asked for.
	ids []uint16
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, c: c}
}

func (cl *client) write(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

// negotiate asks for a protocol and returns what the gateway chose,
// moving into TLS where that is what was agreed.
func (cl *client) negotiate(want uint32, pool *x509.CertPool) uint32 {
	cl.t.Helper()
	req, err := rdp.ConnectionRequest{Protocols: want, HasNegotiation: true,
		Cookie: "Cookie: mstshash=alice"}.Encode()
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(req)
	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		cl.t.Fatalf("negotiation: %v", err)
	}
	cc, err := rdp.ParseConnectionConfirm(pdu.Body)
	if err != nil {
		cl.t.Fatal(err)
	}
	if cc.Failure != 0 {
		return 0
	}
	if cc.Protocol == rdp.ProtocolSSL {
		tc := tls.Client(cl.c, &tls.Config{ServerName: "gate.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			cl.t.Fatalf("tls: %v", err)
		}
		cl.c = tc
	}
	return cc.Protocol
}

// conference asks for these channels and reads back the identifiers.
func (cl *client) conference(names ...string) {
	cl.t.Helper()
	list := make([]rdp.Channel, 0, len(names))
	for _, n := range names {
		list = append(list, rdp.Channel{Name: n, Options: rdp.ChannelOptionInitialized})
	}
	data, err := rdp.EncodeChannels(list)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(buildInitial(data))

	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		cl.t.Fatalf("conference: %v", err)
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		cl.t.Fatal(err)
	}
	conn, err := rdp.ParseConnect(payload)
	if err != nil {
		cl.t.Fatal(err)
	}
	blocks, err := conn.Walk()
	if err != nil {
		cl.t.Fatal(err)
	}
	for _, b := range blocks {
		if b.Type != rdp.BlockServerNetwork {
			continue
		}
		sc, err := rdp.ParseServerChannels(b.Data)
		if err != nil {
			cl.t.Fatal(err)
		}
		cl.io, cl.ids = sc.IOChannel, sc.IDs
	}
	if cl.io == 0 {
		cl.t.Fatal("the gateway sent no server network block")
	}
}

// buildInitial assembles a client's half of the conference exchange.
func buildInitial(chans []byte) []byte {
	block := func(typ uint16, data []byte) []byte {
		head := make([]byte, 4)
		binary.LittleEndian.PutUint16(head[0:2], typ)
		binary.LittleEndian.PutUint16(head[2:4], uint16(len(data)+4))
		return append(head, data...)
	}
	blocks := append(block(rdp.BlockClientCore, bytes.Repeat([]byte{0xAB}, 216)),
		block(rdp.BlockClientSecurity, make([]byte, 8))...)
	blocks = append(blocks, block(rdp.BlockClientNetwork, chans)...)

	inner := []byte{0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00}
	inner = append(inner, []byte("Duca")...)
	inner = append(inner, perLen(len(blocks))...)
	inner = append(inner, blocks...)
	gcc := append([]byte{0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01}, perLen(len(inner))...)
	gcc = append(gcc, inner...)

	var body []byte
	field := func(tag byte, content []byte) {
		body = append(body, tag)
		body = append(body, berLen(len(content))...)
		body = append(body, content...)
	}
	params := bytes.Repeat([]byte{0x02, 0x01, 0x02}, 8)
	field(0x04, []byte{0x01})
	field(0x04, []byte{0x01})
	field(0x01, []byte{0xFF})
	field(0x30, params)
	field(0x30, params)
	field(0x30, params)
	field(0x04, gcc)

	out := append([]byte{0x7F, 0x65}, berLen(len(body))...)
	out = append(out, body...)
	pdu, err := rdp.DataPDU(out)
	if err != nil {
		panic(err)
	}
	return pdu
}

// send puts a payload on a channel.
func (cl *client) send(channel uint16, payload []byte) {
	cl.t.Helper()
	data := rdp.SendData{Request: true, Initiator: 1007, Channel: channel, Priority: 0x70, Payload: payload}
	pdu, err := rdp.DataPDU(data.Encode())
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(pdu)
}

// sendInfo puts a credential on the session channel.
func (cl *client) sendInfo(domain, user, pass string) {
	cl.t.Helper()
	info := &rdp.ClientInfo{CodePage: 0x409, Domain: domain, Username: user, Password: pass,
		Extra: bytes.Repeat([]byte{0xCD}, 20)}
	info.SetUnicode(true)
	body, err := info.Encode()
	if err != nil {
		cl.t.Fatal(err)
	}
	head := rdp.SecurityHeader{Flags: rdp.SecInfoPkt}
	cl.send(cl.io, append(head.Encode(), body...))
}

// sendDevices announces redirected devices on a channel.
func (cl *client) sendDevices(channel uint16, devices ...rdp.Device) {
	cl.t.Helper()
	msg, err := rdp.EncodeDeviceAnnounce(devices)
	if err != nil {
		cl.t.Fatal(err)
	}
	chunk := rdp.ChannelChunk{Total: uint32(len(msg)),
		Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast, Data: msg}
	cl.send(channel, chunk.Encode())
}

// fastPath wraps a payload as a fast path update.
func fastPath(data []byte) []byte {
	if n := len(data) + 2; n < 0x80 {
		return append([]byte{0x00, byte(n)}, data...)
	}
	n := len(data) + 3
	return append([]byte{0x00, byte(0x80 | n>>8), byte(n)}, data...)
}

// update reads one unit from the gateway and returns what it carried.
func (cl *client) update() []byte {
	cl.t.Helper()
	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		cl.t.Fatalf("update: %v", err)
	}
	return pdu.Body
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
