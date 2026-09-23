package rdp_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rdp"
)

// A desktop that speaks the protocol's own encryption and nothing
// else, which is what a gateway meets in front of equipment too old
// for TLS. What is under test is the session: that the key exchange
// happens at the point in the sequence where it belongs, that
// everything the client sends afterwards reaches the desktop
// encrypted, that what the desktop sends comes back decrypted, and
// that the policy and the recording still see plaintext.
//
// The desktop's half here uses the same package as the gateway's, so
// this proves the two halves fit together and the session is wired
// correctly. It is not an interoperability test against Windows: that
// needs a Windows desktop.

// legacyDesktop is the fake, with the key it hands out and the state
// of the session once the exchange is done.
type legacyDesktop struct {
	*desktop
	key    *rsa.PrivateKey
	method uint32
	level  uint32

	mu sync.Mutex
	// in decrypts what the client sent and out encrypts what the
	// desktop shows. They are the gateway's two keys the other way
	// round.
	in, out *rdp.Crypt
	// exchanged says the security exchange arrived, and plain holds
	// what was decrypted out of the packets that followed.
	exchanged bool
	plain     []byte
	// unencrypted counts packets that arrived in the clear after the
	// exchange, which would mean the gateway stopped encrypting.
	unencrypted int
	// input is what arrived on the fast path, which is how a client
	// sends keys and mouse movement once the session is running.
	input []byte
}

// testKey is a fixed five hundred and twelve bit key, which is the
// size the protocol's own certificates carry. It is written down
// rather than generated because the standard library will not generate
// one that small any more -- and rightly: it is a key an afternoon of
// somebody's time would factor, which is part of why this encryption
// is documented as protecting nothing.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	set := func(s string) *big.Int {
		v, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Fatalf("test key %q", s)
		}
		return v
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: set("b83b95042b57e10482b4e70c2294790cd0ed84beea62ee7964fba4af512023cf" +
				"86511c77252a9a2a3e3842735901b43dad53269ca4516592ee40838975a80149"),
			E: 65537,
		},
		Primes: []*big.Int{
			set("ea55fa04504075d17bf9b88dd0381ca2b1ef697b82e2da718756d0cabe22ac57"),
			set("c943d0e3c4740f8cf6720b3e51ee8afbebf69e49d9670024158a9558b43e3b5f"),
		},
	}
	// The private exponent follows from the primes, so only the primes
	// have to be right here.
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(key.Primes[0], one), new(big.Int).Sub(key.Primes[1], one))
	key.D = new(big.Int).ModInverse(big.NewInt(int64(key.E)), phi)
	if key.D == nil {
		t.Fatal("the test key does not invert")
	}
	if new(big.Int).Mul(key.Primes[0], key.Primes[1]).Cmp(key.N) != 0 {
		t.Fatal("the test key's primes do not make its modulus")
	}
	return key
}

// legacySecurityBlock renders the block a legacy desktop sends: the
// method, the level, its random, and the proprietary certificate that
// carries the key the client's random travels under.
func legacySecurityBlock(key *rsa.PrivateKey, method, level uint32, serverRandom []byte) []byte {
	// The key blob of MS-RDPBCGR 2.2.1.4.3.1.1.1: magic, lengths, the
	// exponent, then the modulus little-endian with eight bytes of
	// padding behind it.
	size := key.N.BitLen() / 8
	blob := []byte("RSA1")
	blob = binary.LittleEndian.AppendUint32(blob, uint32(size+8))
	blob = binary.LittleEndian.AppendUint32(blob, uint32(key.N.BitLen()))
	blob = binary.LittleEndian.AppendUint32(blob, uint32(size-1))
	blob = binary.LittleEndian.AppendUint32(blob, uint32(key.E)) //nolint:gosec // a test key
	modulus := key.N.Bytes()
	for i := len(modulus) - 1; i >= 0; i-- {
		blob = append(blob, modulus[i])
	}
	blob = append(blob, make([]byte, 8)...)

	cert := binary.LittleEndian.AppendUint32(nil, 1) // version
	cert = binary.LittleEndian.AppendUint32(cert, 1) // signature algorithm
	cert = binary.LittleEndian.AppendUint32(cert, 1) // key algorithm
	cert = binary.LittleEndian.AppendUint16(cert, 0x0006)
	cert = binary.LittleEndian.AppendUint16(cert, uint16(len(blob))) //nolint:gosec // a test key
	cert = append(cert, blob...)
	// The signature a real desktop puts here is made with a key
	// Microsoft published and a client checks; this gateway reads the
	// key and does not check it, which is one of the things that makes
	// this encryption worth as little as the documentation says.
	cert = binary.LittleEndian.AppendUint16(cert, 0x0008)
	cert = binary.LittleEndian.AppendUint16(cert, 64)
	cert = append(cert, make([]byte, 64)...)

	out := binary.LittleEndian.AppendUint32(nil, method)
	out = binary.LittleEndian.AppendUint32(out, level)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(serverRandom)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(cert)))
	out = append(out, serverRandom...)
	return append(out, cert...)
}

// startLegacyDesktop runs the fake.
func startLegacyDesktop(t *testing.T, method, level uint32) *legacyDesktop {
	t.Helper()
	d := &legacyDesktop{desktop: &desktop{protocol: rdp.ProtocolRDP}, key: testKey(t), method: method, level: level}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.ln = &ln
	d.ioChannel = 1003
	d.got = map[uint16][]byte{}
	d.shown = []byte("DESKTOP-UPDATE")
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serveLegacy(c)
		}
	}()
	return d
}

func (d *legacyDesktop) serveLegacy(c net.Conn) {
	defer func() { _ = c.Close() }()
	// The negotiation: a client asking for the legacy protocol sends
	// no negotiation request at all, and gets no negotiation answer.
	pdu, err := rdp.ReadPDU(c)
	if err != nil {
		return
	}
	if _, err := rdp.ParseConnectionRequest(pdu.Body); err != nil {
		return
	}
	out, err := rdp.ConnectionConfirm{}.Encode()
	if err != nil || func() error { _, e := c.Write(out); return e }() != nil {
		return
	}

	// The conference exchange.
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
	var methods uint32
	for _, b := range blocks {
		switch b.Type {
		case rdp.BlockClientNetwork:
			if list, err = rdp.ParseChannels(b.Data); err != nil {
				return
			}
		case rdp.BlockClientSecurity:
			if len(b.Data) >= 4 {
				methods = binary.LittleEndian.Uint32(b.Data[0:4])
			}
		}
	}
	if d.method != 0 && methods&d.method == 0 {
		// The gateway did not offer what this desktop wants, which is
		// a session that must not start.
		return
	}
	d.mu.Lock()
	d.channels = list
	d.mu.Unlock()

	serverRandom := make([]byte, rdp.RandomSize)
	if _, err := rand.Read(serverRandom); err != nil {
		return
	}
	sc := rdp.ServerChannels{IOChannel: d.ioChannel}
	for i := range list {
		sc.IDs = append(sc.IDs, uint16(1004+i)) //nolint:gosec // a short test list
	}
	scData, err := sc.Encode()
	if err != nil {
		return
	}
	resp, err := rdp.ParseConnect(mustPayload(buildResponse(scData)))
	if err != nil {
		return
	}
	if err := resp.Replace(rdp.BlockServerSecurity,
		legacySecurityBlock(d.key, d.method, d.level, serverRandom)); err != nil {
		return
	}
	answer, err := resp.Encode()
	if err != nil {
		return
	}
	if _, err := c.Write(answer); err != nil {
		return
	}

	for {
		pdu, err := rdp.ReadPDU(c)
		if err != nil {
			return
		}
		if pdu.FastPath {
			d.fastPath(pdu.Raw)
			continue
		}
		payload, err := rdp.X224Payload(pdu.Body)
		if err != nil {
			continue
		}
		data, ok, err := rdp.ParseSendData(payload)
		if err != nil || !ok {
			continue
		}
		if d.handle(c, data, serverRandom) {
			return
		}
	}
}

// fastPath takes one fast path unit from the gateway, which after the
// exchange has to be encrypted.
func (d *legacyDesktop) fastPath(raw []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.exchanged {
		return
	}
	if !rdp.FastPathEncrypted(raw) {
		d.unencrypted++
		return
	}
	plain, err := d.in.FastPathOpen(raw)
	if err != nil {
		d.unencrypted++
		return
	}
	d.input = append(d.input, plain...)
}

// handle takes one data unit from the gateway: the security exchange
// starts the encryption, and everything after it has to be encrypted.
func (d *legacyDesktop) handle(c net.Conn, data rdp.SendData, serverRandom []byte) (stop bool) {
	head, rest, err := rdp.ParseSecurityHeader(data.Payload)
	if err != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case head.Flags&rdp.SecExchangePkt != 0:
		if len(rest) < 4 {
			return true
		}
		n := int(binary.LittleEndian.Uint32(rest[0:4]))
		if n+4 > len(rest) {
			return true
		}
		clientRandom := d.unseal(rest[4 : 4+n])
		keys, err := rdp.DeriveKeys(d.method, clientRandom, serverRandom)
		if err != nil {
			return true
		}
		// The desktop's view of the two keys is the gateway's the
		// other way round.
		if d.in, err = rdp.NewCrypt(keys, keys.Encrypt, d.method); err != nil {
			return true
		}
		if d.out, err = rdp.NewCrypt(keys, keys.Decrypt, d.method); err != nil {
			return true
		}
		d.exchanged = true
		// What the desktop shows travels encrypted from here on.
		update, err := d.out.FastPathSeal(fastPath(d.shown))
		if err != nil {
			return true
		}
		_, _ = c.Write(update)
		return false
	case d.method == 0:
		// A desktop that asked for no encryption reads what arrives.
		return d.keep(head, data, rest)
	case !d.exchanged:
		return false
	case head.Flags&rdp.SecEncrypt == 0:
		d.unencrypted++
		return false
	}
	plain, err := d.in.Open(rest)
	if err != nil {
		return true
	}
	return d.keep(head, data, plain)
}

// keep reads the two payloads a test asks about out of the plaintext,
// whether it arrived that way or was decrypted here.
func (d *legacyDesktop) keep(head rdp.SecurityHeader, data rdp.SendData, plain []byte) bool {
	d.plain = append(d.plain, plain...)
	// The credential and the device announcement are read out of the
	// plaintext, exactly as the unencrypted desktop does.
	if head.Flags&rdp.SecInfoPkt != 0 {
		if info, err := rdp.ParseClientInfo(plain); err == nil {
			d.info = info
		}
		return false
	}
	if data.Channel != d.ioChannel {
		d.got[data.Channel] = append(d.got[data.Channel], plain...)
		if chunk, err := rdp.ParseChannelChunk(plain); err == nil && rdp.IsDeviceAnnounce(chunk.Data) {
			if devices, err := rdp.ParseDeviceAnnounce(chunk.Data); err == nil {
				d.devices, d.sawAnnounce = devices, true
			}
		}
	}
	return false
}

// unseal is the desktop's half of the key exchange: the raw RSA the
// protocol uses, with no padding scheme to speak of.
func (d *legacyDesktop) unseal(sealed []byte) []byte {
	// The value arrives little-endian with eight bytes of padding.
	if len(sealed) > 8 {
		sealed = sealed[:len(sealed)-8]
	}
	be := make([]byte, len(sealed))
	for i := range sealed {
		be[len(sealed)-1-i] = sealed[i]
	}
	m := new(big.Int).Exp(new(big.Int).SetBytes(be), d.key.D, d.key.N)
	out := m.Bytes()
	// Back to little-endian, at the length a random is.
	res := make([]byte, rdp.RandomSize)
	for i := 0; i < len(out) && i < rdp.RandomSize; i++ {
		res[i] = out[len(out)-1-i]
	}
	return res
}

func mustPayload(pdu []byte) []byte {
	body, err := rdp.X224Payload(pdu[4:])
	if err != nil {
		panic(err)
	}
	return body
}

// TestALegacyDesktopIsReachedEncrypted drives a whole session: a TLS
// client, a desktop that speaks only the protocol's own encryption,
// and the policy in between.
func TestALegacyDesktopIsReachedEncrypted(t *testing.T) {
	d := startLegacyDesktop(t, rdp.Encryption128Bit, rdp.EncryptionLevelClientCompatible)
	cert, key, pool := certs(t)
	s, addr := gateway(t, d.desktop, "        upstream_security: rdp\n"+
		"        channels: {allow: [rdpdr]}\n"+
		"        devices: {allow: [printer]}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference("rdpdr")
	cl.sendInfo("EXAMPLE", "alice", "secret")

	// What the desktop shows arrives at the client in the clear,
	// because the client's leg is TLS and the gateway took the
	// protocol's encryption off.
	if got := string(cl.update()); !strings.Contains(got, "DESKTOP-UPDATE") {
		t.Fatalf("the desktop's update did not arrive as plaintext: %q", got)
	}

	waitFor(t, "the credential", func() bool { return d.credentialSeen() != nil })
	info := d.credentialSeen()
	if info.Username != "alice" || info.Password != "secret" || info.Domain != "EXAMPLE" {
		t.Fatalf("credential %+v", info)
	}
	if !d.exchangeDone() {
		t.Fatal("the security exchange never reached the desktop")
	}
	if n := d.clearPackets(); n != 0 {
		t.Fatalf("%d packets reached the desktop unencrypted after the exchange", n)
	}

	// The device policy still applies, which is the point of being
	// inside the encryption rather than outside it.
	cl.sendDevices(cl.ids[0],
		rdp.Device{Type: rdp.DevicePrinter, ID: 1, Name: "PRN"},
		rdp.Device{Type: rdp.DeviceFilesystem, ID: 2, Name: "C"})
	waitFor(t, "the announcement", func() bool { _, ok := d.announcement(); return ok })
	devices, _ := d.announcement()
	if len(devices) != 1 || devices[0].Type != rdp.DevicePrinter {
		t.Fatalf("devices %+v", devices)
	}

	// Input travels the other way on the fast path, and has to be
	// encrypted going out as well as coming in.
	cl.write(fastPath([]byte("KEYSTROKES")))
	waitFor(t, "the input", func() bool { return strings.Contains(string(d.inputSeen()), "KEYSTROKES") })
	if n := d.clearPackets(); n != 0 {
		t.Fatalf("%d units reached the desktop unencrypted", n)
	}

	if n := s.Stats().RDPLegacySessions; n != 1 {
		t.Fatalf("rdp_legacy_sessions %d", n)
	}
}

// TestALegacyDesktopThatEncryptsNothing is the other configuration
// somebody has in the field: the protocol's own framing with the
// encryption turned off on the desktop. The session works and the
// gateway says so in the log rather than pretending otherwise.
func TestALegacyDesktopThatEncryptsNothing(t *testing.T) {
	d := startLegacyDesktop(t, 0, rdp.EncryptionLevelNone)
	cert, key, pool := certs(t)
	_, addr := gateway(t, d.desktop, "        upstream_security: rdp\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.sendInfo("", "bob", "pw")
	waitFor(t, "the credential", func() bool { return d.credentialSeen() != nil })
	if info := d.credentialSeen(); info.Username != "bob" {
		t.Fatalf("credential %+v", info)
	}
	if d.exchangeDone() {
		t.Fatal("a key exchange happened with a desktop that asked for no encryption")
	}
}

// TestAWeakerMethodIsUsedWhenTheDesktopAsksForIt: the forty bit method
// is what the oldest equipment has, and the derivation cuts the keys
// down for it. A session that silently failed here would be one this
// gateway exists to serve.
func TestAWeakerMethodIsUsedWhenTheDesktopAsksForIt(t *testing.T) {
	d := startLegacyDesktop(t, rdp.Encryption40Bit, rdp.EncryptionLevelLow)
	cert, key, pool := certs(t)
	_, addr := gateway(t, d.desktop, "        upstream_security: rdp\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.sendInfo("", "carol", "pw")
	waitFor(t, "the credential", func() bool { return d.credentialSeen() != nil })
	if info := d.credentialSeen(); info.Username != "carol" || info.Password != "pw" {
		t.Fatalf("credential %+v", info)
	}
	if n := d.clearPackets(); n != 0 {
		t.Fatalf("%d packets reached the desktop unencrypted", n)
	}
}

func (d *legacyDesktop) credentialSeen() *rdp.ClientInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.info
}

func (d *legacyDesktop) exchangeDone() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.exchanged
}

func (d *legacyDesktop) clearPackets() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.unencrypted
}

func (d *legacyDesktop) announcement() ([]rdp.Device, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.devices, d.sawAnnounce
}

func (d *legacyDesktop) inputSeen() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.input...)
}

// ---- a client on the protocol's own encryption ----

// legacyClient is enough of an old client to drive the gateway's
// server half: it reads the certificate, checks the signature the way
// a real client does, seals its random under the key it found and then
// speaks encrypted.
type legacyClient struct {
	*client
	method uint32
	// out encrypts towards the gateway and in decrypts what comes
	// back.
	out, in *rdp.Crypt
}

// negotiateLegacy asks for the legacy protocol, which a client does by
// naming no other.
func (cl *legacyClient) negotiateLegacy() uint32 {
	cl.t.Helper()
	req, err := rdp.ConnectionRequest{HasNegotiation: true, Cookie: "Cookie: mstshash=old"}.Encode()
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
	if !cc.HasNegotiation {
		return rdp.ProtocolRDP
	}
	return cc.Protocol
}

// conferenceLegacy runs the client's half of the exchange, reads the
// gateway's certificate, verifies it and performs the key exchange.
func (cl *legacyClient) conferenceLegacy(methods uint32) {
	cl.t.Helper()
	data, err := rdp.EncodeChannels(nil)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(buildInitialWithSecurity(data, methods))

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
	var secBlock []byte
	for _, b := range blocks {
		switch b.Type {
		case rdp.BlockServerNetwork:
			sc, err := rdp.ParseServerChannels(b.Data)
			if err != nil {
				cl.t.Fatal(err)
			}
			cl.io, cl.ids = sc.IOChannel, sc.IDs
		case rdp.BlockServerSecurity:
			secBlock = b.Data
		}
	}
	if secBlock == nil {
		cl.t.Fatal("the gateway sent no security block")
	}
	sec, err := rdp.ParseServerSecurity(secBlock)
	if err != nil {
		cl.t.Fatalf("the security block: %v", err)
	}
	if sec.PublicKey == nil || !sec.Proprietary {
		cl.t.Fatalf("no proprietary certificate: %+v", sec)
	}
	// What a real client checks, and the only thing it can: the
	// signature over the certificate's first six fields.
	cert := certificateFrom(cl.t, secBlock)
	blobLen := int(binary.LittleEndian.Uint16(cert[14:16]))
	if !rdp.VerifyProprietary(cert[:16+blobLen], cert[16+blobLen+4:]) {
		cl.t.Fatal("a real client would refuse the gateway's certificate")
	}
	cl.method = sec.Method

	random, err := rdp.NewRandom()
	if err != nil {
		cl.t.Fatal(err)
	}
	keys, err := rdp.DeriveKeys(sec.Method, random, sec.Random)
	if err != nil {
		cl.t.Fatal(err)
	}
	if cl.out, err = rdp.NewCrypt(keys, keys.Encrypt, sec.Method); err != nil {
		cl.t.Fatal(err)
	}
	if cl.in, err = rdp.NewCrypt(keys, keys.Decrypt, sec.Method); err != nil {
		cl.t.Fatal(err)
	}
	sealed, err := rdp.SealClientRandom(sec.PublicKey, random)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.send(cl.io, rdp.SecurityExchange(sealed))
}

// certificateFrom pulls the certificate out of a security block.
func certificateFrom(t *testing.T, block []byte) []byte {
	t.Helper()
	randomLen := int(binary.LittleEndian.Uint32(block[8:12]))
	certLen := int(binary.LittleEndian.Uint32(block[12:16]))
	return block[16+randomLen : 16+randomLen+certLen]
}

// sendInfoEncrypted puts a credential on the session channel the way a
// client does once the exchange is done.
func (cl *legacyClient) sendInfoEncrypted(domain, user, pass string) {
	cl.t.Helper()
	info := &rdp.ClientInfo{CodePage: 0x409, Domain: domain, Username: user, Password: pass,
		Extra: bytes.Repeat([]byte{0xCD}, 20)}
	info.SetUnicode(true)
	body, err := info.Encode()
	if err != nil {
		cl.t.Fatal(err)
	}
	sealed, err := cl.out.Seal(rdp.SecInfoPkt, body)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.send(cl.io, sealed)
}

// updateDecrypted reads one unit from the gateway and decrypts it.
func (cl *legacyClient) updateDecrypted() []byte {
	cl.t.Helper()
	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		cl.t.Fatalf("update: %v", err)
	}
	if !pdu.FastPath {
		return pdu.Body
	}
	if !rdp.FastPathEncrypted(pdu.Raw) {
		cl.t.Fatal("the gateway sent an unencrypted update after the key exchange")
	}
	plain, err := cl.in.FastPathOpen(pdu.Raw)
	if err != nil {
		cl.t.Fatalf("the gateway's update did not decrypt: %v", err)
	}
	return plain
}

// buildInitialWithSecurity is the client's half of the conference
// exchange with a security block saying what it can encrypt with.
func buildInitialWithSecurity(chans []byte, methods uint32) []byte {
	base := buildInitial(chans)
	payload, err := rdp.X224Payload(base[4:])
	if err != nil {
		panic(err)
	}
	conn, err := rdp.ParseConnect(payload)
	if err != nil {
		panic(err)
	}
	if err := conn.Replace(rdp.BlockClientSecurity, rdp.EncodeClientSecurity(methods)); err != nil {
		panic(err)
	}
	out, err := conn.Encode()
	if err != nil {
		panic(err)
	}
	return out
}

// TestALegacyClientIsServed drives the whole of the server half: an
// old client that speaks nothing but the protocol's own encryption
// reaches a desktop on TLS, and everything in between still applies.
func TestALegacyClientIsServed(t *testing.T) {
	cert, key, _ := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        security: [rdp, tls]\n"+
		"        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")

	cl := &legacyClient{client: dial(t, addr)}
	if got := cl.negotiateLegacy(); got != rdp.ProtocolRDP {
		t.Fatalf("the gateway chose %s", rdp.ProtocolName(got))
	}
	cl.conferenceLegacy(rdp.Encryption128Bit | rdp.Encryption56Bit | rdp.Encryption40Bit)
	if cl.method != rdp.Encryption128Bit {
		t.Fatalf("the gateway chose %s", rdp.EncryptionMethodName(cl.method))
	}
	cl.sendInfoEncrypted("EXAMPLE", "alice", "secret")

	// What the desktop shows comes back encrypted under the keys this
	// client just agreed.
	if got := string(cl.updateDecrypted()); !strings.Contains(got, "DESKTOP-UPDATE") {
		t.Fatalf("the desktop's update did not arrive: %q", got)
	}
	// And the credential reached the desktop in the clear, because the
	// gateway decrypted it, read it and forwarded it on a TLS leg.
	waitFor(t, "the credential", func() bool { return d.credential() != nil })
	info := d.credential()
	if info.Username != "alice" || info.Password != "secret" || info.Domain != "EXAMPLE" {
		t.Fatalf("credential %+v", info)
	}
	if n := s.Stats().RDPLegacyClients; n != 1 {
		t.Fatalf("rdp_legacy_clients %d", n)
	}
}

// TestALegacyClientWithNoMethodIsRefused: a client that offers only
// FIPS mode, which this gateway does not implement, is refused rather
// than answered with a method it cannot use.
func TestALegacyClientWithNoMethodIsRefused(t *testing.T) {
	cert, key, _ := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := gateway(t, d, "        security: [rdp, tls]\n"+
		"        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := &legacyClient{client: dial(t, addr)}
	if got := cl.negotiateLegacy(); got != rdp.ProtocolRDP {
		t.Fatalf("the gateway chose %s", rdp.ProtocolName(got))
	}
	data, err := rdp.EncodeChannels(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl.write(buildInitialWithSecurity(data, rdp.EncryptionFIPS))
	// The session ends rather than continuing without encryption.
	_ = cl.c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := rdp.ReadPDU(cl.c); err == nil {
		t.Fatal("the gateway answered a client it has no method for")
	}
}

// TestAnEncryptedPacketBeforeTheExchangeIsRefused: the order of the
// connection sequence is not the client's to choose.
func TestAnEncryptedPacketBeforeTheExchangeIsRefused(t *testing.T) {
	cert, key, _ := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := gateway(t, d, "        security: [rdp, tls]\n"+
		"        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := &legacyClient{client: dial(t, addr)}
	cl.negotiateLegacy()
	data, err := rdp.EncodeChannels(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl.write(buildInitialWithSecurity(data, rdp.Encryption128Bit))
	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		t.Fatalf("conference: %v", err)
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := rdp.ParseConnect(payload)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := conn.Walk()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		if b.Type == rdp.BlockServerNetwork {
			sc, err := rdp.ParseServerChannels(b.Data)
			if err != nil {
				t.Fatal(err)
			}
			cl.io = sc.IOChannel
		}
	}
	// A packet claiming to be encrypted, without the exchange that
	// would have made a key for it.
	head := rdp.SecurityHeader{Flags: rdp.SecInfoPkt | rdp.SecEncrypt}
	cl.send(cl.io, append(head.Encode(), bytes.Repeat([]byte{0xAA}, 40)...))
	_ = cl.c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := cl.c.Read(buf); err == nil {
		t.Fatal("the gateway kept talking to a client that skipped the key exchange")
	}
}

// TestBothLegsOnTheProtocolsOwnEncryption is the composition: an old
// client and an old desktop, each with its own keys, and the gateway
// decrypting one side and encrypting the other in between. Nothing is
// forwarded from one key schedule to the other, which is what makes
// the policy and the recording possible at all.
func TestBothLegsOnTheProtocolsOwnEncryption(t *testing.T) {
	d := startLegacyDesktop(t, rdp.Encryption128Bit, rdp.EncryptionLevelClientCompatible)
	s, addr := gateway(t, d.desktop, "        security: [rdp]\n"+
		"        upstream_security: rdp")

	cl := &legacyClient{client: dial(t, addr)}
	if got := cl.negotiateLegacy(); got != rdp.ProtocolRDP {
		t.Fatalf("the gateway chose %s", rdp.ProtocolName(got))
	}
	cl.conferenceLegacy(rdp.Encryption128Bit)
	cl.sendInfoEncrypted("", "dave", "pw")

	waitFor(t, "the credential", func() bool { return d.credentialSeen() != nil })
	if info := d.credentialSeen(); info.Username != "dave" || info.Password != "pw" {
		t.Fatalf("credential %+v", info)
	}
	if !d.exchangeDone() {
		t.Fatal("the desktop's key exchange never happened")
	}
	if n := d.clearPackets(); n != 0 {
		t.Fatalf("%d packets reached the desktop unencrypted", n)
	}
	// The desktop's update comes back under the client's keys, which
	// are not the desktop's.
	if got := string(cl.updateDecrypted()); !strings.Contains(got, "DESKTOP-UPDATE") {
		t.Fatalf("the desktop's update did not arrive: %q", got)
	}
	st := s.Stats()
	if st.RDPLegacyClients != 1 || st.RDPLegacySessions != 1 {
		t.Fatalf("counters: clients %d sessions %d", st.RDPLegacyClients, st.RDPLegacySessions)
	}
}

// TestALegacyOnlyListenerNeedsNoCertificate: a listener that offers
// only the protocol's own encryption has no TLS section, and that is a
// valid configuration rather than an oversight.
func TestALegacyOnlyListenerNeedsNoCertificate(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: desks
      address: "127.0.0.1:0"
      kind: rdp
      rdp: {upstream: farm, security: [rdp], upstream_security: rdp}
upstreams:
  - name: farm
    endpoints: [{address: 127.0.0.1:3389}]
`
	if _, err := config.Parse([]byte(yaml)); err != nil {
		t.Fatalf("a legacy-only listener was refused: %v", err)
	}
}
