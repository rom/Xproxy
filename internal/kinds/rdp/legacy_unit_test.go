package rdp

import (
	"bytes"
	"testing"

	"github.com/rom/xproxy/internal/rdp"
)

// The seam where this gateway's own encryption is applied, driven directly.
//
// The end-to-end test puts a client, this gateway and a fake desktop together
// and proves the three fit. What it cannot do is reach one direction at a time:
// `open` is only called on traffic a desktop sends, and a fake desktop that
// sends the awkward cases is a fake desktop nobody would write. So the pair is
// driven here, one unit at a time, because this is the code that decides
// whether something leaves this process in clear.

// legacyPair builds two legs with matched keys, the way the real session does:
// the client's leg takes Encrypt to decrypt with and Decrypt to encrypt with,
// and the desktop's leg takes them the other way round. Sealing on one and
// opening on the other is then exactly what crosses the gateway.
func legacyPair(t *testing.T) (client, desktop *legacyLeg) {
	t.Helper()
	clientRandom := bytes.Repeat([]byte{0xA5}, rdp.RandomSize)
	serverRandom := bytes.Repeat([]byte{0x5A}, rdp.RandomSize)
	keys, err := rdp.DeriveKeys(rdp.Encryption128Bit, clientRandom, serverRandom)
	if err != nil {
		t.Fatal(err)
	}
	newLeg := func(in, out []byte) *legacyLeg {
		l := &legacyLeg{method: rdp.Encryption128Bit, ready: make(chan struct{})}
		if l.in, err = rdp.NewCrypt(keys, in, rdp.Encryption128Bit); err != nil {
			t.Fatal(err)
		}
		if l.out, err = rdp.NewCrypt(keys, out, rdp.Encryption128Bit); err != nil {
			t.Fatal(err)
		}
		return l
	}
	// The gateway's client leg: in decrypts what the client sent.
	client = newLeg(keys.Encrypt, keys.Decrypt)
	// The desktop's leg as the desktop sees it: the mirror.
	desktop = newLeg(keys.Decrypt, keys.Encrypt)
	return client, desktop
}

// unit is a data unit on the session channel, which is what seal takes.
func unit() rdp.SendData {
	return rdp.SendData{Request: true, Initiator: 1007, Channel: 1003, Priority: 0x70}
}

// payloadOf pulls the data unit's payload back out of an encoded PDU, which is
// what the other end of the gateway would hand to its own reader.
func payloadOf(t *testing.T, pdu []byte) []byte {
	t.Helper()
	body, err := rdp.X224Payload(pdu[4:])
	if err != nil {
		t.Fatalf("X224: %v", err)
	}
	data, ok, err := rdp.ParseSendData(body)
	if err != nil || !ok {
		t.Fatalf("send data: %v (%v)", err, ok)
	}
	return data.Payload
}

// TestWhatIsSealedForTheDesktopIsWhatTheDesktopOpens is the round trip, and
// the first thing to establish: the two halves use the same derivation, so a
// payload sealed on one leg comes back byte for byte on the other. Everything
// below is a variation on it.
func TestWhatIsSealedForTheDesktopIsWhatTheDesktopOpens(t *testing.T) {
	client, desktop := legacyPair(t)
	client.exchange = []byte("EXCHANGE")

	// A payload with no security header of its own: the common case once the
	// session is running.
	pdu, err := client.seal(unit(), []byte("the first thing the client sent"))
	if err != nil {
		t.Fatal(err)
	}
	// The exchange travels in front of the first unit, so what comes out is two
	// PDUs: the exchange and then the sealed payload.
	if !client.exchanged {
		t.Error("the first seal did not mark the exchange as sent")
	}
	first := payloadOf(t, pdu)
	if !bytes.Equal(first, client.exchange) {
		t.Fatalf("the first PDU is not the exchange: %q", first)
	}
	rest := pdu[len(pdu)-lenOfSecond(t, pdu):]
	plain, err := desktop.open(payloadOf(t, rest))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "the first thing the client sent" {
		t.Errorf("round trip gave %q", plain)
	}

	// The second unit carries no exchange: a desktop that received it twice
	// would derive different keys and the session would stop.
	pdu, err = client.seal(unit(), []byte("the second"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err = desktop.open(payloadOf(t, pdu))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "the second" {
		t.Errorf("the second unit gave %q", plain)
	}
}

// lenOfSecond finds where the second PDU in a pair starts, by reading the TPKT
// length of the first.
func lenOfSecond(t *testing.T, pdu []byte) int {
	t.Helper()
	if len(pdu) < 4 {
		t.Fatal("not a TPKT")
	}
	n := int(pdu[2])<<8 | int(pdu[3])
	if n >= len(pdu) {
		t.Fatalf("the first PDU is the whole of it: %d of %d", n, len(pdu))
	}
	return len(pdu) - n
}

// TestTheSecurityHeaderIsPutBackOnlyWhereThePacketHasOne: the flags say what
// kind of packet it is, and the ones that carry a header have to keep it --
// while an ordinary session packet must not grow one, because the peer would
// read the first four octets of the payload as flags.
func TestTheSecurityHeaderIsPutBackOnlyWhereThePacketHasOne(t *testing.T) {
	client, desktop := legacyPair(t)
	client.exchange = []byte("x")
	client.exchanged = true

	cases := []struct {
		name   string
		flags  uint16
		header bool
	}{
		{"a licence packet keeps its header", rdp.SecLicensePkt, true},
		{"an info packet keeps its header", rdp.SecInfoPkt, true},
		{"an exchange packet keeps its header", rdp.SecExchangePkt, true},
		{"a session packet gets none", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte("payload")
			in := body
			if c.flags != 0 {
				in = append(rdp.SecurityHeader{Flags: c.flags}.Encode(), body...)
			}
			pdu, err := client.seal(unit(), in)
			if err != nil {
				t.Fatal(err)
			}
			out, err := desktop.open(payloadOf(t, pdu))
			if err != nil {
				t.Fatal(err)
			}
			if !c.header {
				if !bytes.Equal(out, body) {
					t.Fatalf("a session packet came back as %q", out)
				}
				return
			}
			head, rest, err := rdp.ParseSecurityHeader(out)
			if err != nil {
				t.Fatalf("no header on the way out: %v", err)
			}
			if head.Flags != c.flags {
				t.Errorf("flags %#04x, want %#04x", head.Flags, c.flags)
			}
			// The encrypt bit is the transport's and does not belong to the
			// packet: a peer told the packet was encrypted would try to
			// decrypt plaintext.
			if head.Flags&rdp.SecEncrypt != 0 {
				t.Error("the encrypt flag survived the decryption")
			}
			if !bytes.Equal(rest, body) {
				t.Errorf("payload %q", rest)
			}
		})
	}
}

// TestAPacketTheDesktopDidNotEncryptIsPassedThrough: a desktop at encryption
// level low sends everything in clear, and one in the middle of the connection
// sequence sends the sequence in clear whatever the level. Neither is an error,
// and neither may be handed to the decryption.
func TestAPacketTheDesktopDidNotEncryptIsPassedThrough(t *testing.T) {
	_, desktop := legacyPair(t)

	// No header at all: too short to parse, which is the connection sequence.
	raw := []byte{0x01, 0x02}
	out, err := desktop.open(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Errorf("passed through as %q", out)
	}

	// A header whose encrypt bit is clear.
	clear := append(rdp.SecurityHeader{Flags: rdp.SecLicensePkt}.Encode(), []byte("licence")...)
	out, err = desktop.open(clear)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, clear) {
		t.Errorf("a cleartext licence packet came back as %q", out)
	}
}

// TestAPacketThatDoesNotDecryptIsAnError: the signature is checked, so a
// desktop whose keys have diverged from this gateway's -- or anything on the
// path that rewrote a packet -- ends the session rather than being forwarded as
// whatever the plaintext came out as.
func TestAPacketThatDoesNotDecryptIsAnError(t *testing.T) {
	client, desktop := legacyPair(t)
	client.exchange, client.exchanged = []byte("x"), true

	pdu, err := client.seal(unit(), []byte("a payload long enough to matter"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := payloadOf(t, pdu)
	// Flip a bit in the ciphertext, past the header and the signature.
	damaged := append([]byte(nil), sealed...)
	damaged[len(damaged)-1] ^= 0x01
	if _, err := desktop.open(damaged); err == nil {
		t.Error("a packet with a damaged payload was accepted")
	}
}

// TestFastPathInputIsRefusedBeforeTheKeyExchange: input is what carries
// keystrokes, and a client that sends it before the exchange is not a client
// doing its sequence in an unusual order -- a desktop that has not seen the
// exchange cannot read it either way. Refusing is what keeps the keystrokes
// from going out in clear.
func TestFastPathInputIsRefusedBeforeTheKeyExchange(t *testing.T) {
	client, desktop := legacyPair(t)
	client.exchange = []byte("x")

	if _, err := client.sealFast([]byte{0x00, 0x04, 0x00, 0x00}); err == nil {
		t.Fatal("fast path input before the exchange was sealed")
	}

	// After the exchange it is sealed, and the desktop opens it.
	client.exchanged = true
	raw := []byte{0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	sealed, err := client.sealFast(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !rdp.FastPathEncrypted(sealed) {
		t.Fatal("the sealed unit does not say it is encrypted")
	}
	out, err := desktop.openFast(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Errorf("the fast path round trip gave %x, want %x", out, raw)
	}

	// A unit whose header does not claim encryption is left alone, which is
	// what a desktop at level low sends.
	if out, err := desktop.openFast(raw); err != nil || !bytes.Equal(out, raw) {
		t.Errorf("an unencrypted fast path unit: %x (%v)", out, err)
	}
}

// TestWhichUnitsHaveToWaitForTheKeys decides, for each shape of unit, whether
// it is session traffic that must be encrypted or part of the sequence that
// sets the encryption up. Getting it wrong one way stalls every connection at
// the gateway; the other way sends session traffic before there is a key for
// it, which is the direction that matters.
func TestWhichUnitsHaveToWaitForTheKeys(t *testing.T) {
	sendData, err := rdp.DataPDU(rdp.SendData{Request: false, Initiator: 1002,
		Channel: 1003, Priority: 0x70, Payload: []byte("session")}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	// An MCS unit that is not a send data: an attach user confirm, which is
	// part of the sequence and goes out before any key exists.
	notSendData, err := rdp.DataPDU([]byte{0x2E, 0x00, 0x00, 0x03, 0xEF})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  []byte
		want bool
	}{
		{"nothing at all", nil, false},
		{"a fast path unit is always session traffic", []byte{0x00, 0x04, 0x00, 0x00}, true},
		{"a send data unit is session traffic", sendData, true},
		{"an MCS unit that is not send data is the sequence", notSendData, false},
		{"a TPKT whose X224 payload does not parse", []byte{0x03, 0x00, 0x00, 0x05, 0x00}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := needsClientKeys(c.raw); got != c.want {
				t.Errorf("needsClientKeys = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSplitHeaderOnlyTakesAHeaderItRecognises: the flags decide whether the
// first four octets are a header or the payload itself, and a reader that took
// an unknown flag word as a header would cut four octets off a packet and
// encrypt the rest, which the peer cannot put back.
func TestSplitHeaderOnlyTakesAHeaderItRecognises(t *testing.T) {
	body := []byte("0123456789")
	cases := []struct {
		name      string
		in        []byte
		wantFlags uint16
		wantRest  []byte
	}{
		{"a licence header", append(rdp.SecurityHeader{Flags: rdp.SecLicensePkt}.Encode(), body...), rdp.SecLicensePkt, body},
		{"an info header", append(rdp.SecurityHeader{Flags: rdp.SecInfoPkt}.Encode(), body...), rdp.SecInfoPkt, body},
		// Flags this gateway does not know: the whole thing is payload.
		{"flags nobody defined", append(rdp.SecurityHeader{Flags: 0x4000}.Encode(), body...),
			0, append(rdp.SecurityHeader{Flags: 0x4000}.Encode(), body...)},
		// All zero flags: not a header either, which is how an ordinary
		// session packet beginning with four zero octets survives.
		{"no flags", append([]byte{0, 0, 0, 0}, body...), 0, append([]byte{0, 0, 0, 0}, body...)},
		{"too short to hold one", []byte{0x01}, 0, []byte{0x01}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags, rest := splitHeader(c.in)
			if flags != c.wantFlags {
				t.Errorf("flags %#04x, want %#04x", flags, c.wantFlags)
			}
			if !bytes.Equal(rest, c.wantRest) {
				t.Errorf("rest %q, want %q", rest, c.wantRest)
			}
		})
	}
}

// TestWhatGoesToTheClientIsSealedWhereItHasToBe is the other direction, and
// the asymmetry in it is the point: on a leg this gateway encrypts, a unit of
// the session has to be sealed, while a unit of the connection sequence has to
// go out as it is -- a client that received an encrypted channel join confirm
// could not read it, and one that received a cleartext session packet after
// agreeing to encryption could not read that either.
func TestWhatGoesToTheClientIsSealedWhereItHasToBe(t *testing.T) {
	leg, mirror := legacyPair(t)
	close(leg.ready) // the exchange has happened: the keys exist
	se := &session{clientLegacy: leg}

	// A fast path unit is session traffic, so it is sealed, and the client's
	// own half opens it.
	raw := []byte{0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	out, reason := se.toClient(raw)
	if reason != "" {
		t.Fatalf("fast path: %s", reason)
	}
	if !rdp.FastPathEncrypted(out) {
		t.Error("the fast path unit went out in clear")
	}
	if plain, err := mirror.in.FastPathOpen(out); err != nil || !bytes.Equal(plain, raw) {
		t.Errorf("the client could not open it: %x (%v)", plain, err)
	}

	// A data unit on the session channel is sealed inside its MCS wrapper, so
	// the wrapper still parses and the payload does not.
	pdu, err := rdp.DataPDU(rdp.SendData{Request: false, Initiator: 1002, Channel: 1003,
		Priority: 0x70, Payload: []byte("what the desktop is showing")}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	out, reason = se.toClient(pdu)
	if reason != "" {
		t.Fatalf("send data: %s", reason)
	}
	sealed := payloadOf(t, out)
	if bytes.Contains(sealed, []byte("showing")) {
		t.Error("the payload went to the client in clear")
	}
	head, rest, err := rdp.ParseSecurityHeader(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if head.Flags&rdp.SecEncrypt == 0 {
		t.Error("the header does not say the payload is encrypted")
	}
	if plain, err := mirror.in.Open(rest); err != nil {
		t.Errorf("the client could not open it: %v", err)
	} else if string(plain) != "what the desktop is showing" {
		t.Errorf("round trip gave %q", plain)
	}

	// The units that are not session traffic go out as they are.
	notSendData, err := rdp.DataPDU([]byte{0x2E, 0x00, 0x00, 0x03, 0xEF})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"an MCS unit that is not send data", notSendData},
		{"a TPKT whose X224 payload does not parse", []byte{0x03, 0x00, 0x00, 0x05, 0x00}},
	} {
		out, reason := se.toClient(c.in)
		if reason != "" {
			t.Errorf("%s: %s", c.name, reason)
			continue
		}
		if !bytes.Equal(out, c.in) {
			t.Errorf("%s was rewritten: %x", c.name, out)
		}
	}

	// A session with no legacy leg at all -- the ordinary TLS case -- changes
	// nothing, which is what keeps this seam out of the way of every other
	// listener.
	plainSession := &session{}
	if out, reason := plainSession.toClient(raw); reason != "" || !bytes.Equal(out, raw) {
		t.Errorf("a TLS session rewrote a unit: %x (%s)", out, reason)
	}
}

// TestTheCertificateKindIsWhatTheDesktopSent: the kind goes in the access log
// beside the method and the level, and "none" is the one worth being able to
// find -- a desktop that sent no certificate is one whose key nothing vouched
// for.
func TestTheCertificateKindIsWhatTheDesktopSent(t *testing.T) {
	if got := certificateKind(&rdp.ServerSecurity{Proprietary: true}); got != "proprietary" {
		t.Errorf("a proprietary certificate is %q", got)
	}
	if got := certificateKind(&rdp.ServerSecurity{}); got != "none" {
		t.Errorf("no certificate is %q", got)
	}
}

// TestAPacketThatIsNotTheCredentialPassesThroughUntouched: the session channel
// carries the whole session, and exactly one packet on it is this gateway's
// business -- the client info packet with the credential in it. Everything else
// has to cross with nothing of its own changed, because a gateway that rewrote
// session traffic would be a gateway that broke the desktop.
func TestAPacketThatIsNotTheCredentialPassesThroughUntouched(t *testing.T) {
	// No legacy leg: the ordinary TLS case, where passing through means
	// rewrapping and nothing else.
	se := &session{}
	cases := []struct {
		name    string
		payload []byte
	}{
		// Shorter than a security header, which is most of the connection
		// sequence.
		{"too short to hold a header", []byte{0x01, 0x02}},
		// A header that is not the credential: a licence packet.
		{"a licence packet", append(rdp.SecurityHeader{Flags: rdp.SecLicensePkt}.Encode(), []byte("licence")...)},
		// Session traffic whose first four octets are not a header. They are
		// spelled out rather than written as text because text is a trap
		// here: the four octets of "a sc" happen to set the info bit, and a
		// payload that looks like a credential packet is treated as one.
		{"session traffic", append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("a screen update")...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := rdp.SendData{Request: true, Initiator: 1007, Channel: 1003,
				Priority: 0x70, Payload: c.payload}
			out, consumed, reason := se.decideIO(data)
			if reason != "" {
				t.Fatalf("refused: %s", reason)
			}
			if consumed {
				t.Fatal("the unit was swallowed")
			}
			if got := payloadOf(t, out); !bytes.Equal(got, c.payload) {
				t.Errorf("payload %q, want %q", got, c.payload)
			}
		})
	}
}

// TestTheControlPlaneCanReachTheEnrolments: the listener implements
// proxy.MFAHolder so that `xproxyctl mfa` and the GUI can list and change what
// this listener asks for. A nil guard is a listener that asks for no second
// factor, which is not the same as one the control plane cannot see.
func TestTheControlPlaneCanReachTheEnrolments(t *testing.T) {
	if g := (&server{}).MFAGuard(); g != nil {
		t.Errorf("a listener with no second factor reported a guard: %v", g)
	}
}
