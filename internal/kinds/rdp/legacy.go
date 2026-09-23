package rdp

import (
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/rdp"
)

// The desktop's leg when it speaks the protocol's own encryption
// rather than TLS -- standard RDP security, which is RC4 under keys
// derived from two random values.
//
// What this is for. Equipment that speaks nothing else: an appliance,
// an embedded console, a Windows install too old to offer TLS. The
// encryption protects the session against nothing serious -- RC4, MD5
// and SHA-1, under a key the desktop hands out in a certificate
// nothing can check -- and the documentation says so rather than
// implying otherwise. What it does buy is that such a desktop is
// reached through a gateway that records the session, applies the
// channel and device policy and asks for a second factor, instead of
// being reached directly.
//
// The client's leg is a separate question and is always TLS here. So
// the gateway decrypts everything the desktop sends before it reaches
// the client, and encrypts everything the client sends before it
// reaches the desktop. That also means the recording is of the session
// rather than of ciphertext.

// legacyLeg is what the desktop's leg needs once the exchange is done:
// a key in each direction, and the packet that starts it.
type legacyLeg struct {
	method, level uint32
	// serverRandom is this end's half of the key material when this
	// gateway is the server -- the client's leg. It is unused on the
	// desktop's leg, where the desktop sends its own.
	serverRandom []byte
	// out encrypts towards the desktop and in decrypts what comes
	// back. The names are this gateway's view, not the protocol's.
	out, in *rdp.Crypt
	// exchange is the security exchange packet, which travels in
	// front of the first thing the client sends.
	exchange  []byte
	exchanged bool
	// ready is closed once the keys exist. On the client's leg the
	// exchange is answered by the goroutine reading the client while
	// the other one is already copying the desktop's traffic towards
	// it, and that traffic cannot go out until there is a key to
	// encrypt it with.
	ready chan struct{}
}

// wantsLegacy says whether the desktop's leg is the legacy one.
func (t *server) wantsLegacy() bool { return t.upstreamProtocol == rdp.ProtocolRDP }

// offersLegacy says whether a client may use the legacy protocol here,
// which needs the listener's own key.
func (t *server) offersLegacy() bool { return t.offered&legacyBit != 0 }

// clientLegacySecurity answers the client's half of the security
// negotiation: the method it offered that this gateway will use, its
// own random, and a certificate carrying its own key, signed with the
// key Microsoft published so that clients could check exactly this.
//
// What the client is told is about the client's own leg and nothing
// else. The desktop's leg has its own arrangement, which may be TLS,
// network level authentication or this again with different keys.
func (se *session) clientLegacySecurity(resp *rdp.Connect, offered uint32) string {
	t := se.t
	method, ok := rdp.StrongestMethod(offered)
	if !ok {
		t.deny(se.ip, "rdp_no_encryption_method", fmt.Sprintf("%#x", offered))
		return "client_no_method"
	}
	random, err := rdp.NewRandom()
	if err != nil {
		return "client_conference"
	}
	cert, err := rdp.ProprietaryCertificate(&t.legacyKey.PublicKey)
	if err != nil {
		t.engine.Logs().Error.Warn("rdp legacy certificate could not be built",
			"listener", t.cfg.Name, "err", err.Error())
		return "client_conference"
	}
	// Client compatible: both directions encrypted at whatever the
	// client can do. The weaker levels exist to encrypt less, which is
	// not a thing to offer.
	block, err := rdp.ServerSecurityData(method, rdp.EncryptionLevelClientCompatible, random, cert)
	if err != nil {
		return "client_conference"
	}
	if err := resp.Replace(rdp.BlockServerSecurity, block); err != nil {
		return "client_conference"
	}
	se.clientLegacy = &legacyLeg{method: method, level: rdp.EncryptionLevelClientCompatible,
		serverRandom: random, ready: make(chan struct{})}
	return ""
}

// clientExchange finishes the client's key exchange: the random it
// sealed under this listener's key is opened, the session keys follow
// from it, and from there the client's leg is encrypted in both
// directions.
func (se *session) clientExchange(payload []byte) string {
	t := se.t
	l := se.clientLegacy
	sealed, err := rdp.ParseSecurityExchange(payload)
	if err != nil {
		t.deny(se.ip, "rdp_security_exchange", err.Error())
		return "client_protocol"
	}
	clientRandom, err := rdp.OpenClientRandom(t.legacyKey, sealed)
	if err != nil {
		t.deny(se.ip, "rdp_security_exchange", err.Error())
		return "client_protocol"
	}
	keys, err := rdp.DeriveKeys(l.method, clientRandom, l.serverRandom)
	if err != nil {
		t.deny(se.ip, "rdp_security_exchange", err.Error())
		return "client_protocol"
	}
	// The server's view of the two keys is the client's the other way
	// round: what the client encrypts with is what this end decrypts
	// with.
	if l.in, err = rdp.NewCrypt(keys, keys.Encrypt, l.method); err != nil {
		return "client_encryption"
	}
	if l.out, err = rdp.NewCrypt(keys, keys.Decrypt, l.method); err != nil {
		return "client_encryption"
	}
	l.exchanged = true
	// Everything written to the client from here on is encrypted, and
	// closing this is what lets the other goroutine do it. The keys
	// are set before the close, so the goroutine that waits on it sees
	// them.
	close(l.ready)
	t.engine.Counters().RDPLegacyClients.Add(1)
	t.engine.Logs().Access.Info("rdp_legacy_client", "listener", t.cfg.Name,
		"client_ip", se.ip.String(), "method", rdp.EncryptionMethodName(l.method),
		"level", rdp.EncryptionLevelName(l.level))
	return ""
}

// legacyClientSecurity rewrites what the client said it can encrypt
// with into what this gateway can, because past the conference
// exchange it is this gateway and not the client that holds the keys
// on that leg.
func (se *session) legacyClientSecurity(conn *rdp.Connect) string {
	if err := conn.Replace(rdp.BlockClientSecurity, rdp.EncodeClientSecurity(rdp.ClientMethods)); err != nil {
		return "client_conference"
	}
	return ""
}

// legacyServerSecurity reads what the desktop settled on, sets the
// session's keys up from it, and rewrites the block the client sees to
// say that nothing is encrypted -- which is true of the client's own
// leg, where TLS is doing that work.
func (se *session) legacyServerSecurity(resp *rdp.Connect) string {
	t := se.t
	blocks, err := resp.Walk()
	if err != nil {
		return "upstream_conference"
	}
	var raw []byte
	for _, b := range blocks {
		if b.Type == rdp.BlockServerSecurity {
			raw = b.Data
		}
	}
	if raw == nil {
		t.engine.Logs().Error.Warn("rdp desktop sent no security block on a legacy leg",
			"listener", t.cfg.Name, "target", se.target)
		return "upstream_no_security"
	}
	sec, err := rdp.ParseServerSecurity(raw)
	if err != nil {
		t.engine.Logs().Error.Warn("rdp desktop's security block could not be read",
			"listener", t.cfg.Name, "target", se.target, "err", err.Error())
		return "upstream_conference"
	}
	if reason := se.startLegacy(sec); reason != "" {
		return reason
	}
	// The client is on TLS, so what it is told here is the truth about
	// its own leg: nothing on it is encrypted by the protocol.
	if err := resp.Replace(rdp.BlockServerSecurity,
		rdp.EncodeServerSecurity(0, rdp.EncryptionLevelNone)); err != nil {
		return "upstream_conference"
	}
	return ""
}

// startLegacy performs the key exchange: this end's random is drawn,
// sealed under the desktop's key and kept until there is a packet to
// send it in front of.
func (se *session) startLegacy(sec *rdp.ServerSecurity) string {
	t := se.t
	if sec.Method == 0 || sec.Level == rdp.EncryptionLevelNone {
		// A desktop that encrypts nothing. That is a configuration
		// somebody chose on the desktop, and this gateway is not the
		// place to overrule it -- but it is the place to say so,
		// because a session nobody encrypts looks exactly like one
		// everybody does.
		t.engine.Logs().Error.Warn("rdp desktop asked for no encryption at all on a legacy leg",
			"listener", t.cfg.Name, "target", se.target,
			"method", sec.Method, "level", sec.Level)
		return ""
	}
	clientRandom, err := rdp.NewRandom()
	if err != nil {
		return "upstream_conference"
	}
	keys, err := rdp.DeriveKeys(sec.Method, clientRandom, sec.Random)
	if err != nil {
		t.engine.Logs().Error.Warn("rdp legacy keys could not be derived",
			"listener", t.cfg.Name, "target", se.target, "err", err.Error())
		return "upstream_encryption"
	}
	sealed, err := rdp.SealClientRandom(sec.PublicKey, clientRandom)
	if err != nil {
		t.engine.Logs().Error.Warn("rdp legacy key exchange could not be sealed",
			"listener", t.cfg.Name, "target", se.target, "err", err.Error())
		return "upstream_encryption"
	}
	out, err := rdp.NewCrypt(keys, keys.Encrypt, sec.Method)
	if err != nil {
		return "upstream_encryption"
	}
	in, err := rdp.NewCrypt(keys, keys.Decrypt, sec.Method)
	if err != nil {
		return "upstream_encryption"
	}
	se.legacy = &legacyLeg{method: sec.Method, level: sec.Level,
		out: out, in: in, exchange: rdp.SecurityExchange(sealed)}
	t.engine.Counters().RDPLegacySessions.Add(1)
	t.engine.Logs().Access.Info("rdp_legacy", "listener", t.cfg.Name,
		"client_ip", se.ip.String(), "target", se.target,
		"method", rdp.EncryptionMethodName(sec.Method),
		"level", rdp.EncryptionLevelName(sec.Level),
		"certificate", certificateKind(sec))
	return ""
}

func certificateKind(sec *rdp.ServerSecurity) string {
	if sec.Proprietary {
		return "proprietary"
	}
	return "none"
}

// headerFlags are the packet kinds that carry a basic security header
// on a leg where the protocol is not encrypting: the exchange, the
// credential and the licence. Everything else on such a leg has no
// header at all, so a payload whose first four bytes are not one of
// these is payload rather than header (MS-RDPBCGR 2.2.8.1.1.2.1).
const headerFlags = rdp.SecExchangePkt | rdp.SecInfoPkt | rdp.SecLicensePkt

// splitHeader separates a security header from what follows, where
// there is one.
func splitHeader(payload []byte) (flags uint16, rest []byte) {
	head, after, err := rdp.ParseSecurityHeader(payload)
	if err != nil || head.Flags == 0 || head.Flags&^headerFlags != 0 {
		return 0, payload
	}
	return head.Flags, after
}

// seal encrypts one data unit for the desktop, putting the security
// exchange in front of the first one. Everything the client sends
// after the channel joins goes through here.
func (l *legacyLeg) seal(data rdp.SendData, payload []byte) ([]byte, error) {
	flags, rest := splitHeader(payload)
	sealed, err := l.out.Seal(flags, rest)
	if err != nil {
		return nil, err
	}
	pdu, err := rewrap(data, sealed)
	if err != nil {
		return nil, err
	}
	if l.exchanged {
		return pdu, nil
	}
	// The exchange itself is not encrypted -- it is what makes the
	// encryption possible -- and it travels on the same channel, from
	// the same user, as the packet it precedes.
	first, err := rewrap(data, l.exchange)
	if err != nil {
		return nil, err
	}
	l.exchanged = true
	return append(first, pdu...), nil
}

// open decrypts one data unit from the desktop and returns the payload
// the client's leg should carry: the plaintext, with a security header
// in front of it only where the packet is one of the kinds that has
// one.
func (l *legacyLeg) open(payload []byte) ([]byte, error) {
	head, rest, err := rdp.ParseSecurityHeader(payload)
	if err != nil || head.Flags&rdp.SecEncrypt == 0 {
		// Not encrypted: a desktop at encryption level low sends
		// everything this way, and so does one in the middle of the
		// connection sequence.
		return payload, nil
	}
	plain, err := l.in.Open(rest)
	if err != nil {
		return nil, err
	}
	flags := head.Flags &^ rdp.SecEncrypt
	if flags&headerFlags == 0 {
		return plain, nil
	}
	return append(rdp.SecurityHeader{Flags: flags, FlagsHi: head.FlagsHi}.Encode(), plain...), nil
}

// waitForClientKeys holds a unit until the client's exchange has been
// answered. Units of the connection sequence go straight out: an MCS
// connect response, an attach user confirm or a channel join confirm
// is not encrypted even in a session that is.
func (se *session) waitForClientKeys(raw []byte) string {
	l := se.clientLegacy
	select {
	case <-l.ready:
		return ""
	default:
	}
	if !needsClientKeys(raw) {
		return ""
	}
	// The bound is the one on the connection sequence: a client that
	// has not exchanged keys by then is not going to.
	timer := time.NewTimer(se.t.v.HandshakeTimeout.D())
	defer timer.Stop()
	select {
	case <-l.ready:
		return ""
	case <-se.ended:
		return "closed"
	case <-timer.C:
		se.t.deny(se.ip, "rdp_security_exchange", "no key exchange before the desktop had something to show")
		return "client_no_exchange"
	}
}

// needsClientKeys says whether a unit is session traffic, which has to
// be encrypted, rather than part of the sequence that sets the
// encryption up.
func needsClientKeys(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	if raw[0] != 3 {
		return true // fast path is only ever session traffic
	}
	body, err := rdp.X224Payload(raw[4:])
	if err != nil {
		return false
	}
	_, ok, err := rdp.ParseSendData(body)
	return err == nil && ok
}

// sealFast encrypts a fast path unit, which is what carries input once
// the session is running.
func (l *legacyLeg) sealFast(raw []byte) ([]byte, error) {
	if !l.exchanged {
		// Input before the credential is not something a client does;
		// a desktop that has not seen the exchange cannot read this
		// either way.
		return nil, fmt.Errorf("rdp: fast path input before the key exchange")
	}
	return l.out.FastPathSeal(raw)
}

// openFast decrypts a fast path unit from the desktop where its header
// says it is encrypted.
func (l *legacyLeg) openFast(raw []byte) ([]byte, error) {
	if !rdp.FastPathEncrypted(raw) {
		return raw, nil
	}
	return l.in.FastPathOpen(raw)
}

// ---- the client's leg, where this gateway is the server ----

// fromClient turns one unit the client sent into plaintext, and says
// whether the unit was the key exchange -- which the gateway answers
// itself and does not forward, because the desktop's leg has its own.
func (se *session) fromClient(pdu rdp.PDU) (out []byte, consumed bool, reason string) {
	l := se.clientLegacy
	if l == nil {
		return pdu.Raw, false, ""
	}
	if pdu.FastPath {
		if !rdp.FastPathEncrypted(pdu.Raw) {
			return pdu.Raw, false, ""
		}
		plain, err := l.in.FastPathOpen(pdu.Raw)
		if err != nil {
			se.t.deny(se.ip, "rdp_client_encryption", err.Error())
			return nil, false, "client_encryption"
		}
		return plain, false, ""
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		return pdu.Raw, false, "" // the conference layer's own units
	}
	data, ok, err := rdp.ParseSendData(payload)
	if err != nil || !ok {
		return pdu.Raw, false, ""
	}
	head, rest, err := rdp.ParseSecurityHeader(data.Payload)
	if err != nil {
		return pdu.Raw, false, ""
	}
	if head.Flags&rdp.SecExchangePkt != 0 {
		if l.exchanged {
			se.t.deny(se.ip, "rdp_security_exchange", "a second key exchange")
			return nil, false, "client_protocol"
		}
		return nil, true, se.clientExchange(rest)
	}
	if head.Flags&rdp.SecEncrypt == 0 {
		if l.exchanged {
			// After the exchange the client encrypts everything. One
			// that stops is either broken or is not the client that
			// did the exchange.
			se.t.deny(se.ip, "rdp_client_encryption", "a packet in the clear after the key exchange")
			return nil, false, "client_encryption"
		}
		return pdu.Raw, false, ""
	}
	if !l.exchanged {
		se.t.deny(se.ip, "rdp_client_encryption", "an encrypted packet before the key exchange")
		return nil, false, "client_protocol"
	}
	plain, err := l.in.Open(rest)
	if err != nil {
		se.t.deny(se.ip, "rdp_client_encryption", err.Error())
		return nil, false, "client_encryption"
	}
	flags := head.Flags &^ rdp.SecEncrypt
	payloadOut := plain
	if flags&headerFlags != 0 {
		payloadOut = append(rdp.SecurityHeader{Flags: flags, FlagsHi: head.FlagsHi}.Encode(), plain...)
	}
	out, err = rewrap(data, payloadOut)
	if err != nil {
		return nil, false, "client_protocol"
	}
	return out, false, ""
}

// toClient encrypts one unit on its way to a client whose leg uses the
// protocol's own encryption.
//
// Session traffic waits for the key exchange rather than going out in
// the clear: a client that agreed to encryption cannot read a packet
// that is not encrypted, so forwarding one early does not degrade the
// session, it ends it. The connection sequence's own units are not
// waited on, because they are what the exchange itself is part of.
func (se *session) toClient(raw []byte) ([]byte, string) {
	l := se.clientLegacy
	if l == nil {
		return raw, ""
	}
	if reason := se.waitForClientKeys(raw); reason != "" {
		return nil, reason
	}
	if len(raw) > 0 && raw[0] != 3 {
		sealed, err := l.out.FastPathSeal(raw)
		if err != nil {
			return nil, "client_encryption"
		}
		return sealed, ""
	}
	body, err := rdp.X224Payload(raw[4:])
	if err != nil {
		return raw, "" // not a data unit
	}
	data, ok, err := rdp.ParseSendData(body)
	if err != nil || !ok {
		return raw, ""
	}
	flags, rest := splitHeader(data.Payload)
	sealed, err := l.out.Seal(flags, rest)
	if err != nil {
		return nil, "client_encryption"
	}
	out, err := rewrap(data, sealed)
	if err != nil {
		return nil, "client_encryption"
	}
	return out, ""
}
