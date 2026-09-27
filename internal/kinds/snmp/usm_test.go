package snmp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:staticcheck,gosec // RFC 3414's own cipher, in a test of reading it
	"crypto/hmac"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	wire "github.com/rom/xproxy/internal/snmp"
)

// Version 3, read rather than taken on trust.
//
// The gap these tests are about: without the user's keys a v3 message is a
// header and an opaque payload, so every rule an operator wrote about
// operations and object identifiers applied to v1 and v2c and did not apply to
// v3 -- the version an operator is told to insist on. With the keys the same
// rules decide about it, which is what the first two tests assert; the rest are
// the ways a message can fail to be the message it claims to be.
//
// Every message here is built and signed by the independent encoder in
// build_test.go, the way a manager builds one, so a test that passes says the
// relay agrees with something other than itself.

const testPass = "maplesyrup"
const testPriv = "othersyrup"

// engine is the authoritative engine every message in this file names, which
// is what both ends localise their keys to.
var engine = []byte("engine-a")

// signedV3 builds a version 3 message and signs it: the digest field zeroed,
// the whole message hashed, the result written back into the same place. When
// ciphertext is given the message is authPriv and carries it.
//
// The two passes are what a manager does, and the reason it can be done that
// way is that filling the field in does not change any length.
func signedV3(t *testing.T, o v3Options) []byte {
	t.Helper()
	auth, ok := wire.AuthAlgoOf(o.auth)
	if !ok {
		t.Fatalf("%q is not an authentication protocol", o.auth)
	}
	eng := o.engine
	if eng == nil {
		eng = engine
	}
	flags := byte(0x05) // authNoPriv, reportable
	var body []byte
	if o.priv != "" {
		flags = 0x07 // authPriv
		body = tlv(wire.TagOctetStr, encryptFor(t, o, eng)...)
	} else {
		body = tlv(wire.TagSequence, join(
			tlv(wire.TagOctetStr, eng...), octets(wire.TagOctetStr, o.context), o.pdu)...)
	}
	if o.noAuth {
		flags = 0x04 // reportable only: the downgrade
	}
	build := func(digest []byte) []byte {
		usm := tlv(wire.TagOctetStr, tlv(wire.TagSequence, join(
			tlv(wire.TagOctetStr, eng...),
			integer(o.boots), integer(o.time),
			octets(wire.TagOctetStr, o.user),
			tlv(wire.TagOctetStr, digest...),
			tlv(wire.TagOctetStr, testSalt()...),
		)...)...)
		global := tlv(wire.TagSequence, join(
			integer(7), integer(65507), tlv(wire.TagOctetStr, flags), integer(3))...)
		return tlv(wire.TagSequence, join(integer(int64(wire.V3)), global, usm, body)...)
	}
	zeroed := build(make([]byte, auth.DigestLen()))
	mac := hmac.New(auth.NewHash(), authKeyFor(t, o.auth, eng))
	mac.Write(zeroed)
	return build(mac.Sum(nil)[:auth.DigestLen()])
}

// v3Options is what varies between the messages in this file.
type v3Options struct {
	user    string
	auth    string
	priv    string
	engine  []byte
	context string
	boots   int64
	time    int64
	pdu     []byte
	noAuth  bool // strip the authentication flag: the cheapest forgery
}

func testSalt() []byte { return []byte{0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71} }

func authKeyFor(t *testing.T, algo string, eng []byte) []byte {
	t.Helper()
	a, ok := wire.AuthAlgoOf(algo)
	if !ok {
		t.Fatalf("%q is not an authentication protocol", algo)
	}
	return wire.PasswordToKey(a, testPass, eng)
}

// encryptFor is a manager's side of the privacy layer: the scoped PDU, padded
// where the cipher chains, under the key both ends derive.
func encryptFor(t *testing.T, o v3Options, eng []byte) []byte {
	t.Helper()
	auth, _ := wire.AuthAlgoOf(o.auth)
	priv, ok := wire.PrivAlgoOf(o.priv)
	if !ok {
		t.Fatalf("%q is not a privacy protocol", o.priv)
	}
	key := wire.PasswordToKey(auth, testPriv, eng)
	if len(key) < priv.KeyLen() {
		t.Fatalf("%s needs %d key octets and %s derives %d", priv, priv.KeyLen(), auth, len(key))
	}
	plain := tlv(wire.TagSequence, join(
		tlv(wire.TagOctetStr, eng...), octets(wire.TagOctetStr, o.context), o.pdu)...)
	if priv == wire.PrivDES {
		block, err := des.NewCipher(key[:8]) //nolint:gosec // the protocol's own cipher
		if err != nil {
			t.Fatal(err)
		}
		iv := make([]byte, des.BlockSize)
		for i := range iv {
			iv[i] = key[8+i] ^ testSalt()[i]
		}
		padded := make([]byte, (len(plain)+7)/8*8)
		copy(padded, plain)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out
	}
	block, err := aes.NewCipher(key[:priv.KeyLen()])
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 0, 16)
	iv = binary.BigEndian.AppendUint32(iv, uint32(o.boots)) //nolint:gosec // a test's own clock
	iv = binary.BigEndian.AppendUint32(iv, uint32(o.time))  //nolint:gosec // and likewise
	iv = append(iv, testSalt()...)
	out := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, plain) //nolint:staticcheck // RFC 3826 is CFB
	return out
}

// readerFor builds the listener's USM reader from a section of configuration,
// with the pass phrases in the environment so the ordinary file:/env:/vault:
// resolution is what is exercised.
func readerFor(t *testing.T, l *config.SNMPListener) *usm {
	t.Helper()
	t.Setenv("XPROXY_TEST_SNMP_AUTH", testPass)
	t.Setenv("XPROXY_TEST_SNMP_PRIV", testPriv)
	u, err := compileUSM(l, keysource.New(nil, time.Minute, nil))
	if err != nil {
		t.Fatalf("compileUSM: %v", err)
	}
	return u
}

// oneUser is a listener holding one user's keys.
func oneUser(auth, priv string) *config.SNMPListener {
	u := config.SNMPUser{Name: "poller", Auth: auth, AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"}
	if priv != "" {
		u.Privacy = priv
		u.PrivacySecret = "env:XPROXY_TEST_SNMP_PRIV"
	}
	return &config.SNMPListener{Versions: []string{"v3"}, USMUsers: []config.SNMPUser{u}}
}

// A signed message verifies, and the policy then decides about the operation
// and the object -- which is the whole point: the rules stop being a policy
// about v1 and v2c only.
func TestTheRulesApplyToAnAuthenticatedVersion3Message(t *testing.T) {
	for _, algo := range []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512"} {
		l := oneUser(algo, "")
		l.Rules = []config.SNMPRule{{Name: "system-only", Action: "allow", OIDs: []string{"1.3.6.1.2.1.1"}}}
		u := readerFor(t, l)
		p := policyFor(t, l)
		for _, tc := range []struct {
			what  string
			oid   []uint32
			allow bool
		}{
			{"an object the rule covers", []uint32{1, 3, 6, 1, 2, 1, 1, 5, 0}, true},
			{"an object it does not", []uint32{1, 3, 6, 1, 2, 1, 4, 22, 1, 2}, false},
		} {
			raw := signedV3(t, v3Options{user: "poller", auth: algo, boots: 3, time: 12345,
				pdu: get(7, tc.oid...)})
			m := parse(raw)
			if reason, detail := u.read(m); reason != "" {
				t.Fatalf("%s: %s did not verify: %s %s", algo, tc.what, reason, detail)
			}
			if m.PDU == nil {
				t.Fatalf("%s: %s left no PDU for the rules to read", algo, tc.what)
			}
			d := p.Decide(request{client: netip.MustParseAddr("10.0.0.1"), msg: m})
			if d.Allow != tc.allow {
				t.Errorf("%s: %s decided %+v", algo, tc.what, d)
			}
		}
	}
}

// And an encrypted one, in all four ciphers: decrypted, and then decided about
// on its operation and its objects like any other.
func TestTheRulesApplyToAnEncryptedVersion3Message(t *testing.T) {
	for _, tc := range []struct{ auth, priv string }{
		{"md5", "des"}, {"md5", "aes128"}, {"sha256", "aes192"}, {"sha384", "aes256"},
	} {
		l := oneUser(tc.auth, tc.priv)
		l.ReadOnly = true
		u := readerFor(t, l)
		p := policyFor(t, l)
		// A SetRequest, encrypted. read_only is the one line that covers
		// "nobody reconfigures anything through this relay", and without the
		// key it covered everything except the version an operator insists on.
		raw := signedV3(t, v3Options{user: "poller", auth: tc.auth, priv: tc.priv,
			boots: 3, time: 12345, context: "", pdu: set(9, "rogue", 1, 3, 6, 1, 2, 1, 1, 5, 0)})
		m := parse(raw)
		if !m.V3.ScopedPDUEncrypted || m.PDU != nil {
			t.Fatalf("%s/%s: the test built a message that was not encrypted", tc.auth, tc.priv)
		}
		if reason, detail := u.read(m); reason != "" {
			t.Fatalf("%s/%s: %s %s", tc.auth, tc.priv, reason, detail)
		}
		if m.PDU == nil || m.PDU.Type != wire.SetRequest {
			t.Fatalf("%s/%s: the decrypted payload read back as %+v", tc.auth, tc.priv, m.PDU)
		}
		if !m.V3.ScopedPDUEncrypted {
			t.Errorf("%s/%s: the message stopped reporting that it arrived encrypted", tc.auth, tc.priv)
		}
		d := p.Decide(request{client: netip.MustParseAddr("10.0.0.1"), msg: m})
		if d.Allow || d.Reason != "snmp_read_only" {
			t.Errorf("%s/%s: an encrypted SetRequest decided %+v", tc.auth, tc.priv, d)
		}
	}
}

// The context name and engine come out of the *encrypted* half of the message,
// which is the only place a rule can read them from honestly: a v3 message
// carries no context outside the scoped PDU.
func TestTheContextIsReadFromTheDecryptedPayload(t *testing.T) {
	l := oneUser("sha256", "aes128")
	l.Rules = []config.SNMPRule{{Name: "one-vrf", Action: "allow", Contexts: []string{"vrf-red"}}}
	l.DefaultAction = "deny"
	u := readerFor(t, l)
	p := policyFor(t, l)
	for _, tc := range []struct {
		context string
		allow   bool
	}{
		{"vrf-red", true},
		{"vrf-blue", false},
	} {
		m := parse(signedV3(t, v3Options{user: "poller", auth: "sha256", priv: "aes128",
			boots: 3, time: 12345, context: tc.context, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
		if reason, _ := u.read(m); reason != "" {
			t.Fatalf("%s: %s", tc.context, reason)
		}
		if m.V3.ContextName != tc.context {
			t.Fatalf("the context read back as %q, want %q", m.V3.ContextName, tc.context)
		}
		d := p.Decide(request{client: netip.MustParseAddr("10.0.0.1"), msg: m})
		if d.Allow != tc.allow {
			t.Errorf("context %q decided %+v", tc.context, d)
		}
	}
}

// A message somebody changed on the way past. This is the forgery the digest
// exists to stop and the one a relay reading only the header would carry: the
// user name is a field the policy decides on.
func TestAForgedMessageIsRefused(t *testing.T) {
	l := oneUser("sha256", "")
	// A second user with the same pass phrase, so the two derive the *same*
	// key and the only thing separating them is the name in the message. A
	// relay that left the name out of what it hashed would verify the swap
	// below; the standard puts the whole message inside the digest precisely
	// so that it cannot.
	l.USMUsers = append(l.USMUsers, config.SNMPUser{Name: "setter", Auth: "sha256",
		AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"})
	u := readerFor(t, l)
	raw := signedV3(t, v3Options{user: "poller", auth: "sha256", boots: 3, time: 12345,
		pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)})
	// Every edit changes one octet of a *value*, never a length, so the
	// message still parses and the digest is the only thing that rejects it --
	// which is what is being tested.
	at := parse(raw).V3.AuthParamsAt
	name := bytes.Index(raw, []byte("poller"))
	if name < 0 {
		t.Fatal("the test built a message with no user name in it")
	}
	for _, tc := range []struct {
		what string
		edit func([]byte) []byte
	}{
		{"the user name, which the policy decides on", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			copy(c[name:], "setter")
			return c
		}},
		{"the object identifier, which the rules decide on", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			// The last octet of the object identifier: the sub-identifier a
			// rule's subtree test reads, and one octet wide.
			c[len(c)-3] ^= 0x01
			return c
		}},
		{"the digest itself", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[at] ^= 0xff
			return c
		}},
	} {
		m := parse(tc.edit(raw))
		reason, _ := u.read(m)
		if reason != reasonAuthFailed {
			t.Errorf("%s changed and the message still read as %q", tc.what, reason)
		}
	}
	// And the honest message, so the test is about the edit and not about the
	// builder.
	if reason, detail := u.read(parse(raw)); reason != "" {
		t.Fatalf("the unedited message did not verify: %s %s", reason, detail)
	}
}

// Stripping the authentication flags: the cheapest forgery on this protocol,
// because it asks the relay to stop checking rather than to produce a digest.
func TestDroppingTheAuthenticationFlagsIsRefused(t *testing.T) {
	u := readerFor(t, oneUser("sha256", ""))
	m := parse(signedV3(t, v3Options{user: "poller", auth: "sha256", boots: 3, time: 12345,
		noAuth: true, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	if m.V3.Level != wire.NoAuthNoPriv {
		t.Fatalf("the test built a message at level %s", m.V3.Level)
	}
	if reason, detail := u.read(m); reason != reasonDowngrade {
		t.Errorf("a downgraded message read as %q %q", reason, detail)
	}
	// A user this listener holds no keys for is not this reader's business: the
	// users allow list is where an operator says who may send at all.
	other := parse(signedV3(t, v3Options{user: "stranger", auth: "sha256", boots: 3, time: 12345,
		noAuth: true, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	if reason, _ := u.read(other); reason != "" {
		t.Errorf("a user with no keys here was refused %q", reason)
	}
}

// An encrypted message from a user configured for authentication only. It
// cannot be read, and forwarding what cannot be read would make privacy the
// way round every rule on the listener.
func TestAnEncryptedMessageWithNoPrivacyKeyIsRefused(t *testing.T) {
	u := readerFor(t, oneUser("sha256", ""))
	m := parse(signedV3(t, v3Options{user: "poller", auth: "sha256", priv: "aes128",
		boots: 3, time: 12345, pdu: set(1, "rogue", 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	if reason, _ := u.read(m); reason != reasonNoPrivKey {
		t.Errorf("an encrypted message with no key read as %q", reason)
	}
}

// The wrong cipher, or a payload that is not a scoped PDU once decrypted. The
// digest checked out, so these octets are the sender's own; what they are not
// is a message.
func TestAPayloadThatIsNotAScopedPDUIsRefused(t *testing.T) {
	// Configured for AES and sent under DES: the digest is over the whole
	// message and covers the ciphertext, so it still verifies -- and then the
	// decryption produces something that is not a message.
	l := oneUser("sha256", "aes128")
	u := readerFor(t, l)
	raw := signedV3(t, v3Options{user: "poller", auth: "sha256", priv: "des",
		boots: 3, time: 12345, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)})
	m := parse(raw)
	if reason, _ := u.read(m); reason != reasonUnreadable {
		t.Errorf("a payload encrypted under another cipher read as %q", reason)
	}
}

// The time window, which is RFC 3414 s2.2.3 from the outside: it is what makes
// a captured datagram unusable later, and it is the one thing the digest alone
// does not give.
func TestAClockThatGoesBackwardsIsRefused(t *testing.T) {
	l := oneUser("sha256", "")
	u := readerFor(t, l)
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	u.now = func() time.Time { return at }
	send := func(boots, clock int64) string {
		m := parse(signedV3(t, v3Options{user: "poller", auth: "sha256",
			boots: boots, time: clock, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
		reason, _ := u.read(m)
		return reason
	}
	if r := send(3, 100000); r != "" {
		t.Fatalf("the first message was refused: %s", r)
	}
	// Inside the window, either way: the standard's window is 150 seconds and
	// a manager's notion of an agent's clock drifts inside it.
	if r := send(3, 99900); r != "" {
		t.Errorf("a clock 100 seconds behind was refused: %s", r)
	}
	// And outside it. This is the replay: a datagram captured earlier, sent
	// again now.
	if r := send(3, 99000); r != reasonReplay {
		t.Errorf("a clock a thousand seconds behind read as %q", r)
	}
	// A clock that advances moves the mark, so what counts as "behind" is
	// measured from the newest message believed rather than the first one.
	if r := send(3, 101000); r != "" {
		t.Fatalf("a clock that advanced was refused: %s", r)
	}
	if r := send(3, 100700); r != reasonReplay {
		t.Errorf("a clock 300 seconds behind the newest message read as %q", r)
	}
	// A lower boot count is a replay from before the last restart.
	if r := send(2, 101000); r != reasonReplay {
		t.Errorf("a lower boot count read as %q", r)
	}
	// A higher one is the agent restarting, which resets its clock: the high
	// water mark follows the boot count rather than refusing the estate after
	// every power cut.
	if r := send(4, 12); r != "" {
		t.Errorf("an agent that restarted was refused: %s", r)
	}
	// And the mark really moved with it: the boot count that was current a
	// moment ago is now the past.
	if r := send(3, 101000); r != reasonReplay {
		t.Errorf("the boot count before the restart read as %q", r)
	}
	if r := send(4, 400); r != "" {
		t.Errorf("the clock after a restart was refused: %s", r)
	}
	// Time passes, and the engine's clock passes with it. A quiet hour does
	// not make the next message look like a replay --
	at = at.Add(time.Hour)
	if r := send(4, 400+3600); r != "" {
		t.Errorf("a message after a quiet hour was refused: %s", r)
	}
	// -- and a message whose clock did *not* move over that hour is a replay,
	// which is the half of this that the elapsed time is what decides. Without
	// it a captured datagram would stay usable for ever, because the window
	// would be measured from a mark that never advanced.
	at = at.Add(time.Hour)
	if r := send(4, 400+3600); r != reasonReplay {
		t.Errorf("a clock that stood still for an hour read as %q", r)
	}
}

// The clock values the standard puts outside the window by definition, tested
// on a reader with nothing remembered yet -- which is the only place they are
// the reason rather than the boot count being lower than the last one.
func TestABootCountThatMeansNothingIsRefused(t *testing.T) {
	for _, tc := range []struct {
		what  string
		boots int64
	}{
		// Zero is what discovery carries, and discovery is unauthenticated;
		// in a message with a digest it is a clock that means nothing.
		{"a boot count of zero", 0},
		{"a negative boot count", -1},
		// RFC 3414's own out-of-range value: an engine that has counted to
		// the top of the range has lost count.
		{"a boot count at the top of the range", 2147483647},
	} {
		u := readerFor(t, oneUser("sha256", ""))
		m := parse(signedV3(t, v3Options{user: "poller", auth: "sha256",
			boots: tc.boots, time: 400, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
		if r, _ := u.read(m); r != reasonReplay {
			t.Errorf("%s read as %q", tc.what, r)
		}
	}
}

// The window can be turned off, for an estate whose clocks are worse than its
// adversaries.
func TestTheReplayWindowCanBeTurnedOff(t *testing.T) {
	u := readerFor(t, oneUser("sha256", ""))
	u.window = 0
	send := func(boots, clock int64) string {
		m := parse(signedV3(t, v3Options{user: "poller", auth: "sha256",
			boots: boots, time: clock, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
		r, _ := u.read(m)
		return r
	}
	if r := send(3, 100000); r != "" {
		t.Fatalf("the first message was refused: %s", r)
	}
	// Both of the things the window refuses, and neither refused.
	if r := send(3, 1); r != "" {
		t.Errorf("replay_window 0 still refused a clock far behind: %s", r)
	}
	if r := send(1, 100000); r != "" {
		t.Errorf("replay_window 0 still refused a lower boot count: %s", r)
	}
}

// A pinned engine identifier: the stronger setting, where an operator knows
// it. One key is derived at load and a message naming another engine is
// refused rather than costing a derivation.
func TestAPinnedEngineRefusesAnother(t *testing.T) {
	l := oneUser("sha256", "")
	l.USMUsers[0].EngineID = "656e67696e652d61" // "engine-a"
	u := readerFor(t, l)
	if n := u.byName["poller"].engines(); n != 1 {
		t.Errorf("a pinned user holds %d keys at load, want 1", n)
	}
	if r, _ := u.read(parse(signedV3(t, v3Options{user: "poller", auth: "sha256",
		boots: 3, time: 12345, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))); r != "" {
		t.Errorf("the pinned engine was refused: %s", r)
	}
	other := parse(signedV3(t, v3Options{user: "poller", auth: "sha256", engine: []byte("engine-b"),
		boots: 3, time: 12345, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	if r, _ := u.read(other); r != reasonEngine {
		t.Errorf("another engine read as %q", r)
	}
}

// The bound on key derivation, which is a bound on work rather than on policy.
//
// RFC 3414 s2.6 hashes a megabyte of repeated pass phrase on purpose, so that
// guessing a pass phrase costs a megabyte per guess. The engine identifier
// that decides which key is needed arrives in the message, so without a bound
// a sender would be buying milliseconds of this relay's processor per datagram
// by varying one field.
func TestDerivingKeysIsBounded(t *testing.T) {
	l := oneUser("md5", "")
	l.MaxUSMEngines = 2
	u := readerFor(t, l)
	for i, eng := range []string{"engine-a", "engine-b"} {
		m := parse(signedV3(t, v3Options{user: "poller", auth: "md5", engine: []byte(eng),
			boots: 3, time: 12345, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
		if r, _ := u.read(m); r != "" {
			t.Fatalf("engine %d was refused below the bound: %s", i, r)
		}
	}
	third := parse(signedV3(t, v3Options{user: "poller", auth: "md5", engine: []byte("engine-c"),
		boots: 3, time: 12345, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	if r, _ := u.read(third); r != reasonEngines {
		t.Errorf("a third engine past a bound of two read as %q", r)
	}
	if n := u.byName["poller"].engines(); n != 2 {
		t.Errorf("the user holds keys for %d engines, want 2", n)
	}
	// The engines already known still work: the bound refuses new derivations
	// and does not close the listener.
	again := parse(signedV3(t, v3Options{user: "poller", auth: "md5", engine: []byte("engine-a"),
		boots: 3, time: 12400, pdu: get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	if r, _ := u.read(again); r != "" {
		t.Errorf("a known engine was refused once the bound was spent: %s", r)
	}
}

// A listener with no usm_users reads a v3 message exactly as it did before
// this file existed: the header, and an opaque payload it says so about.
func TestWithoutKeysNothingChanges(t *testing.T) {
	var none *usm
	m := parse(v3(0x07, "poller", "", get(1, 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	if r, _ := none.read(m); r != "" {
		t.Errorf("a listener with no keys refused a message: %s", r)
	}
	if m.PDU != nil {
		t.Error("a listener with no keys read a payload it has no key for")
	}
	p := policyFor(t, &config.SNMPListener{DefaultAction: "deny"})
	if d := p.Decide(request{client: netip.MustParseAddr("10.0.0.1"), msg: m}); !d.Allow ||
		d.Reason != "snmp_encrypted" {
		t.Errorf("an opaque message decided %+v", d)
	}
}

// What the configuration refuses to compile, because the alternative is a
// listener that starts and then refuses the traffic it was built to read.
func TestTheUserSectionRefusesWhatCannotWork(t *testing.T) {
	t.Setenv("XPROXY_TEST_SNMP_AUTH", testPass)
	t.Setenv("XPROXY_TEST_SNMP_EMPTY", "")
	res := keysource.New(nil, time.Minute, nil)
	for _, tc := range []struct {
		what  string
		users []config.SNMPUser
		wants string
	}{
		{"no name", []config.SNMPUser{{Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"}}, "name: required"},
		{"an algorithm that is not one",
			[]config.SNMPUser{{Name: "p", Auth: "sha3", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"}},
			"not an authentication protocol"},
		{"no pass phrase", []config.SNMPUser{{Name: "p", Auth: "md5"}}, "auth_secret: required"},
		{"a pass phrase that resolves to nothing",
			[]config.SNMPUser{{Name: "p", Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_EMPTY"}},
			"resolved to nothing"},
		{"a cipher that is not one",
			[]config.SNMPUser{{Name: "p", Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH",
				Privacy: "rc4", PrivacySecret: "env:XPROXY_TEST_SNMP_AUTH"}},
			"not a privacy protocol"},
		{"a hash too narrow for the cipher",
			[]config.SNMPUser{{Name: "p", Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH",
				Privacy: "aes256", PrivacySecret: "env:XPROXY_TEST_SNMP_AUTH"}},
			"needs 32"},
		{"an engine identifier that is not hexadecimal",
			[]config.SNMPUser{{Name: "p", Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH",
				EngineID: "engine-a"}},
			"not hexadecimal"},
		{"one user twice", []config.SNMPUser{
			{Name: "p", Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"},
			{Name: "p", Auth: "sha256", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"},
		}, "appears twice"},
	} {
		_, err := compileUSM(&config.SNMPListener{USMUsers: tc.users}, res)
		if err == nil {
			t.Errorf("%s: compiled", tc.what)
			continue
		}
		if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: %v, want %q", tc.what, err, tc.wants)
		}
	}
	// And a listener with no users at all has no reader, which is what makes
	// every path above a no-op for the estates that do not configure this.
	if u, err := compileUSM(&config.SNMPListener{}, res); err != nil || u != nil {
		t.Errorf("an empty section built %v, %v", u, err)
	}
	// A pass phrase that is there and is nothing. The resolver refuses an
	// empty secret itself, but not one that is only whitespace: a file holding
	// a newline resolves, and trims to nothing, and would derive a key from
	// the empty pass phrase -- which is a key, and not the one anybody meant.
	blank := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(blank, []byte("\n   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := compileUSM(&config.SNMPListener{USMUsers: []config.SNMPUser{
		{Name: "p", Auth: "md5", AuthSecret: "file:" + blank},
	}}, keysource.New(nil, time.Minute, nil)); err == nil ||
		!strings.Contains(err.Error(), "resolved to nothing") {
		t.Errorf("a pass phrase of whitespace compiled: %v", err)
	}
	// A pass phrase with nowhere to come from.
	if _, err := compileUSM(&config.SNMPListener{USMUsers: []config.SNMPUser{
		{Name: "p", Auth: "md5", AuthSecret: "env:XPROXY_TEST_SNMP_AUTH"},
	}}, nil); err == nil {
		t.Error("a listener with no secret resolver compiled")
	}
}

// Engine identifiers, written the several ways the tools print them.
func TestEngineIdentifiersAreReadAsHexadecimal(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"80001f8880", "\x80\x00\x1f\x88\x80"},
		{"0x80001f8880", "\x80\x00\x1f\x88\x80"},
		{"80:00:1f:88:80", "\x80\x00\x1f\x88\x80"},
		{"80-00-1f-88-80", "\x80\x00\x1f\x88\x80"},
	} {
		got, err := parseEngineID(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%q read as %x, want %x", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "zz", "0x", "8", strings.Repeat("00", 33)} {
		if _, err := parseEngineID(bad); err == nil {
			t.Errorf("%q was read as an engine identifier", bad)
		}
	}
}

// The table of engine clocks is bounded, like every other per-peer table on
// this listener, and a full one stops checking rather than refusing.
//
// The window is a detection. A relay that refused every message once a bounded
// table filled would be a relay an attacker could close by naming engines --
// the opposite of what the bound is for. This drives u.clock directly, because
// filling the table through read would mean deriving a key per engine and the
// derivation is a megabyte of hashing by design.
func TestTheClockTableIsBoundedAndStopsChecking(t *testing.T) {
	u := &usm{window: 150 * time.Second, clocks: map[string]*engineClock{},
		now: func() time.Time { return time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC) }}
	head := func(id string, boots, clock int64) *wire.V3Header {
		return &wire.V3Header{EngineID: []byte(id), EngineBoots: boots, EngineTime: clock}
	}
	// One engine, remembered, and a replay from it refused.
	if why := u.clock(head("engine-a", 3, 100000)); why != "" {
		t.Fatalf("the first message was refused: %s", why)
	}
	if why := u.clock(head("engine-a", 3, 1)); why != reasonReplay {
		t.Errorf("a replay read as %q", why)
	}
	for i := len(u.clocks); i < maxClocks; i++ {
		u.clocks[itoa(i)+"-filler"] = &engineClock{boots: 1, time: 1}
	}
	// A new engine past the bound: not remembered, and not refused either.
	if why := u.clock(head("engine-z", 3, 100000)); why != "" {
		t.Errorf("a new engine past the bound was refused: %s", why)
	}
	if len(u.clocks) != maxClocks {
		t.Errorf("the table grew to %d past a bound of %d", len(u.clocks), maxClocks)
	}
	// And the engine already in the table is still checked: the bound stops
	// new entries, not the detection.
	if why := u.clock(head("engine-a", 3, 2)); why != reasonReplay {
		t.Errorf("a replay from a known engine read as %q once the bound was spent", why)
	}
}
