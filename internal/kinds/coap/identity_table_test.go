package coap

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/keysource"
)

// The credential tables, built at load and never after.
//
// That is the whole security argument for doing this here: a key that arrives
// at runtime is a key nobody reviewed. It only holds if every row is checked
// at load, so a table with one unusable row is a listener that refuses to
// start rather than one that silently holds a row no device can use -- which
// on a segment where the identity is the identity would read as a device that
// has gone quiet.

func secretFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEveryCredentialRowIsCheckedAtLoad(t *testing.T) {
	good := secretFile(t, "key", "0123456789abcdef")
	res := keysource.New(nil, time.Minute, nil)
	for _, tc := range []struct {
		name string
		m    config.CoAPListener
		want string
	}{{
		// The hint is sent in the clear to every client, and the record
		// layer bounds it. A listener that took a longer one would fail at
		// the first handshake instead of at load.
		name: "a hint past the record layer's bound",
		m: config.CoAPListener{PSK: &config.CoAPPSK{Hint: strings.Repeat("h", dtlsx.MaxPSKIdentity+1),
			Identities: []config.CoAPPSKIdentity{{Identity: "boiler-3", Key: good}}}},
		want: "hint",
	}, {
		// A row with no key is a row that cannot derive anything, and the
		// message names the identity so an operator knows which line.
		name: "an identity with no key",
		m: config.CoAPListener{PSK: &config.CoAPPSK{
			Identities: []config.CoAPPSKIdentity{{Identity: "boiler-3"}}}},
		want: `psk identity "boiler-3"`,
	}, {
		// An empty identity would be the row every client that names
		// nothing reaches, which is the opposite of an identity.
		name: "an empty identity",
		m: config.CoAPListener{PSK: &config.CoAPPSK{
			Identities: []config.CoAPPSKIdentity{{Key: good}}}},
		want: "may not be empty",
	}, {
		name: "a key shorter than the cipher's own key",
		m: config.CoAPListener{PSK: &config.CoAPPSK{
			Identities: []config.CoAPPSKIdentity{{Identity: "boiler-3",
				Key: secretFile(t, "short", "tooshort")}}}},
		want: "least this accepts",
	}, {
		name: "a fingerprint that is not one",
		m: config.CoAPListener{PublicKeys: []config.CoAPPublicKey{
			{Fingerprint: "the key on the sticker", Name: "boiler-3"}}},
		want: "public_keys[0].fingerprint",
	}, {
		// A pinned key with no name authenticates a peer and tells the
		// policy nothing, which is the mode this table exists to avoid.
		name: "a pinned key with no name",
		m: config.CoAPListener{PublicKeys: []config.CoAPPublicKey{
			{Fingerprint: strings.Repeat("ab", 32)}}},
		want: "public_keys[0].name: required",
	}} {
		_, err := compileIdentities(&tc.m, res, func(string) {})
		if err == nil {
			t.Errorf("%s: compiled", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", tc.name, err, tc.want)
		}
	}

	// And the table a good configuration produces: an identity with no name
	// of its own maps to itself, one with a name maps to it, and a pinned
	// key maps to the name beside it.
	m := config.CoAPListener{
		PSK: &config.CoAPPSK{Hint: "segment-a", Identities: []config.CoAPPSKIdentity{
			{Identity: "boiler-3", Key: good},
			{Identity: "boiler-4", Key: good, Name: "hall-sensors"},
		}},
		PublicKeys: []config.CoAPPublicKey{{Fingerprint: strings.Repeat("ab", 32), Name: "pinned"}},
	}
	ids, err := compileIdentities(&m, res, func(string) {})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if ids.names["boiler-3"] != "boiler-3" || ids.names["boiler-4"] != "hall-sensors" {
		t.Errorf("names %v", ids.names)
	}
	if len(ids.keys) != 1 {
		t.Errorf("keys %v", ids.keys)
	}
	if ids.psk == nil {
		t.Error("the transport was given no table to consult")
	}
	// A session that is not there is nobody, which is what the relay asks
	// about a datagram that arrived outside DTLS.
	if got := ids.of(nil); got != (identity{}) {
		t.Errorf("of(nil) = %+v", got)
	}
}

// A pre-shared key is read as octets unless it says it is hexadecimal.
//
// Half the devices in the field are provisioned with a hex string and the
// other half with a pass phrase, and the key that comes out of this has to be
// the key the device derived from: a wrong guess is a handshake that fails
// with nothing to look at.
func TestAPreSharedKeyIsReadAsOctetsUnlessItSaysHexadecimal(t *testing.T) {
	res := keysource.New(nil, time.Minute, nil)

	// A pass phrase is its own octets, and the editor's trailing newline is
	// not part of the credential.
	raw, err := pskKey(res, secretFile(t, "phrase", "a pass phrase on a sticker\n"))
	if err != nil {
		t.Fatalf("a pass phrase: %v", err)
	}
	if string(raw) != "a pass phrase on a sticker" {
		t.Errorf("a pass phrase read as %q", raw)
	}

	// 0x says hexadecimal, and the separators whatever printed it put in are
	// ignored.
	for _, body := range []string{"0x00112233445566778899aabbccddeeff",
		"0X00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"} {
		raw, err := pskKey(res, secretFile(t, "hex", body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if len(raw) != 16 || raw[0] != 0x00 || raw[15] != 0xff {
			t.Errorf("%s read as %x", body, raw)
		}
	}

	for _, tc := range []struct{ name, ref, want string }{
		{"no reference at all", "", "key: required"},
		{"a file that is not there", filepath.Join(t.TempDir(), "never-provisioned"), "key:"},
		{"a file with nothing in it", secretFile(t, "blank", "   \n"), "resolved to nothing"},
		{"0x and then something else", secretFile(t, "notHex", "0xthe key on the sticker"),
			"0x says hexadecimal and it is not"},
	} {
		if _, err := pskKey(res, tc.ref); err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", tc.name, err, tc.want)
		}
	}

	// A listener with no resolver at all cannot read a secret, and saying so
	// is better than reading the reference itself as the key.
	if _, err := pskKey(nil, "/etc/xproxy/psk/boiler-3"); err == nil ||
		!strings.Contains(err.Error(), "no secret resolver") {
		t.Errorf("with no resolver: %v", err)
	}
}

// The pairing table, which is what keeps one device's answer from reaching a
// client that asked a different device.
//
// CoAP has no connection and no sequence: the token and the device are the
// whole of the pairing, so the table's own rules -- when an exchange is
// forgotten, when it is kept, and how many may be outstanding -- are the
// security properties here rather than housekeeping.
func TestThePairingTableForgetsWhatNobodyAnswered(t *testing.T) {
	now := time.Now()
	dev := netipPort(t, "10.0.0.9:5683")
	cl := netipPort(t, "192.0.2.10:40000")
	p := newPending(2, time.Second)

	one := &exchange{client: cl, device: dev, token: "a"}
	if !p.add(one, now) {
		t.Fatal("the first exchange was refused")
	}
	// An answer that came too late is not this exchange's answer, and the
	// exchange goes rather than being left for a later datagram carrying the
	// same token to claim.
	if e, ok := p.take(one.key(), now.Add(2*time.Second)); ok || e != nil {
		t.Errorf("a late answer was paired: %+v", e)
	}
	if n := p.len(); n != 0 {
		t.Errorf("the late answer left %d outstanding", n)
	}

	// An observed registration outlives its first answer, because a
	// notification is another answer to the same request -- and the sweep
	// leaves it alone for the same reason, while an ordinary exchange nobody
	// answered is dropped.
	watch := &exchange{client: cl, device: dev, token: "w", observing: true}
	quiet := &exchange{client: cl, device: dev, token: "q"}
	if !p.add(watch, now) || !p.add(quiet, now) {
		t.Fatal("the table refused an exchange it had room for")
	}
	if e, ok := p.take(watch.key(), now); !ok || e == nil {
		t.Error("a notification did not pair with the registration")
	}
	if n := p.len(); n != 2 {
		t.Errorf("the first notification ended the registration: %d", n)
	}
	p.sweep(now.Add(2 * time.Second))
	if n := p.len(); n != 1 {
		t.Errorf("the sweep left %d of 1", n)
	}
	if _, ok := p.take(watch.key(), now.Add(2*time.Second)); !ok {
		t.Error("the sweep dropped the registration it is meant to keep")
	}

	// The bound is a refusal, and it is on the table rather than on one
	// client: a relay that let the table grow would answer "how many
	// exchanges may be outstanding" with whoever asked for the most.
	p.drop(watch.key())
	if !p.add(&exchange{client: cl, device: dev, token: "1"}, now) ||
		!p.add(&exchange{client: cl, device: dev, token: "2"}, now) {
		t.Fatal("the table refused an exchange it had room for")
	}
	if p.add(&exchange{client: cl, device: dev, token: "3"}, now) {
		t.Error("the table took an exchange past its bound")
	}
	// A retransmission of one already in the table is not a new exchange, so
	// it is taken even with the table full.
	if !p.add(&exchange{client: cl, device: dev, token: "2"}, now) {
		t.Error("a retransmission was refused by the bound")
	}
}

// The registrations are bounded separately, because a registration has no
// timeout: it lasts until the client deregisters or the device stops. Without
// a bound of its own, how many open-ended flows may exist would be answered by
// whoever asked for the most.
func TestTheRegistrationsAreBoundedOnTheirOwn(t *testing.T) {
	dev := netipPort(t, "10.0.0.9:5683")
	o := newObservers(1)
	first := key{device: dev, token: "a"}
	if !o.add(first) {
		t.Fatal("the first registration was refused")
	}
	// The same registration again is the same registration: a client
	// re-registering must not spend another slot, or a device that
	// retransmits fills the table.
	if !o.add(first) {
		t.Error("re-registering the same token was refused")
	}
	if n := o.len(); n != 1 {
		t.Errorf("re-registering took a second slot: %d", n)
	}
	if o.add(key{device: dev, token: "b"}) {
		t.Error("a registration past the bound was taken")
	}
	o.remove(first)
	if !o.add(key{device: dev, token: "b"}) {
		t.Error("the slot was not released")
	}
}

func netipPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}
