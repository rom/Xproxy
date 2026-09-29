package coap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/textsafe"
)

// Who a DTLS peer is, on a protocol that otherwise has nobody.
//
// RFC 7252 s9 gives three security modes and this listener now serves all
// three, which matters because they are not alternatives an estate chooses
// between on taste:
//
//   - **PreSharedKey** is what a device with sixty kilobytes of flash ships
//     with. The client sends an identity in the clear and proves it by
//     deriving from a secret; s9.1.3.1 makes TLS_PSK_WITH_AES_128_CCM_8
//     mandatory, which is why this is the mode in the field.
//   - **RawPublicKey** is an asymmetric key with nothing vouching for it:
//     no chain, no expiry, no authority. An estate with a hundred sensors and
//     no certificate authority pins keys, and that is the right shape for it.
//   - **Certificate** is what the rest of this proxy already did.
//
// What all three produce here is one thing: a **security name**. That is the
// identity a rule names, the identity a log line carries, and on a shared
// segment it is the only thing that distinguishes one sensor from another --
// the source address does not, because on this protocol an address is a guess.
// The name is the same idea as the snmp kind's cert_to_name, deliberately: an
// operator running both reads one idea and not two.
//
// The tables are built at load and never change, for the reason every other
// credential table here is: a key that arrives at runtime is a key nobody
// reviewed.

// identity is what a session's peer turned out to be.
type identity struct {
	// name is the security name, empty when the peer maps to none.
	name string
	// kind says how it was established: psk, key, certificate or none. It is
	// separate from the name because the *way* a peer proved itself is worth a
	// log line of its own -- a name that arrived by pre-shared key and the
	// same name arriving by certificate are two different facts.
	kind string
	// why says what happened where there is no name, for the log: a peer with
	// no certificate at all reads differently from one whose key is not
	// pinned.
	why string
}

// The ways a peer can have proved itself.
const (
	identityPSK  = "psk"
	identityKey  = "key"
	identityCert = "certificate"
	identityNone = ""
)

// identities is the compiled form of the psk and public_keys tables.
type identities struct {
	// psk is the transport's own table, which the handshake consults. Nil
	// where the listener has no pre-shared keys.
	psk *dtlsx.PSK
	// names maps a pre-shared key identity to its security name. An identity
	// with no name of its own maps to itself.
	names map[string]string
	// keys maps a pinned public key's fingerprint to its security name.
	keys map[string]string
	// require refuses a message from a session that mapped to no name.
	require bool
}

// compileIdentities builds the tables.
//
// onUnknown is called with an identity a peer named that the table does not
// hold. It is the listener's, not the table's: an unknown identity is a
// security event on a segment where the identity is the identity, and the
// table has no counters and no log.
func compileIdentities(m *config.CoAPListener, secrets *keysource.Resolver,
	onUnknown func(identity string)) (*identities, error) {
	out := &identities{names: map[string]string{}, keys: map[string]string{},
		require: m.RequiresSecurityName()}
	if m.PSK != nil && len(m.PSK.Identities) > 0 {
		t, err := dtlsx.NewPSK(m.PSK.Hint, onUnknown)
		if err != nil {
			return nil, err
		}
		for i := range m.PSK.Identities {
			row := &m.PSK.Identities[i]
			key, err := pskKey(secrets, row.Key)
			if err != nil {
				return nil, fmt.Errorf("coap psk identity %q: %w", clip(row.Identity), err)
			}
			if err := t.Add(row.Identity, key); err != nil {
				return nil, err
			}
			name := row.Name
			if name == "" {
				name = row.Identity
			}
			out.names[row.Identity] = name
		}
		out.psk = t
	}
	for i := range m.PublicKeys {
		row := &m.PublicKeys[i]
		sum, err := dtlsx.ParseKeyFingerprint(row.Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("coap public_keys[%d].fingerprint: %w", i, err)
		}
		if row.Name == "" {
			return nil, fmt.Errorf("coap public_keys[%d].name: required", i)
		}
		out.keys[sum] = row.Name
	}
	return out, nil
}

// pskKey resolves one row's secret.
//
// It is raw octets unless it is hexadecimal with an 0x prefix, in which case
// it is decoded. Half the devices in the field are provisioned with a hex
// string and the other half with a pass phrase, and a relay that guessed which
// one a file held would be the wrong kind of helpful: the key that comes out
// of this has to be the same key the device derived from, and a wrong guess is
// a handshake that fails with nothing to look at.
func pskKey(secrets *keysource.Resolver, ref string) ([]byte, error) {
	if ref == "" {
		return nil, errors.New("key: required")
	}
	if secrets == nil {
		return nil, errors.New("key: no secret resolver is configured")
	}
	s, err := secrets.StringValue(ref)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("key: resolved to nothing")
	}
	if t := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"); len(t) != len(s) {
		raw, err := hex.DecodeString(strings.NewReplacer(":", "", "-", "", " ", "").Replace(t))
		if err != nil {
			return nil, fmt.Errorf("key: 0x says hexadecimal and it is not: %w", err)
		}
		return raw, nil
	}
	return []byte(s), nil
}

// of is the identity a session's peer has.
//
// The order is the order of proof. A pre-shared key identity is what the peer
// *said* and then derived from, so it is read first and needs nothing else; a
// certificate is looked at only where there was no key exchange to read, and
// what is taken from it is the public key rather than the chain -- the key is
// the identity in RFC 7250's mode, and the chain is the envelope it came in.
func (t *identities) of(sess *dtlsx.Session) identity {
	if sess == nil {
		return identity{}
	}
	if raw, ok := sess.PeerIdentity(); ok {
		if name, held := t.names[string(raw)]; held {
			return identity{name: name, kind: identityPSK}
		}
		// A session established with a key this listener handed out, under an
		// identity it no longer maps. It cannot happen while the tables are
		// built together and is not assumed away: the session is real and the
		// name is not, which is exactly what require_security_name decides
		// about.
		return identity{kind: identityPSK, why: "identity_not_mapped"}
	}
	chain, err := sess.PeerCertificates()
	if err != nil {
		if errors.Is(err, dtlsx.ErrNoCertificate) {
			return identity{why: "no_certificate"}
		}
		return identity{why: "bad_certificate"}
	}
	sum := dtlsx.KeyFingerprint(chain[0])
	if name, ok := t.keys[sum]; ok {
		return identity{name: name, kind: identityKey}
	}
	// A certificate the handshake accepted, holding a key this listener does
	// not pin. That is a peer with a real credential and no name -- which is
	// a different thing from a peer with no credential, and the two read
	// differently in a log.
	if len(t.keys) > 0 {
		return identity{kind: identityCert, why: "key_not_pinned"}
	}
	return identity{kind: identityCert}
}

// clip bounds a string from a configuration or a peer for a message.
func clip(s string) string { return textsafe.Clip(s, 64) }
