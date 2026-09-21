// Package ech encodes and decodes Encrypted Client Hello configurations
// (draft-ietf-tls-esni, the version TLS 1.3 implementations deployed as
// 0xfe0d) and the ECHConfigList that a DNS HTTPS record publishes.
//
// What ECH is for. A TLS 1.3 handshake still names its destination in
// the clear: the SNI in the ClientHello tells every network on the path
// which site is being visited, which is the last plaintext identifier
// left in a modern connection and the one censors and monitors actually
// use. ECH encrypts the real ClientHello — SNI, ALPN, the lot — to a
// public key the client learned from DNS, and sends it inside an outer
// ClientHello that names a *public name* shared by everything behind
// the same key. An observer sees a connection to the public name and
// cannot tell which of the hosted sites it was for.
//
// What it costs. The public name must have a certificate on the
// listener, because a client whose key is stale falls back to it and
// completes an ordinary handshake with it; that fallback is what makes
// key rotation safe. And the outer name is the only name a layer 4
// listener can route on, which is why a `kind: tcp` listener in front
// of an ECH listener routes everything to one place (see USAGE.md).
//
// This package does the encoding only. The handshake is Go's.
package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// Version is the ECHConfig version this package writes and accepts. It
// is the one every deployed implementation speaks.
const Version uint16 = 0xfe0d

// HPKE identifiers. Only the profile Go's crypto/tls accepts is
// produced: X25519 with HKDF-SHA256, and the three AEADs.
const (
	KEMX25519HKDFSHA256 uint16 = 0x0020
	KDFHKDFSHA256       uint16 = 0x0001

	AEADAES128GCM        uint16 = 0x0001
	AEADAES256GCM        uint16 = 0x0002
	AEADChaCha20Poly1305 uint16 = 0x0003
)

// DefaultMaxNameLength is the padding hint: the length of the longest
// name behind this key, so that the encrypted ClientHello is padded to
// a size that does not leak which name it holds. 64 covers ordinary
// host names with room to spare.
const DefaultMaxNameLength uint8 = 64

// maxConfigBytes bounds a config read from disk or from a record. An
// ECHConfig is a couple of hundred bytes; anything near this is either
// a mistake or an attempt to make the parser work.
const maxConfigBytes = 8 << 10

// Cipher is one symmetric suite offered by a config.
type Cipher struct {
	KDF  uint16
	AEAD uint16
}

// DefaultCiphers is the suite list to publish: all three AEADs, so a
// client picks what its platform implements fastest.
func DefaultCiphers() []Cipher {
	return []Cipher{
		{KDFHKDFSHA256, AEADAES128GCM},
		{KDFHKDFSHA256, AEADAES256GCM},
		{KDFHKDFSHA256, AEADChaCha20Poly1305},
	}
}

// Config is one ECH configuration: a key a client encrypts to, and the
// public name it uses in the outer ClientHello.
type Config struct {
	// ID distinguishes keys served at the same time. A client echoes it
	// so the server knows which private key to try; two live configs
	// must not share one, or half the handshakes pick the wrong key and
	// fall back.
	ID uint8
	// PublicName is what an observer sees, and what the client falls
	// back to when its key is stale. It needs a certificate here.
	PublicName string
	// PublicKey is the X25519 public key, 32 bytes.
	PublicKey []byte
	// MaxNameLength is the padding hint.
	MaxNameLength uint8
	// Ciphers are the symmetric suites offered.
	Ciphers []Cipher
}

// Generate makes a fresh key pair and the config that publishes it. The
// private key is returned separately because it never goes in a record.
func Generate(publicName string, id uint8) (Config, []byte, error) {
	if err := ValidPublicName(publicName); err != nil {
		return Config{}, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Config{}, nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	c := Config{
		ID:            id,
		PublicName:    publicName,
		PublicKey:     priv.PublicKey().Bytes(),
		MaxNameLength: DefaultMaxNameLength,
		Ciphers:       DefaultCiphers(),
	}
	return c, priv.Bytes(), nil
}

// ValidPublicName checks the name that will be visible on the wire. It
// must be a host name: an address would be pointless (it identifies the
// server anyway) and an empty name is refused by clients.
func ValidPublicName(name string) error {
	switch {
	case name == "":
		return errors.New("public_name is required")
	case len(name) > 255:
		return errors.New("public_name is longer than 255 bytes")
	case strings.ContainsAny(name, " \t\r\n\x00"):
		return errors.New("public_name contains whitespace")
	case !strings.Contains(name, "."):
		return errors.New("public_name must be a fully qualified domain name")
	case strings.HasPrefix(name, "."), strings.HasSuffix(name, "."):
		return errors.New("public_name must not begin or end with a dot")
	case strings.Contains(name, ".."):
		return errors.New("public_name has an empty label")
	case strings.HasPrefix(name, "*"):
		return errors.New("public_name must not be a wildcard")
	}
	for _, r := range name {
		if r > 127 {
			return errors.New("public_name must be in A-label (punycode) form")
		}
	}
	return nil
}

// Marshal encodes one ECHConfig, header included. This is the form
// crypto/tls wants for a server key.
func (c Config) Marshal() ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint16(Version)
	b.AddUint16LengthPrefixed(func(contents *cryptobyte.Builder) {
		contents.AddUint8(c.ID)
		contents.AddUint16(KEMX25519HKDFSHA256)
		contents.AddUint16LengthPrefixed(func(k *cryptobyte.Builder) {
			k.AddBytes(c.PublicKey)
		})
		contents.AddUint16LengthPrefixed(func(cs *cryptobyte.Builder) {
			for _, s := range c.Ciphers {
				cs.AddUint16(s.KDF)
				cs.AddUint16(s.AEAD)
			}
		})
		contents.AddUint8(c.MaxNameLength)
		contents.AddUint8LengthPrefixed(func(n *cryptobyte.Builder) {
			n.AddBytes([]byte(c.PublicName))
		})
		// No extensions. A mandatory extension a client does not know
		// makes it skip the config, so nothing is added here without a
		// reason to.
		contents.AddUint16(0)
	})
	return b.Bytes()
}

func (c Config) check() error {
	if err := ValidPublicName(c.PublicName); err != nil {
		return err
	}
	if len(c.PublicKey) != 32 {
		return fmt.Errorf("public key is %d bytes, want 32 (X25519)", len(c.PublicKey))
	}
	if len(c.Ciphers) == 0 {
		return errors.New("no cipher suites")
	}
	for _, s := range c.Ciphers {
		if s.KDF != KDFHKDFSHA256 {
			return fmt.Errorf("unsupported KDF %#04x (only HKDF-SHA256)", s.KDF)
		}
		switch s.AEAD {
		case AEADAES128GCM, AEADAES256GCM, AEADChaCha20Poly1305:
		default:
			return fmt.Errorf("unsupported AEAD %#04x", s.AEAD)
		}
	}
	return nil
}

// MarshalList encodes an ECHConfigList: what a DNS HTTPS record's `ech`
// parameter carries. Several configs in one list is how a key rotation
// overlaps — clients pick the first they understand.
func MarshalList(cs []Config) ([]byte, error) {
	if len(cs) == 0 {
		return nil, errors.New("no configs")
	}
	var body []byte
	for i, c := range cs {
		enc, err := c.Marshal()
		if err != nil {
			return nil, fmt.Errorf("config %d: %w", i, err)
		}
		body = append(body, enc...)
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(l *cryptobyte.Builder) { l.AddBytes(body) })
	return b.Bytes()
}

// ListBase64 is the value to put in an HTTPS record's ech= parameter.
func ListBase64(cs []Config) (string, error) {
	l, err := MarshalList(cs)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(l), nil
}

// Parse decodes one ECHConfig. A config of another version is reported
// as such rather than guessed at.
func Parse(enc []byte) (Config, error) {
	if len(enc) > maxConfigBytes {
		return Config{}, fmt.Errorf("ech config is %d bytes, over the %d byte bound", len(enc), maxConfigBytes)
	}
	s := cryptobyte.String(enc)
	var version, length uint16
	if !s.ReadUint16(&version) || !s.ReadUint16(&length) {
		return Config{}, errors.New("truncated ech config header")
	}
	if version != Version {
		return Config{}, fmt.Errorf("ech config version %#04x is not the supported %#04x", version, Version)
	}
	if int(length) != len(s) {
		return Config{}, fmt.Errorf("ech config length %d does not match the %d bytes that follow", length, len(s))
	}
	var c Config
	var pub, suites, name, exts cryptobyte.String
	if !s.ReadUint8(&c.ID) {
		return Config{}, errors.New("truncated config_id")
	}
	var kem uint16
	if !s.ReadUint16(&kem) {
		return Config{}, errors.New("truncated kem_id")
	}
	if kem != KEMX25519HKDFSHA256 {
		return Config{}, fmt.Errorf("unsupported KEM %#04x (only DHKEM(X25519, HKDF-SHA256))", kem)
	}
	if !s.ReadUint16LengthPrefixed(&pub) {
		return Config{}, errors.New("truncated public_key")
	}
	c.PublicKey = append([]byte(nil), pub...)
	if !s.ReadUint16LengthPrefixed(&suites) {
		return Config{}, errors.New("truncated cipher_suites")
	}
	for !suites.Empty() {
		var one Cipher
		if !suites.ReadUint16(&one.KDF) || !suites.ReadUint16(&one.AEAD) {
			return Config{}, errors.New("truncated cipher suite")
		}
		c.Ciphers = append(c.Ciphers, one)
	}
	if !s.ReadUint8(&c.MaxNameLength) {
		return Config{}, errors.New("truncated maximum_name_length")
	}
	if !s.ReadUint8LengthPrefixed(&name) {
		return Config{}, errors.New("truncated public_name")
	}
	c.PublicName = string(name)
	if !s.ReadUint16LengthPrefixed(&exts) {
		return Config{}, errors.New("truncated extensions")
	}
	// A mandatory extension (high bit set) that this build does not
	// implement means the config cannot be honoured; say so rather than
	// serve a key clients will not use.
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return Config{}, errors.New("truncated extension")
		}
		if typ&0x8000 != 0 {
			return Config{}, fmt.Errorf("mandatory ech extension %#04x is not supported", typ)
		}
	}
	if !s.Empty() {
		return Config{}, errors.New("trailing bytes after the ech config")
	}
	if err := c.check(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// ParseList decodes an ECHConfigList, as published in DNS.
func ParseList(enc []byte) ([]Config, error) {
	s := cryptobyte.String(enc)
	var body cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&body) {
		return nil, errors.New("truncated ech config list")
	}
	if !s.Empty() {
		return nil, errors.New("trailing bytes after the ech config list")
	}
	var out []Config
	for !body.Empty() {
		// Each config carries its own length, so one is taken at a time
		// from the front of what is left.
		if len(body) < 4 {
			return nil, errors.New("truncated ech config in list")
		}
		length := int(body[2])<<8 | int(body[3])
		if len(body) < length+4 {
			return nil, errors.New("ech config in list is shorter than its length")
		}
		c, err := Parse(body[:length+4])
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		body = body[length+4:]
	}
	if len(out) == 0 {
		return nil, errors.New("ech config list is empty")
	}
	return out, nil
}

// PrivateKeyPublic derives the public key from a stored private key, so
// a loaded pair can be checked to belong together. A config served with
// the wrong key fails every ECH handshake and falls back silently,
// which is the hardest ECH fault to notice.
func PrivateKeyPublic(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("not an X25519 private key: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}
