package ntske

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/siv"
)

// Key derivation, RFC 8915 s5.1.
//
// The keys are exported from the TLS connection rather than sent over it, which
// is the property that makes NTS worth having: a party that recorded the whole
// TLS exchange and later obtained the server's private key still cannot derive
// them, because the exporter's input includes the handshake secrets and not the
// key exchange's long-term key.
const (
	// exporterLabel is the label RFC 8915 assigns.
	exporterLabel = "EXPORTER-network-time-security"
	// KeyLen is the length of each derived key for AEAD_AES_SIV_CMAC_256.
	KeyLen = siv.KeySize256
	// directionC2S and directionS2C are the last octet of the exporter
	// context. They are what make the two directions' keys different, so that a
	// packet the server sent cannot be replayed to the server as one the client
	// sent.
	directionC2S = 0x00
	directionS2C = 0x01
)

// Keys are one association's two directions.
type Keys struct {
	C2S, S2C []byte
}

// Exporter is the one thing this needs from a TLS connection, named so that the
// derivation can be tested without one.
type Exporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// Derive exports the two keys for a negotiated protocol and algorithm.
func Derive(e Exporter, nextProto, aead uint16) (*Keys, error) {
	if e == nil {
		return nil, errors.New("ntske: no exporter")
	}
	ctx := func(dir byte) []byte {
		b := make([]byte, 0, 5)
		b = binary.BigEndian.AppendUint16(b, nextProto)
		b = binary.BigEndian.AppendUint16(b, aead)
		return append(b, dir)
	}
	c2s, err := e.ExportKeyingMaterial(exporterLabel, ctx(directionC2S), KeyLen)
	if err != nil {
		return nil, fmt.Errorf("ntske: exporting the client-to-server key: %w", err)
	}
	s2c, err := e.ExportKeyingMaterial(exporterLabel, ctx(directionS2C), KeyLen)
	if err != nil {
		return nil, fmt.Errorf("ntske: exporting the server-to-client key: %w", err)
	}
	return &Keys{C2S: c2s, S2C: s2c}, nil
}

// ErrNoHandshake is a connection whose handshake has not finished. It is its
// own error because the listener has to be able to tell it from an export that
// failed: one is a connection used too early, the other is a TLS stack that
// cannot do what NTS needs.
var ErrNoHandshake = errors.New("ntske: the TLS handshake is not complete")

// DeriveFromTLS is Derive over a finished TLS connection.
//
// The handshake has to be complete, and it is checked rather than assumed: the
// exporter on an unfinished connection would either fail or -- worse, on some
// implementations -- return material derived from a handshake nobody
// authenticated.
func DeriveFromTLS(c *tls.Conn, nextProto, aead uint16) (*Keys, error) {
	if c == nil {
		return nil, errors.New("ntske: no connection")
	}
	if !c.ConnectionState().HandshakeComplete {
		return nil, ErrNoHandshake
	}
	st := c.ConnectionState()
	return Derive(&st, nextProto, aead)
}

// The cookie.
//
// RFC 8915 s6 leaves the format to the server and states what it must achieve:
// the server must be able to recover the algorithm and both keys from it, and
// nobody else must be able to read or forge one. So it is sealed under a key
// this relay holds and nothing in it is readable on the wire.
//
// The shape is a key identifier, a nonce, and the sealed body. The identifier
// is what makes rotation possible without invalidating the cookies already
// issued: a cookie names the key that sealed it, so a new key can start being
// used for new cookies while the old one still opens the ones in flight. A
// client's cookies are a week's worth of its polling interval, and a rotation
// that invalidated them all at once would be a rotation that took the estate's
// time service down.
const (
	// cookieKeyIDLen and cookieNonceLen are the cleartext prefix.
	cookieKeyIDLen = 4
	cookieNonceLen = 16
	// MaxCookie bounds a cookie this will open, which bounds what an attacker
	// can make this relay try to decrypt.
	MaxCookie = 256
	// CookiesPerResponse is how many cookies a key establishment answers with.
	// Eight is what RFC 8915 s5.5 recommends and what every implementation
	// sends: a client spends one per time exchange and gets one back, so eight
	// is the depth of the buffer that absorbs lost packets.
	CookiesPerResponse = 8
)

// ErrCookie is a cookie that did not open: unknown key, wrong length, or a
// forgery. They are one error on purpose -- a caller that could tell them apart
// would be an oracle for which key identifiers exist.
var ErrCookie = errors.New("ntske: the cookie did not open")

// CookieKey is one master key with its identifier.
type CookieKey struct {
	ID  uint32
	Key []byte
}

// CookieKeys is the set of master keys: one current, and the recent ones that
// still open cookies already issued.
type CookieKeys struct {
	mu      sync.RWMutex
	current CookieKey
	old     []CookieKey
	keep    int
	// rotated is when the current key became current.
	rotated time.Time
	now     func() time.Time
}

// NewCookieKeys starts a key set with one random key.
//
// keep is how many previous keys still open cookies. Two is the useful minimum
// with a rotation interval of a day: a cookie issued just before a rotation is
// spent after it, and a client that was switched off over a weekend comes back
// with cookies from two rotations ago.
func NewCookieKeys(keep int) (*CookieKeys, error) {
	if keep < 0 {
		return nil, errors.New("ntske: negative key history")
	}
	k := &CookieKeys{keep: keep, now: time.Now}
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	k.current, k.rotated = key, k.now()
	return k, nil
}

func randomKey() (CookieKey, error) {
	b := make([]byte, siv.KeySize256)
	if _, err := rand.Read(b); err != nil {
		return CookieKey{}, err
	}
	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		return CookieKey{}, err
	}
	return CookieKey{ID: binary.BigEndian.Uint32(id[:]), Key: b}, nil
}

// Rotate makes a new current key and retires the old one.
func (k *CookieKeys) Rotate() error {
	key, err := randomKey()
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.old = append([]CookieKey{k.current}, k.old...)
	if len(k.old) > k.keep {
		k.old = k.old[:k.keep]
	}
	k.current, k.rotated = key, k.now()
	return nil
}

// Rotated is when the current key became current, so a caller can rotate on an
// interval without keeping the clock itself.
func (k *CookieKeys) Rotated() time.Time {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.rotated
}

// Keys is the current key and the retired ones, for a status view and for
// persisting across a restart.
func (k *CookieKeys) Keys() (CookieKey, []CookieKey) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current, append([]CookieKey(nil), k.old...)
}

// Restore replaces the set, which is how a restart keeps the cookies already
// issued working.
func (k *CookieKeys) Restore(current CookieKey, old []CookieKey) error {
	if len(current.Key) != siv.KeySize256 {
		return fmt.Errorf("ntske: a cookie key is %d octets, not %d", len(current.Key), siv.KeySize256)
	}
	for _, o := range old {
		if len(o.Key) != siv.KeySize256 {
			return fmt.Errorf("ntske: a retired cookie key is %d octets, not %d", len(o.Key), siv.KeySize256)
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.current, k.old = current, append([]CookieKey(nil), old...)
	if len(k.old) > k.keep {
		k.old = k.old[:k.keep]
	}
	k.rotated = k.now()
	return nil
}

// cookieBody is the plaintext inside a cookie: the algorithm and the two keys.
//
// Encoded with explicit lengths rather than at fixed offsets, because the AEAD
// number decides the key length and a format that assumed one length would have
// to change to add an algorithm.
func cookieBody(aead uint16, keys *Keys) []byte {
	out := make([]byte, 0, 6+len(keys.C2S)+len(keys.S2C))
	out = binary.BigEndian.AppendUint16(out, aead)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keys.C2S))) //nolint:gosec // a key length
	out = append(out, keys.C2S...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keys.S2C))) //nolint:gosec // a key length
	return append(out, keys.S2C...)
}

func parseCookieBody(b []byte) (uint16, *Keys, error) {
	if len(b) < 6 {
		return 0, nil, ErrCookie
	}
	aead := binary.BigEndian.Uint16(b)
	n := int(binary.BigEndian.Uint16(b[2:]))
	if len(b) < 4+n+2 {
		return 0, nil, ErrCookie
	}
	c2s := b[4 : 4+n]
	rest := b[4+n:]
	m := int(binary.BigEndian.Uint16(rest))
	if len(rest) < 2+m {
		return 0, nil, ErrCookie
	}
	return aead, &Keys{C2S: c2s, S2C: rest[2 : 2+m]}, nil
}

// Seal makes a cookie for one association.
func (k *CookieKeys) Seal(aead uint16, keys *Keys) ([]byte, error) {
	if keys == nil || len(keys.C2S) == 0 || len(keys.S2C) == 0 {
		return nil, errors.New("ntske: sealing a cookie with no keys")
	}
	k.mu.RLock()
	cur := k.current
	k.mu.RUnlock()
	a, err := siv.New(cur.Key, cookieNonceLen)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, cookieNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, cookieKeyIDLen+cookieNonceLen+64)
	out = binary.BigEndian.AppendUint32(out, cur.ID)
	out = append(out, nonce...)
	// The identifier and the nonce are the associated data, so a cookie whose
	// prefix was edited does not open: an attacker who moved a cookie to
	// another key identifier would otherwise be handed a decryption oracle.
	out = a.Seal(out, nonce, cookieBody(aead, keys), out[:cookieKeyIDLen])
	if len(out) > MaxCookie {
		return nil, fmt.Errorf("ntske: the cookie is %d octets, past the bound of %d", len(out), MaxCookie)
	}
	return out, nil
}

// Open reads a cookie, trying the current key and then the retired ones.
func (k *CookieKeys) Open(cookie []byte) (uint16, *Keys, error) {
	if len(cookie) < cookieKeyIDLen+cookieNonceLen+siv.TagSize || len(cookie) > MaxCookie {
		return 0, nil, ErrCookie
	}
	id := binary.BigEndian.Uint32(cookie)
	nonce := cookie[cookieKeyIDLen : cookieKeyIDLen+cookieNonceLen]
	body := cookie[cookieKeyIDLen+cookieNonceLen:]
	k.mu.RLock()
	keys := append([]CookieKey{k.current}, k.old...)
	k.mu.RUnlock()
	for _, ck := range keys {
		if ck.ID != id {
			continue
		}
		a, err := siv.New(ck.Key, cookieNonceLen)
		if err != nil {
			continue
		}
		plain, err := a.Open(nil, nonce, body, cookie[:cookieKeyIDLen])
		if err != nil {
			// The identifier matched and the seal did not. Not tried against
			// the other keys: two keys with one identifier is not a thing this
			// produces, and trying them all would make the work per cookie
			// depend on how many keys are held.
			return 0, nil, ErrCookie
		}
		return parseCookieBody(plain)
	}
	return 0, nil, ErrCookie
}
