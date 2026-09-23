package rdp

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // the protocol specifies MD5
	"crypto/rand"
	"crypto/rc4" //nolint:gosec // the protocol specifies RC4
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the protocol specifies SHA-1
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// The protocol's own encryption, which MS-RDPBCGR section 5.3 calls
// standard RDP security and everyone else calls the legacy one: RC4
// under keys derived from two random values, one of which the client
// sends encrypted under an RSA key the server puts in the connection
// sequence.
//
// What it is worth. Nothing, against anyone on the path. The key
// derivation is MD5 and SHA-1, the cipher is RC4, and the RSA key
// arrives inside a certificate the client has no way to check without
// a public key infrastructure the protocol never had. It is here for
// one reason: equipment that speaks nothing else. A desktop reached
// this way is better reached through a gateway that records the
// session and holds the policy than reached directly, and the
// documentation says exactly that rather than implying the connection
// is protected.
//
// Only the client half is implemented -- this proxy can open an old
// desktop, it cannot pretend to be one. The server half needs a
// certificate signed with the private key Microsoft published in
// MS-RDPBCGR 5.3.3.1.1, which a client checks against the public half
// built into it; without that key a certificate this gateway made is
// refused by every client, so the client-facing half is refused at
// load instead of failing at the first connection.

// ErrLegacy is a failure in the legacy exchange.
var ErrLegacy = errors.New("rdp: legacy encryption")

// The encryption methods of MS-RDPBCGR 2.2.1.4.3.
const (
	Encryption40Bit  = 0x00000001
	Encryption128Bit = 0x00000002
	Encryption56Bit  = 0x00000008
	EncryptionFIPS   = 0x00000010
)

// The encryption levels, which say how much of the session is
// encrypted rather than how strongly. Low encrypts what the client
// sends and nothing of what the desktop sends; the rest encrypt both
// directions. Nothing here branches on the level to decide what to
// decrypt -- each packet says whether it is encrypted, and that is
// what is acted on, so a desktop that encrypts more than its level
// promised is read correctly anyway.
const (
	EncryptionLevelNone             = 0
	EncryptionLevelLow              = 1
	EncryptionLevelClientCompatible = 2
	EncryptionLevelHigh             = 3
	EncryptionLevelFIPS             = 4
)

// EncodeClientSecurity renders the block a client sends to say what it
// can encrypt with (MS-RDPBCGR 2.2.1.3.3). The second word is the
// French locale's extra method, which this gateway never asks for.
func EncodeClientSecurity(methods uint32) []byte {
	out := binary.LittleEndian.AppendUint32(nil, methods)
	return binary.LittleEndian.AppendUint32(out, 0)
}

// ClientMethods is what this gateway offers a desktop: the three RC4
// widths, strongest first by the desktop's own choice. FIPS is left
// out because it is 3DES with a different derivation and a different
// packet layout, and a gateway that claimed it would fail after the
// exchange rather than before it.
const ClientMethods = Encryption128Bit | Encryption56Bit | Encryption40Bit

// RandomSize is the length of each end's random value.
const RandomSize = 32

// ServerSecurity is the block a desktop sends: what it will encrypt
// with, and the key the client's random travels under.
type ServerSecurity struct {
	Method uint32
	Level  uint32
	Random []byte
	// PublicKey is the RSA key taken out of the certificate, or nil
	// where the desktop encrypts nothing.
	PublicKey *rsa.PublicKey
	// certificate is kept for the log: which kind it was.
	Proprietary bool
}

// maxCertificate bounds the certificate a desktop sends.
const maxCertificate = 16 << 10

// ParseServerSecurity reads the block.
func ParseServerSecurity(b []byte) (*ServerSecurity, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("%w: a security block of %d bytes", ErrLegacy, len(b))
	}
	s := &ServerSecurity{
		Method: binary.LittleEndian.Uint32(b[0:4]),
		Level:  binary.LittleEndian.Uint32(b[4:8]),
	}
	if s.Method == 0 && s.Level == EncryptionLevelNone {
		// Nothing is encrypted, which is what a desktop on TLS says.
		return s, nil
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("%w: a security block of %d bytes with a method set", ErrLegacy, len(b))
	}
	randomLen := int(binary.LittleEndian.Uint32(b[8:12]))
	certLen := int(binary.LittleEndian.Uint32(b[12:16]))
	if randomLen != RandomSize {
		return nil, fmt.Errorf("%w: a server random of %d bytes, want %d", ErrLegacy, randomLen, RandomSize)
	}
	if certLen > maxCertificate {
		return nil, fmt.Errorf("%w: a certificate of %d bytes", ErrLegacy, certLen)
	}
	if 16+randomLen+certLen > len(b) {
		return nil, fmt.Errorf("%w: a block promising %d bytes with %d there", ErrLegacy, 16+randomLen+certLen, len(b))
	}
	s.Random = append([]byte(nil), b[16:16+randomLen]...)
	key, proprietary, err := parseCertificate(b[16+randomLen : 16+randomLen+certLen])
	if err != nil {
		return nil, err
	}
	s.PublicKey, s.Proprietary = key, proprietary
	return s, nil
}

// EncodeServerSecurity renders a block, which the gateway uses to tell
// a client on another kind of leg that nothing here is encrypted.
func EncodeServerSecurity(method, level uint32) []byte {
	out := binary.LittleEndian.AppendUint32(nil, method)
	return binary.LittleEndian.AppendUint32(out, level)
}

// parseCertificate takes the RSA key out of whichever kind of
// certificate the desktop sent.
func parseCertificate(b []byte) (*rsa.PublicKey, bool, error) {
	if len(b) < 4 {
		return nil, false, fmt.Errorf("%w: a certificate of %d bytes", ErrLegacy, len(b))
	}
	version := binary.LittleEndian.Uint32(b[0:4]) & 0x7FFFFFFF
	if version != 1 {
		// An X.509 chain, which this gateway does not walk: the
		// protocol gives it nothing to check the chain against, so
		// walking it would be theatre. A desktop offering one is one
		// to reach over TLS instead.
		return nil, false, fmt.Errorf("%w: the desktop sent a certificate chain, which this gateway does not use; reach it over tls", ErrLegacy)
	}
	key, err := proprietaryKey(b)
	return key, true, err
}

// proprietaryKey walks the proprietary certificate to its public key
// blob. Every length in it is the desktop's to choose.
func proprietaryKey(b []byte) (*rsa.PublicKey, error) {
	// dwVersion, dwSigAlgId, dwKeyAlgId, then the key blob's type and
	// length.
	if len(b) < 16 {
		return nil, fmt.Errorf("%w: a proprietary certificate of %d bytes", ErrLegacy, len(b))
	}
	blobLen := int(binary.LittleEndian.Uint16(b[14:16]))
	if 16+blobLen > len(b) {
		return nil, fmt.Errorf("%w: a key blob of %d bytes with %d there", ErrLegacy, blobLen, len(b)-16)
	}
	return parseRSAPublicKey(b[16 : 16+blobLen])
}

// rsaMagic opens the public key blob.
var rsaMagic = []byte("RSA1")

// parseRSAPublicKey reads the key blob of MS-RDPBCGR 2.2.1.4.3.1.1.1.
func parseRSAPublicKey(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 20 || string(b[:4]) != string(rsaMagic) {
		return nil, fmt.Errorf("%w: not an RSA key blob", ErrLegacy)
	}
	bitLen := int(binary.LittleEndian.Uint32(b[8:12]))
	if bitLen < 512 || bitLen > 8192 || bitLen%8 != 0 {
		return nil, fmt.Errorf("%w: a key of %d bits", ErrLegacy, bitLen)
	}
	exponent := binary.LittleEndian.Uint32(b[16:20])
	if exponent < 3 || exponent%2 == 0 {
		return nil, fmt.Errorf("%w: an exponent of %d", ErrLegacy, exponent)
	}
	// The modulus is the key's own length plus eight bytes of padding.
	size := bitLen / 8
	if 20+size > len(b) {
		return nil, fmt.Errorf("%w: a modulus of %d bytes with %d there", ErrLegacy, size, len(b)-20)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(reverse(b[20 : 20+size])), E: int(exponent)}, nil
}

// leftPad grows a big integer's bytes to a fixed width.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// reverse returns the bytes the other way round. The protocol carries
// its large integers little-endian and everything else here reads
// them big-endian.
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// SealClientRandom encrypts this end's random under the desktop's key,
// in the raw form the protocol uses: no padding, little-endian, and a
// length field in front.
//
// There is no padding scheme here to get wrong because the protocol
// does not have one. That is one of the reasons this is not
// encryption anybody should rely on.
func SealClientRandom(pub *rsa.PublicKey, random []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: the desktop offered no key", ErrLegacy)
	}
	if len(random) != RandomSize {
		return nil, fmt.Errorf("%w: a random of %d bytes", ErrLegacy, len(random))
	}
	m := new(big.Int).SetBytes(reverse(random))
	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	size := (pub.N.BitLen() + 7) / 8
	out := reverse(leftPad(c.Bytes(), size))
	// Eight bytes of padding follow the value, which is what the
	// protocol's own implementations send.
	return append(out, make([]byte, 8)...), nil
}

// NewRandom draws one end's random value.
func NewRandom() ([]byte, error) {
	b := make([]byte, RandomSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// SecurityExchange renders the packet that carries the sealed random.
func SecurityExchange(sealed []byte) []byte {
	out := SecurityHeader{Flags: SecExchangePkt}.Encode()
	out = binary.LittleEndian.AppendUint32(out, uint32(len(sealed))) //nolint:gosec // bounded by the key size
	return append(out, sealed...)
}

// Keys are what a session encrypts and signs with.
type Keys struct {
	// MAC is the key every signature is taken under, and does not
	// change for the life of the session.
	MAC []byte
	// Encrypt and Decrypt are this end's two directions.
	Encrypt, Decrypt []byte
	// size is the key length in bytes, which the weaker methods cut
	// down.
	size int
}

// DeriveKeys works out the session keys from the two randoms, as
// MS-RDPBCGR section 5.3.5 sets out. The result is this end's view:
// the client encrypts with one key and decrypts with the other, and
// the server's view is the two the other way round.
func DeriveKeys(method uint32, clientRandom, serverRandom []byte) (*Keys, error) {
	if len(clientRandom) != RandomSize || len(serverRandom) != RandomSize {
		return nil, fmt.Errorf("%w: randoms of %d and %d bytes", ErrLegacy, len(clientRandom), len(serverRandom))
	}
	size := 16
	switch method {
	case Encryption128Bit:
	case Encryption40Bit, Encryption56Bit:
		size = 8
	case EncryptionFIPS:
		// FIPS mode is 3DES with a different derivation entirely.
		return nil, fmt.Errorf("%w: the desktop asked for FIPS mode, which this gateway does not implement", ErrLegacy)
	default:
		return nil, fmt.Errorf("%w: encryption method %#x", ErrLegacy, method)
	}
	// The premaster secret is the first three quarters of each random.
	pre := append(append([]byte(nil), clientRandom[:24]...), serverRandom[:24]...)
	master := concatSalted(pre, clientRandom, serverRandom, "A", "BB", "CCC")
	blob := concatSalted(master, clientRandom, serverRandom, "X", "YY", "ZZZ")

	k := &Keys{size: size, MAC: blob[:16]}
	// The two directions, each finalised with the randoms again.
	k.Decrypt = finalHash(blob[16:32], clientRandom, serverRandom)
	k.Encrypt = finalHash(blob[32:48], clientRandom, serverRandom)
	if size == 8 {
		// The weakened methods keep the first eight bytes and start
		// them with a fixed prefix, so that what is left is the
		// advertised number of bits.
		k.MAC = weaken(k.MAC, method)
		k.Encrypt = weaken(k.Encrypt, method)
		k.Decrypt = weaken(k.Decrypt, method)
	}
	return k, nil
}

// weaken cuts a key down to what the method actually carries.
func weaken(key []byte, method uint32) []byte {
	out := append([]byte(nil), key[:8]...)
	out[0] = 0xD1
	if method == Encryption40Bit {
		out[1], out[2] = 0x26, 0x9E
	}
	return out
}

// concatSalted is the three-part hash the derivation uses twice.
func concatSalted(secret, clientRandom, serverRandom []byte, salts ...string) []byte {
	var out []byte
	for _, s := range salts {
		out = append(out, saltedHash(secret, []byte(s), clientRandom, serverRandom)...)
	}
	return out
}

// saltedHash is MD5 over the secret and a SHA-1 over everything.
func saltedHash(secret, salt, clientRandom, serverRandom []byte) []byte {
	sh := sha1.New() //nolint:gosec // the protocol specifies SHA-1
	sh.Write(salt)
	sh.Write(secret)
	sh.Write(clientRandom)
	sh.Write(serverRandom)
	mh := md5.New() //nolint:gosec // the protocol specifies MD5
	mh.Write(secret)
	mh.Write(sh.Sum(nil))
	return mh.Sum(nil)
}

// finalHash mixes a key with the two randoms once more.
func finalHash(key, clientRandom, serverRandom []byte) []byte {
	h := md5.New() //nolint:gosec // the protocol specifies MD5
	h.Write(key)
	h.Write(clientRandom)
	h.Write(serverRandom)
	return h.Sum(nil)
}

// The padding the signature and the key update are taken over.
var (
	pad1 = repeat(0x36, 40)
	pad2 = repeat(0x5C, 48)
)

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// rekeyEvery is how many packets a key survives.
const rekeyEvery = 4096

// Crypt is one direction of a legacy session: its RC4 state, its
// starting key and how many packets that key has done.
type Crypt struct {
	mac     []byte
	start   []byte
	current []byte
	method  uint32
	size    int
	rc4     *rc4.Cipher
	count   int
}

// NewCrypt starts one direction.
func NewCrypt(k *Keys, key []byte, method uint32) (*Crypt, error) {
	c := &Crypt{mac: k.MAC, start: append([]byte(nil), key...),
		current: append([]byte(nil), key...), method: method, size: k.size}
	return c, c.reset()
}

func (c *Crypt) reset() error {
	r, err := rc4.NewCipher(c.current) //nolint:gosec // the protocol specifies RC4
	if err != nil {
		return err
	}
	c.rc4, c.count = r, 0
	return nil
}

// Sign is the eight byte signature that travels with an encrypted
// packet.
func (c *Crypt) Sign(data []byte) []byte {
	sh := sha1.New() //nolint:gosec // the protocol specifies SHA-1
	sh.Write(c.mac)
	sh.Write(pad1)
	sh.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(data)))) //nolint:gosec // bounded by a pdu
	sh.Write(data)
	mh := md5.New() //nolint:gosec // the protocol specifies MD5
	mh.Write(c.mac)
	mh.Write(pad2)
	mh.Write(sh.Sum(nil))
	return mh.Sum(nil)[:8]
}

// Apply encrypts or decrypts in place and rolls the key over when it
// has done its packets. RC4 is its own inverse, so one method serves
// both directions.
func (c *Crypt) Apply(data []byte) error {
	c.rc4.XORKeyStream(data, data)
	c.count++
	if c.count < rekeyEvery {
		return nil
	}
	return c.rekey()
}

// rekey derives the next key from the starting one and the current.
func (c *Crypt) rekey() error {
	sh := sha1.New() //nolint:gosec // the protocol specifies SHA-1
	sh.Write(c.start)
	sh.Write(pad1)
	sh.Write(c.current)
	mh := md5.New() //nolint:gosec // the protocol specifies MD5
	mh.Write(c.start)
	mh.Write(pad2)
	mh.Write(sh.Sum(nil))
	next := mh.Sum(nil)

	// The new key is the derived one run through RC4 under itself.
	r, err := rc4.NewCipher(next) //nolint:gosec // the protocol specifies RC4
	if err != nil {
		return err
	}
	out := make([]byte, len(next))
	r.XORKeyStream(out, next)
	if c.size == 8 {
		out = weaken(out, c.method)
	}
	c.current = out
	return c.reset()
}

// ---- packets, once the keys exist ----

// signatureSize is the eight bytes that travel in front of an
// encrypted payload.
const signatureSize = 8

// Seal renders the security header, signature and encrypted payload
// that a packet carries once the session is encrypted. The signature is
// taken over the plaintext, which is why it is computed first.
//
// The flags the caller passes are the packet's own -- what kind of
// packet it is -- and SEC_ENCRYPT is added here, because whether the
// packet is encrypted is this function's business rather than the
// caller's.
func (c *Crypt) Seal(flags uint16, payload []byte) ([]byte, error) {
	body := append([]byte(nil), payload...)
	sig := c.Sign(body)
	if err := c.Apply(body); err != nil {
		return nil, err
	}
	out := SecurityHeader{Flags: flags | SecEncrypt}.Encode()
	out = append(out, sig...)
	return append(out, body...), nil
}

// Open reverses Seal: it takes the payload of a data unit whose
// security header says it is encrypted, decrypts it and checks the
// signature.
//
// A signature that does not match is the end of the session. There is
// nothing to salvage: either the key schedule has diverged, in which
// case every packet after this is nonsense, or somebody on the path
// changed the packet.
func (c *Crypt) Open(b []byte) ([]byte, error) {
	if len(b) < signatureSize {
		return nil, fmt.Errorf("%w: an encrypted payload of %d bytes", ErrLegacy, len(b))
	}
	sig := b[:signatureSize]
	body := append([]byte(nil), b[signatureSize:]...)
	if err := c.Apply(body); err != nil {
		return nil, err
	}
	if !hmac.Equal(sig, c.Sign(body)) {
		return nil, fmt.Errorf("%w: a packet whose signature does not match its contents", ErrLegacy)
	}
	return body, nil
}

// The fast path headers of MS-RDPBCGR 2.2.9.1.2 and 2.2.8.1.2. Bits
// six and seven of the first byte say whether the rest is encrypted,
// and a value of two there means it is.
const (
	fastPathEncryptedShift = 6
	fastPathEncrypted      = 2
)

// FastPathEncrypted says whether a fast path PDU's header claims the
// rest of it is encrypted. It takes the PDU as it arrived.
func FastPathEncrypted(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	return raw[0]>>fastPathEncryptedShift&3 == fastPathEncrypted
}

// FastPathOpen decrypts a fast path PDU whose header says it is
// encrypted, and returns the PDU with the plaintext in place of the
// signature and ciphertext, its header no longer claiming encryption.
// A gateway forwards that onwards: the leg it is going out on is a
// different one, with encryption of its own or none.
func (c *Crypt) FastPathOpen(raw []byte) ([]byte, error) {
	head, body, err := splitFastPath(raw)
	if err != nil {
		return nil, err
	}
	plain, err := c.Open(body)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), head...)
	out[0] &^= 3 << fastPathEncryptedShift
	out = append(out, plain...)
	return setFastPathLength(out, len(head))
}

// FastPathSeal is the other direction: a plaintext fast path PDU
// becomes an encrypted one, with the signature in front of the body
// and the header saying so.
func (c *Crypt) FastPathSeal(raw []byte) ([]byte, error) {
	head, body, err := splitFastPath(raw)
	if err != nil {
		return nil, err
	}
	sealed := append([]byte(nil), body...)
	sig := c.Sign(sealed)
	if err := c.Apply(sealed); err != nil {
		return nil, err
	}
	out := append([]byte(nil), head...)
	out[0] = out[0]&^(3<<fastPathEncryptedShift) | fastPathEncrypted<<fastPathEncryptedShift
	out = append(out, sig...)
	out = append(out, sealed...)
	return setFastPathLength(out, len(head))
}

// splitFastPath separates a fast path PDU's header from its body. The
// header is one byte of action and flags plus a length of one or two
// bytes, and which of those it is depends on the top bit of the first
// length byte.
func splitFastPath(raw []byte) (head, body []byte, err error) {
	if len(raw) < 2 {
		return nil, nil, fmt.Errorf("%w: a fast path pdu of %d bytes", ErrLegacy, len(raw))
	}
	n := 2
	if raw[1]&0x80 != 0 {
		n = 3
	}
	if len(raw) < n {
		return nil, nil, fmt.Errorf("%w: a fast path header of %d bytes", ErrLegacy, len(raw))
	}
	return raw[:n], raw[n:], nil
}

// setFastPathLength writes the new total length into a rewritten PDU's
// header. The header keeps the width it had, so a PDU that grew or
// shrank by the signature has to still fit that width.
func setFastPathLength(out []byte, headLen int) ([]byte, error) {
	switch headLen {
	case 2:
		if len(out) > 0x7F {
			// One byte of length cannot say more than 127, so the
			// header has to grow -- and growing it moves the body,
			// which is what the two byte form is for.
			grown := append([]byte{out[0], 0, 0}, out[2:]...)
			return setFastPathLength(grown, 3)
		}
		out[1] = byte(len(out))
	case 3:
		if len(out) > 0x7FFF {
			return nil, fmt.Errorf("%w: a fast path pdu of %d bytes", ErrLegacy, len(out))
		}
		out[1] = byte(len(out)>>8) | 0x80
		out[2] = byte(len(out))
	default:
		return nil, fmt.Errorf("%w: a fast path header of %d bytes", ErrLegacy, headLen)
	}
	return out, nil
}

// EncryptionMethodName names a method for a log line.
func EncryptionMethodName(m uint32) string {
	switch m {
	case 0:
		return "none"
	case Encryption40Bit:
		return "rc4-40"
	case Encryption56Bit:
		return "rc4-56"
	case Encryption128Bit:
		return "rc4-128"
	case EncryptionFIPS:
		return "fips"
	default:
		return fmt.Sprintf("%#x", m)
	}
}

// EncryptionLevelName names a level for a log line. The level says how
// much of the session is encrypted, not how strongly.
func EncryptionLevelName(l uint32) string {
	switch l {
	case EncryptionLevelNone:
		return "none"
	case EncryptionLevelLow:
		return "low"
	case EncryptionLevelClientCompatible:
		return "client-compatible"
	case EncryptionLevelHigh:
		return "high"
	case EncryptionLevelFIPS:
		return "fips"
	default:
		return fmt.Sprintf("%#x", l)
	}
}
