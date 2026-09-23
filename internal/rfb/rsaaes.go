package rfb

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the protocol specifies SHA-1 for the 128 bit variants
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/eax"
)

// RSA-AES is RealVNC's family of security types: 129 (RA2, AES-128
// with the session encrypted), 130 (RA2ne, the same handshake with the
// session left in clear) and 133 (RA2-256, AES-256).
//
// Where this comes from. RealVNC publishes no specification. The
// exchange below follows TigerVNC's implementation and the description
// in its rfbproto, which is the only public account of it: an RSA key
// each way, a random each way encrypted under the other's key, session
// keys hashed out of the two randoms, and everything after that inside
// AES-EAX with a counter for a nonce and the message's own length as
// its associated data.
//
// What is solid and what is not. The cryptography here is not guessed
// at: RSA and the hashes are the standard library's, and EAX is
// implemented in internal/eax against the published vectors of the EAX
// paper and NIST SP 800-38B. What is reconstructed is the order and
// framing of the messages. That matters, because getting it wrong
// means a handshake that does not complete -- which is visible
// immediately and says which step failed -- rather than a session that
// looks encrypted and is not. Interoperability with RealVNC's own
// server is NOT verified by this repository's tests, and docs/CONFIG.md
// says so.

const (
	// RSAAESMinKeyBits is the smallest peer key this proxy will use.
	// TigerVNC will talk to 1024, and 1024 bit RSA is not a size to
	// protect a desktop credential with in the years this will run.
	RSAAESMinKeyBits = 2048
	// RSAAESMaxKeyBits bounds what a peer can make this proxy do: an
	// RSA operation on an enormous modulus is work an unauthenticated
	// peer should not be able to ask for.
	RSAAESMaxKeyBits = 8192
	// rsaAESMaxMessage bounds one framed message inside the channel.
	rsaAESMaxMessage = 1 << 16
	// RSAAESSubtypeUserPassword and RSAAESSubtypePassword are what a
	// server says it wants: a name and a password, or a password only.
	RSAAESSubtypeUserPassword = 1
	RSAAESSubtypePassword     = 2
	// rsaAESMaxCredential bounds each credential field, which the
	// protocol length-prefixes with one byte anyway.
	rsaAESMaxCredential = 255
)

// RSAAESFamily is the three types this exchange covers.
var RSAAESFamily = map[uint8]bool{
	SecRSAAES: true, SecRSAAESne: true, SecRSAAES256: true,
}

// ErrRSAAES is the class of failure in this exchange.
var ErrRSAAES = errors.New("rfb: rsa-aes")

// RSAAESKeySize is how wide the session keys are for a type.
func RSAAESKeySize(sec uint8) int {
	if sec == SecRSAAES256 {
		return 32
	}
	return 16
}

// RSAAESEncrypted says whether the session after the handshake stays
// inside the channel. The "ne" type authenticates and then hands the
// desktop back to a cleartext socket, which is a choice an operator
// should be told about rather than one to make quietly.
func RSAAESEncrypted(sec uint8) bool { return sec != SecRSAAESne }

// rsaAESHash is the hash the type uses: SHA-1 for the 128 bit
// variants, SHA-256 for the 256 bit one. SHA-1 is not this project's
// choice; it is what the type does.
func rsaAESHash(sec uint8) hash.Hash {
	if sec == SecRSAAES256 {
		return sha256.New()
	}
	return sha1.New() //nolint:gosec // the protocol specifies it
}

// RSAAESPublicKey is a peer's key as this protocol carries it: a
// length in bits, then the modulus and the exponent, each in that many
// bits' worth of bytes.
type RSAAESPublicKey struct {
	Bits int
	N, E []byte
}

// OwnRSAAESKey renders this end's public key the way the protocol
// sends it, which is also the form the transcript hash is taken over.
func OwnRSAAESKey(pub *rsa.PublicKey) (RSAAESPublicKey, error) {
	bits := pub.N.BitLen()
	if bits < RSAAESMinKeyBits || bits > RSAAESMaxKeyBits {
		return RSAAESPublicKey{}, fmt.Errorf("%w: own key is %d bits, want %d to %d", ErrRSAAES, bits, RSAAESMinKeyBits, RSAAESMaxKeyBits)
	}
	size := (bits + 7) / 8
	return RSAAESPublicKey{
		Bits: bits,
		N:    leftPad(pub.N.Bytes(), size),
		E:    leftPad(big.NewInt(int64(pub.E)).Bytes(), size),
	}, nil
}

// ReadRSAAESKey reads one, refusing a size that is not worth doing the
// arithmetic for before any of it is allocated.
func ReadRSAAESKey(r io.Reader) (RSAAESPublicKey, *rsa.PublicKey, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return RSAAESPublicKey{}, nil, err
	}
	bits := int(binary.BigEndian.Uint32(head[:]))
	if bits < RSAAESMinKeyBits || bits > RSAAESMaxKeyBits {
		return RSAAESPublicKey{}, nil, fmt.Errorf("%w: peer key is %d bits, want %d to %d", ErrRSAAES, bits, RSAAESMinKeyBits, RSAAESMaxKeyBits)
	}
	size := (bits + 7) / 8
	buf := make([]byte, 2*size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return RSAAESPublicKey{}, nil, err
	}
	k := RSAAESPublicKey{Bits: bits, N: buf[:size], E: buf[size:]}
	n := new(big.Int).SetBytes(k.N)
	e := new(big.Int).SetBytes(k.E)
	if n.BitLen() != bits {
		return RSAAESPublicKey{}, nil, fmt.Errorf("%w: peer key says %d bits and carries %d", ErrRSAAES, bits, n.BitLen())
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 || e.Bit(0) == 0 {
		return RSAAESPublicKey{}, nil, fmt.Errorf("%w: peer exponent is not a usable one", ErrRSAAES)
	}
	return k, &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// Encode renders a key that was read, which is what the transcript
// hash is taken over.
func (k RSAAESPublicKey) Encode() []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(k.Bits)) //nolint:gosec // bounded at read
	out = append(out, k.N...)
	return append(out, k.E...)
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// FingerprintMatches compares a configured fingerprint with one just
// computed, ignoring case and the colons an operator may or may not
// have copied.
func FingerprintMatches(want, got string) bool {
	return strings.EqualFold(stripColons(want), stripColons(got))
}

func stripColons(s string) string { return strings.ReplaceAll(s, ":", "") }

// LoadRSAKey reads the listener's own RSA key from a PEM file, in
// either of the two encodings a key is usually written in, and refuses
// one anybody else can read.
func LoadRSAKey(path string) (*rsa.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o; a private key must not be readable by anyone else", path, fi.Mode().Perm())
	}
	pemBytes, err := os.ReadFile(path) //nolint:gosec // an operator named this path
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, k.Validate()
	}
	any, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	k, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: the key is %T, and rsa-aes needs an RSA key", path, any)
	}
	if k.N.BitLen() < RSAAESMinKeyBits {
		return nil, fmt.Errorf("%s: the key is %d bits, and rsa-aes here wants at least %d", path, k.N.BitLen(), RSAAESMinKeyBits)
	}
	return k, k.Validate()
}

// RSAAESRandom draws the random half of the session keys.
func RSAAESRandom(sec uint8) ([]byte, error) {
	b := make([]byte, RSAAESKeySize(sec))
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// SealRSAAESRandom encrypts a random under the peer's key and frames
// it with its length.
func SealRSAAESRandom(pub *rsa.PublicKey, random []byte) ([]byte, error) {
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, random)
	if err != nil {
		return nil, err
	}
	if len(ct) > rsaAESMaxMessage-1 {
		return nil, fmt.Errorf("%w: encrypted random of %d bytes", ErrRSAAES, len(ct))
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(ct))), ct...), nil //nolint:gosec // bounded above
}

// OpenRSAAESRandom reads one and decrypts it with this end's key.
func OpenRSAAESRandom(r io.Reader, priv *rsa.PrivateKey, sec uint8) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 || n > priv.Size() {
		return nil, fmt.Errorf("%w: encrypted random of %d bytes for a %d byte key", ErrRSAAES, n, priv.Size())
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, err
	}
	random, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ct)
	if err != nil {
		return nil, fmt.Errorf("%w: the peer's random did not decrypt", ErrRSAAES)
	}
	if len(random) != RSAAESKeySize(sec) {
		return nil, fmt.Errorf("%w: peer random of %d bytes, want %d", ErrRSAAES, len(random), RSAAESKeySize(sec))
	}
	return random, nil
}

// RSAAESSessionKeys derives the two directions' keys from the two
// randoms. Each direction is hashed from the pair in its own order, so
// the two keys differ and a message cannot be replayed back the way it
// came.
func RSAAESSessionKeys(sec uint8, clientRandom, serverRandom []byte) (clientKey, serverKey []byte) {
	size := RSAAESKeySize(sec)
	h := rsaAESHash(sec)
	h.Write(serverRandom)
	h.Write(clientRandom)
	clientKey = h.Sum(nil)[:size]
	h.Reset()
	h.Write(clientRandom)
	h.Write(serverRandom)
	return clientKey, h.Sum(nil)[:size]
}

// RSAAESTranscript is the hash each end sends to prove it saw the same
// two public keys the other did, which is what stops the exchange
// being relayed by a third party that swapped them.
func RSAAESTranscript(sec uint8, first, second RSAAESPublicKey) []byte {
	h := rsaAESHash(sec)
	h.Write(first.Encode())
	h.Write(second.Encode())
	return h.Sum(nil)
}

// RSAAESFingerprint names a peer's key for pinning, as the SHA-256 of
// the encoding the protocol sends it in. The spelling is this
// project's own, since there is nothing to be compatible with: it is
// what upstream_rsa_fingerprint holds and what the log prints when a
// target's key is not the pinned one.
func RSAAESFingerprint(k RSAAESPublicKey) string {
	sum := sha256.Sum256(k.Encode())
	out := make([]byte, 0, len(sum)*3)
	const hexDigits = "0123456789abcdef"
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&0xf])
	}
	return string(out)
}

// AESConn is the channel the rest of the exchange runs inside: every
// message is its own EAX box, framed by a two byte length that is also
// the box's associated data, with a counter for a nonce.
type AESConn struct {
	net.Conn
	in, out    aesDir
	buf        []byte // plaintext already opened and not yet read
	maxMessage int
}

// aesDir is one direction of the channel: its AEAD and its nonce.
type aesDir struct {
	seal  func(dst, nonce, pt, ad []byte) []byte
	open  func(dst, nonce, ct, ad []byte) ([]byte, error)
	nonce []byte
}

// NewAESConn wraps a connection with the two directions' keys. sendKey
// is what this end encrypts with and recvKey what it decrypts with.
func NewAESConn(c net.Conn, sendKey, recvKey []byte) (*AESConn, error) {
	send, err := newAESDir(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := newAESDir(recvKey)
	if err != nil {
		return nil, err
	}
	return &AESConn{Conn: c, out: send, in: recv, maxMessage: rsaAESMaxMessage - 1 - eax.TagSize}, nil
}

func newAESDir(key []byte) (aesDir, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return aesDir{}, err
	}
	a, err := eax.New(block, eax.TagSize)
	if err != nil {
		return aesDir{}, err
	}
	return aesDir{seal: a.Seal, open: a.Open, nonce: make([]byte, eax.TagSize)}, nil
}

// step advances the direction's nonce, which counts messages from zero
// as a little-endian integer. A nonce that repeated would lose EAX
// every guarantee it has.
func (d *aesDir) step() {
	for i := range d.nonce {
		d.nonce[i]++
		if d.nonce[i] != 0 {
			break
		}
	}
}

func (c *AESConn) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		n := min(len(b), c.maxMessage)
		head := []byte{byte(n >> 8), byte(n)}
		msg := c.out.seal(head, c.out.nonce, b[:n], head)
		c.out.step()
		if _, err := c.Conn.Write(msg); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *AESConn) Read(b []byte) (int, error) {
	if len(c.buf) == 0 {
		if err := c.next(); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// next reads and opens one message.
func (c *AESConn) next() error {
	var head [2]byte
	if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 || n > c.maxMessage {
		return fmt.Errorf("%w: framed message of %d bytes", ErrRSAAES, n)
	}
	body := make([]byte, n+eax.TagSize)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return err
	}
	pt, err := c.in.open(body[:0], c.in.nonce, body, head[:])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRSAAES, err)
	}
	c.in.step()
	c.buf = pt
	return nil
}

// ReadFull reads exactly n bytes of plaintext, which the handshake
// needs because each of its messages has a length it knows.
func (c *AESConn) ReadFull(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(c, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Unwrap is the connection underneath, which the "ne" type goes back
// to once the credential has been checked. It refuses while opened
// plaintext is still unread, because that data would be lost and the
// stream would resume in the wrong place.
func (c *AESConn) Unwrap() (net.Conn, error) {
	if len(c.buf) != 0 {
		return nil, fmt.Errorf("%w: %d bytes still buffered when leaving the channel", ErrRSAAES, len(c.buf))
	}
	return c.Conn, nil
}

// SetDeadline and its two halves go to the connection underneath, so a
// caller holding an AESConn can still bound a read.
func (c *AESConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *AESConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *AESConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

// RSAAESCredential renders the credential message: a name and a
// password, each with a one byte length.
func RSAAESCredential(user, pass string) ([]byte, error) {
	if len(user) > rsaAESMaxCredential || len(pass) > rsaAESMaxCredential {
		return nil, fmt.Errorf("%w: credential field over %d bytes", ErrRSAAES, rsaAESMaxCredential)
	}
	out := append([]byte{byte(len(user))}, user...)
	return append(append(out, byte(len(pass))), pass...), nil
}

// ReadRSAAESCredential reads one.
func ReadRSAAESCredential(r io.Reader) (string, string, error) {
	user, err := readByteString(r)
	if err != nil {
		return "", "", err
	}
	pass, err := readByteString(r)
	if err != nil {
		return "", "", err
	}
	return user, pass, nil
}

func readByteString(r io.Reader) (string, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	if n[0] == 0 {
		return "", nil
	}
	b := make([]byte, n[0])
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// RSAAESTranscriptMatches compares a transcript hash in constant time.
func RSAAESTranscriptMatches(got, want []byte) bool {
	return subtle.ConstantTimeCompare(got, want) == 1
}
