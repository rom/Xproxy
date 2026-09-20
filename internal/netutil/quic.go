package netutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// QUIC version 1 (RFC 9000, RFC 9001): the Initial packet is protected
// with keys every observer can derive from the destination connection
// id, which is what lets a relay read the ClientHello's server name
// without being a party to the connection.

var (
	ErrNotQUIC      = errors.New("not a QUIC v1 Initial packet")
	ErrQUICNeedMore = errors.New("ClientHello continues in a later packet")

	quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
)

const quicV1 = 0x00000001

// QUICCryptoData decrypts a QUIC v1 Initial datagram and returns the
// CRYPTO frame payloads it carries, each with its stream offset, so a
// caller can reassemble a ClientHello that spans packets. Datagrams that
// are not v1 Initial packets return ErrNotQUIC.
func QUICCryptoData(datagram []byte) ([]QUICCrypto, error) {
	var out []QUICCrypto
	rest := datagram
	// Each Initial packet derives its own key schedule — an HKDF extract,
	// four expands and two AES key schedules — from its own connection
	// id, and coalescing is unbounded in the protocol. A single 64 KiB
	// datagram of minimum-size Initials is over two thousand of those, on
	// the listener's own read goroutine, which also forwards every
	// established flow: about a hundred spoofed packets per second stall
	// the whole listener. A real client coalesces two or three packets,
	// and they share a connection id, so the schedule is derived once per
	// id and at most a handful of packets are read.
	keys := quicKeyCache{}
	for n := 0; len(rest) > 0 && n < maxCoalescedInitials; n++ {
		frames, next, err := quicInitialPacket(rest, keys)
		if err != nil {
			if len(out) > 0 {
				return out, nil // trailing padding or another packet type after a good Initial
			}
			return nil, err
		}
		out = append(out, frames...)
		rest = next
	}
	if len(out) == 0 {
		return nil, ErrNotQUIC
	}
	return out, nil
}

// QUICCrypto is one CRYPTO frame's data at its offset.
type QUICCrypto struct {
	Offset uint64
	Data   []byte
}

// maxCoalescedInitials bounds the Initial packets read from one
// datagram; see QUICCryptoData.
const maxCoalescedInitials = 4

// quicKeyCache memoises one datagram's Initial key schedule by
// connection id. It lives for one datagram on one goroutine, so it needs
// no locking and cannot grow past maxCoalescedInitials entries.
type quicKeyCache map[string]quicInitialKeys

// quicInitialKeys is the client's Initial key material for one
// connection id.
type quicInitialKeys struct {
	key, iv, hp []byte
}

// derive returns the Initial keys for dcid, computing them at most once
// per datagram.
func (c quicKeyCache) derive(dcid []byte) (quicInitialKeys, error) {
	if k, ok := c[string(dcid)]; ok {
		return k, nil
	}
	initial, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return quicInitialKeys{}, err
	}
	clientSecret, err := hkdfExpandLabel(initial, "client in", 32)
	if err != nil {
		return quicInitialKeys{}, err
	}
	var k quicInitialKeys
	if k.key, err = hkdfExpandLabel(clientSecret, "quic key", 16); err != nil {
		return quicInitialKeys{}, err
	}
	if k.iv, err = hkdfExpandLabel(clientSecret, "quic iv", 12); err != nil {
		return quicInitialKeys{}, err
	}
	if k.hp, err = hkdfExpandLabel(clientSecret, "quic hp", 16); err != nil {
		return quicInitialKeys{}, err
	}
	c[string(dcid)] = k
	return k, nil
}

// quicInitialPacket parses one Initial packet at the head of b and
// returns its CRYPTO frames and the bytes after the packet.
func quicInitialPacket(b []byte, keys quicKeyCache) ([]QUICCrypto, []byte, error) {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return nil, nil, ErrNotQUIC // not a long header
	}
	if binary.BigEndian.Uint32(b[1:5]) != quicV1 || (b[0]&0x30)>>4 != 0 {
		return nil, nil, ErrNotQUIC // other version or not Initial
	}
	off := 5
	dcidLen := int(b[off])
	off++
	if dcidLen > 20 || off+dcidLen > len(b) {
		return nil, nil, ErrNotQUIC
	}
	dcid := b[off : off+dcidLen]
	off += dcidLen
	if off >= len(b) {
		return nil, nil, ErrNotQUIC
	}
	scidLen := int(b[off])
	off++
	if scidLen > 20 || off+scidLen > len(b) {
		return nil, nil, ErrNotQUIC
	}
	off += scidLen
	tokenLen, n := quicVarint(b[off:])
	if n == 0 || tokenLen > 1<<16 || int(tokenLen) > len(b)-off-n { //nolint:gosec // bounded just before
		return nil, nil, ErrNotQUIC
	}
	off += n + int(tokenLen) //nolint:gosec // bounded above
	length, n := quicVarint(b[off:])
	if n == 0 {
		return nil, nil, ErrNotQUIC
	}
	off += n
	pnOff := off
	if length < 20 || length > 1<<16 || int(length) > len(b)-pnOff { //nolint:gosec // bounded just before
		return nil, nil, ErrNotQUIC
	}
	end := pnOff + int(length) //nolint:gosec // bounded above
	// Keys, derived once per connection id in this datagram.
	ks, err := keys.derive(dcid)
	if err != nil {
		return nil, nil, err
	}
	key, iv, hp := ks.key, ks.iv, ks.hp
	// Header protection: the sample starts 4 bytes after the packet number
	// field's start.
	if pnOff+4+16 > end {
		return nil, nil, ErrNotQUIC
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, nil, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], b[pnOff+4:pnOff+20])
	hdr := make([]byte, end)
	copy(hdr, b[:end])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	payloadOff := pnOff + pnLen
	plain, err := gcm.Open(nil, nonce, hdr[payloadOff:end], hdr[:payloadOff])
	if err != nil {
		return nil, nil, ErrNotQUIC // wrong keys: not a client Initial we can read
	}
	frames, err := quicCryptoFrames(plain)
	if err != nil {
		return nil, nil, err
	}
	return frames, b[end:], nil
}

// quicCryptoFrames walks the frames of a decrypted Initial payload.
func quicCryptoFrames(p []byte) ([]QUICCrypto, error) {
	var out []QUICCrypto
	off := 0
	for off < len(p) {
		t := p[off]
		off++
		switch t {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK
			n, err := quicSkipAck(p[off:], t == 0x03)
			if err != nil {
				return nil, err
			}
			off += n
		case 0x06: // CRYPTO
			offset, n := quicVarint(p[off:])
			if n == 0 {
				return nil, ErrNotQUIC
			}
			off += n
			length, n := quicVarint(p[off:])
			if n == 0 || length > 1<<16 || int(length) > len(p)-off-n { //nolint:gosec // bounded just before
				return nil, ErrNotQUIC
			}
			off += n
			out = append(out, QUICCrypto{Offset: offset, Data: p[off : off+int(length)]}) //nolint:gosec // bounded
			off += int(length)                                                            //nolint:gosec // bounded
		case 0x1c: // CONNECTION_CLOSE
			return nil, ErrNotQUIC
		default:
			// Any other frame is not allowed in an Initial packet.
			return nil, ErrNotQUIC
		}
	}
	return out, nil
}

func quicSkipAck(p []byte, ecn bool) (int, error) {
	off := 0
	for i := 0; i < 3; i++ { // largest, delay, range count
		_, n := quicVarint(p[off:])
		if n == 0 {
			return 0, ErrNotQUIC
		}
		if i == 2 {
			count, _ := quicVarint(p[off:])
			off += n
			_, n = quicVarint(p[off:]) // first range
			if n == 0 {
				return 0, ErrNotQUIC
			}
			off += n
			for j := uint64(0); j < count; j++ {
				for k := 0; k < 2; k++ {
					_, n = quicVarint(p[off:])
					if n == 0 {
						return 0, ErrNotQUIC
					}
					off += n
				}
			}
			break
		}
		off += n
	}
	if ecn {
		for k := 0; k < 3; k++ {
			_, n := quicVarint(p[off:])
			if n == 0 {
				return 0, ErrNotQUIC
			}
			off += n
		}
	}
	return off, nil
}

// quicVarint decodes a QUIC variable length integer.
func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length)) //nolint:gosec // small
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// QUICHelloAssembler collects CRYPTO data across the Initial packets of
// one flow until a ClientHello can be parsed.
type QUICHelloAssembler struct {
	parts []QUICCrypto
	size  int
}

// MaxQUICHello bounds the bytes an assembler keeps.
const MaxQUICHello = 16 << 10

// Add records frames; it returns the server name once the ClientHello
// is complete, ErrQUICNeedMore while it is not, or ErrNotTLS.
func (a *QUICHelloAssembler) Add(frames []QUICCrypto) (string, error) {
	for _, f := range frames {
		a.size += len(f.Data)
		if a.size > MaxQUICHello {
			return "", ErrNotTLS
		}
		a.parts = append(a.parts, f)
	}
	sort.Slice(a.parts, func(i, j int) bool { return a.parts[i].Offset < a.parts[j].Offset })
	var buf []byte
	var next uint64
	for _, p := range a.parts {
		if p.Offset > next {
			break // a gap: wait for the missing packet
		}
		if p.Offset+uint64(len(p.Data)) <= next {
			continue // duplicate
		}
		buf = append(buf, p.Data[next-p.Offset:]...)
		next = p.Offset + uint64(len(p.Data))
	}
	if len(buf) < 4 {
		return "", ErrQUICNeedMore
	}
	// The CRYPTO stream is the handshake layer; wrap it in one TLS record
	// so the record based parser can read it.
	record := make([]byte, 0, 5+len(buf))
	record = append(record, 0x16, 0x03, 0x01)
	record = binary.BigEndian.AppendUint16(record, uint16(min(len(buf), 65535))) //nolint:gosec // bounded
	record = append(record, buf...)
	sni, err := ClientHelloSNI(record)
	if errors.Is(err, ErrNeedMore) {
		return "", ErrQUICNeedMore
	}
	return sni, err
}
