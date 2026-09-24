package netutil

import (
	"encoding/binary"
	"errors"
	"strings"
)

// ErrNotTLS reports bytes that are not a TLS ClientHello.
var ErrNotTLS = errors.New("not a TLS client hello")

// ErrNeedMore reports that the record is longer than the bytes given.
var ErrNeedMore = errors.New("incomplete TLS record")

const (
	// maxClientHello bounds the handshake message this parser will
	// assemble. A ClientHello is a few kilobytes; the record layer
	// allows far more.
	maxClientHello = 1 << 16
	// maxHelloRecords bounds the records one ClientHello may be split
	// across.
	maxHelloRecords = 64
)

// handshakeBytes returns the body of the first handshake message at the
// head of b, joining consecutive handshake records when the message is
// split across them.
//
// Every TLS stack behind this proxy reassembles a handshake message
// across records, so bounding the ClientHello by the first record alone
// meant proxy and backend read different things: a client that
// fragments (OpenSSL with a small max_send_fragment, the fragmenting
// clients used against censorship) presented a name to the origin and
// nothing readable here, so its flow either stalled until the peek
// timeout or, padded past the caller's buffer, took the default route
// with no name at all.
func handshakeBytes(b []byte) ([]byte, error) {
	if len(b) < 5 {
		return nil, ErrNeedMore
	}
	if b[0] != 0x16 || b[1] != 0x03 { // handshake record, SSL 3.0 / TLS major version
		return nil, ErrNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 1 || recLen > 1<<14+256 {
		return nil, ErrNotTLS
	}
	if len(b) < 5+recLen {
		return nil, ErrNeedMore
	}
	first := b[5 : 5+recLen]
	if first[0] != 0x01 { // ClientHello
		return nil, ErrNotTLS
	}
	done := func(buf []byte) ([]byte, bool, error) {
		if len(buf) < 4 {
			return nil, false, nil
		}
		hsLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if hsLen > maxClientHello {
			return nil, false, ErrNotTLS
		}
		if 4+hsLen > len(buf) {
			return nil, false, nil
		}
		return buf[4 : 4+hsLen], true, nil
	}
	if h, ok, err := done(first); err != nil || ok {
		return h, err // the common case: one record carries the whole hello
	}
	buf := append([]byte(nil), first...)
	off := 5 + recLen
	for n := 0; n < maxHelloRecords; n++ {
		if len(b)-off < 5 {
			return nil, ErrNeedMore
		}
		if b[off] != 0x16 || b[off+1] != 0x03 {
			return nil, ErrNotTLS
		}
		rl := int(binary.BigEndian.Uint16(b[off+3 : off+5]))
		if rl < 1 || rl > 1<<14+256 {
			return nil, ErrNotTLS
		}
		if len(b)-off-5 < rl {
			return nil, ErrNeedMore
		}
		buf = append(buf, b[off+5:off+5+rl]...)
		off += 5 + rl
		if h, ok, err := done(buf); err != nil || ok {
			return h, err
		}
	}
	return nil, ErrNotTLS
}

// ClientHelloSNI extracts the server name from the TLS ClientHello at
// the head of b, without terminating TLS. It parses defensively: every
// length is checked against the bytes available and nothing but a
// fragmented handshake message is copied. An empty name with a nil error
// means a ClientHello without SNI.
func ClientHelloSNI(b []byte) (string, error) {
	ext, err := helloExtensions(b)
	if err != nil {
		return "", err
	}
	name := ""
	var bad error
	if err := eachExtension(ext, func(typ uint16, body []byte) bool {
		if typ != extServerName {
			return true
		}
		if len(body) < 2 {
			bad = ErrNotTLS
			return false
		}
		listLen := int(binary.BigEndian.Uint16(body[0:2]))
		body = body[2:]
		if listLen > len(body) {
			bad = ErrNotTLS
			return false
		}
		for len(body) >= 3 {
			nameType := body[0]
			nl := int(binary.BigEndian.Uint16(body[1:3]))
			body = body[3:]
			if nl > len(body) {
				bad = ErrNotTLS
				return false
			}
			if nameType == 0 {
				n := strings.TrimSuffix(strings.ToLower(string(body[:nl])), ".")
				// The name becomes a layer 4 routing key, so it must
				// have one spelling: an empty label would miss its own
				// route's table and fall through to tcp.default (see
				// labelsNonEmpty).
				if n == "" || len(n) > 253 || !labelsNonEmpty(n) || strings.ContainsAny(n, " \x00/\\") {
					bad = ErrNotTLS
					return false
				}
				name = n
				return false
			}
			body = body[nl:]
		}
		return false
	}); err != nil {
		return "", err
	}
	if bad != nil {
		return "", bad
	}
	return name, nil
}
