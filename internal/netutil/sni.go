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

// ClientHelloSNI extracts the server name from the first TLS record of a
// connection without terminating TLS. It parses defensively: every
// length is checked against the bytes available and nothing is copied.
// An empty name with a nil error means a ClientHello without SNI.
func ClientHelloSNI(b []byte) (string, error) {
	if len(b) < 5 {
		return "", ErrNeedMore
	}
	if b[0] != 0x16 || b[1] != 0x03 { // handshake record, SSL 3.0 / TLS major version
		return "", ErrNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 || recLen > 1<<14+256 {
		return "", ErrNotTLS
	}
	if len(b) < 5+recLen {
		return "", ErrNeedMore
	}
	h := b[5 : 5+recLen]
	if h[0] != 0x01 { // ClientHello
		return "", ErrNotTLS
	}
	hsLen := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if hsLen+4 > len(h) {
		return "", ErrNeedMore
	}
	h = h[4 : 4+hsLen]
	// version(2) random(32) session id length(1): the length octet is read
	// immediately below, so 34 bytes are not enough — 35 are.
	if len(h) < 35 {
		return "", ErrNotTLS
	}
	p := 34
	sidLen := int(h[p])
	p++
	if p+sidLen > len(h) {
		return "", ErrNotTLS
	}
	p += sidLen
	if p+2 > len(h) {
		return "", ErrNotTLS
	}
	csLen := int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if p+csLen > len(h) {
		return "", ErrNotTLS
	}
	p += csLen
	if p+1 > len(h) {
		return "", ErrNotTLS
	}
	cmLen := int(h[p])
	p++
	if p+cmLen > len(h) {
		return "", ErrNotTLS
	}
	p += cmLen
	if p == len(h) {
		return "", nil // no extensions
	}
	if p+2 > len(h) {
		return "", ErrNotTLS
	}
	extLen := int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if p+extLen > len(h) {
		return "", ErrNotTLS
	}
	ext := h[p : p+extLen]
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext[0:2])
		l := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if l > len(ext) {
			return "", ErrNotTLS
		}
		body := ext[:l]
		ext = ext[l:]
		if typ != 0 { // server_name
			continue
		}
		if len(body) < 2 {
			return "", ErrNotTLS
		}
		listLen := int(binary.BigEndian.Uint16(body[0:2]))
		body = body[2:]
		if listLen > len(body) {
			return "", ErrNotTLS
		}
		for len(body) >= 3 {
			nameType := body[0]
			nl := int(binary.BigEndian.Uint16(body[1:3]))
			body = body[3:]
			if nl > len(body) {
				return "", ErrNotTLS
			}
			if nameType == 0 {
				name := strings.TrimSuffix(strings.ToLower(string(body[:nl])), ".")
				// The name becomes a layer 4 routing key, so it must have
				// one spelling: an empty label would miss its own route's
				// table and fall through to tcp.default (see
				// labelsNonEmpty).
				if name == "" || len(name) > 253 || !labelsNonEmpty(name) || strings.ContainsAny(name, " \x00/\\") {
					return "", ErrNotTLS
				}
				return name, nil
			}
			body = body[nl:]
		}
		return "", nil
	}
	return "", nil
}
