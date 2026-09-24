package netutil

import "encoding/binary"

// The ClientHello extensions this package reads, and the bounds on them.
const (
	// extServerName and extALPN are the two extension types a layer 4
	// listener can decide on without terminating TLS: the name the
	// client asked for, and the application protocol it offers.
	extServerName uint16 = 0
	extALPN       uint16 = 16
	// maxALPNProtocols bounds the protocol list. A client offers a
	// handful; a list of thousands is somebody spending the reader's
	// time.
	maxALPNProtocols = 32
	// maxALPNName bounds one protocol name. The longest registered one
	// is a dozen characters.
	maxALPNName = 64
)

// helloExtensions returns the extension block of the ClientHello at the
// head of b: a nil block with a nil error means a hello with no
// extensions, which is legal and says nothing.
//
// Every length in the walk is checked against the bytes actually there.
// The fields before the extensions are all variable, so a reader that
// trusted any of their lengths would be reading somebody else's memory --
// which is the whole reason this parser exists rather than a TLS
// handshake.
func helloExtensions(b []byte) ([]byte, error) {
	h, err := handshakeBytes(b)
	if err != nil {
		return nil, err
	}
	// version(2) random(32) session id length(1): the length octet is
	// read immediately below, so 34 bytes are not enough -- 35 are.
	if len(h) < 35 {
		return nil, ErrNotTLS
	}
	p := 34
	sidLen := int(h[p])
	p++
	if p+sidLen > len(h) {
		return nil, ErrNotTLS
	}
	p += sidLen
	if p+2 > len(h) {
		return nil, ErrNotTLS
	}
	csLen := int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if p+csLen > len(h) {
		return nil, ErrNotTLS
	}
	p += csLen
	if p+1 > len(h) {
		return nil, ErrNotTLS
	}
	cmLen := int(h[p])
	p++
	if p+cmLen > len(h) {
		return nil, ErrNotTLS
	}
	p += cmLen
	if p == len(h) {
		return nil, nil // no extensions
	}
	if p+2 > len(h) {
		return nil, ErrNotTLS
	}
	extLen := int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if p+extLen > len(h) {
		return nil, ErrNotTLS
	}
	return h[p : p+extLen], nil
}

// eachExtension walks an extension block, calling fn until it returns
// false. A length that does not fit ends the walk with ErrNotTLS: half a
// block is not a block to draw conclusions from.
func eachExtension(ext []byte, fn func(typ uint16, body []byte) bool) error {
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext[0:2])
		l := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if l > len(ext) {
			return ErrNotTLS
		}
		body := ext[:l]
		ext = ext[l:]
		if !fn(typ, body) {
			return nil
		}
	}
	return nil
}

// ClientHelloALPN extracts the application protocols offered by the TLS
// ClientHello at the head of b, without terminating TLS. An empty list
// with a nil error means a hello that offers none.
//
// It exists for the ports that carry exactly one application protocol,
// where the ALPN is the only thing in the handshake that says whether a
// connection is what the port is for. NTS key establishment is the clear
// case: RFC 8915 gives it TCP 4460 and the protocol name "ntske/1", so a
// connection there that does not offer it is not an NTS client, and that
// can be known before a byte is relayed.
func ClientHelloALPN(b []byte) ([]string, error) {
	ext, err := helloExtensions(b)
	if err != nil {
		return nil, err
	}
	var out []string
	var bad error
	if err := eachExtension(ext, func(typ uint16, body []byte) bool {
		if typ != extALPN {
			return true
		}
		if len(body) < 2 {
			bad = ErrNotTLS
			return false
		}
		listLen := int(binary.BigEndian.Uint16(body))
		body = body[2:]
		if listLen != len(body) {
			bad = ErrNotTLS
			return false
		}
		for len(body) > 0 {
			n := int(body[0])
			body = body[1:]
			if n == 0 || n > len(body) || n > maxALPNName {
				bad = ErrNotTLS
				return false
			}
			name := string(body[:n])
			body = body[n:]
			if !printableProtocol(name) || len(out) >= maxALPNProtocols {
				bad = ErrNotTLS
				return false
			}
			out = append(out, name)
		}
		return false
	}); err != nil {
		return nil, err
	}
	if bad != nil {
		return nil, bad
	}
	return out, nil
}

// printableProtocol keeps a protocol name to what a name can be, because
// it is compared against a configured list and written to a log: a name
// carrying a control character or a space would be one an operator could
// not read and could not match.
func printableProtocol(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return s != ""
}
