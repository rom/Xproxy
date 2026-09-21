// Package mqtt holds the wire format an MQTT-aware proxy needs: packet
// framing, the fields of the packets whose contents are a policy
// decision (CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE), and topic filter
// matching.
//
// MQTT 3.1.1 (OASIS, also ISO/IEC 20922) and 5.0 share a framing and
// differ in what follows it: 5.0 adds a property block to most packets
// and reason codes to the acknowledgements. Both are parsed here, and
// the version is carried explicitly rather than guessed, because a
// field read at the wrong offset is a policy check applied to the wrong
// bytes.
package mqtt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Packet types, the high nibble of the first octet.
const (
	CONNECT     = 1
	CONNACK     = 2
	PUBLISH     = 3
	PUBACK      = 4
	PUBREC      = 5
	PUBREL      = 6
	PUBCOMP     = 7
	SUBSCRIBE   = 8
	SUBACK      = 9
	UNSUBSCRIBE = 10
	UNSUBACK    = 11
	PINGREQ     = 12
	PINGRESP    = 13
	DISCONNECT  = 14
	AUTH        = 15 // 5.0 only
)

// Protocol levels: 4 is 3.1.1, 5 is 5.0. 3 is the older 3.1, which this
// proxy does not parse.
const (
	V311 = 4
	V5   = 5
)

var (
	// ErrPacketTooLarge is a packet over the configured bound. It is
	// refused before the body is read, so the bound is on what the
	// proxy allocates and not merely on what it accepts.
	ErrPacketTooLarge = errors.New("mqtt: packet too large")
	// ErrMalformed is a packet whose fields do not fit its length, a
	// reserved value, or a string that is not UTF-8. MQTT calls this a
	// malformed packet and requires the connection to close.
	ErrMalformed = errors.New("mqtt: malformed packet")
	// ErrVarintTooLong is a remaining-length field over four octets,
	// which no legal packet has.
	ErrVarintTooLong = errors.New("mqtt: remaining length is not four octets or fewer")
)

// MaxRemaining is the largest remaining length the encoding can carry,
// 256 MiB minus one octet.
const MaxRemaining = 268435455

// Packet is one MQTT control packet: its type, the four flag bits of
// the first octet, and the body after the remaining-length field.
type Packet struct {
	Type  byte
	Flags byte
	Body  []byte
}

// Name is the packet type's name, for logs.
func (p Packet) Name() string {
	names := [...]string{"", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL",
		"PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP",
		"DISCONNECT", "AUTH"}
	if int(p.Type) < len(names) && p.Type > 0 {
		return names[p.Type]
	}
	return fmt.Sprintf("type %d", p.Type)
}

// Encode renders a packet on the wire.
func (p Packet) Encode() []byte {
	out := make([]byte, 0, len(p.Body)+5)
	out = append(out, p.Type<<4|p.Flags&0x0f)
	out = appendRemaining(out, len(p.Body))
	return append(out, p.Body...)
}

func appendRemaining(b []byte, n int) []byte {
	for {
		d := byte(n % 128) //nolint:gosec // one base-128 digit
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		b = append(b, d)
		if n == 0 {
			return b
		}
	}
}

// ReadPacket reads one packet, refusing anything over max before its
// body is allocated. A packet type of 0 is reserved and never legal.
func ReadPacket(r io.Reader, max int) (Packet, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return Packet{}, err
	}
	p := Packet{Type: first[0] >> 4, Flags: first[0] & 0x0f}
	if p.Type == 0 {
		return Packet{}, ErrMalformed
	}
	n, err := readRemaining(r)
	if err != nil {
		return Packet{}, err
	}
	if max > 0 && n+2 > max {
		return Packet{}, ErrPacketTooLarge
	}
	if n > 0 {
		p.Body = make([]byte, n)
		if _, err := io.ReadFull(r, p.Body); err != nil {
			return Packet{}, err
		}
	}
	return p, nil
}

func readRemaining(r io.Reader) (int, error) {
	var b [1]byte
	n, mult := 0, 1
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		n += int(b[0]&0x7f) * mult
		if b[0]&0x80 == 0 {
			// The encoding must be the shortest one: a continuation bit
			// on a zero digit would give two spellings of one length,
			// and two spellings are two readings.
			if i > 0 && b[0] == 0 {
				return 0, ErrMalformed
			}
			return n, nil
		}
		mult *= 128
	}
	return 0, ErrVarintTooLong
}

// reader walks a packet body. Every accessor checks the bound, so a
// truncated packet is an error rather than a short read of the next
// field.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) byte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, ErrMalformed
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) uint16() (uint16, error) {
	if r.pos+2 > len(r.b) {
		return 0, ErrMalformed
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

// str reads a length-prefixed UTF-8 string. MQTT forbids a string that
// is not valid UTF-8, one containing U+0000, and the surrogate range;
// all three are refused here rather than passed to a broker that may
// read them differently.
func (r *reader) str() (string, error) {
	n, err := r.uint16()
	if err != nil {
		return "", err
	}
	if r.pos+int(n) > len(r.b) {
		return "", ErrMalformed
	}
	s := string(r.b[r.pos : r.pos+int(n)])
	r.pos += int(n)
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return "", ErrMalformed
	}
	for _, c := range s {
		if c >= 0xd800 && c <= 0xdfff {
			return "", ErrMalformed
		}
	}
	return s, nil
}

// skipBytes steps over a length-prefixed binary field. The contents are
// never returned: the will payload and the password are both of this
// shape, and a secret the proxy does not hold is one it cannot log.
func (r *reader) skipBytes() error {
	n, err := r.uint16()
	if err != nil {
		return err
	}
	if r.pos+int(n) > len(r.b) {
		return ErrMalformed
	}
	r.pos += int(n)
	return nil
}

// varint reads a variable byte integer, used for property lengths.
func (r *reader) varint() (int, error) {
	n, mult := 0, 1
	for i := 0; i < 4; i++ {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		n += int(b&0x7f) * mult
		if b&0x80 == 0 {
			if i > 0 && b == 0 {
				return 0, ErrMalformed
			}
			return n, nil
		}
		mult *= 128
	}
	return 0, ErrVarintTooLong
}

// skipProps steps over a 5.0 property block. The properties themselves
// are not interpreted: nothing in them is a policy decision here, and
// parsing what it does not use is how a proxy grows bugs.
func (r *reader) skipProps(v byte) error {
	if v < V5 {
		return nil
	}
	n, err := r.varint()
	if err != nil {
		return err
	}
	if r.pos+n > len(r.b) {
		return ErrMalformed
	}
	r.pos += n
	return nil
}

// Connect is the part of a CONNECT packet a policy decides on.
type Connect struct {
	Version    byte
	ClientID   string
	Username   string
	HasUser    bool
	HasPass    bool
	WillTopic  string
	WillRetain bool
	WillQoS    byte
	CleanStart bool
	KeepAlive  uint16
}

// ParseConnect reads a CONNECT packet. The password is deliberately not
// returned: the proxy forwards the packet as it arrived, and a secret
// that is never held is a secret that cannot be logged.
func ParseConnect(p Packet) (Connect, error) {
	if p.Type != CONNECT || p.Flags != 0 {
		return Connect{}, ErrMalformed
	}
	r := &reader{b: p.Body}
	name, err := r.str()
	if err != nil {
		return Connect{}, err
	}
	if name != "MQTT" {
		return Connect{}, fmt.Errorf("%w: protocol name %q", ErrMalformed, clip(name))
	}
	var c Connect
	if c.Version, err = r.byte(); err != nil {
		return Connect{}, err
	}
	flags, err := r.byte()
	if err != nil {
		return Connect{}, err
	}
	// Bit 0 is reserved and must be zero (3.1.1 section 3.1.2.3).
	if flags&0x01 != 0 {
		return Connect{}, ErrMalformed
	}
	c.CleanStart = flags&0x02 != 0
	hasWill := flags&0x04 != 0
	c.WillQoS = (flags >> 3) & 0x03
	c.WillRetain = flags&0x20 != 0
	c.HasPass = flags&0x40 != 0
	c.HasUser = flags&0x80 != 0
	if !hasWill && (c.WillQoS != 0 || c.WillRetain) {
		return Connect{}, ErrMalformed
	}
	if c.WillQoS == 3 {
		return Connect{}, ErrMalformed
	}
	if c.KeepAlive, err = r.uint16(); err != nil {
		return Connect{}, err
	}
	if err := r.skipProps(c.Version); err != nil {
		return Connect{}, err
	}
	if c.ClientID, err = r.str(); err != nil {
		return Connect{}, err
	}
	if hasWill {
		if err := r.skipProps(c.Version); err != nil {
			return Connect{}, err
		}
		if c.WillTopic, err = r.str(); err != nil {
			return Connect{}, err
		}
		if err := r.skipBytes(); err != nil {
			return Connect{}, err
		}
	}
	if c.HasUser {
		if c.Username, err = r.str(); err != nil {
			return Connect{}, err
		}
	}
	if c.HasPass {
		if err := r.skipBytes(); err != nil {
			return Connect{}, err
		}
	}
	if r.pos != len(r.b) {
		return Connect{}, ErrMalformed
	}
	return c, nil
}

// Publish is the part of a PUBLISH packet a policy decides on.
type Publish struct {
	Topic    string
	QoS      byte
	Retain   bool
	Dup      bool
	PacketID uint16
	// Size is the whole packet's size on the wire.
	Size int
}

// ParsePublish reads a PUBLISH header. The payload is not returned: it
// is forwarded untouched, and a proxy that copies it only adds a place
// for it to leak.
func ParsePublish(p Packet) (Publish, error) {
	if p.Type != PUBLISH {
		return Publish{}, ErrMalformed
	}
	var pub Publish
	pub.Dup = p.Flags&0x08 != 0
	pub.QoS = (p.Flags >> 1) & 0x03
	pub.Retain = p.Flags&0x01 != 0
	if pub.QoS == 3 {
		return Publish{}, ErrMalformed
	}
	// A QoS 0 message is never a retransmission, so DUP on one is a
	// packet two implementations would treat differently.
	if pub.QoS == 0 && pub.Dup {
		return Publish{}, ErrMalformed
	}
	r := &reader{b: p.Body}
	var err error
	if pub.Topic, err = r.str(); err != nil {
		return Publish{}, err
	}
	if pub.QoS > 0 {
		if pub.PacketID, err = r.uint16(); err != nil {
			return Publish{}, err
		}
		if pub.PacketID == 0 {
			return Publish{}, ErrMalformed
		}
	}
	pub.Size = len(p.Body) + 5
	return pub, nil
}

// Subscription is one entry of a SUBSCRIBE packet.
type Subscription struct {
	Filter  string
	Options byte
}

// Subscribe is a parsed SUBSCRIBE or UNSUBSCRIBE packet.
type Subscribe struct {
	PacketID uint16
	Filters  []Subscription
}

// ParseSubscribe reads SUBSCRIBE (with the option octet per filter) or
// UNSUBSCRIBE (without). Both must carry at least one filter.
func ParseSubscribe(p Packet, version byte) (Subscribe, error) {
	if p.Type != SUBSCRIBE && p.Type != UNSUBSCRIBE {
		return Subscribe{}, ErrMalformed
	}
	// Both are defined with the flag bits 0010 and nothing else.
	if p.Flags != 0x02 {
		return Subscribe{}, ErrMalformed
	}
	r := &reader{b: p.Body}
	var s Subscribe
	var err error
	if s.PacketID, err = r.uint16(); err != nil {
		return Subscribe{}, err
	}
	if s.PacketID == 0 {
		return Subscribe{}, ErrMalformed
	}
	if err := r.skipProps(version); err != nil {
		return Subscribe{}, err
	}
	for r.pos < len(r.b) {
		f, err := r.str()
		if err != nil {
			return Subscribe{}, err
		}
		var opts byte
		if p.Type == SUBSCRIBE {
			if opts, err = r.byte(); err != nil {
				return Subscribe{}, err
			}
			if opts&0x03 == 3 {
				return Subscribe{}, ErrMalformed
			}
			if version < V5 && opts&0xfc != 0 {
				return Subscribe{}, ErrMalformed
			}
		}
		s.Filters = append(s.Filters, Subscription{Filter: f, Options: opts})
	}
	if len(s.Filters) == 0 {
		return Subscribe{}, ErrMalformed
	}
	return s, nil
}

func clip(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:24] + "..."
}
