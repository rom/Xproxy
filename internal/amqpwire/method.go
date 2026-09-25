package amqpwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The AMQP 0-9-1 class and method catalogue, and the arguments a policy is
// written about.
//
// Every operation on this version is a method frame: two octets of class,
// two of method, then arguments laid out in an order the specification
// fixes. That is what makes a policy possible at all -- "may this
// connection delete a queue" is a question about two octets -- and it is
// also the whole of the risk, because the arguments are read from the
// network and every length in them is the sender's.
//
// The names are spelled the way the specification spells them,
// `exchange.declare` and `basic.publish`, because that is what an operator
// writes in a policy and what a broker's own documentation and logs say.

// Method is one method frame's payload.
type Method struct {
	Class, ID uint16
	// Args is the arguments, unread. Each accessor reads what it needs
	// from them rather than this package decoding every method eagerly:
	// most frames on a busy connection are basic.publish and basic.ack,
	// and a relay that decoded the tables of every declare it never
	// checks would be paying for policy it was not asked for.
	Args []byte
}

// The class identifiers of AMQP 0-9-1, plus the two extensions every
// deployed broker has: confirm (85) and the exchange-to-exchange binding
// methods inside class 40.
const (
	ClassConnection uint16 = 10
	ClassChannel    uint16 = 20
	ClassAccess     uint16 = 30
	ClassExchange   uint16 = 40
	ClassQueue      uint16 = 50
	ClassBasic      uint16 = 60
	ClassTx         uint16 = 90
	ClassConfirm    uint16 = 85
)

// key is a class and method in one comparable value.
func key(class, id uint16) uint32 { return uint32(class)<<16 | uint32(id) }

// methods is the catalogue. A class and method missing from it is one this
// package does not know, which every accessor then answers `known` false
// about -- a broker may have an extension, and a relay that invented a
// layout for one would check a policy against whatever octet happened to
// be in that position.
//
// It is a list rather than a map so that the names come out in the order
// they are written, which is the order the specification puts them in and
// the order an operator reads them in the documentation.
var methods = []struct {
	class, id uint16
	name      string
}{
	{ClassConnection, 10, "connection.start"},
	{ClassConnection, 11, "connection.start-ok"},
	{ClassConnection, 20, "connection.secure"},
	{ClassConnection, 21, "connection.secure-ok"},
	{ClassConnection, 30, "connection.tune"},
	{ClassConnection, 31, "connection.tune-ok"},
	{ClassConnection, 40, "connection.open"},
	{ClassConnection, 41, "connection.open-ok"},
	{ClassConnection, 50, "connection.close"},
	{ClassConnection, 51, "connection.close-ok"},
	{ClassConnection, 60, "connection.blocked"},
	{ClassConnection, 61, "connection.unblocked"},
	{ClassConnection, 70, "connection.update-secret"},
	{ClassConnection, 71, "connection.update-secret-ok"},
	{ClassChannel, 10, "channel.open"},
	{ClassChannel, 11, "channel.open-ok"},
	{ClassChannel, 20, "channel.flow"},
	{ClassChannel, 21, "channel.flow-ok"},
	{ClassChannel, 40, "channel.close"},
	{ClassChannel, 41, "channel.close-ok"},
	{ClassAccess, 10, "access.request"},
	{ClassAccess, 11, "access.request-ok"},
	{ClassExchange, 10, "exchange.declare"},
	{ClassExchange, 11, "exchange.declare-ok"},
	{ClassExchange, 20, "exchange.delete"},
	{ClassExchange, 21, "exchange.delete-ok"},
	{ClassExchange, 30, "exchange.bind"},
	{ClassExchange, 31, "exchange.bind-ok"},
	{ClassExchange, 40, "exchange.unbind"},
	{ClassExchange, 51, "exchange.unbind-ok"},
	{ClassQueue, 10, "queue.declare"},
	{ClassQueue, 11, "queue.declare-ok"},
	{ClassQueue, 20, "queue.bind"},
	{ClassQueue, 21, "queue.bind-ok"},
	{ClassQueue, 30, "queue.purge"},
	{ClassQueue, 31, "queue.purge-ok"},
	{ClassQueue, 40, "queue.delete"},
	{ClassQueue, 41, "queue.delete-ok"},
	{ClassQueue, 50, "queue.unbind"},
	{ClassQueue, 51, "queue.unbind-ok"},
	{ClassBasic, 10, "basic.qos"},
	{ClassBasic, 11, "basic.qos-ok"},
	{ClassBasic, 20, "basic.consume"},
	{ClassBasic, 21, "basic.consume-ok"},
	{ClassBasic, 30, "basic.cancel"},
	{ClassBasic, 31, "basic.cancel-ok"},
	{ClassBasic, 40, "basic.publish"},
	{ClassBasic, 50, "basic.return"},
	{ClassBasic, 60, "basic.deliver"},
	{ClassBasic, 70, "basic.get"},
	{ClassBasic, 71, "basic.get-ok"},
	{ClassBasic, 72, "basic.get-empty"},
	{ClassBasic, 80, "basic.ack"},
	{ClassBasic, 90, "basic.reject"},
	{ClassBasic, 100, "basic.recover-async"},
	{ClassBasic, 110, "basic.recover"},
	{ClassBasic, 111, "basic.recover-ok"},
	{ClassBasic, 120, "basic.nack"},
	{ClassTx, 10, "tx.select"},
	{ClassTx, 11, "tx.select-ok"},
	{ClassTx, 20, "tx.commit"},
	{ClassTx, 21, "tx.commit-ok"},
	{ClassTx, 30, "tx.rollback"},
	{ClassTx, 31, "tx.rollback-ok"},
	{ClassConfirm, 10, "confirm.select"},
	{ClassConfirm, 11, "confirm.select-ok"},
}

// The two lookups the catalogue is read through: by the octets on the wire,
// and by the name a policy is written with.
var (
	methodNames = map[uint32]string{}
	methodIDs   = map[string][2]uint16{}
)

func init() {
	for _, m := range methods {
		methodNames[key(m.class, m.id)] = m.name
		methodIDs[m.name] = [2]uint16{m.class, m.id}
	}
}

// ParseMethod reads a method frame's payload.
func ParseMethod(payload []byte) (*Method, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("a method frame of %d octets has no class and method", len(payload))
	}
	return &Method{
		Class: binary.BigEndian.Uint16(payload[0:2]),
		ID:    binary.BigEndian.Uint16(payload[2:4]),
		Args:  payload[4:],
	}, nil
}

// Name is the method's name, or the class and method as digits when this
// package does not know it. A name is never invented: the digits are
// obviously not a name, which is what an operator reading a refusal needs
// to see.
func (m *Method) Name() string {
	if n, ok := methodNames[key(m.Class, m.ID)]; ok {
		return n
	}
	return fmt.Sprintf("%d.%d", m.Class, m.ID)
}

// Known says whether this is a method in the catalogue.
func (m *Method) Known() bool { _, ok := methodNames[key(m.Class, m.ID)]; return ok }

// MethodID returns the class and method a name stands for, for a caller
// checking a policy's spelling at load time rather than at the first
// frame.
func MethodID(name string) (class, id uint16, ok bool) {
	v, ok := methodIDs[name]
	return v[0], v[1], ok
}

// Names is every method this package knows, for the configuration's own
// validation and for the documentation to be checked against.
func Names() []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, m.name)
	}
	return out
}

// dec reads the argument layouts. Every read is bounded by what is left,
// and the first failure is sticky: a caller checks err once at the end
// rather than after every field, and a decoder that kept going past a
// short read would be reading the next field from the wrong offset.
type dec struct {
	b   []byte
	i   int
	err error
	// bits is the packed boolean accumulator. Consecutive bit fields
	// share an octet, least significant first (§4.2.5.2), and any
	// non-bit field ends the run.
	bits  uint8
	bitAt uint8
	inBit bool
}

var errShort = errors.New("the arguments end before the method's fields do")

func (d *dec) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *dec) need(n int) bool {
	d.inBit = false
	if d.err != nil {
		return false
	}
	if d.i+n > len(d.b) {
		d.fail(errShort)
		return false
	}
	return true
}

func (d *dec) octet() uint8 {
	if !d.need(1) {
		return 0
	}
	v := d.b[d.i]
	d.i++
	return v
}

func (d *dec) short() uint16 {
	if !d.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(d.b[d.i:])
	d.i += 2
	return v
}

func (d *dec) long() uint32 {
	if !d.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(d.b[d.i:])
	d.i += 4
	return v
}

// longlong steps over an eight-octet field. It returns nothing because
// nothing here reads one: a delivery tag and a timestamp are not what a
// policy is about, and a value every caller dropped would only invite one
// to be used without being checked.
func (d *dec) longlong() {
	if !d.need(8) {
		return
	}
	d.i += 8
}

// bit reads one packed boolean.
func (d *dec) bit() bool {
	if d.err != nil {
		return false
	}
	if !d.inBit || d.bitAt > 7 {
		if d.i >= len(d.b) {
			d.fail(errShort)
			return false
		}
		d.bits = d.b[d.i]
		d.i++
		d.bitAt = 0
		d.inBit = true
	}
	v := d.bits&(1<<d.bitAt) != 0
	d.bitAt++
	return v
}

// shortstr is a length octet and that many octets of text.
func (d *dec) shortstr() string {
	n := int(d.octet())
	if !d.need(n) {
		return ""
	}
	s := string(d.b[d.i : d.i+n])
	d.i += n
	return s
}

// longstr is a four-octet length and that many octets. It is returned as
// the bytes it is: a long string on this protocol is as often a SASL
// response or a binary blob as it is text.
func (d *dec) longstr() []byte {
	n := int64(d.long())
	if d.err != nil {
		return nil
	}
	if n < 0 || d.i+int(n) > len(d.b) {
		d.fail(errShort)
		return nil
	}
	b := d.b[d.i : d.i+int(n)]
	d.i += int(n)
	d.inBit = false
	return b
}

// done says the fields were all there. It does not require the arguments
// to be exhausted: a broker's extension can add fields to the end of a
// method, and a relay that refused the connection for reading a name it
// understood out of a frame with more in it would be refusing an upgrade.
func (d *dec) done() error { return d.err }
