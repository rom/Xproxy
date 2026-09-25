package amqpwire

import (
	"errors"
	"fmt"
)

// The field table, which is where a policy on this protocol has to be
// careful.
//
// A table is a length and then entries of a name and a typed value, and
// two of those values are an access boundary: `alternate-exchange` on an
// exchange and `x-dead-letter-exchange` on a queue both name an exchange
// that messages will be routed to. A relay that checked only the exchange
// a method declares would let a client name an exchange it may not
// publish to, and have the broker route to it on the client's behalf.
//
// The type codes are the part where implementations disagree. The 0-9-1
// specification says `s` is a short string; RabbitMQ -- which is what
// almost every deployment is -- says `s` is a signed 16-bit integer, and
// publishes an errata table saying so. A reader has to pick one, because
// reading a two-octet integer as a string of that length puts every
// following entry at the wrong offset. This reads RabbitMQ's table, and
// when the octets do not lay out it says so rather than returning the
// entries it managed: a policy that acted on half a table would be
// checking a list against whatever survived.
//
// The depth bound is not decoration. A table may hold a table, and the
// nesting is the sender's: without a bound, forty octets of `F` describe a
// structure deep enough to exhaust the stack of whatever reads it.

// maxTableDepth is how deeply tables may nest. Real brokers and clients
// use one level; two is generous.
const maxTableDepth = 8

// errTableDepth is a table nested past the bound.
var errTableDepth = errors.New("the field table is nested deeper than this relay reads")

// table reads a field table's entries, keeping the ones whose value is
// text and skipping the rest.
//
// Only the text matters to a policy: the two entries that name an exchange
// are strings, and a bound or a timestamp is not something an access rule
// is written about. The rest still has to be *walked*, because skipping a
// value means knowing its length.
func (d *dec) table(depth int) map[string]string {
	n := int64(d.long())
	if d.err != nil {
		return nil
	}
	if n < 0 || d.i+int(n) > len(d.b) {
		d.fail(errShort)
		return nil
	}
	body := d.b[d.i : d.i+int(n)]
	d.i += int(n)
	d.inBit = false
	out := map[string]string{}
	inner := &dec{b: body}
	for inner.i < len(body) {
		name := inner.shortstr()
		if inner.err != nil {
			d.fail(inner.err)
			return nil
		}
		v, text, err := inner.fieldValue(depth + 1)
		if err != nil {
			d.fail(err)
			return nil
		}
		if text {
			out[name] = v
		}
	}
	if inner.err != nil {
		d.fail(inner.err)
		return nil
	}
	return out
}

// fieldValue reads one typed value, returning it as text when it is text.
func (d *dec) fieldValue(depth int) (string, bool, error) {
	if depth > maxTableDepth {
		return "", false, errTableDepth
	}
	t := d.octet()
	if d.err != nil {
		return "", false, d.err
	}
	switch t {
	case 't': // boolean
		d.octet()
	case 'b', 'B': // 8-bit, signed and unsigned
		d.octet()
	case 's', 'u', 'U': // 16-bit. `s` is RabbitMQ's; `U` is the specification's.
		d.short()
	case 'I', 'i': // 32-bit
		d.long()
	case 'l', 'L', 'T', 'f', 'd': // 64-bit, and the timestamp and floats
		if t == 'f' {
			d.long()
		} else {
			d.longlong()
		}
	case 'D': // decimal: one octet of scale and a 32-bit value
		d.octet()
		d.long()
	case 'S': // long string
		b := d.longstr()
		if d.err != nil {
			return "", false, d.err
		}
		return string(b), true, nil
	case 'x': // byte array, which is a length and octets like a long string
		d.longstr()
	case 'A': // array
		if err := d.array(depth); err != nil {
			return "", false, err
		}
	case 'F': // nested table
		if d.table(depth); d.err != nil {
			return "", false, d.err
		}
	case 'V': // void, no value at all
	default:
		// An unknown type code cannot be skipped, because its length is
		// whatever its definition says. Everything after it is
		// unreadable, so the table is unreadable, and saying so is the
		// only honest answer.
		return "", false, fmt.Errorf("field type %q is not one this relay reads", string(rune(t)))
	}
	if d.err != nil {
		return "", false, d.err
	}
	return "", false, nil
}

// array is a length and that many octets of values, each with its own type
// code and no names.
func (d *dec) array(depth int) error {
	n := int64(d.long())
	if d.err != nil {
		return d.err
	}
	if n < 0 || d.i+int(n) > len(d.b) {
		return errShort
	}
	body := d.b[d.i : d.i+int(n)]
	d.i += int(n)
	inner := &dec{b: body}
	for inner.i < len(body) {
		if _, _, err := inner.fieldValue(depth + 1); err != nil {
			return err
		}
	}
	return inner.err
}

// LoginTable reads the entries of a table that arrives without its own
// length octets, which is the shape RabbitMQ's AMQPLAIN mechanism puts in
// a SASL response.
//
// It exists for one field: the LOGIN entry, which is the username. The
// password is in the same table under PASSWORD and is not returned -- the
// caller gets the identity and nothing else, so no code path that logs a
// decision can reach the secret.
func LoginTable(b []byte) (map[string]string, error) {
	d := &dec{b: b}
	out := map[string]string{}
	for d.i < len(b) {
		name := d.shortstr()
		if d.err != nil {
			return nil, d.err
		}
		v, text, err := d.fieldValue(1)
		if err != nil {
			return nil, err
		}
		if text {
			out[name] = v
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	return out, nil
}
