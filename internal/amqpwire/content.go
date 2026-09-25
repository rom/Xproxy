package amqpwire

import (
	"encoding/binary"
	"fmt"
)

// The content header, which is the frame between a basic.publish and the
// octets of the message.
//
// Three things in it are a policy's business.
//
// **The body size, before the body.** The header declares how many octets
// the message will be, and the broker will hold them. A relay that only
// counted body frames as they arrived would refuse a message after
// accepting most of it; reading the declared size means refusing it before
// the first octet of content is taken.
//
// **The user identifier.** RabbitMQ checks this property against the
// connection's authenticated user when a publisher sets it, which makes it
// the one field on the protocol that ties a message to a person. Nothing
// makes a publisher set it. A relay can require it, which turns "somebody
// published this" into an attributable act.
//
// **The reply-to.** It is a queue name inside the message's properties, and
// it is where a request-reply service will send its answer. A policy that
// checked only the exchange and routing key of the publish would let a
// client name a reply queue it has no business naming and have the
// responder deliver to it.
type ContentHeader struct {
	Class    uint16
	BodySize uint64

	ContentType  string
	DeliveryMode uint8
	Priority     uint8
	ReplyTo      string
	Expiration   string
	UserID       string
	AppID        string
	// Set says which properties were present, by name, so a caller can
	// tell an empty user identifier from an absent one -- which is the
	// difference between a publisher that set it to nothing and one that
	// did not set it at all.
	Set map[string]bool
}

// The property bits of the basic class, most significant first (§4.2.6.1).
const (
	propContentType     = 15
	propContentEncoding = 14
	propHeaders         = 13
	propDeliveryMode    = 12
	propPriority        = 11
	propCorrelationID   = 10
	propReplyTo         = 9
	propExpiration      = 8
	propMessageID       = 7
	propTimestamp       = 6
	propType            = 5
	propUserID          = 4
	propAppID           = 3
	propClusterID       = 2
)

// ParseContentHeader reads a content header frame's payload.
func ParseContentHeader(payload []byte) (*ContentHeader, error) {
	// class-id, weight, body-size, property flags: fourteen octets before
	// the first property.
	if len(payload) < 14 {
		return nil, fmt.Errorf("a content header of %d octets is shorter than its own fixed fields", len(payload))
	}
	h := &ContentHeader{
		Class:    binary.BigEndian.Uint16(payload[0:2]),
		BodySize: binary.BigEndian.Uint64(payload[4:12]),
		Set:      map[string]bool{},
	}
	flags := binary.BigEndian.Uint16(payload[12:14])
	d := &dec{b: payload, i: 14}
	// A set continuation bit means another flags word follows, holding the
	// properties of a class this relay does not read. The fields it
	// already has are still the fields it read; what it must not do is
	// carry on decoding the next word's properties as if they were the
	// basic class's.
	more := flags&1 != 0
	has := func(bit uint) bool { return flags&(1<<bit) != 0 }
	if has(propContentType) {
		h.ContentType = d.shortstr()
		h.Set["content_type"] = true
	}
	if has(propContentEncoding) {
		d.shortstr()
	}
	if has(propHeaders) {
		d.table(1)
	}
	if has(propDeliveryMode) {
		h.DeliveryMode = d.octet()
		h.Set["delivery_mode"] = true
	}
	if has(propPriority) {
		h.Priority = d.octet()
		h.Set["priority"] = true
	}
	if has(propCorrelationID) {
		d.shortstr()
	}
	if has(propReplyTo) {
		h.ReplyTo = d.shortstr()
		h.Set["reply_to"] = true
	}
	if has(propExpiration) {
		h.Expiration = d.shortstr()
		h.Set["expiration"] = true
	}
	if has(propMessageID) {
		d.shortstr()
	}
	if has(propTimestamp) {
		d.longlong()
	}
	if has(propType) {
		d.shortstr()
	}
	if has(propUserID) {
		h.UserID = d.shortstr()
		h.Set["user_id"] = true
	}
	if has(propAppID) {
		h.AppID = d.shortstr()
		h.Set["app_id"] = true
	}
	if has(propClusterID) {
		d.shortstr()
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	if more {
		h.Set["continued"] = true
	}
	return h, nil
}
