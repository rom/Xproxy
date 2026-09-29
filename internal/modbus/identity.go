package modbus

import (
	"errors"

	"github.com/rom/xproxy/internal/textsafe"
)

// Read Device Identification, read as what the device says it is.
//
// Function code 43 with MEI type 14 is the one place in this protocol where a
// device names itself: a vendor, a product code, a firmware revision and up to
// four more strings (section 6.21). Nothing else in Modbus carries any of it --
// there is no banner, no capability exchange, no version register everybody
// agrees on -- so this response is the whole of what a relay can learn about
// what it is in front of without asking a question of its own.
//
// That is why it is parsed here rather than treated as opaque bytes like the
// file records and the event log beside it. The estate that runs Modbus is the
// estate that cannot be scanned, and an inventory that knows a controller's
// firmware revision is an inventory that can be matched against the vendor's
// advisories. A relay reading an answer a master asked for anyway is the only
// way that number arrives.
//
// Two things it does not do. It does not *ask*: the response is read when a
// master requests it, and nothing here originates a request, because a frame
// this relay invents is a frame on somebody's process network that nobody
// scheduled. And it does not believe the strings: every one of them is
// peer-chosen, so each is clipped and stripped of the characters that would
// make a log line lie -- a device that answers with a control sequence in its
// product name is a device doing something other than reporting a product name.

// MEIIdentification is the MEI type of function code 43 that asks a device what
// it is. The other type the specification defines, 13, is the CANopen tunnel.
const MEIIdentification = 14

// The object identifiers of section 6.21's basic and regular identification.
const (
	IDVendor      = 0x00 // VendorName
	IDProductCode = 0x01 // ProductCode
	IDRevision    = 0x02 // MajorMinorRevision, which is the firmware version
	IDVendorURL   = 0x03 // VendorUrl
	IDProduct     = 0x04 // ProductName
	IDModel       = 0x05 // ModelName
	IDApplication = 0x06 // UserApplicationName
)

// Bounds on an identification response.
const (
	// MaxIDObjects bounds the objects one response may carry. The
	// specification defines seven and reserves the rest; a device answering
	// with more than this many is a device walking a list this does not need
	// all of.
	MaxIDObjects = 64
	// MaxIDValue bounds one object's value as it is kept. The wire allows 255
	// octets per object; an inventory field that long is a paragraph, and the
	// marker on a clipped string says it was cut.
	MaxIDValue = 96
)

// ErrIdentity is returned for an identification response whose object list does
// not fit the bytes it arrived in. It is separate from the other parse errors
// because it says something specific: the device's own length fields disagree
// with each other, which is a device this relay should not be reading strings
// out of.
var ErrIdentity = errors.New("modbus: malformed device identification")

// DeviceIdentity is what a device answered about itself.
//
// Every string field is the device's own claim, clipped and made safe to log.
// An empty one means the device did not send that object, which is ordinary:
// basic identification is three objects, and most devices send exactly those.
type DeviceIdentity struct {
	Vendor      string
	ProductCode string
	// Revision is object 0x02, MajorMinorRevision -- the firmware version, in
	// whatever form the device felt like writing it. Nothing normalises it
	// here: what a version string means is the reader's problem, and a relay
	// that tidied it up would be deciding a comparison it cannot see.
	Revision    string
	VendorURL   string
	Product     string
	Model       string
	Application string

	// Conformity is the conformity level octet: 1, 2 or 3, with the high bit
	// set when the device also serves individual access.
	Conformity byte
	// More says the device has more objects than fitted, and Next is where a
	// walk resumes. Both are the device's own statement and are kept so that
	// an operator can see an inventory entry is partial.
	More bool
	Next byte
	// Private counts the vendor-specific objects (0x80 and above) and Reserved
	// the ones the specification reserves. Counted rather than kept: they are
	// whatever a vendor decided, and an inventory made of them would be an
	// inventory of one vendor's tooling.
	Private, Reserved int
}

// Empty says the response carried none of the fields an inventory uses.
func (d *DeviceIdentity) Empty() bool {
	return d == nil || d.Vendor == "" && d.ProductCode == "" && d.Revision == "" &&
		d.Product == "" && d.Model == ""
}

// parseIdentity reads the object list of an identification response.
//
// data is the response PDU past the function code, so it begins at the MEI
// type. A response whose MEI type is not 14 is not identification -- it is the
// CANopen tunnel, which carries whatever CANopen carries -- and is not an
// error here: the caller keeps it as opaque bytes, as it always has.
func parseIdentity(data []byte) (*DeviceIdentity, error) {
	// Six fields before the list: the MEI type, the identification code, the
	// conformity level, more-follows, the object id a walk resumes at, and the
	// number of objects.
	if len(data) < 6 || data[0] != MEIIdentification {
		return nil, nil
	}
	d := &DeviceIdentity{Conformity: data[2], More: data[3] == 0xFF, Next: data[4]}
	count := int(data[5])
	if count > MaxIDObjects {
		return nil, ErrIdentity
	}
	rest := data[6:]
	for i := 0; i < count; i++ {
		if len(rest) < 2 {
			// The device said more objects than it sent. Refusing is the
			// point: a truncated list read as a complete one would put half a
			// string in an inventory and call it a firmware version.
			return nil, ErrIdentity
		}
		id, n := rest[0], int(rest[1])
		if len(rest) < 2+n {
			return nil, ErrIdentity
		}
		value := textsafe.Clip(string(rest[2:2+n]), MaxIDValue)
		rest = rest[2+n:]
		switch {
		case id == IDVendor:
			d.Vendor = value
		case id == IDProductCode:
			d.ProductCode = value
		case id == IDRevision:
			d.Revision = value
		case id == IDVendorURL:
			d.VendorURL = value
		case id == IDProduct:
			d.Product = value
		case id == IDModel:
			d.Model = value
		case id == IDApplication:
			d.Application = value
		case id >= 0x80:
			d.Private++
		default:
			d.Reserved++
		}
	}
	if len(rest) != 0 {
		// Objects past the count the device declared. The two readings of this
		// frame disagree, which is the class of thing this relay refuses
		// rather than resolves.
		return nil, ErrIdentity
	}
	return d, nil
}
