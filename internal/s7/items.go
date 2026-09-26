package s7

import (
	"encoding/binary"
	"fmt"
)

// The items of a read or a write, which are the addresses a policy is
// written about.
//
// A read or write job carries a count and then that many item
// specifications, each of which says which memory area, which data block
// and which address. Three things about them shape this code.
//
// **The address is in bits.** The three octets are a bit address, so the
// byte a request names is the address divided by eight -- and a policy
// written in bytes, which is how an operator thinks about a data block, has
// to divide rather than compare the number on the wire.
//
// **The syntax identifier says whether the item is an address at all.**
// `S7ANY` is the ordinary one; the others address a symbol, a database
// variable or a DRIVES parameter, and a relay cannot locate those in an
// area and a byte. Each is reported as the syntax it is, so a listener with
// an address policy refuses what it cannot place instead of checking a list
// against a field that means something else.
//
// **A write's values are in the other half of the PDU.** The parameters say
// where, the data says what, and the two are separate lists that have to be
// walked together: a write of three items has three specifications and
// three data items, and a relay that read only the first would be deciding
// about one third of the operation.

// The syntax identifiers of an item specification.
const (
	// SyntaxAny is the address form: an area, a data block and a bit
	// address.
	SyntaxAny uint8 = 0x10
	// SyntaxPBCR is a PBC connection reference.
	SyntaxPBCR uint8 = 0x13
	// SyntaxAlarmLock and the rest are alarm and message services.
	SyntaxAlarmLock  uint8 = 0x15
	SyntaxAlarmInd   uint8 = 0x16
	SyntaxAlarmAck   uint8 = 0x19
	SyntaxAlarmQuery uint8 = 0x1A
	SyntaxNotify     uint8 = 0x1C
	// SyntaxDriveAny, SyntaxSym1200, SyntaxDBRead and SyntaxNCK are the
	// forms other families and tools use.
	SyntaxDriveAny uint8 = 0xA2
	SyntaxSym1200  uint8 = 0xB2
	SyntaxDBRead   uint8 = 0xB0
	SyntaxNCK      uint8 = 0x82
)

// The memory areas. The names are the ones an operator writes: a data
// block is `db`, the flags are `flags` (Siemens calls them merkers), and
// the process image is `inputs` and `outputs`.
const (
	AreaSysInfo200   uint8 = 0x03
	AreaSysFlags200  uint8 = 0x05
	AreaAnalogIn200  uint8 = 0x06
	AreaAnalogOut200 uint8 = 0x07
	AreaCounter      uint8 = 0x1C
	AreaTimer        uint8 = 0x1D
	AreaCounter200   uint8 = 0x1E
	AreaTimer200     uint8 = 0x1F
	AreaDirectPeriph uint8 = 0x80
	AreaInputs       uint8 = 0x81
	AreaOutputs      uint8 = 0x82
	AreaFlags        uint8 = 0x83
	AreaDB           uint8 = 0x84
	AreaInstanceDB   uint8 = 0x85
	AreaLocal        uint8 = 0x86
	AreaPrevLocal    uint8 = 0x87
)

var areaNames = map[uint8]string{
	AreaSysInfo200:   "sysinfo_200",
	AreaSysFlags200:  "sysflags_200",
	AreaAnalogIn200:  "analog_in_200",
	AreaAnalogOut200: "analog_out_200",
	AreaCounter:      "counter",
	AreaTimer:        "timer",
	AreaCounter200:   "counter_200",
	AreaTimer200:     "timer_200",
	AreaDirectPeriph: "peripheral",
	AreaInputs:       "inputs",
	AreaOutputs:      "outputs",
	AreaFlags:        "flags",
	AreaDB:           "db",
	AreaInstanceDB:   "instance_db",
	AreaLocal:        "local",
	AreaPrevLocal:    "previous_local",
}

// AreaName names a memory area, or gives its number.
func AreaName(a uint8) string {
	if n, ok := areaNames[a]; ok {
		return n
	}
	return fmt.Sprintf("%#x", a)
}

// AreaOf reads an area name as the configuration spells it.
func AreaOf(s string) (uint8, bool) {
	for code, name := range areaNames {
		if name == s {
			return code, true
		}
	}
	return 0, false
}

// AreaNames is every area name, for the configuration's validation and the
// documentation to be checked against.
func AreaNames() []string {
	out := make([]string, 0, len(areaNames))
	for _, n := range areaNames {
		out = append(out, n)
	}
	return out
}

// The transport sizes an item specification names. They say how the count
// is measured -- in bits for the first, in octets for the rest -- which is
// what makes a length bound possible at all.
const (
	TransportBit   uint8 = 0x01
	TransportByte  uint8 = 0x02
	TransportChar  uint8 = 0x03
	TransportWord  uint8 = 0x04
	TransportInt   uint8 = 0x05
	TransportDWord uint8 = 0x06
	TransportDInt  uint8 = 0x07
	TransportReal  uint8 = 0x08
	TransportDate  uint8 = 0x09
	TransportTOD   uint8 = 0x0A
	TransportTime  uint8 = 0x0B
	TransportS5    uint8 = 0x0C
	TransportDT    uint8 = 0x0F
	TransportCntr  uint8 = 0x1C
	TransportTimer uint8 = 0x1D
)

// Item is one thing a read or write job names.
type Item struct {
	// Syntax is the item's syntax identifier, and Address says whether
	// this is the addressing form -- the only one whose area, block and
	// byte mean what a policy about them means.
	Syntax  uint8
	Address bool

	Transport uint8
	// Count is the number of elements, in bits for a bit transport and in
	// octets for the rest.
	Count uint16
	// DB is the data block number, zero for the areas that have none.
	DB   uint16
	Area uint8
	// Bit is the address as it arrives, which is a bit address.
	Bit uint32

	// Value is the octets a write carries for this item, and ValueTransport
	// the transport size the data item declared -- which need not be the
	// one the specification did, and a relay reports both rather than
	// assuming they agree.
	Value          []byte
	ValueTransport uint8
	// HasValue says a data item was found for this specification.
	HasValue bool
}

// Byte is the byte address the item names.
func (i Item) Byte() int { return int(i.Bit / 8) }

// BitOffset is the bit within that byte, which is only meaningful for a bit
// transport.
func (i Item) BitOffset() int { return int(i.Bit % 8) }

// Bytes is how many octets the item covers, which is what an address range
// is checked against: a read of ten words starting at byte 4 covers bytes 4
// to 23, and a policy that compared only the start would allow a read that
// runs off the end of what it meant to allow.
func (i Item) Bytes() int {
	switch i.Transport {
	case TransportBit:
		// A count of bits, which covers at least one byte.
		n := (int(i.Count) + 7) / 8
		if n == 0 {
			n = 1
		}
		return n
	case TransportWord, TransportInt, TransportCntr, TransportTimer:
		return int(i.Count) * 2
	case TransportDWord, TransportDInt, TransportReal:
		return int(i.Count) * 4
	case TransportDT, TransportTOD, TransportDate, TransportTime:
		// The date and time forms are eight, four and four octets; the
		// widest is taken, because a bound that under-counted would allow
		// a range it meant to refuse.
		return int(i.Count) * 8
	}
	return int(i.Count)
}

// Last is the last byte the item covers.
func (i Item) Last() int {
	n := i.Bytes()
	if n <= 0 {
		return i.Byte()
	}
	return i.Byte() + n - 1
}

// TransportName names a transport size.
func TransportName(t uint8) string {
	switch t {
	case TransportBit:
		return "bit"
	case TransportByte:
		return "byte"
	case TransportChar:
		return "char"
	case TransportWord:
		return "word"
	case TransportInt:
		return "int"
	case TransportDWord:
		return "dword"
	case TransportDInt:
		return "dint"
	case TransportReal:
		return "real"
	case TransportDate:
		return "date"
	case TransportTOD:
		return "time_of_day"
	case TransportTime:
		return "time"
	case TransportS5:
		return "s5time"
	case TransportDT:
		return "date_and_time"
	case TransportCntr:
		return "counter"
	case TransportTimer:
		return "timer"
	}
	return fmt.Sprintf("%#x", t)
}

// Items reads the items of a read or write job.
//
// The second return says whether the specifications laid out. A job whose
// items this package cannot read is not a job with fewer items: it is one
// whose addresses are unknown, and the policy refuses it rather than
// checking a list against the ones it managed.
func (p *PDU) Items() ([]Item, bool) {
	if !p.HasFunction {
		return nil, false
	}
	switch p.Function {
	case FnReadVar, FnWriteVar:
	default:
		return nil, false
	}
	if len(p.Param) < 2 {
		return nil, false
	}
	count := int(p.Param[1])
	out := make([]Item, 0, min(count, 32))
	b := p.Param[2:]
	for n := 0; n < count; n++ {
		// Every specification begins with a specification type, a length
		// and a syntax identifier. The length counts what follows it, so
		// an item this package does not understand is still stepped over
		// exactly -- which is what lets it report the syntax rather than
		// losing the rest of the list.
		if len(b) < 3 {
			return nil, false
		}
		if b[0] != 0x12 {
			// Not an item specification. Everything after it is at an
			// unknown offset.
			return nil, false
		}
		ln := int(b[1])
		if ln < 1 || 2+ln > len(b) {
			return nil, false
		}
		body := b[2 : 2+ln]
		it := Item{Syntax: body[0]}
		if it.Syntax == SyntaxAny {
			if ln < 10 {
				return nil, false
			}
			it.Address = true
			it.Transport = body[1]
			it.Count = binary.BigEndian.Uint16(body[2:4])
			it.DB = binary.BigEndian.Uint16(body[4:6])
			it.Area = body[6]
			it.Bit = uint32(body[7])<<16 | uint32(body[8])<<8 | uint32(body[9])
		}
		out = append(out, it)
		b = b[2+ln:]
	}
	if p.Function == FnWriteVar {
		if !readValues(out, p.Data) {
			return nil, false
		}
	}
	return out, true
}

// readValues walks the data half of a write job and attaches each value to
// its specification.
//
// The two lists are parallel and separately framed, and the padding is the
// part that catches a reader out: a data item whose length is odd is
// followed by a fill octet, so a reader that did not skip it would read the
// next item's return code as its transport size.
func readValues(items []Item, b []byte) bool {
	for i := range items {
		if len(b) == 0 {
			// Fewer data items than specifications. The PLC would refuse
			// the job; this reports the mismatch rather than deciding
			// about a write whose values it does not have.
			return false
		}
		if len(b) < 4 {
			return false
		}
		transport := b[1]
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if transport == TransportBit || transport == TransportByte || transport == TransportChar {
			// A length in bits for these three, which is how the protocol
			// writes it.
			n = (n + 7) / 8
		}
		if 4+n > len(b) {
			return false
		}
		items[i].ValueTransport = transport
		items[i].Value = b[4 : 4+n]
		items[i].HasValue = true
		b = b[4+n:]
		// The fill octet after an odd-length item, except on the last one.
		if n%2 != 0 && len(b) > 0 {
			b = b[1:]
		}
	}
	return true
}
