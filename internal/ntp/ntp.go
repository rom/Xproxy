package ntp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The sizes and ports the protocol fixes.
const (
	// HeaderLen is the fixed header: forty-eight octets, and nothing
	// more. A packet is the header plus whatever extension fields and
	// MAC follow it, so an implementation that reads exactly
	// forty-eight octets is an implementation that cannot see NTS.
	HeaderLen = 48
	// MaxPacket bounds what this package will read at all. A time
	// packet has no business being larger, and a listener bounds it
	// tighter still.
	MaxPacket = 4096
	// Port is the time service port and KEPort the NTS key
	// establishment port (RFC 8915).
	Port   = 123
	KEPort = 4460
	// ALPN is the application protocol NTS key establishment
	// negotiates over TLS. A connection to the key establishment port
	// that does not offer it is not an NTS client.
	ALPN = "ntske/1"
	// MaxExtensions bounds the extension fields one packet may carry,
	// because a packet made of ten thousand four-octet claims is a way
	// to spend a relay's time rather than a way to ask it the time.
	MaxExtensions = 32
)

// Mode is the association mode, the low three bits of the first octet.
type Mode uint8

// The modes of RFC 5905 section 7.3, and the two that are not time
// service at all.
const (
	ModeReserved   Mode = 0
	ModeSymActive  Mode = 1
	ModeSymPassive Mode = 2
	ModeClient     Mode = 3
	ModeServer     Mode = 4
	ModeBroadcast  Mode = 5
	ModeControl    Mode = 6
	ModePrivate    Mode = 7
)

var modeNames = map[Mode]string{
	ModeReserved: "reserved", ModeSymActive: "symmetric_active",
	ModeSymPassive: "symmetric_passive", ModeClient: "client",
	ModeServer: "server", ModeBroadcast: "broadcast",
	ModeControl: "control", ModePrivate: "private",
}

func (m Mode) String() string {
	if s, ok := modeNames[m]; ok {
		return s
	}
	return fmt.Sprintf("mode_%d", uint8(m))
}

// ModeOf reads a mode by the name a configuration uses.
func ModeOf(s string) (Mode, bool) {
	for m, name := range modeNames {
		if name == s {
			return m, true
		}
	}
	return 0, false
}

// TimeService says whether this mode is one that carries time. Modes 6
// and 7 are management protocols that share the port and share nothing
// else: mode 6 is ntpq's control protocol, mode 7 the vendor-private one
// that monlist belongs to, and neither has the header this package
// parses.
func (m Mode) TimeService() bool { return m >= ModeSymActive && m <= ModeBroadcast }

// Management says whether this mode is one of the two that are not time.
func (m Mode) Management() bool { return m == ModeControl || m == ModePrivate }

// Leap is the leap indicator, the top two bits of the first octet.
type Leap uint8

const (
	LeapNone           Leap = 0
	LeapAddSecond      Leap = 1
	LeapDeleteSecond   Leap = 2
	LeapUnsynchronised Leap = 3
)

func (l Leap) String() string {
	switch l {
	case LeapNone:
		return "none"
	case LeapAddSecond:
		return "add_second"
	case LeapDeleteSecond:
		return "delete_second"
	}
	return "unsynchronised"
}

// The versions this package will parse. NTPv1 and v2 share the v3 and v4
// header, so one parser reads all four; NTPv5 does not, which is why a
// version dispatch that fell through to this parser would be reading a
// different protocol's fields as if they were these.
const (
	MinVersion = 1
	MaxVersion = 4
	// Version5 is the experimental version whose packet format is not
	// this one. It is named so a dispatch can refuse it by name.
	Version5 = 5
)

// Errors this package returns. They are distinguished because a relay
// logs them differently: a version it does not implement is an estate
// fact, a malformed extension field is a sender doing something.
var (
	ErrShort     = errors.New("ntp: packet shorter than the header")
	ErrBounds    = errors.New("ntp: packet outside the bounds")
	ErrVersion   = errors.New("ntp: version this parser does not read")
	ErrMode      = errors.New("ntp: mode this parser does not read")
	ErrExtension = errors.New("ntp: malformed extension field")
	ErrTail      = errors.New("ntp: trailing bytes that are neither an extension field nor a MAC")
)

// Kind is what the first octet says, which is all a dispatch needs and
// all it should read: the version decides which parser may touch the
// rest, so reading anything else first would be the mistake the dispatch
// exists to prevent.
type Kind struct {
	Leap    Leap
	Version uint8
	Mode    Mode
}

// Classify reads the first octet.
//
// It is separate from Parse on purpose. A version-5 packet and a mode-6
// control message are not this header with a different number in it --
// they are different layouts -- so the only safe order is: read the
// version and the mode, decide whether this parser may read the packet
// at all, and only then parse it.
func Classify(b []byte) (Kind, error) {
	if len(b) < 1 {
		return Kind{}, ErrShort
	}
	return Kind{Leap: Leap(b[0] >> 6), Version: (b[0] >> 3) & 7, Mode: Mode(b[0] & 7)}, nil
}

// Parsable says whether this package's parser reads this packet's layout.
func (k Kind) Parsable() bool {
	return k.Version >= MinVersion && k.Version <= MaxVersion && !k.Mode.Management()
}

// EffectiveMode is the mode a policy should decide about.
//
// NTPv1 has no mode field: the three bits are zero, and a version 1
// packet arriving at a time service port with them zero is a client
// asking the time -- which is what it is, and what every server has
// always treated it as. Saying so here is what lets a listener that
// names version 1 for an identified device also name the mode, instead
// of having to allow a reserved value nobody can write down.
func (k Kind) EffectiveMode() Mode {
	if k.Version == 1 && k.Mode == ModeReserved {
		return ModeClient
	}
	return k.Mode
}

// Packet is a parsed time packet.
type Packet struct {
	Leap      Leap
	Version   uint8
	Mode      Mode
	Stratum   uint8
	Poll      int8
	Precision int8

	RootDelay      Short
	RootDispersion Short
	ReferenceID    [4]byte

	Reference Timestamp
	Origin    Timestamp
	Receive   Timestamp
	Transmit  Timestamp

	// Extensions are the fields between the header and the MAC, in the
	// order they arrived.
	Extensions []Extension
	// KeyID and MAC are the symmetric authentication, when there is
	// any. HasMAC says whether there was: an empty MAC and no MAC are
	// different things.
	KeyID  uint32
	MAC    []byte
	HasMAC bool
	// CryptoNAK is a four-octet tail: a key identifier with no digest,
	// which is how a server says "I will not authenticate this".
	CryptoNAK bool
	// MACAmbiguous marks a packet whose tail is both a valid MAC and a
	// syntactically valid extension field (RFC 7822's own ambiguity).
	// It is read as a MAC, which is what every implementation does, and
	// the flag is here so a policy can refuse a packet whose meaning
	// depends on that choice rather than acting on a guess.
	MACAmbiguous bool
	// MACStart is where the authenticated bytes end: the MAC covers the
	// header and every extension field before it.
	MACStart int
	// Raw is the packet as it arrived. A relay forwards these bytes,
	// never a re-encoding: an authenticated packet re-encoded is an
	// authenticated packet broken, and an unauthenticated one
	// re-encoded is a relay and a client disagreeing about what was
	// said.
	Raw []byte
}

// Parse reads a time packet. The caller has already classified it, and
// Parse refuses a version or mode it does not read rather than trusting
// that.
func Parse(b []byte) (*Packet, error) {
	k, err := Classify(b)
	if err != nil {
		return nil, err
	}
	if k.Mode.Management() {
		return nil, ErrMode
	}
	if k.Version < MinVersion || k.Version > MaxVersion {
		return nil, ErrVersion
	}
	if len(b) < HeaderLen {
		return nil, ErrShort
	}
	if len(b) > MaxPacket {
		return nil, ErrBounds
	}
	p := &Packet{
		Leap: k.Leap, Version: k.Version, Mode: k.Mode,
		Stratum:        b[1],
		Poll:           int8(b[2]), //nolint:gosec // the field is signed
		Precision:      int8(b[3]), //nolint:gosec // the field is signed
		RootDelay:      Short(binary.BigEndian.Uint32(b[4:])),
		RootDispersion: Short(binary.BigEndian.Uint32(b[8:])),
		Reference:      Timestamp(binary.BigEndian.Uint64(b[16:])),
		Origin:         Timestamp(binary.BigEndian.Uint64(b[24:])),
		Receive:        Timestamp(binary.BigEndian.Uint64(b[32:])),
		Transmit:       Timestamp(binary.BigEndian.Uint64(b[40:])),
		Raw:            b,
		MACStart:       len(b),
	}
	copy(p.ReferenceID[:], b[12:16])
	if err := p.parseTail(b[HeaderLen:], k.Version); err != nil {
		return nil, err
	}
	return p, nil
}

// Bytes renders a packet. It is used for the packets this relay
// originates -- its own probes towards a server, and the kiss-o'-death
// it answers a rate-limited client with -- and never to re-encode one it
// is forwarding.
func (p *Packet) Bytes() []byte {
	b := make([]byte, HeaderLen)
	b[0] = byte(p.Leap)<<6 | (p.Version&7)<<3 | byte(p.Mode&7)
	b[1] = p.Stratum
	b[2] = byte(p.Poll)      //nolint:gosec // the field is signed
	b[3] = byte(p.Precision) //nolint:gosec // the field is signed
	binary.BigEndian.PutUint32(b[4:], uint32(p.RootDelay))
	binary.BigEndian.PutUint32(b[8:], uint32(p.RootDispersion))
	copy(b[12:16], p.ReferenceID[:])
	binary.BigEndian.PutUint64(b[16:], uint64(p.Reference))
	binary.BigEndian.PutUint64(b[24:], uint64(p.Origin))
	binary.BigEndian.PutUint64(b[32:], uint64(p.Receive))
	binary.BigEndian.PutUint64(b[40:], uint64(p.Transmit))
	for _, e := range p.Extensions {
		b = append(b, e.Bytes()...)
	}
	if p.HasMAC || p.CryptoNAK {
		var id [4]byte
		binary.BigEndian.PutUint32(id[:], p.KeyID)
		b = append(b, id[:]...)
		b = append(b, p.MAC...)
	}
	return b
}

// Unsynchronised reports a server that says its own clock is not
// synchronised. It is a different state from unreachable and from
// wrong, and a relay that conflated them would distribute time from a
// server that is telling it not to.
func (p *Packet) Unsynchronised() bool { return p.Leap == LeapUnsynchronised }

// KissOfDeath reports the stratum-0 packet a server sends instead of
// time: a rate limit, a denial, or a request to slow down. Stratum 0 is
// not "a very good clock" and it is not an error either -- it is a
// message whose four reference identifier octets are the kiss code.
func (p *Packet) KissOfDeath() bool { return p.Mode == ModeServer && p.Stratum == 0 }

// KissCode is the four-character code a kiss-o'-death carries (RATE,
// DENY, RSTR and the others). It is empty for anything else.
func (p *Packet) KissCode() string {
	if !p.KissOfDeath() {
		return ""
	}
	return printableID(p.ReferenceID)
}

// RefID renders the reference identifier the way its stratum says to
// read it, which is the field most often read wrongly.
//
// At stratum 0 it is a kiss code and at stratum 1 the reference clock's
// four-character name -- both ASCII. At stratum 2 and above it is an
// IPv4 address for an IPv4 association and, for IPv6, the first four
// octets of a hash of the address, which is not an address at all: a
// relay that printed it as one would be logging a destination nothing
// ever talks to.
func (p *Packet) RefID() string {
	switch p.Stratum {
	case 0:
		if s := printableID(p.ReferenceID); s != "" {
			return "kiss:" + s
		}
		return "unspecified"
	case 1:
		if s := printableID(p.ReferenceID); s != "" {
			return "refclock:" + s
		}
		return "refclock"
	default:
		// An IPv4 association's identifier is the address. Anything
		// else -- an IPv6 association, or a server that hashes it -- is
		// four octets of a digest, and saying so is better than
		// printing a plausible address nobody can reach.
		return fmt.Sprintf("%d.%d.%d.%d (or a hash: the field does not say which)",
			p.ReferenceID[0], p.ReferenceID[1], p.ReferenceID[2], p.ReferenceID[3])
	}
}

// printableID reads the identifier as the four-character ASCII the low
// strata use, or returns "" when it is not that.
func printableID(id [4]byte) string {
	out := make([]byte, 0, 4)
	for _, c := range id {
		if c == 0 {
			break
		}
		if c < 0x21 || c > 0x7E {
			return ""
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return ""
	}
	return string(out)
}

// ServerQuality is what a server's answer says about the time in it. It
// is deliberately only about responses: a client's request carries a
// stratum and a root dispersion too, and they mean nothing -- so a relay
// that applied these rules to requests would be refusing clients for
// fields the protocol does not ask them to fill in.
type ServerQuality struct {
	// Unsynchronised is the leap indicator saying so.
	Unsynchronised bool
	// Kiss is a stratum-0 answer: a message rather than a time.
	Kiss string
	// Stratum is the server's distance from a reference clock. 16 is
	// the protocol's "unsynchronised" stratum, which is a different
	// statement from the leap indicator's and is worth both checks.
	Stratum uint8
	// RootDelay and RootDispersion are the total delay and accumulated
	// error towards the reference clock: the server's own statement of
	// how good its time is.
	RootDelay, RootDispersion time.Duration
	// ReferenceStale is the age of the server's last synchronisation,
	// as it reports it, measured against the receiving clock.
	ReferenceStale time.Duration
}

// Quality reads the answer's own statement about itself. now is the
// receiving clock, which is what places the reference timestamp in an
// era.
func (p *Packet) Quality(now time.Time) ServerQuality {
	q := ServerQuality{
		Unsynchronised: p.Unsynchronised(),
		Kiss:           p.KissCode(),
		Stratum:        p.Stratum,
		RootDelay:      p.RootDelay.Duration(),
		RootDispersion: p.RootDispersion.Duration(),
	}
	if !p.Reference.IsZero() {
		q.ReferenceStale = now.Sub(p.Reference.Time(now))
	}
	return q
}

// Offset and Delay are the two numbers a client computes from an
// exchange: t1 is when the request left, t4 when the answer arrived, and
// the server's receive and transmit timestamps are in the packet.
//
// The arithmetic is done on the wire values with the protocol's own
// modular subtraction, so an exchange that spans the end of an era gives
// the small numbers it really is rather than overflowing into a
// hundred-year error.
func Offset(t1 Timestamp, p *Packet, t4 Timestamp) time.Duration {
	return (p.Receive.Sub(t1) + p.Transmit.Sub(t4)) / 2
}

// Delay is the round trip minus the server's own processing time.
func Delay(t1 Timestamp, p *Packet, t4 Timestamp) time.Duration {
	d := t4.Sub(t1) - p.Transmit.Sub(p.Receive)
	if d < 0 {
		// A negative delay is not a measurement; it is a clock that
		// moved during the exchange or a server whose timestamps do not
		// agree with each other.
		return 0
	}
	return d
}

// AnswersRequest says whether this response answers the request whose
// transmit timestamp was sent.
//
// The origin timestamp of a server's answer is the client's own transmit
// timestamp, echoed. That is the only thing tying an answer to a
// question in NTP -- there is no identifier, no port guarantee beyond
// the socket, and the address can be forged -- so a relay that did not
// check it would forward whatever arrived first.
//
// Interleaved mode is the exception the rule has to know about: there
// the server echoes its own previous transmit timestamp instead, so an
// answer that fails this check may still be a valid interleaved one, and
// the caller decides by whether the association is interleaved.
func (p *Packet) AnswersRequest(sent Timestamp) bool {
	return p.Origin == sent && !sent.IsZero()
}

// RootDistance is the synchronisation distance: half the total round
// trip to the reference clock plus the accumulated error (RFC 5905
// section 11.2's lambda + epsilon). It is the single number that says
// how far from the reference clock this answer really is, and it is the
// one a server cannot make look good by reporting a small delay and a
// large dispersion or the other way about.
func (p *Packet) RootDistance() time.Duration {
	return p.RootDelay.Duration()/2 + p.RootDispersion.Duration()
}

// Announcing reports a leap indicator that announces a leap second,
// which is different from one that says the clock is unsynchronised.
func (l Leap) Announcing() bool { return l == LeapAddSecond || l == LeapDeleteSecond }

// LeapPlausible says whether a leap second could be announced at this
// moment.
//
// A leap second is inserted or removed only at the end of a UTC month,
// and the IERS uses the end of June and December first, the end of March
// and September only if it must (Bulletin C). So an announcement in the
// closing window of one of those four months is the real thing, and one
// in the middle of August is either a fault or somebody's work -- which
// matters because the announcement makes every client that hears it plan
// to move its clock.
//
// The window is the caller's, because implementations differ: RFC 5905
// sets the indicator during the last day, and some servers announce from
// the start of the month.
func LeapPlausible(now time.Time, window time.Duration) bool {
	if window <= 0 {
		window = 24 * time.Hour
	}
	u := now.UTC()
	switch u.Month() {
	case time.March, time.June, time.September, time.December:
	default:
		return false
	}
	// The end of the month, as an instant: the first day of the next
	// month at midnight UTC.
	end := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return !u.Before(end.Add(-window))
}

// TimestampsConsistent reads the four timestamps of a server's answer
// against each other and returns why they are not a measurement, or the
// empty string when they are.
//
// This is deliberately a check between the packet's own fields and not
// against the receiving clock: a relay whose own clock is wrong would
// otherwise refuse every correct answer, which is the failure mode that
// makes a check like this get turned off. What it catches is an answer
// whose numbers cannot describe an exchange -- a zero transmit
// timestamp, a server that says it answered before it received, a
// reference epoch after the answer was made -- each of which produces an
// offset a client will act on and none of which a client checks.
//
// It is not applied to an interleaved answer, where the transmit
// timestamp is the server's *previous* one on purpose and is therefore
// older than this request's arrival -- the caller knows which kind of
// answer it matched, and this cannot.
func (p *Packet) TimestampsConsistent() string {
	if p.Mode != ModeServer && p.Mode != ModeSymPassive && p.Mode != ModeSymActive {
		return ""
	}
	switch {
	case p.Transmit.IsZero():
		return "the transmit timestamp is zero, so the answer says nothing about when it was sent"
	case p.Receive.IsZero():
		return "the receive timestamp is zero, so the answer says nothing about when the request arrived"
	case p.Receive.Sub(p.Transmit) > 0:
		// The server's own processing time, backwards: it claims to
		// have sent the answer before the request reached it. Read
		// modularly, so an exchange across the end of an era is the
		// small number it is.
		return "the answer was transmitted before the request was received"
	case !p.Reference.IsZero() && p.Reference.Sub(p.Receive) > 0:
		return "the last synchronisation is later than the request's arrival"
	}
	return ""
}

// RefIDSane reads the reference identifier against the stratum that says
// how to read it, and returns why it is not one, or the empty string.
//
// The field is the most often misread in the header, and a wrong value
// in it is what a server looks like when it is not the server it claims
// to be: a stratum-1 answer whose identifier is not a reference clock's
// name is not from a reference clock, and a stratum-2-or-worse answer
// with no identifier at all is a server saying it synchronises to
// nothing while claiming a place in the tree.
//
// At stratum 2 and above the field may be four octets of a hash of an
// IPv6 address rather than an IPv4 address, so only the all-zero value
// is called wrong -- anything else could be a digest, and refusing a
// digest for looking like a multicast address would refuse a correct
// server.
func (p *Packet) RefIDSane() string {
	switch p.Stratum {
	case 0:
		return ""
	case 1:
		if printableID(p.ReferenceID) == "" {
			return "a stratum 1 answer whose reference identifier is not a reference clock's name"
		}
	default:
		if p.ReferenceID == [4]byte{} {
			return fmt.Sprintf("a stratum %d answer whose reference identifier is unset, so it names no upstream", p.Stratum)
		}
	}
	return ""
}

// RefIDText is the identifier as a policy compares it: the four-character
// name at stratum 0 and 1, and the dotted quad at stratum 2 and above.
// It is also the identity a change of source is measured against, which
// is why it is one string rather than a formatted sentence.
func (p *Packet) RefIDText() string {
	if p.Stratum <= 1 {
		return printableID(p.ReferenceID)
	}
	return fmt.Sprintf("%d.%d.%d.%d", p.ReferenceID[0], p.ReferenceID[1], p.ReferenceID[2], p.ReferenceID[3])
}
