// Package ntp reads and writes the Network Time Protocol: the packet of
// RFC 5905, the extension fields of RFC 7822, the symmetric
// authentication of RFC 8573, and enough of NTS (RFC 8915) to tell a
// protected packet from a plain one without pretending to have verified
// it.
//
// It exists because a relay that forwards time has to read what it
// forwards. A time packet is small, has no session and carries no
// identity, and every field in it is a number a device will act on: a
// stratum, a leap indicator, a root dispersion, four timestamps. A relay
// that passed those bytes through unread would be forwarding a decision
// it never made -- and unlike a mail relay or a broker front end, the
// thing behind it will not merely believe something false, it will step
// its clock to it.
//
// Two rules run through the package. Nothing is assumed about a packet's
// length: 48 octets is the header, not the packet, and a packet with
// extension fields, a MAC or both is the normal case rather than the
// exception. And nothing is guessed: where the wire form is ambiguous --
// which it is, between an extension field and a MAC (RFC 7822) -- the
// ambiguity is reported rather than resolved silently, because the
// device on the other side may resolve it the other way.
package ntp

import "time"

// The NTP era begins in 1900, seventy years before the Unix epoch.
const eraOffset = 2208988800

// eraSeconds is 2^32 seconds: the length of an NTP era, after which the
// 32-bit seconds field wraps. The first era ends in 2036.
const eraSeconds = 1 << 32

// Timestamp is an NTP 64-bit timestamp: seconds since 1900 in the high
// 32 bits, a binary fraction of a second in the low 32.
type Timestamp uint64

// TimestampOf converts a Go time to an NTP timestamp. The conversion is
// modulo the era, which is what the wire format is: an NTP timestamp
// does not say which era it is in, and pretending otherwise is how an
// implementation breaks in 2036.
func TimestampOf(t time.Time) Timestamp {
	if t.IsZero() {
		return 0
	}
	secs := t.Unix() + eraOffset
	// The multiplication is done in 64 bits and then shifted, so a
	// nanosecond value near a second does not round up into the next
	// one.
	frac := (uint64(t.Nanosecond()) << 32) / 1e9         //nolint:gosec // Nanosecond is 0..999999999
	return Timestamp(uint64(secs)<<32 | frac&0xFFFFFFFF) //nolint:gosec // modular by definition
}

// IsZero reports the timestamp every field starts as, which in NTP means
// "not set": an origin timestamp of zero is a packet that is not
// answering anything.
func (t Timestamp) IsZero() bool { return t == 0 }

// Seconds and Fraction are the two halves of the wire form.
func (t Timestamp) Seconds() uint32  { return uint32(t >> 32) } //nolint:gosec // the high half
func (t Timestamp) Fraction() uint32 { return uint32(t) }       //nolint:gosec // the low half

// Time converts to a Go time, choosing the era that puts the result
// nearest near. A timestamp carries no era, so the only way to place one
// is against a time already known to be close -- the receiving clock --
// and saying that plainly is better than assuming era zero and being
// wrong for eighty years at a time.
func (t Timestamp) Time(near time.Time) time.Time {
	if t == 0 {
		return time.Time{}
	}
	secs := int64(t.Seconds())
	nanos := (int64(t.Fraction()) * 1e9) >> 32
	// Walk the era so the result is within half an era of near.
	base := near.Unix() + eraOffset
	era := (base - secs + eraSeconds/2) / eraSeconds
	secs += era * eraSeconds
	return time.Unix(secs-eraOffset, nanos).UTC()
}

// Sub is the difference between two timestamps, as the protocol defines
// it: the subtraction is modular and the result is signed, so a
// difference that spans the end of an era is the small number it really
// is rather than a hundred and thirty-six years.
//
// This is the arithmetic RFC 5905 section 6 describes, and it is why the
// offset calculation still works across 2036 without knowing the era.
func (t Timestamp) Sub(u Timestamp) time.Duration {
	d := int64(t - u) //nolint:gosec // the modular difference is the point
	secs := d >> 32
	frac := d & 0xFFFFFFFF
	return time.Duration(secs)*time.Second + time.Duration((frac*1e9)>>32)
}

// Short is the 32-bit fixed point of the root delay and root dispersion
// fields: sixteen bits of seconds, sixteen of fraction.
type Short uint32

// ShortOf converts a duration, saturating rather than wrapping: a delay
// this format cannot hold is the largest it can, because a wrapped root
// dispersion reads as an excellent clock.
func ShortOf(d time.Duration) Short {
	if d <= 0 {
		return 0
	}
	v := (int64(d) << 16) / int64(time.Second)
	if v > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return Short(v) //nolint:gosec // bounded above
}

// Duration is the value as a duration.
func (s Short) Duration() time.Duration {
	return time.Duration((int64(s) * int64(time.Second)) >> 16)
}
