// Package dns is a forwarding DNS proxy: it answers clients over UDP and
// TCP from a bounded cache, applies a block policy (NXDOMAIN, REFUSED or
// a sinkhole address) and otherwise forwards questions to upstream
// resolvers with fresh transaction ids and source ports, falling back
// to TCP on truncation. Messages are handled as bytes: only the header,
// the question and the resource record framing are parsed.
package dns

import (
	"encoding/binary"
	"errors"
	"github.com/rom/xproxy/internal/netutil"
	"strings"
)

// Well known values.
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeMX    = 15
	TypeTXT   = 16
	// TypeNULL (RFC 1035) exists to carry anything at all and is used
	// by nothing but tunnels, which is why it is named here.
	TypeNULL = 10
	TypeAAAA = 28
	TypeOPT  = 41
	TypeANY  = 255
	ClassIN  = 1

	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5

	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7

	headerLen  = 12
	maxNameLen = 255
	maxUDP     = 512
	// MaxMessage bounds any message handled.
	MaxMessage = 65535
)

var (
	ErrShort   = errors.New("dns: short message")
	ErrName    = errors.New("dns: bad name")
	ErrPointer = errors.New("dns: bad compression pointer")
)

// Header is the fixed part of a message.
type Header struct {
	ID               uint16
	Flags            uint16
	QDCount, ANCount uint16
	NSCount, ARCount uint16
}

// Question is the single question of a query.
type Question struct {
	Name  string // lower case, no trailing dot ("" for the root)
	Type  uint16
	Class uint16
}

// ParseHeader reads the header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < headerLen {
		return Header{}, ErrShort
	}
	return Header{
		ID: binary.BigEndian.Uint16(b), Flags: binary.BigEndian.Uint16(b[2:]),
		QDCount: binary.BigEndian.Uint16(b[4:]), ANCount: binary.BigEndian.Uint16(b[6:]),
		NSCount: binary.BigEndian.Uint16(b[8:]), ARCount: binary.BigEndian.Uint16(b[10:]),
	}, nil
}

// Opcode of the header flags.
func (h Header) Opcode() int { return int(h.Flags>>11) & 0xf }

// Rcode of the header flags.
func (h Header) Rcode() int { return int(h.Flags & 0xf) }

// Truncated reports the TC bit.
func (h Header) Truncated() bool { return h.Flags&flagTC != 0 }

// Response reports the QR bit.
func (h Header) Response() bool { return h.Flags&flagQR != 0 }

// RecursionDesired reports the RD bit.
func (h Header) RecursionDesired() bool { return h.Flags&flagRD != 0 }

// ParseQuestion reads the first question and returns it with the offset
// of the byte after it.
func ParseQuestion(b []byte) (Question, int, error) {
	name, off, err := readName(b, headerLen)
	if err != nil {
		return Question{}, 0, err
	}
	if off+4 > len(b) {
		return Question{}, 0, ErrShort
	}
	return Question{Name: name, Type: binary.BigEndian.Uint16(b[off:]), Class: binary.BigEndian.Uint16(b[off+2:])}, off + 4, nil
}

// readName decodes a possibly compressed name at off and returns it in
// lower case with the offset after the name as it appears at off (not
// after any pointer target).
// labelOK reports a label the proxy can carry as text without changing
// what it means.
//
// A name becomes a string the moment it is parsed, and that string is
// the block list key, the cache key, the name DNSSEC compares and the
// value written to the security log. Joining labels with "." is only
// reversible while no label contains a dot: the wire names
// [www.bank][test] and [www][bank][test] are different names that join
// to the same string, so one would be answered from the other's cache
// entry and would satisfy the other's DNSSEC binding. A byte below
// space has the same problem in a log record, where a newline ends the
// line and lets a client write the next one.
//
// RFC 1035 section 5.1 escapes these in the presentation form instead.
// Refusing them is the smaller change and costs nothing that is used:
// no deployed name needs a dot, a backslash or a control byte inside a
// label, and a query carrying one is answered FORMERR.
func labelOK(l string) bool {
	for i := 0; i < len(l); i++ {
		if c := l[i]; c <= ' ' || c > '~' || c == '.' || c == '\\' {
			return false
		}
	}
	return true
}

func readName(b []byte, off int) (string, int, error) {
	var labels []string
	total := 0
	end := -1
	hops := 0
	for {
		if off >= len(b) {
			return "", 0, ErrShort
		}
		l := int(b[off])
		switch {
		case l == 0:
			off++
			if end < 0 {
				end = off
			}
			return netutil.ASCIILower(strings.Join(labels, ".")), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if ptr >= off || ptr < headerLen {
				return "", 0, ErrPointer // pointers only go backwards, never into the header
			}
			if end < 0 {
				end = off + 2
			}
			hops++
			if hops > 16 {
				return "", 0, ErrPointer
			}
			off = ptr
		case l&0xc0 != 0:
			return "", 0, ErrName
		default:
			off++
			if off+l > len(b) || l > 63 {
				return "", 0, ErrName
			}
			total += l + 1
			if total > maxNameLen {
				return "", 0, ErrName
			}
			lab := string(b[off : off+l])
			if !labelOK(lab) {
				return "", 0, ErrName
			}
			labels = append(labels, lab)
			off += l
		}
	}
}

// skipName returns the offset after a name without decoding it.
func skipName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, ErrShort
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return 0, ErrShort
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, ErrName
		default:
			off += 1 + l
		}
	}
}

// packName encodes a name without compression.
func packName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxNameLen-2 {
		return nil, ErrName
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, ErrName
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// rrWalk calls fn for every resource record after the question with the
// offset of its TTL field, its type and its rdata length; it stops at
// the first framing error.
func rrWalk(b []byte, qEnd int, h Header, fn func(ttlOff int, typ uint16, ttl uint32)) error {
	off := qEnd
	n := int(h.ANCount) + int(h.NSCount) + int(h.ARCount)
	for i := 0; i < n; i++ {
		var err error
		off, err = skipName(b, off)
		if err != nil {
			return err
		}
		if off+10 > len(b) {
			return ErrShort
		}
		typ := binary.BigEndian.Uint16(b[off:])
		ttl := binary.BigEndian.Uint32(b[off+4:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		fn(off+4, typ, ttl)
		off += 10 + rdlen
		if off > len(b) {
			return ErrShort
		}
	}
	return nil
}

// MinTTL returns the smallest TTL of the answer, authority and
// additional records (OPT excluded) and whether any record was seen.
func MinTTL(b []byte, qEnd int, h Header) (uint32, bool) {
	minTTL, seen := uint32(0), false
	_ = rrWalk(b, qEnd, h, func(_ int, typ uint16, ttl uint32) {
		if typ == TypeOPT {
			return
		}
		if !seen || ttl < minTTL {
			minTTL, seen = ttl, true
		}
	})
	return minTTL, seen
}

// AdjustTTL subtracts elapsed seconds from every TTL (floor 0), OPT
// records excluded.
func AdjustTTL(b []byte, qEnd int, h Header, elapsed uint32) {
	_ = rrWalk(b, qEnd, h, func(ttlOff int, typ uint16, ttl uint32) {
		if typ == TypeOPT {
			return
		}
		if ttl > elapsed {
			ttl -= elapsed
		} else {
			ttl = 0
		}
		binary.BigEndian.PutUint32(b[ttlOff:], ttl)
	})
}

// maxEDNSUDP caps the UDP payload size honoured from a client's OPT record
// (RFC 9715's recommended 1232): larger advertised sizes fragment on the
// path and, on a listener reachable by spoofed sources, turn the resolver
// into an amplifier.
const maxEDNSUDP = 1232

// ClampEDNSSize lowers the UDP payload size an OPT record advertises to
// at most maximum, in place. The query this proxy forwards carries the
// client's own OPT record, so without this the client, not the proxy,
// decides how large an answer the upstream may send while the proxy can
// only read one datagram of a fixed size.
func ClampEDNSSize(b []byte, qEnd int, h Header, maximum int) {
	_ = rrWalk(b, qEnd, h, func(ttlOff int, typ uint16, _ uint32) {
		if typ != TypeOPT {
			return
		}
		if int(binary.BigEndian.Uint16(b[ttlOff-2:])) > maximum {
			binary.BigEndian.PutUint16(b[ttlOff-2:], uint16(maximum)) //nolint:gosec // callers pass a small bound
		}
	})
}

// EDNSSize returns the UDP payload size the query advertises in an OPT
// record, capped at maxEDNSUDP, or 512 when it has none.
func EDNSSize(b []byte, qEnd int, h Header) int {
	size := maxUDP
	_ = rrWalk(b, qEnd, h, func(ttlOff int, typ uint16, _ uint32) {
		if typ == TypeOPT {
			if s := int(binary.BigEndian.Uint16(b[ttlOff-2:])); s > size {
				size = s
			}
		}
	})
	if size > maxEDNSUDP {
		size = maxEDNSUDP
	}
	return size
}

// Reply builds a response to query with the given rcode and no records:
// the header (QR, RA, RD copied, AA clear) and the question. A caller
// with no question to echo — the FORMERR paths pass query[:headerLen] —
// gets a question count of zero rather than a message that claims one
// question and carries none, which this package's own parser refuses
// and a downstream stub may drop or retry instead of reading the rcode.
func Reply(query []byte, qEnd int, h Header, rcode int) []byte {
	out := make([]byte, qEnd)
	copy(out, query[:qEnd])
	qd := uint16(0)
	if qEnd > headerLen {
		qd = 1
	}
	flags := flagQR | flagRA | (h.Flags & flagRD) | uint16(h.Opcode()<<11) | uint16(rcode&0xf) //nolint:gosec // bounded
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], qd)
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return out
}

// Truncate returns query's header and question with TC set, for a
// response that does not fit the client's UDP size.
func Truncate(resp []byte, qEnd int) []byte {
	out := make([]byte, qEnd)
	copy(out, resp[:qEnd])
	flags := binary.BigEndian.Uint16(out[2:]) | flagTC
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return out
}

// Sinkhole answers an A or AAAA question with addr (4 or 16 bytes) and
// ttl; other types get an empty NOERROR answer.
func Sinkhole(query []byte, qEnd int, h Header, q Question, addr []byte, ttl uint32) []byte {
	out := Reply(query, qEnd, h, RcodeNoError)
	want := 0
	switch q.Type {
	case TypeA:
		want = 4
	case TypeAAAA:
		want = 16
	}
	if want == 0 || len(addr) != want {
		return out
	}
	binary.BigEndian.PutUint16(out[6:], 1)
	rr := []byte{0xc0, headerLen} // pointer to the question name
	rr = binary.BigEndian.AppendUint16(rr, q.Type)
	rr = binary.BigEndian.AppendUint16(rr, q.Class)
	rr = binary.BigEndian.AppendUint32(rr, ttl)
	rr = binary.BigEndian.AppendUint16(rr, uint16(want)) //nolint:gosec // 4 or 16
	rr = append(rr, addr...)
	return append(out, rr...)
}

// Query builds a standard recursive query (used by tests and probes).
func Query(id uint16, name string, qtype uint16) ([]byte, error) {
	n, err := packName(name)
	if err != nil {
		return nil, err
	}
	out := make([]byte, headerLen, headerLen+len(n)+4)
	binary.BigEndian.PutUint16(out, id)
	binary.BigEndian.PutUint16(out[2:], flagRD)
	binary.BigEndian.PutUint16(out[4:], 1)
	out = append(out, n...)
	out = binary.BigEndian.AppendUint16(out, qtype)
	return binary.BigEndian.AppendUint16(out, ClassIN), nil
}

// SetID overwrites the transaction id.
func SetID(b []byte, id uint16) { binary.BigEndian.PutUint16(b, id) }

// AnswerA builds a NOERROR response to query with one A or AAAA record
// (used by tests and the sinkhole).
func AnswerA(query []byte, qEnd int, h Header, q Question, addr []byte, ttl uint32) []byte {
	return Sinkhole(query, qEnd, h, q, addr, ttl)
}
