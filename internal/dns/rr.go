package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
)

// Record types and flags used by the validator.
const (
	TypeDNAME      = 39
	TypeSRV        = 33
	TypeDS         = 43
	TypeRRSIG      = 46
	TypeNSEC       = 47
	TypeDNSKEY     = 48
	TypeNSEC3      = 50
	TypeNSEC3PARAM = 51

	flagAD = 1 << 5
	flagCD = 1 << 4
	// ednsDO is the DNSSEC OK bit in the OPT TTL field.
	ednsDO = 1 << 15
)

// RR is one resource record with its rdata in uncompressed wire form.
type RR struct {
	Name  string // lower case, no trailing dot; "" is the root
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Message is a parsed message.
type Message struct {
	Header     Header
	Question   Question
	QEnd       int
	Answer     []RR
	Authority  []RR
	Additional []RR
}

var errMalformed = errors.New("dns: malformed message")

// ParseMessage parses every section. Names inside rdata are decompressed
// so records can be compared and signed as in RFC 4034.
func ParseMessage(b []byte) (*Message, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	m := &Message{Header: h}
	if h.QDCount != 1 {
		return nil, errMalformed
	}
	q, qEnd, err := ParseQuestion(b)
	if err != nil {
		return nil, err
	}
	m.Question, m.QEnd = q, qEnd
	off := qEnd
	read := func(n uint16) ([]RR, error) {
		out := make([]RR, 0, n)
		for i := 0; i < int(n); i++ {
			rr, next, err := parseRR(b, off)
			if err != nil {
				return nil, err
			}
			out = append(out, rr)
			off = next
		}
		return out, nil
	}
	if m.Answer, err = read(h.ANCount); err != nil {
		return nil, err
	}
	if m.Authority, err = read(h.NSCount); err != nil {
		return nil, err
	}
	if m.Additional, err = read(h.ARCount); err != nil {
		return nil, err
	}
	return m, nil
}

func parseRR(b []byte, off int) (RR, int, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return RR{}, 0, err
	}
	if next+10 > len(b) {
		return RR{}, 0, ErrShort
	}
	rr := RR{Name: name, Type: binary.BigEndian.Uint16(b[next:]), Class: binary.BigEndian.Uint16(b[next+2:]), TTL: binary.BigEndian.Uint32(b[next+4:])}
	rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
	start := next + 10
	if start+rdlen > len(b) {
		return RR{}, 0, ErrShort
	}
	data, err := decompressRData(b, start, rdlen, rr.Type)
	if err != nil {
		return RR{}, 0, err
	}
	rr.Data = data
	return rr, start + rdlen, nil
}

// decompressRData expands compressed names inside rdata for the types
// that may carry them (RFC 3597 lists the compressible well known
// types); other types are copied.
func decompressRData(b []byte, off, rdlen int, typ uint16) ([]byte, error) {
	end := off + rdlen
	switch typ {
	case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
		return nameAt(b, off, end, 0, false)
	case TypeMX:
		return nameAt(b, off, end, 2, false)
	case TypeSRV:
		return nameAt(b, off, end, 6, false)
	case TypeSOA:
		mname, n1, err := readNameCase(b, off, false)
		if err != nil {
			return nil, err
		}
		rname, n2, err := readNameCase(b, n1, false)
		if err != nil {
			return nil, err
		}
		if n2+20 != end {
			return nil, errMalformed
		}
		p1, _ := packNameCase(mname)
		p2, _ := packNameCase(rname)
		out := append(append(p1, p2...), b[n2:end]...)
		return out, nil
	case TypeRRSIG:
		// Signer names keep their case (RFC 6840, section 5.1).
		if off+18 > end {
			return nil, errMalformed
		}
		signer, n, err := readNameCase(b, off+18, true)
		if err != nil {
			return nil, err
		}
		p, _ := packNameCase(signer)
		out := append(append(append([]byte{}, b[off:off+18]...), p...), b[n:end]...)
		return out, nil
	case TypeNSEC:
		nextName, n, err := readNameCase(b, off, true)
		if err != nil {
			return nil, err
		}
		p, _ := packNameCase(nextName)
		return append(p, b[n:end]...), nil
	default:
		return append([]byte(nil), b[off:end]...), nil
	}
}

// nameAt copies prefix bytes then one name from rdata.
func nameAt(b []byte, off, end, prefix int, keepCase bool) ([]byte, error) {
	if off+prefix > end {
		return nil, errMalformed
	}
	name, n, err := readNameCase(b, off+prefix, keepCase)
	if err != nil {
		return nil, err
	}
	if n != end {
		return nil, errMalformed
	}
	p, _ := packNameCase(name)
	return append(append([]byte{}, b[off:off+prefix]...), p...), nil
}

// readNameCase is readName with optional case preservation.
func readNameCase(b []byte, off int, keepCase bool) (string, int, error) {
	if !keepCase {
		return readName(b, off)
	}
	var labels []string
	total, end, hops := 0, -1, 0
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
			return strings.Join(labels, "."), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if ptr >= off || ptr < headerLen {
				return "", 0, ErrPointer
			}
			if end < 0 {
				end = off + 2
			}
			if hops++; hops > 16 {
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
			if total += l + 1; total > maxNameLen {
				return "", 0, ErrName
			}
			labels = append(labels, string(b[off:off+l]))
			off += l
		}
	}
}

// packNameCase packs a name as is (labels may contain dots only when
// they came from the wire, which never happens for hostnames).
func packNameCase(name string) ([]byte, error) { return packName(name) }

// canonicalName lowercases a name (owner names are already lower case;
// rdata names of the RFC 4034 section 6.2 types are lowered here).
func canonicalName(name string) string { return strings.ToLower(name) }

// Names of the types above contain only name bytes and small integers;
// lower casing binary counters (SOA serial, MX preference) could change
// bytes 0x41 to 0x5a, so those fields are restored below.
func canonicalRDataExact(typ uint16, data []byte) []byte {
	switch typ {
	case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
		return lowerName(data, 0)
	case TypeMX:
		return append(append([]byte{}, data[:min(2, len(data))]...), lowerName(data, 2)...)
	case TypeSRV:
		return append(append([]byte{}, data[:min(6, len(data))]...), lowerName(data, 6)...)
	case TypeSOA:
		// two names then 20 bytes of counters
		n1 := nameLen(data, 0)
		n2 := nameLen(data, n1)
		out := append([]byte{}, data...)
		copy(out, lowerName(data[:n1+n2], 0))
		return out
	}
	return data
}

// lowerName lowercases the wire name starting at off (labels only).
func lowerName(data []byte, off int) []byte {
	out := append([]byte{}, data[off:]...)
	i := 0
	for i < len(out) {
		l := int(out[i])
		if l == 0 || l > 63 {
			break
		}
		for j := i + 1; j <= i+l && j < len(out); j++ {
			if out[j] >= 'A' && out[j] <= 'Z' {
				out[j] += 'a' - 'A'
			}
		}
		i += 1 + l
	}
	return out
}

// nameLen returns the wire length of an uncompressed name at off.
func nameLen(data []byte, off int) int {
	i := off
	for i < len(data) {
		l := int(data[i])
		i++
		if l == 0 {
			break
		}
		i += l
	}
	return i - off
}

// rrsetKey identifies an RRset.
type rrsetKey struct {
	name string
	typ  uint16
}

// RRset is the records of one name and type plus their signatures.
type RRset struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RRs   []RR
	Sigs  []RR
}

// groupRRsets groups a section into RRsets with their RRSIGs, keeping
// first appearance order.
func groupRRsets(rrs []RR) []*RRset {
	idx := map[rrsetKey]*RRset{}
	var order []*RRset
	get := func(name string, typ, class uint16, ttl uint32) *RRset {
		k := rrsetKey{name, typ}
		set, ok := idx[k]
		if !ok {
			set = &RRset{Name: name, Type: typ, Class: class, TTL: ttl}
			idx[k] = set
			order = append(order, set)
		}
		return set
	}
	for _, rr := range rrs {
		if rr.Type == TypeRRSIG {
			if len(rr.Data) < 18 {
				continue
			}
			covered := binary.BigEndian.Uint16(rr.Data)
			get(rr.Name, covered, rr.Class, rr.TTL).Sigs = append(get(rr.Name, covered, rr.Class, rr.TTL).Sigs, rr)
			continue
		}
		if rr.Type == TypeOPT {
			continue
		}
		set := get(rr.Name, rr.Type, rr.Class, rr.TTL)
		set.RRs = append(set.RRs, rr)
		if rr.TTL < set.TTL {
			set.TTL = rr.TTL
		}
	}
	return order
}

// sortedCanonical returns the RRs' canonical rdata in RFC 4034 6.3
// order, deduplicated.
func sortedCanonical(rrs []RR) [][]byte {
	out := make([][]byte, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, canonicalRDataExact(rr.Type, rr.Data))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	dedup := out[:0]
	for i, d := range out {
		if i > 0 && bytes.Equal(d, out[i-1]) {
			continue
		}
		dedup = append(dedup, d)
	}
	return dedup
}

// Pack serialises a message without compression.
func (m *Message) Pack() []byte {
	out := make([]byte, headerLen, 512)
	binary.BigEndian.PutUint16(out, m.Header.ID)
	binary.BigEndian.PutUint16(out[2:], m.Header.Flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	binary.BigEndian.PutUint16(out[6:], uint16(len(m.Answer)))      //nolint:gosec // bounded by the message
	binary.BigEndian.PutUint16(out[8:], uint16(len(m.Authority)))   //nolint:gosec // bounded by the message
	binary.BigEndian.PutUint16(out[10:], uint16(len(m.Additional))) //nolint:gosec // bounded by the message
	qn, _ := packName(m.Question.Name)
	out = append(out, qn...)
	out = binary.BigEndian.AppendUint16(out, m.Question.Type)
	out = binary.BigEndian.AppendUint16(out, m.Question.Class)
	for _, sec := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for _, rr := range sec {
			out = appendRR(out, rr)
		}
	}
	return out
}

func appendRR(out []byte, rr RR) []byte {
	n, _ := packName(rr.Name)
	out = append(out, n...)
	out = binary.BigEndian.AppendUint16(out, rr.Type)
	out = binary.BigEndian.AppendUint16(out, rr.Class)
	out = binary.BigEndian.AppendUint32(out, rr.TTL)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rr.Data))) //nolint:gosec // rdata is bounded by the message
	return append(out, rr.Data...)
}

// parentName returns the name one label up ("" for the root).
func parentName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// labelCount counts labels ("" has none).
func labelCount(name string) int {
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}

// isSubdomain reports whether name is child or equal to zone.
func isSubdomain(name, zone string) bool {
	return zone == "" || name == zone || strings.HasSuffix(name, "."+zone)
}

// canonicalLess orders names as RFC 4034 section 6.1: by label from the
// right, labels compared as lowercase octet strings.
func canonicalLess(a, b string) bool { return canonicalCompare(a, b) < 0 }

func canonicalCompare(a, b string) int {
	la, lb := labelsOf(a), labelsOf(b)
	for i := 0; i < len(la) && i < len(lb); i++ {
		x, y := la[len(la)-1-i], lb[len(lb)-1-i]
		if c := bytes.Compare([]byte(strings.ToLower(x)), []byte(strings.ToLower(y))); c != 0 {
			return c
		}
	}
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	}
	return 0
}

func labelsOf(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}
