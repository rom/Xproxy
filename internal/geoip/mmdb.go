// Package geoip maps client addresses to countries from a MaxMind DB
// (MMDB) file or a CSV prefix table, with no external dependency: the
// reader implements the subset of the MMDB format needed to find the
// country ISO code of an address.
package geoip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
)

const metadataMarker = "\xab\xcd\xefMaxMind.com"

// MMDB is an opened MaxMind DB file held in memory.
type MMDB struct {
	data        []byte // whole file
	nodeCount   uint32
	recordSize  uint32
	ipVersion   uint16
	dbType      string
	buildEpoch  uint64
	treeSize    uint32
	dataSection []byte // after the 16 byte separator
	ipv4Start   uint32 // node where the IPv4 subtree starts in an IPv6 tree
}

// OpenMMDB reads and validates a file.
func OpenMMDB(path string) (*MMDB, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator supplied path
	if err != nil {
		return nil, err
	}
	return ParseMMDB(b)
}

// ParseMMDB parses an in-memory file.
func ParseMMDB(b []byte) (*MMDB, error) {
	i := bytes.LastIndex(b, []byte(metadataMarker))
	if i < 0 {
		return nil, errors.New("mmdb: metadata marker not found")
	}
	metaBytes := b[i+len(metadataMarker):]
	d := &decoder{data: metaBytes}
	metaAny, _, err := d.decode(0, 0)
	if err != nil {
		return nil, fmt.Errorf("mmdb: metadata: %w", err)
	}
	meta, ok := metaAny.(map[string]any)
	if !ok {
		return nil, errors.New("mmdb: metadata is not a map")
	}
	m := &MMDB{data: b}
	m.nodeCount = uint32(toUint(meta["node_count"]))   //nolint:gosec // validated below
	m.recordSize = uint32(toUint(meta["record_size"])) //nolint:gosec // validated below
	m.ipVersion = uint16(toUint(meta["ip_version"]))   //nolint:gosec // validated below
	m.dbType, _ = meta["database_type"].(string)
	m.buildEpoch = toUint(meta["build_epoch"])
	switch m.recordSize {
	case 24, 28, 32:
	default:
		return nil, fmt.Errorf("mmdb: unsupported record size %d", m.recordSize)
	}
	if m.ipVersion != 4 && m.ipVersion != 6 {
		return nil, fmt.Errorf("mmdb: unsupported ip version %d", m.ipVersion)
	}
	if m.nodeCount == 0 || uint64(m.nodeCount)*uint64(m.recordSize)/4 > uint64(len(b)) {
		return nil, errors.New("mmdb: node count out of range")
	}
	m.treeSize = m.nodeCount * m.recordSize / 4 // two records of recordSize bits per node
	if int(m.treeSize)+16 > i {
		return nil, errors.New("mmdb: search tree exceeds file")
	}
	m.dataSection = b[m.treeSize+16 : i]
	if m.ipVersion == 6 {
		// IPv4 addresses live under ::/96: walk 96 zero bits once.
		node := uint32(0)
		for i := 0; i < 96 && node < m.nodeCount; i++ {
			node = m.record(node, 0)
		}
		m.ipv4Start = node
	}
	return m, nil
}

// Type returns the database_type from the metadata.
func (m *MMDB) Type() string { return m.dbType }

// BuildEpoch returns the build time from the metadata.
func (m *MMDB) BuildEpoch() uint64 { return m.buildEpoch }

// record reads the left (0) or right (1) record of a node.
func (m *MMDB) record(node uint32, bit int) uint32 {
	switch m.recordSize {
	case 24:
		off := node*6 + uint32(bit)*3 //nolint:gosec // bit is 0 or 1
		return uint32(m.data[off])<<16 | uint32(m.data[off+1])<<8 | uint32(m.data[off+2])
	case 28:
		off := node * 7
		mid := m.data[off+3]
		if bit == 0 {
			return uint32(mid>>4)<<24 | uint32(m.data[off])<<16 | uint32(m.data[off+1])<<8 | uint32(m.data[off+2])
		}
		return uint32(mid&0x0f)<<24 | uint32(m.data[off+4])<<16 | uint32(m.data[off+5])<<8 | uint32(m.data[off+6])
	default:
		off := node*8 + uint32(bit)*4 //nolint:gosec // bit is 0 or 1
		return binary.BigEndian.Uint32(m.data[off : off+4])
	}
}

// Lookup returns the decoded record for an address, or nil when the
// address is not in the database.
func (m *MMDB) Lookup(addr netip.Addr) (map[string]any, error) {
	addr = addr.Unmap()
	var bits []byte
	node := uint32(0)
	if addr.Is4() {
		a := addr.As4()
		bits = a[:]
		if m.ipVersion == 6 {
			node = m.ipv4Start
		}
	} else {
		if m.ipVersion == 4 {
			return nil, nil
		}
		a := addr.As16()
		bits = a[:]
	}
	for _, b := range bits {
		for shift := 7; shift >= 0; shift-- {
			if node >= m.nodeCount {
				break
			}
			node = m.record(node, int(b>>shift)&1)
		}
	}
	switch {
	case node == m.nodeCount:
		return nil, nil
	case node < m.nodeCount:
		return nil, errors.New("mmdb: tree walk ended on a node")
	}
	off := node - m.nodeCount - 16
	if uint64(off) >= uint64(len(m.dataSection)) {
		return nil, errors.New("mmdb: data pointer out of range")
	}
	d := &decoder{data: m.dataSection}
	v, _, err := d.decode(int(off), 0)
	if err != nil {
		return nil, err
	}
	rec, _ := v.(map[string]any)
	return rec, nil
}

// Country returns the ISO code of the country (falling back to the
// registered country) for an address, or "" when unknown.
func (m *MMDB) Country(addr netip.Addr) string {
	rec, err := m.Lookup(addr)
	if err != nil || rec == nil {
		return ""
	}
	for _, key := range []string{"country", "registered_country"} {
		if c, ok := rec[key].(map[string]any); ok {
			if code, ok := c["iso_code"].(string); ok && code != "" {
				return code
			}
		}
	}
	return ""
}

func toUint(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case uint16:
		return uint64(x)
	case int32:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case float64:
		if x < 0 || x > math.MaxUint32 {
			return 0
		}
		return uint64(x)
	}
	return 0
}

// decoder reads the MMDB data format.
type decoder struct {
	data []byte
}

const maxDepth = 64

func (d *decoder) decode(off int, depth int) (any, int, error) {
	if depth > maxDepth {
		return nil, 0, errors.New("mmdb: nesting too deep")
	}
	if off < 0 || off >= len(d.data) {
		return nil, 0, errors.New("mmdb: offset out of range")
	}
	ctrl := d.data[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 0 { // extended type
		if off >= len(d.data) {
			return nil, 0, errors.New("mmdb: truncated")
		}
		typ = 7 + int(d.data[off])
		off++
	}
	if typ == 1 { // pointer
		ss := int(ctrl>>3) & 3
		vvv := int(ctrl & 7)
		var ptr int
		need := ss + 1
		if ss == 3 {
			need = 4
		}
		if off+need > len(d.data) {
			return nil, 0, errors.New("mmdb: truncated pointer")
		}
		switch ss {
		case 0:
			ptr = vvv<<8 | int(d.data[off])
		case 1:
			ptr = (vvv<<16 | int(d.data[off])<<8 | int(d.data[off+1])) + 2048
		case 2:
			ptr = (vvv<<24 | int(d.data[off])<<16 | int(d.data[off+1])<<8 | int(d.data[off+2])) + 526336
		default:
			ptr = int(binary.BigEndian.Uint32(d.data[off : off+4]))
		}
		v, _, err := d.decode(ptr, depth+1)
		return v, off + need, err
	}
	size := int(ctrl & 0x1f)
	switch size {
	case 29:
		if off >= len(d.data) {
			return nil, 0, errors.New("mmdb: truncated size")
		}
		size = 29 + int(d.data[off])
		off++
	case 30:
		if off+2 > len(d.data) {
			return nil, 0, errors.New("mmdb: truncated size")
		}
		size = 285 + int(d.data[off])<<8 + int(d.data[off+1])
		off += 2
	case 31:
		if off+3 > len(d.data) {
			return nil, 0, errors.New("mmdb: truncated size")
		}
		size = 65821 + int(d.data[off])<<16 + int(d.data[off+1])<<8 + int(d.data[off+2])
		off += 3
	}
	switch typ {
	case 2: // utf8 string
		if off+size > len(d.data) {
			return nil, 0, errors.New("mmdb: truncated string")
		}
		return string(d.data[off : off+size]), off + size, nil
	case 3: // double
		if size != 8 || off+8 > len(d.data) {
			return nil, 0, errors.New("mmdb: bad double")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d.data[off : off+8])), off + 8, nil
	case 4: // bytes
		if off+size > len(d.data) {
			return nil, 0, errors.New("mmdb: truncated bytes")
		}
		return append([]byte{}, d.data[off:off+size]...), off + size, nil
	case 5, 6, 9: // uint16, uint32, uint64
		if size > 8 || off+size > len(d.data) {
			return nil, 0, errors.New("mmdb: bad integer")
		}
		var v uint64
		for _, b := range d.data[off : off+size] {
			v = v<<8 | uint64(b)
		}
		return v, off + size, nil
	case 10: // uint128: returned as bytes
		if size > 16 || off+size > len(d.data) {
			return nil, 0, errors.New("mmdb: bad uint128")
		}
		return append([]byte{}, d.data[off:off+size]...), off + size, nil
	case 8: // int32
		if size > 4 || off+size > len(d.data) {
			return nil, 0, errors.New("mmdb: bad int32")
		}
		var v uint32
		for _, b := range d.data[off : off+size] {
			v = v<<8 | uint32(b)
		}
		return int32(v), off + size, nil //nolint:gosec // two's complement by format definition
	case 7: // map
		if size > 1<<16 {
			return nil, 0, errors.New("mmdb: map too large")
		}
		m := make(map[string]any, size)
		for i := 0; i < size; i++ {
			k, next, err := d.decode(off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, 0, errors.New("mmdb: map key is not a string")
			}
			v, next2, err := d.decode(next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			m[ks] = v
			off = next2
		}
		return m, off, nil
	case 11: // array
		if size > 1<<16 {
			return nil, 0, errors.New("mmdb: array too large")
		}
		arr := make([]any, 0, size)
		for i := 0; i < size; i++ {
			v, next, err := d.decode(off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			off = next
		}
		return arr, off, nil
	case 14: // boolean
		return size != 0, off, nil
	case 15: // float
		if size != 4 || off+4 > len(d.data) {
			return nil, 0, errors.New("mmdb: bad float")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(d.data[off : off+4]))), off + 4, nil
	case 12, 13: // data cache container, end marker
		return nil, off, nil
	}
	return nil, 0, fmt.Errorf("mmdb: unknown type %d", typ)
}
