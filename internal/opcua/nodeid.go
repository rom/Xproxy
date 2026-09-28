package opcua

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// IDKind is how a NodeId's identifier is encoded, which is also what it can be
// compared and written as.
type IDKind byte

// The encodings of IEC 62541-6 s5.2.2.9.
const (
	// TwoByte is a numeric identifier under 256 in namespace 0.
	TwoByte IDKind = 0x00
	// FourByte is a numeric identifier under 65536 in a namespace under 256.
	FourByte IDKind = 0x01
	// Numeric is a full 32-bit identifier in a 16-bit namespace.
	Numeric IDKind = 0x02
	// String is a textual identifier, which is what most vendor address spaces
	// use and what a configuration file names.
	String IDKind = 0x03
	// Guid is a 16-octet identifier.
	Guid IDKind = 0x04
	// Opaque is a ByteString identifier, used for identifiers a server generates
	// and a client is not meant to interpret. Session authentication tokens are
	// the common case.
	Opaque IDKind = 0x05
)

// The flags above the encoding nibble, from the same clause.
const (
	// flagNamespaceURI says a namespace URI string follows the node id, and that
	// the NamespaceIndex in the id itself is to be ignored.
	flagNamespaceURI = 0x80
	// flagServerIndex says a server index follows, for a node in another server
	// the client reached through this one.
	flagServerIndex = 0x40
	// kindMask is the low six bits, which hold the encoding.
	kindMask = 0x3F
)

func (k IDKind) String() string {
	switch k {
	case TwoByte:
		return "two_byte"
	case FourByte:
		return "four_byte"
	case Numeric:
		return "numeric"
	case String:
		return "string"
	case Guid:
		return "guid"
	case Opaque:
		return "opaque"
	}
	return fmt.Sprintf("kind(%d)", byte(k))
}

// A NodeId names one node in one server's address space: a namespace and an
// identifier within it.
//
// This is the field every service-level rule is about. A Read names node ids, a
// Write names node ids, a Call names the object and the method as node ids, and a
// subscription is a list of them. So the type's job is to be *comparable* — two
// encodings of the same identifier must produce the same key — and to render in a
// form a configuration file can write. That is what Key does, and it is the reason
// the four numeric encodings collapse into one here: a server may send i=2253 as a
// FourByte on Monday and a Numeric on Tuesday, and a rule that distinguished them
// would be a rule that stopped working.
type NodeId struct {
	// Namespace is the namespace index, or zero when NamespaceURI is set.
	Namespace uint16
	// Kind is how the identifier was encoded, kept for a log line rather than
	// for comparison.
	Kind IDKind
	// Numeric holds the identifier for the three numeric encodings.
	Numeric uint32
	// Text holds it for String, the hex rendering for Guid, and the hex
	// rendering for Opaque.
	Text string
	// NamespaceURI is the URI form, when the flag was set. A node id carrying
	// one names a namespace by name rather than by the index in this server's
	// table, which is the portable form and the one an allow-list should
	// prefer — an index is only meaningful against the table it came from.
	NamespaceURI string
	// ServerIndex is non-zero when the node lives in another server.
	ServerIndex uint32
}

// nodeID reads a NodeId. ext says whether the ExpandedNodeId flags are permitted:
// a plain NodeId with them set is a malformed message rather than an expanded one,
// because the two types are distinguished by position and not by content.
func (r *reader) nodeID(ext bool) NodeId {
	mask := r.byte()
	if r.err != nil {
		return NodeId{}
	}
	kind := IDKind(mask & kindMask)
	var n NodeId
	n.Kind = kind
	switch kind {
	case TwoByte:
		n.Numeric = uint32(r.byte())
	case FourByte:
		n.Namespace = uint16(r.byte())
		n.Numeric = uint32(r.uint16())
	case Numeric:
		n.Namespace = r.uint16()
		n.Numeric = r.uint32()
	case String:
		n.Namespace = r.uint16()
		n.Text = r.str()
	case Guid:
		n.Namespace = r.uint16()
		// A Guid is sixteen octets, and its rendering is not a straight hex
		// dump: the first three fields are little-endian on the wire and
		// big-endian in the canonical text form. Getting that wrong would
		// produce an identifier that matches no allow-list anyone wrote from a
		// server's own documentation.
		g := r.bytes(16)
		if g != nil {
			n.Text = guid(g)
		}
	case Opaque:
		n.Namespace = r.uint16()
		n.Text = hex.EncodeToString(r.byteString())
	default:
		r.fail("%w: a node id encoding of %d", ErrEncoding, kind)
		return NodeId{}
	}
	if mask&flagNamespaceURI != 0 {
		if !ext {
			r.fail("%w: a node id with a namespace uri where none is allowed", ErrEncoding)
			return NodeId{}
		}
		n.NamespaceURI = r.str()
	}
	if mask&flagServerIndex != 0 {
		if !ext {
			r.fail("%w: a node id with a server index where none is allowed", ErrEncoding)
			return NodeId{}
		}
		n.ServerIndex = r.uint32()
	}
	if n.Namespace > MaxNamespaces-1 {
		r.fail("%w: namespace %d", ErrTooLong, n.Namespace)
		return NodeId{}
	}
	return n
}

// guid renders the sixteen octets in the canonical text form, honouring the mixed
// endianness of the first three fields.
func guid(g []byte) string {
	var b strings.Builder
	b.Grow(36)
	for _, i := range []int{3, 2, 1, 0} {
		fmt.Fprintf(&b, "%02X", g[i])
	}
	b.WriteByte('-')
	for _, i := range []int{5, 4} {
		fmt.Fprintf(&b, "%02X", g[i])
	}
	b.WriteByte('-')
	for _, i := range []int{7, 6} {
		fmt.Fprintf(&b, "%02X", g[i])
	}
	b.WriteByte('-')
	for _, i := range []int{8, 9} {
		fmt.Fprintf(&b, "%02X", g[i])
	}
	b.WriteByte('-')
	for i := 10; i < 16; i++ {
		fmt.Fprintf(&b, "%02X", g[i])
	}
	return b.String()
}

// Key renders the node id in the form OPC UA's own tooling uses and a
// configuration file writes: "ns=3;i=1001", "ns=0;i=2253", "ns=4;s=Motor/Speed".
//
// Namespace zero is written out rather than elided. The elided form "i=2253" is
// common in documentation and it makes a configuration file ambiguous the moment
// someone adds a rule for another namespace, so the canonical form here always
// names the namespace and Parse accepts both.
func (n NodeId) Key() string {
	ns := "ns=" + strconv.FormatUint(uint64(n.Namespace), 10)
	if n.NamespaceURI != "" {
		ns = "nsu=" + n.NamespaceURI
	}
	var id string
	switch n.Kind {
	case TwoByte, FourByte, Numeric:
		id = "i=" + strconv.FormatUint(uint64(n.Numeric), 10)
	case String:
		id = "s=" + n.Text
	case Guid:
		id = "g=" + n.Text
	case Opaque:
		id = "b=" + n.Text
	default:
		id = "?=" + n.Text
	}
	if n.ServerIndex != 0 {
		return "svr=" + strconv.FormatUint(uint64(n.ServerIndex), 10) + ";" + ns + ";" + id
	}
	return ns + ";" + id
}

func (n NodeId) String() string { return n.Key() }

// Zero says the node id is the null node id, which every service treats as "no
// node". A request naming it where a node is required is a request the server will
// reject, and one carrying it as an authentication token is an unactivated session.
func (n NodeId) Zero() bool {
	return n.Namespace == 0 && n.NamespaceURI == "" && n.Numeric == 0 && n.Text == ""
}

// ParseNodeId reads a node id from the text form, which is what a configuration
// file holds. The namespace may be given as an index or a URI, and may be omitted
// for namespace zero.
func ParseNodeId(s string) (NodeId, error) {
	var n NodeId
	parts := strings.Split(s, ";")
	if len(parts) == 0 {
		return n, fmt.Errorf("%w: an empty node id", ErrEncoding)
	}
	seen := false
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return n, fmt.Errorf("%w: %q is not key=value", ErrEncoding, p)
		}
		switch k {
		case "ns":
			ns, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return n, fmt.Errorf("%w: namespace %q", ErrEncoding, v)
			}
			n.Namespace = uint16(ns)
		case "nsu":
			n.NamespaceURI = v
		case "svr":
			si, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return n, fmt.Errorf("%w: server index %q", ErrEncoding, v)
			}
			n.ServerIndex = uint32(si)
		case "i":
			id, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return n, fmt.Errorf("%w: identifier %q", ErrEncoding, v)
			}
			n.Numeric, n.Kind, seen = uint32(id), Numeric, true
		case "s":
			n.Text, n.Kind, seen = v, String, true
		case "g":
			n.Text, n.Kind, seen = strings.ToUpper(v), Guid, true
		case "b":
			n.Text, n.Kind, seen = strings.ToLower(v), Opaque, true
		default:
			return n, fmt.Errorf("%w: %q is not a node id part", ErrEncoding, k)
		}
	}
	if !seen {
		return n, fmt.Errorf("%w: %q names no identifier", ErrEncoding, s)
	}
	return n, nil
}
