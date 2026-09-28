package opcua

import (
	"encoding/binary"
	"math"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
)

// The message builder the tests speak OPC UA with.
//
// It exists because the kind reads and does not write: a test that hand-wrote
// octets would be a test nobody could change, and one that pulled in a third-party
// stack would be testing that stack's agreement with this parser rather than the
// relay. Every message here is built the way IEC 62541-6 says, and anything the
// relay refuses is refused because of what the message says rather than because the
// test got the encoding wrong.
type builder struct{ b []byte }

func build() *builder { return &builder{} }

func (w *builder) byte(v byte) *builder    { w.b = append(w.b, v); return w }
func (w *builder) bool(v bool) *builder    { return w.byte(map[bool]byte{true: 1, false: 0}[v]) }
func (w *builder) bytes(v []byte) *builder { w.b = append(w.b, v...); return w }

func (w *builder) u16(v uint16) *builder {
	w.b = binary.LittleEndian.AppendUint16(w.b, v)
	return w
}

func (w *builder) u32(v uint32) *builder {
	w.b = binary.LittleEndian.AppendUint32(w.b, v)
	return w
}

func (w *builder) i32(v int32) *builder { return w.u32(uint32(v)) }

func (w *builder) u64(v uint64) *builder {
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
	return w
}

func (w *builder) i64(v int64) *builder   { return w.u64(uint64(v)) }
func (w *builder) f64(v float64) *builder { return w.u64(math.Float64bits(v)) }
func (w *builder) str(v string) *builder  { return w.i32(int32(len(v))).bytes([]byte(v)) }
func (w *builder) null() *builder         { return w.i32(-1) }
func (w *builder) bstr(v []byte) *builder { return w.i32(int32(len(v))).bytes(v) }
func (w *builder) array(n int) *builder   { return w.i32(int32(n)) }

func (w *builder) localized(v string) *builder {
	if v == "" {
		return w.byte(0)
	}
	return w.byte(0x02).str(v)
}

// node writes a node identifier in the Numeric encoding, which can express any
// namespace and any identifier.
func (w *builder) node(ns uint16, id uint32) *builder {
	return w.byte(0x02).u16(ns).u32(id)
}

// snode writes one with a string identifier, which is what a vendor address space
// uses and what a configuration file names.
func (w *builder) snode(ns uint16, id string) *builder {
	return w.byte(0x03).u16(ns).str(id)
}

func (w *builder) nullNode() *builder { return w.byte(0x00).byte(0) }
func (w *builder) emptyExt() *builder { return w.nullNode().byte(0x00) }
func (w *builder) noDiag() *builder   { return w.byte(0) }

// chunk frames the accumulated octets as one UA TCP message.
func (w *builder) chunk(t wire.MessageType, ct wire.ChunkType) []byte {
	out := make([]byte, wire.HeaderLen+len(w.b))
	copy(out, t[:])
	out[3] = byte(ct)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[wire.HeaderLen:], w.b)
	return out
}

// hello builds a Hello proposing the sizes a real client proposes.
func hello(endpoint string) []byte {
	return build().u32(0).u32(65536).u32(65536).u32(16777216).u32(5).
		str(endpoint).chunk(wire.Hello, wire.Final)
}

// helloSized builds one proposing a receive buffer of n.
func helloSized(endpoint string, n uint32) []byte {
	return build().u32(0).u32(n).u32(65536).u32(0).u32(0).
		str(endpoint).chunk(wire.Hello, wire.Final)
}

// ack builds the Acknowledge a server answers a Hello with.
func ack() []byte {
	return build().u32(0).u32(65536).u32(65536).u32(16777216).u32(5).
		chunk(wire.Acknowledge, wire.Final)
}

// openChannel builds an OpenSecureChannel naming a policy and a mode.
func openChannel(pol wire.SecurityPolicy, mode wire.MessageSecurityMode, lifetime uint32) []byte {
	body := build().
		u32(0).           // no channel yet
		str(string(pol)). // the security policy
		null().           // no sender certificate
		null().           // no receiver thumbprint
		u32(1).u32(1)     // the sequence header
	body.bytes(call(wire.SvcOpenChannel, 1, build().
		u32(0).                         // the client protocol version
		u32(uint32(wire.ChannelIssue)). // issue rather than renew
		u32(uint32(mode)).
		null(). // no nonce
		u32(lifetime)))
	return body.chunk(wire.OpenSecureChannel, wire.Final)
}

// call builds a service call body: the TypeId, the request header and the service's
// own fields.
func call(svc wire.Service, handle uint32, body *builder) []byte {
	w := build().node(0, uint32(svc)).
		nullNode().                       // the authentication token
		i64(wire.ToFileTime(time.Now())). // the timestamp
		u32(handle).
		u32(0). // return diagnostics
		null(). // no audit entry
		u32(0). // no timeout hint
		emptyExt()
	if body != nil {
		w.bytes(body.b)
	}
	return w.b
}

// msg frames a service call as a MSG chunk on a channel.
func msg(channel, token, sequence, request uint32, body []byte) []byte {
	return build().u32(channel).u32(token).u32(sequence).u32(request).
		bytes(body).chunk(wire.Message, wire.Final)
}

// The service bodies the tests send.

func readBody(nodes ...[2]any) *builder {
	w := build().f64(0).u32(0).array(len(nodes))
	for _, n := range nodes {
		writeNode(w, n[0])
		w.u32(uint32(n[1].(wire.Attribute))).null().u16(0).null()
	}
	return w
}

func writeBody(nodes ...[3]any) *builder {
	w := build().array(len(nodes))
	for _, n := range nodes {
		writeNode(w, n[0])
		w.u32(uint32(n[1].(wire.Attribute))).null()
		// A DataValue carrying one Double, which is what a setpoint is.
		w.byte(0x01).byte(11).f64(n[2].(float64))
	}
	return w
}

func callBody(object, method any, args int) *builder {
	w := build().array(1)
	writeNode(w, object)
	writeNode(w, method)
	w.array(args)
	for i := 0; i < args; i++ {
		w.byte(11).f64(float64(i))
	}
	return w
}

func browseBody(nodes ...any) *builder {
	w := build().nullNode().i64(0).u32(0).u32(0).array(len(nodes))
	for _, n := range nodes {
		writeNode(w, n)
		w.u32(0)      // forward
		w.nullNode()  // any reference type
		w.bool(true). // subtypes
				u32(0).u32(63)
	}
	return w
}

func subscriptionBody(intervalMs float64) *builder {
	return build().f64(intervalMs).u32(1200).u32(20).u32(0).bool(true).byte(0)
}

func monitoredBody(sampling float64, nodes ...any) *builder {
	w := build().u32(1).u32(0).array(len(nodes))
	for _, n := range nodes {
		writeNode(w, n)
		w.u32(uint32(wire.AttrValue)).null().u16(0).null()
		w.u32(2).u32(1).f64(sampling).emptyExt().u32(10).bool(true)
	}
	return w
}

func createSessionBody(appURI, sessionName string, cert []byte) *builder {
	w := build().str(appURI).str("urn:test:product").localized("test client").
		u32(1).       // a client
		null().null() // no gateway, no discovery profile
	w.array(0). // no discovery urls
			null(). // no server uri
			str("opc.tcp://127.0.0.1:4840").
			str(sessionName)
	w.bstr(make([]byte, 32))
	if cert == nil {
		w.null()
	} else {
		w.bstr(cert)
	}
	return w.f64(600000).u32(0)
}

func activateBody(kind wire.TokenKind, user, password, algorithm string) *builder {
	w := build().null().null().array(0).array(0)
	w.node(0, uint32(kind)).byte(0x01)
	token := build().str("policy")
	switch kind {
	case wire.TokenUserName:
		token.str(user)
		if password == "" {
			token.null()
		} else {
			token.bstr([]byte(password))
		}
		if algorithm == "" {
			token.null()
		} else {
			token.str(algorithm)
		}
	case wire.TokenX509:
		token.bstr([]byte{0x30, 0x82})
	case wire.TokenIssued:
		token.bstr([]byte("ey.ey.sig")).null()
	}
	return w.bstr(token.b)
}

// writeNode accepts a node written either as a numeric pair or as a string
// identifier, so a test can say what it means.
func writeNode(w *builder, n any) {
	switch v := n.(type) {
	case [2]uint32:
		w.node(uint16(v[0]), v[1])
	case string:
		id, err := wire.ParseNodeId(v)
		if err != nil {
			panic("a test wrote a node identifier that does not parse: " + v)
		}
		switch id.Kind {
		case wire.String:
			w.snode(id.Namespace, id.Text)
		default:
			w.node(id.Namespace, id.Numeric)
		}
	default:
		panic("a test wrote a node that is neither a pair nor an identifier")
	}
}

// n is shorthand for a numeric node in a namespace.
func n(ns, id uint32) [2]uint32 { return [2]uint32{ns, id} }

// op is shorthand for a read's node and attribute.
func op(node any, a wire.Attribute) [2]any { return [2]any{node, a} }

// wr is shorthand for a write's node, attribute and value.
func wr(node any, a wire.Attribute, v float64) [3]any { return [3]any{node, a, v} }
