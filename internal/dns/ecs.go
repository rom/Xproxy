package dns

import "encoding/binary"

// ednsECS is the EDNS Client Subnet option code (RFC 7871).
const ednsECS = 8

// The client subnet option, and why it is removed by default.
//
// EDNS Client Subnet lets a resolver tell an authoritative server which
// network the query is really for, so the answer can be the one nearest
// the client. It exists for a recursive resolver talking to a content
// network, and this proxy is neither: it forwards to a resolver that
// will add its own option describing this proxy, which is the correct
// thing for it to describe.
//
// Forwarding a client's option instead breaks the cache. The cache key
// here is the question -- name, type and class -- and nothing else, as
// it is in every forwarder of this shape. An answer tailored to one
// client's subnet is therefore stored for every client of the listener:
// one client asking for a name on behalf of 203.0.113.0/24 decides
// which address the next thousand get. A client that can pick the
// subnet can pick the answer, which is cache poisoning with no spoofing
// and no race in it, and it is also a way to have the proxy ask
// upstream about somebody else's network a query at a time.
//
// So the option is removed on the way out unless an operator says
// forward, and an operator who says it is telling the proxy that its
// clients are one network.
const (
	// ECSStrip removes the client's subnet option from the forwarded
	// query. The default.
	ECSStrip = "strip"
	// ECSForward passes it through unchanged.
	ECSForward = "forward"
)

// HasECS reports whether the message carries a client subnet option.
// It is a scan rather than a parse because it runs on every query and
// the answer is almost always no.
func HasECS(b []byte, qEnd int, h Header) bool {
	found := false
	_ = optWalk(b, qEnd, h, func(code uint16, _ []byte) {
		if code == ednsECS {
			found = true
		}
	})
	return found
}

// optWalk calls fn for every EDNS option in the message's OPT record.
func optWalk(b []byte, qEnd int, h Header, fn func(code uint16, data []byte)) error {
	off := qEnd
	n := int(h.ANCount) + int(h.NSCount) + int(h.ARCount)
	for i := 0; i < n; i++ {
		next, err := skipName(b, off)
		if err != nil {
			return err
		}
		if next+10 > len(b) {
			return ErrShort
		}
		typ := binary.BigEndian.Uint16(b[next:])
		rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
		start := next + 10
		if start+rdlen > len(b) {
			return ErrShort
		}
		if typ == TypeOPT {
			rdata := b[start : start+rdlen]
			for p := 0; p+4 <= len(rdata); {
				code := binary.BigEndian.Uint16(rdata[p:])
				olen := int(binary.BigEndian.Uint16(rdata[p+2:]))
				if p+4+olen > len(rdata) {
					return errMalformed
				}
				fn(code, rdata[p+4:p+4+olen])
				p += 4 + olen
			}
		}
		off = start + rdlen
	}
	return nil
}

// StripECS returns the query without its client subnet option, or the
// query unchanged when it has none or cannot be rebuilt.
//
// It repacks the message rather than cutting the bytes out in place.
// Shortening one record's rdata moves every record after it, and a
// compression pointer in one of those records names an absolute offset:
// editing the bytes would leave pointers aimed a few bytes off the name
// they meant, which is a malformed query the upstream answers FORMERR
// at best. Packing decompresses the names first, so there are no
// pointers left to be wrong.
func StripECS(b []byte) []byte {
	m, err := ParseMessage(b)
	if err != nil {
		return b
	}
	changed := false
	for i, rr := range m.Additional {
		if rr.Type != TypeOPT {
			continue
		}
		rdata, dropped := dropOption(rr.Data, ednsECS)
		if !dropped {
			continue
		}
		m.Additional[i].Data = rdata
		changed = true
	}
	if !changed {
		return b
	}
	out, ok := m.Pack()
	if !ok {
		return b
	}
	return out
}

// dropOption removes every instance of one option code from OPT rdata.
func dropOption(rdata []byte, code uint16) ([]byte, bool) {
	out := make([]byte, 0, len(rdata))
	dropped := false
	for p := 0; p+4 <= len(rdata); {
		c := binary.BigEndian.Uint16(rdata[p:])
		olen := int(binary.BigEndian.Uint16(rdata[p+2:]))
		if p+4+olen > len(rdata) {
			// Trailing bytes that are not an option: the record is
			// malformed, and rebuilding it would change what the client
			// sent into something else. Leave it to the upstream.
			return rdata, false
		}
		if c == code {
			dropped = true
		} else {
			out = append(out, rdata[p:p+4+olen]...)
		}
		p += 4 + olen
	}
	return out, dropped
}
