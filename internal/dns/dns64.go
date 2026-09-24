package dns

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/netutil"
)

// DNS64, RFC 6147: an AAAA answer for a name that has only an A record,
// so an IPv6-only client can reach an IPv4-only service through a
// translator.
//
// The client asks for AAAA, the name has none, and this resolver asks for
// A instead and answers with the IPv4 address embedded in a prefix
// (RFC 6052) that routes to the translator. Nothing on the client changes;
// it believes it is speaking IPv6 throughout, which is the point.
//
// Two things about it are security decisions rather than protocol.
//
// The first is that a synthesised address is an address this resolver
// invented, so the answer policy has to see the IPv4 address before it is
// embedded and not after. `64:ff9b::7f00:1` is not inside `127.0.0.0/8`
// and no prefix list would catch it, but it is 127.0.0.1 to everything
// past the translator -- so DNS64 without this check would be a way around
// rebinding protection rather than a feature beside it. The A lookup runs
// through the same path as a client's own, which screens it.
//
// The second is that a synthesised answer carries no signatures and never
// claims to: the reply is built fresh from the client's question, so the
// AD bit is clear by construction (RFC 6147 section 5.5). A validating
// client that wants the truth asks for A itself.
type DNS64 struct {
	// Prefix is the translation prefix: a /32, /40, /48, /56, /64 or /96
	// of IPv6, most often the well-known 64:ff9b::/96.
	Prefix netip.Prefix
	// Clients are the networks this applies to; empty is every client.
	// An estate with both IPv6-only and dual-stack networks names the
	// first here, because a dual-stack client handed a synthesised
	// address reaches the service the long way round.
	Clients []netip.Prefix
	// TTL overrides the TTL of a synthesised record; 0 keeps the A
	// record's own, which is what RFC 6147 section 5.1.7 prefers.
	TTL uint32
}

// WellKnownPrefix is the prefix RFC 6052 reserves for translation.
const WellKnownPrefix = "64:ff9b::/96"

// PrefixLengthOK reports whether a DNS64 prefix length is one RFC 6052
// defines. Any other length has no defined place to put the address.
func PrefixLengthOK(bits int) bool {
	switch bits {
	case 32, 40, 48, 56, 64, 96:
		return true
	}
	return false
}

// on reports whether this client's AAAA queries are synthesised.
func (d *DNS64) on(client netip.Addr) bool {
	switch {
	case d == nil || !d.Prefix.IsValid():
		return false
	case len(d.Clients) == 0:
		return true
	}
	return netutil.Contains(d.Clients, client)
}

// Embed places an IPv4 address in the prefix, as RFC 6052 section 2.2
// lays it out: the address follows the prefix, and octet 8 -- the "u"
// octet, which must be zero -- is skipped over rather than written into.
func Embed(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, bool) {
	if !prefix.IsValid() || !PrefixLengthOK(prefix.Bits()) || !v4.Unmap().Is4() {
		return netip.Addr{}, false
	}
	// Masking first means a prefix with bits set past its length cannot
	// smuggle them into the result.
	out := prefix.Masked().Addr().As16()
	b := v4.Unmap().As4()
	pos := prefix.Bits() / 8
	for _, x := range b {
		if pos == 8 {
			pos++
		}
		if pos >= 16 {
			return netip.Addr{}, false
		}
		out[pos] = x
		pos++
	}
	return netip.AddrFrom16(out), true
}

// hasAAAA reports whether a response carries an AAAA record in its answer
// section: the one question DNS64 asks of the first answer.
func hasAAAA(resp []byte, qEnd int, h Header) bool {
	found := false
	_ = rrWalk(resp, qEnd, h, func(_ int, typ uint16, _ uint32) {
		if typ == TypeAAAA {
			found = true
		}
	})
	return found
}

// addressesOf collects the A records of an answer section, with their
// TTLs, in order.
func addressesOf(resp []byte, qEnd int, h Header) []struct {
	Addr netip.Addr
	TTL  uint32
} {
	var out []struct {
		Addr netip.Addr
		TTL  uint32
	}
	answers := int(h.ANCount)
	seen := 0
	_ = rrWalk(resp, qEnd, h, func(ttlOff int, typ uint16, ttl uint32) {
		seen++
		if seen > answers || typ != TypeA {
			return
		}
		class := binary.BigEndian.Uint16(resp[ttlOff-2:])
		if class != ClassIN {
			return
		}
		length := int(binary.BigEndian.Uint16(resp[ttlOff+4:]))
		if length != 4 || ttlOff+6+4 > len(resp) {
			return
		}
		out = append(out, struct {
			Addr netip.Addr
			TTL  uint32
		}{netip.AddrFrom4([4]byte(resp[ttlOff+6 : ttlOff+10])), ttl})
	})
	return out
}

// synthesise builds an AAAA answer for the client's question from an A
// response. deny, when not nil, refuses an address the answer policy
// would not allow -- which is checked on the IPv4 address, before it
// disappears into a prefix no list would recognise.
func (d *DNS64) synthesise(query []byte, qEnd int, h Header, q Question, aResp []byte, aEnd int, aHdr Header, deny func(netip.Addr) bool) ([]byte, int, int) {
	out := Reply(query, qEnd, h, RcodeNoError)
	count := 0
	for _, rec := range addressesOf(aResp, aEnd, aHdr) {
		if deny != nil && deny(rec.Addr) {
			continue
		}
		addr, ok := Embed(d.Prefix, rec.Addr)
		if !ok {
			continue
		}
		ttl := rec.TTL
		if d.TTL > 0 {
			ttl = d.TTL
		}
		b := addr.As16()
		rr := []byte{0xc0, headerLen} // a pointer to the question's name
		rr = binary.BigEndian.AppendUint16(rr, TypeAAAA)
		rr = binary.BigEndian.AppendUint16(rr, q.Class)
		rr = binary.BigEndian.AppendUint32(rr, ttl)
		rr = binary.BigEndian.AppendUint16(rr, 16)
		rr = append(rr, b[:]...)
		out = append(out, rr...)
		count++
		if count >= maxSynthesised {
			break
		}
	}
	binary.BigEndian.PutUint16(out[6:], uint16(count)) //nolint:gosec // bounded by maxSynthesised
	return out, qEnd, count
}

// maxSynthesised bounds the records one synthesised answer carries. An
// upstream that answers an A query with hundreds of addresses would
// otherwise decide the size of this listener's reply.
const maxSynthesised = 32

// dns64 answers an AAAA query that came back without one, by asking for A
// and embedding what it finds. It returns the answer to send and whether
// it synthesised anything.
func (s *Server) dns64(ctx context.Context, p *Policy, query []byte, qEnd int, h Header, q Question,
	client netip.Addr, proto string, now time.Time, resp []byte, rEnd int, stream bool) ([]byte, int, bool) {
	d := p.DNS64
	if d == nil || q.Type != TypeAAAA || q.Class != ClassIN || !d.on(client) {
		return resp, rEnd, false
	}
	rh, err := ParseHeader(resp)
	if err != nil || rh.Rcode() != RcodeNoError || hasAAAA(resp, rEnd, rh) {
		// A name that does not exist stays NXDOMAIN, and a name with an
		// AAAA record of its own is answered with it: synthesising over
		// either would be this resolver inventing a second answer.
		return resp, rEnd, false
	}
	aQuery, qerr := Query(h.ID, q.Name, TypeA)
	if qerr != nil {
		return resp, rEnd, false
	}
	aHdr, herr := ParseHeader(aQuery)
	aQ, aEnd, qerr2 := ParseQuestion(aQuery)
	if herr != nil || qerr2 != nil {
		return resp, rEnd, false
	}
	// The cache first, so a name whose A record is already held costs
	// nothing; then the ordinary lookup path, which validates, screens
	// where the answer points and caches it for the A queries that
	// follow.
	aResp, aRespEnd := s.cache.Get(aQ, h.ID, now)
	if aResp == nil {
		lk := s.ask(ctx, p, aQuery, aQuery, aEnd, aHdr, aQ, client, proto, now, stream)
		if lk.err != nil || lk.bogus || lk.resp == nil {
			return resp, rEnd, false
		}
		aResp, aRespEnd = lk.resp, lk.rEnd
	}
	aRespHdr, aerr := ParseHeader(aResp)
	if aerr != nil || aRespHdr.Rcode() != RcodeNoError {
		return resp, rEnd, false
	}
	var deny func(netip.Addr) bool
	if p.Answers != nil {
		deny = p.Answers.Denies
	}
	out, outEnd, count := d.synthesise(query, qEnd, h, q, aResp, aRespEnd, aRespHdr, deny)
	if count == 0 {
		return resp, rEnd, false
	}
	s.Synthesised.Add(1)
	return out, outEnd, true
}
