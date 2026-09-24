package dns

import (
	"encoding/binary"
	"net/netip"
)

// An answer screened by what it points at, rather than by what was
// asked.
//
// A block list works on names, and the name is the part an attacker
// chooses last: it is theirs, and when one is blocked they register
// another. The address in the answer is the part they cannot choose
// freely, because it is the address they want the client to talk to.
// Two attacks live entirely in that gap.
//
// DNS rebinding. A name the attacker owns answers with a public address
// while the page loads and with 127.0.0.1 or 10.0.0.5 a second later.
// The browser's same-origin policy keeps treating the two answers as
// one origin, so the page reads whatever is listening on the loopback
// interface of the machine that opened it. Nothing about the name is
// wrong; the second answer is.
//
// The metadata endpoint. Every cloud provider serves instance
// credentials at 169.254.169.254 to any process that can make an HTTP
// request. A name that resolves there turns "fetch this URL for me"
// into "read my credentials", which is how a server-side request
// forgery becomes a key compromise.
//
// Neither is a bad name, so neither is something a name list can
// express. This is the check that says where an answer may point.
type AnswerPolicy struct {
	// Deny are the ranges an answer may not point into.
	Deny []netip.Prefix
	// Allow are carved back out of Deny: the ranges this network really
	// does resolve names into. An address in both is allowed, so an
	// operator writes deny_private once and names their own /16 here
	// instead of enumerating the rest of RFC 6890.
	Allow []netip.Prefix
	// Exempt are the names allowed to point into a denied range
	// whatever their addresses, in the forms the block list takes. A
	// split-horizon zone belongs here.
	Exempt *BlockList
	// Action is what a denied answer becomes: nxdomain (the default),
	// refuse, servfail or strip.
	Action string
}

// The actions of an answer policy, named because they are also metric
// label values and configuration words.
const (
	AnswerNXDomain = "nxdomain"
	AnswerRefuse   = "refuse"
	AnswerServFail = "servfail"
	AnswerStrip    = "strip"
)

// PrivateRanges are the ranges deny_private stands for: everything RFC
// 6890 says is not globally reachable, plus the IPv4-mapped range.
//
// The mapped range matters more than it looks. An AAAA record may hold
// ::ffff:127.0.0.1, which a v6 deny list of loopback (::1/128) does not
// cover and which every socket API connects to 127.0.0.1 regardless.
// Screening unmaps first and keeps the range denied as well, so the
// address is caught whichever way it is read.
//
// 6to4 (2002::/16) and Teredo (2001::/32) embed an IPv4 address the
// same way and are deliberately not here: reaching the embedded address
// takes a relay this network probably does not have, and denying them
// by default would refuse names that resolve legitimately. An operator
// whose network does carry them adds the two prefixes to deny.
func PrivateRanges() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),          // this network
		netip.MustParsePrefix("10.0.0.0/8"),         // private
		netip.MustParsePrefix("100.64.0.0/10"),      // carrier NAT
		netip.MustParsePrefix("127.0.0.0/8"),        // loopback
		netip.MustParsePrefix("169.254.0.0/16"),     // link local, and the metadata endpoint
		netip.MustParsePrefix("172.16.0.0/12"),      // private
		netip.MustParsePrefix("192.0.0.0/24"),       // protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),       // documentation
		netip.MustParsePrefix("192.168.0.0/16"),     // private
		netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"),    // documentation
		netip.MustParsePrefix("203.0.113.0/24"),     // documentation
		netip.MustParsePrefix("224.0.0.0/4"),        // multicast
		netip.MustParsePrefix("240.0.0.0/4"),        // reserved
		netip.MustParsePrefix("255.255.255.255/32"), // broadcast
		netip.MustParsePrefix("::/128"),             // unspecified
		netip.MustParsePrefix("::1/128"),            // loopback
		netip.MustParsePrefix("::ffff:0:0/96"),      // IPv4 mapped
		netip.MustParsePrefix("100::/64"),           // discard
		netip.MustParsePrefix("2001:db8::/32"),      // documentation
		netip.MustParsePrefix("fc00::/7"),           // unique local
		netip.MustParsePrefix("fe80::/10"),          // link local
		netip.MustParsePrefix("ff00::/8"),           // multicast
	}
}

// Denies reports whether the policy refuses this address.
func (a *AnswerPolicy) Denies(addr netip.Addr) bool {
	if a == nil || len(a.Deny) == 0 || !addr.IsValid() {
		return false
	}
	// An IPv4 address written as ::ffff:10.0.0.1 is the same address to
	// every socket API, so it is tested as the v4 address it is rather
	// than only as the v6 form it was written in.
	plain := addr.Unmap()
	for _, p := range a.Allow {
		if p.Contains(addr) || p.Contains(plain) {
			return false
		}
	}
	for _, p := range a.Deny {
		if p.Contains(addr) || p.Contains(plain) {
			return true
		}
	}
	return false
}

// Screen returns the first address in the answer section that the
// policy denies.
//
// The answer section only. Glue in the additional section is a
// resolver's business -- a stub client connects to what it was
// answered, not to what the delegation mentioned -- and a delegation
// whose name servers sit on private addresses is ordinary in a split
// network, so screening glue would refuse names that work.
//
// Both the query name and the owner name of the record are checked
// against the exemptions, so a public name that is a CNAME into an
// internal zone is covered by exempting either end.
func (a *AnswerPolicy) Screen(resp []byte, qEnd int, h Header, qname string) (netip.Addr, bool) {
	if a == nil || len(a.Deny) == 0 || qEnd <= 0 {
		return netip.Addr{}, false
	}
	if a.Exempt.Match(qname) {
		return netip.Addr{}, false
	}
	off := qEnd
	for i := 0; i < int(h.ANCount); i++ {
		name, next, err := readName(resp, off)
		if err != nil || next+10 > len(resp) {
			return netip.Addr{}, false
		}
		typ := binary.BigEndian.Uint16(resp[next:])
		class := binary.BigEndian.Uint16(resp[next+2:])
		rdlen := int(binary.BigEndian.Uint16(resp[next+8:]))
		start := next + 10
		if start+rdlen > len(resp) {
			return netip.Addr{}, false
		}
		if addr, ok := rdataAddr(typ, class, resp[start:start+rdlen]); ok && a.Denies(addr) && !a.Exempt.Match(name) {
			return addr, true
		}
		off = start + rdlen
	}
	return netip.Addr{}, false
}

// Strip removes the denied records from the answer section and returns
// the message again, with the offset after its question.
//
// It exists for the name that legitimately has both a public address
// and an internal one -- a split-horizon zone seen from the wrong side,
// a load balancer that publishes its own management address -- where
// refusing the whole answer takes away the address that works. What is
// left may be an answer with no addresses in it, which is a NODATA and
// the correct thing to say: the name exists and has nothing this client
// may be told about.
func (a *AnswerPolicy) Strip(resp []byte, qname string) ([]byte, int, bool) {
	m, err := ParseMessage(resp)
	if err != nil {
		return resp, 0, false
	}
	kept := make([]RR, 0, len(m.Answer))
	removed := false
	for _, rr := range m.Answer {
		if addr, ok := rdataAddr(rr.Type, rr.Class, rr.Data); ok && a.Denies(addr) && !a.Exempt.Match(rr.Name) && !a.Exempt.Match(qname) {
			removed = true
			continue
		}
		kept = append(kept, rr)
	}
	if !removed {
		return resp, 0, false
	}
	// A signature over a set one record has left is a signature that no
	// longer verifies, and a client that checks it would call the
	// answer bogus rather than short. The records this proxy removed
	// are removed with their signatures, which leaves an unsigned
	// answer -- honest about the fact that the proxy, not the zone, is
	// what the client is now trusting.
	m.Answer = dropSignatures(kept, m.Answer)
	m.Header.ANCount = uint16(len(m.Answer)) //nolint:gosec // bounded by the message
	out, ok := m.Pack()
	if !ok {
		return resp, 0, false
	}
	_, qe, err := ParseQuestion(out)
	if err != nil {
		return resp, 0, false
	}
	return out, qe, true
}

// dropSignatures removes the RRSIGs covering a type that lost records.
// A type that lost one of three records is as unverifiable as one that
// lost all of them, so the count decides rather than the presence.
func dropSignatures(kept, before []RR) []RR {
	was := map[uint16]int{}
	for _, rr := range before {
		was[rr.Type]++
	}
	for _, rr := range kept {
		was[rr.Type]--
	}
	short := map[uint16]bool{}
	for typ, n := range was {
		if n > 0 {
			short[typ] = true
		}
	}
	if len(short) == 0 {
		return kept
	}
	out := kept[:0]
	for _, rr := range kept {
		if rr.Type == TypeRRSIG && len(rr.Data) >= 2 && short[binary.BigEndian.Uint16(rr.Data)] {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// rdataAddr reads an address out of an A or AAAA record.
func rdataAddr(typ, class uint16, rdata []byte) (netip.Addr, bool) {
	if class != ClassIN {
		return netip.Addr{}, false
	}
	switch {
	case typ == TypeA && len(rdata) == 4:
		return netip.AddrFrom4([4]byte(rdata)), true
	case typ == TypeAAAA && len(rdata) == 16:
		return netip.AddrFrom16([16]byte(rdata)), true
	}
	return netip.Addr{}, false
}

// act is the configured action with its default filled in.
func (a *AnswerPolicy) act() string {
	if a == nil || a.Action == "" {
		return AnswerNXDomain
	}
	return a.Action
}

// screened is what the answer policy did to one response.
type screened struct {
	resp []byte
	rEnd int
	// addr is the address that tripped the policy.
	addr netip.Addr
	// action is what was done: empty when nothing was.
	action string
}

// screen applies the answer policy. The response it returns is the one
// to send and, for strip, the one to cache; nothing acted when the
// action is empty.
func (s *Server) screen(p *Policy, query []byte, qEnd int, h Header, q Question, resp []byte, rEnd int) screened {
	a := p.Answers
	if a == nil || len(a.Deny) == 0 {
		return screened{resp: resp, rEnd: rEnd}
	}
	addr, bad := a.Screen(resp, rEnd, mustHeader(resp), q.Name)
	if !bad {
		return screened{resp: resp, rEnd: rEnd}
	}
	out := screened{addr: addr, action: a.act()}
	switch out.action {
	case AnswerStrip:
		stripped, e, ok := a.Strip(resp, q.Name)
		if !ok {
			// The answer holds something the policy denies and could not
			// be rebuilt without it. Refusing is the only honest end:
			// passing it on would hand the client the address the policy
			// exists to withhold.
			out.action, out.resp, out.rEnd = AnswerServFail, Reply(query, qEnd, h, RcodeServFail), qEnd
			s.AnswerDenied.Add(1)
			return out
		}
		out.resp, out.rEnd = stripped, e
		s.AnswerStripped.Add(1)
		return out
	case AnswerRefuse:
		out.resp, out.rEnd = Reply(query, qEnd, h, RcodeRefused), qEnd
	case AnswerServFail:
		out.resp, out.rEnd = Reply(query, qEnd, h, RcodeServFail), qEnd
	default:
		out.action = AnswerNXDomain
		out.resp, out.rEnd = Reply(query, qEnd, h, RcodeNXDomain), qEnd
	}
	s.AnswerDenied.Add(1)
	return out
}

// mustHeader reads a header that has already been parsed once.
func mustHeader(b []byte) Header {
	h, _ := ParseHeader(b)
	return h
}

// answerEvent records one screened answer: a counter by reason, a
// security event for the client that asked, and a log line through
// finish. It is a security event rather than a note because a name
// resolving into a denied range is either an attack on this network or a
// configuration that needs an exemption, and both want somebody told.
func (s *Server) answerEvent(client netip.Addr, proto string, q Question, sc screened) {
	if sc.action == AnswerStrip {
		s.refuse("answer_stripped")
	} else {
		s.Refused.Add(1)
		s.refuse("answer_denied")
	}
	if s.hooks.Event != nil {
		s.hooks.Event(client, "dns_answer_denied", proto != "udp", "listener", s.Name,
			"name", q.Name, "type", TypeName(q.Type), "address", sc.addr.String(),
			"action", sc.action, "proto", proto)
	}
}
