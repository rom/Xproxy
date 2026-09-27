package dns

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/deception"
)

// A resolver that is not there.
//
// See internal/deception for why. What is specific to DNS is that the refusal
// this replaces is *itself* information, and the query that drew it is the only
// thing the visitor ever sends.
//
// A name on a threat feed, a name a policy zone names, a domain a client was
// caught tunnelling under: each one is currently answered NXDOMAIN, REFUSED or
// with a sinkhole address. All three tell the other end the same thing -- that
// something here is deciding -- and a tunnel that is told NXDOMAIN switches to
// another channel, which is the channel nobody is watching.
//
// A fabricated answer does not. The name resolves, the client keeps going, and
// every query after the first is collected: the next domain in the rotation, the
// next chunk of the payload, the next name the implant was told to try.
//
// Two things are specific to this protocol and both of them are about not
// becoming a weapon.
//
// **A resolver is an amplifier.** A UDP datagram proves nothing about where it
// came from, so a fabrication that answered a forty-octet question with a
// kilobyte would be a reflector aimed at whoever the source address really
// belongs to. The answers here are small by construction, and a datagram answer
// to a client whose address is not proved is bounded against the question that
// asked for it: past that bound it is truncated, and a real client comes back
// over TCP while a spoofed source cannot.
//
// **A fabricated address is somewhere a visitor then goes.** So the default
// pool is the documentation range of RFC 5737 and RFC 3849, which nothing
// routes: a decoy that answered with an address inside the estate would be
// directing traffic at a real host. An operator who wants the next step
// collected as well points the pool at their own honeypot, deliberately.
//
// And one thing that makes this more than the sinkhole this kind already has: a
// sinkhole answers one address for every name, which is how a sinkhole is
// recognised in one extra lookup. A fabrication answers a *different* address
// per name, stable for the life of the configuration, so the map a visitor draws
// looks like hosting rather than like a list.

// DecoyProfile decides where a fabricated answer points, which on this protocol
// is the whole of the shape: there is no version string to get right and no
// banner to match, because the only thing a resolver discloses about itself is
// the answers it gives.
type DecoyProfile struct {
	// Name is the profile as an operator wrote it, for the status view.
	Name string
	// V4 and V6 are the pools a fabricated A and AAAA answer are drawn from.
	V4, V6 netip.Prefix
}

// The built-in profiles.
var decoyProfiles = map[string]DecoyProfile{
	// The documentation ranges, which nothing routes and nobody hosts in: a
	// fabricated answer cannot send a visitor at a real host, and an operator
	// reading a firewall log recognises the range on sight.
	"documentation": {
		Name: "documentation",
		V4:   netip.MustParsePrefix("192.0.2.0/24"),
		V6:   netip.MustParsePrefix("2001:db8::/32"),
	},
	// The client's own machine, which is where a great deal of malware
	// analysis wants a blocked name to go: the implant connects to itself and
	// fails, having told you which name it wanted.
	"loopback": {
		Name: "loopback",
		V4:   netip.MustParsePrefix("127.0.0.0/8"),
		V6:   netip.MustParsePrefix("::1/128"),
	},
	// The classic sinkhole, reached through the fabrication so that the
	// tripwires and the record still apply. One address for every name, which
	// is a tell -- it is here because an estate whose monitoring already
	// watches for 0.0.0.0 answers should be able to keep that.
	"unroutable": {
		Name: "unroutable",
		V4:   netip.MustParsePrefix("0.0.0.0/32"),
		V6:   netip.MustParsePrefix("::/128"),
	},
}

// DefaultDecoyProfile is the profile a section that names none gets.
const DefaultDecoyProfile = "documentation"

// DecoyProfiles are the shapes a fabricated resolver can have, for validation.
func DecoyProfiles() []string {
	out := make([]string, 0, len(decoyProfiles))
	for name := range decoyProfiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// The query shapes nothing legitimate sends a fabricated resolver. These are
// types rather than names, because on this protocol the escalation is a *type*:
// a zone transfer, a signature set, or the record that exists to carry anything
// at all.
const (
	typeDNSKEY = 48
	typeIXFR   = 251
	typeAXFR   = 252
)

// The names that ask a resolver what it is. None of them is answered -- see
// answer -- and each one raises the tripwire, because a client that asks has no
// use for the answer except to decide what to try next.
var decoyFingerprintNames = []string{
	"version.bind", "version.server", "hostname.bind", "id.server",
	"authors.bind", "trustanchor.unbound",
}

// maxDecoyName is the query name length past which the name is the payload.
// A hostname somebody typed is not 100 octets long; a tunnel's is, every time,
// because that is where the data goes.
const maxDecoyName = 100

// maxDecoyGrowth bounds a fabricated datagram answer against the query that
// asked for it, for a client whose address a cookie has not proved.
//
// Two is not a round number chosen for neatness: a question of forty octets
// answered with an address and a TTL is about sixty, so the bound is loose
// enough never to bite on an honest answer and tight enough that no shape of
// fabrication is worth aiming at somebody else.
const maxDecoyGrowth = 2

// The synthetic address the one fabricated value lives at: the nonce a TXT
// answer is built from, which changes between periods because a tunnel that got
// the same answer twice would know.
const addrTextNonce = 1

// maxDecoyText is the length of a fabricated TXT string. It is short on purpose:
// a TXT answer is the one shape on this protocol that can be made large, and
// large is what an amplifier wants.
const maxDecoyText = 48

// Decoy is the fabricated resolver.
type Decoy struct {
	// whole says the listener is a honeypot: every query is answered here and
	// there is no resolver behind it.
	whole   bool
	profile DecoyProfile
	ttl     uint32
	trip    map[string]bool
	values  *deception.Values
	policy  *deception.Policy
	seed    uint64
}

// DecoyOptions is a fabricated resolver as an operator configured it. It is
// plain values rather than a configuration type because this package resolves
// names and does not read files.
type DecoyOptions struct {
	// Whole makes the listener a honeypot with no resolver behind it.
	Whole bool
	// Profile names a built-in pool; empty takes the default.
	Profile string
	// V4 and V6 replace the profile's pools.
	V4, V6 netip.Prefix
	// TTL is the TTL a fabricated answer carries. Zero takes 300s.
	TTL time.Duration
	// Tripwire are names that raise the tripwire in addition to the built-in
	// set.
	Tripwire []string
	// Clients are the networks the fabrication answers. Empty answers every
	// client, which is what a honeypot wants and what mode answer's validator
	// refuses.
	Clients []netip.Prefix
	// Seed makes the fabricated values reproducible; zero derives one from the
	// listener name.
	Seed uint64
	// Name is the listener's name, for the seed.
	Name string
	// Period is how long one sample lasts. Zero takes the default.
	Period time.Duration
	// MaxClients bounds the record of who has been answered.
	MaxClients int
}

// NewDecoy compiles a fabricated resolver.
func NewDecoy(o DecoyOptions) (*Decoy, error) {
	p, ok := decoyProfiles[o.Profile]
	if !ok {
		if o.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", o.Profile)
		}
		p = decoyProfiles[DefaultDecoyProfile]
	}
	if o.V4.IsValid() {
		if !o.V4.Addr().Is4() {
			return nil, fmt.Errorf("deception.addresses: %s is not IPv4", o.V4)
		}
		p.V4 = o.V4.Masked()
	}
	if o.V6.IsValid() {
		if o.V6.Addr().Is4() || o.V6.Addr().Is4In6() {
			return nil, fmt.Errorf("deception.addresses: %s is not IPv6", o.V6)
		}
		p.V6 = o.V6.Masked()
	}
	d := &Decoy{whole: o.Whole, profile: p, trip: map[string]bool{}}
	ttl := o.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	// Never zero: a TTL of zero is a tell, and it also makes every client ask
	// again for every lookup, which turns the fabrication into the thing under
	// load rather than the thing watching.
	d.ttl = uint32(max(int64(ttl/time.Second), 1)) //nolint:gosec // bounded by the validator
	for _, n := range decoyFingerprintNames {
		d.trip[n] = true
	}
	for i, n := range o.Tripwire {
		norm := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(n, ".")))
		if norm == "" || strings.ContainsAny(norm, " \t\r\n") {
			return nil, fmt.Errorf("deception.tripwire[%d]: %q is not a name", i, n)
		}
		d.trip[norm] = true
	}
	d.seed = o.Seed
	if d.seed == 0 {
		d.seed = deception.SeedFor(o.Name)
	}
	period := o.Period
	if period <= 0 {
		period = deception.DefaultPeriod
	}
	d.values = deception.NewValues(d.seed, period, []deception.Band{
		{Lo: addrTextNonce, Hi: addrTextNonce, Shape: deception.ShapeAnalogue, Min: 0, Max: 65535},
	})
	d.policy = deception.NewPolicy(o.Clients, o.MaxClients)
	return d, nil
}

// Whole says this listener has nothing behind it.
func (d *Decoy) Whole() bool { return d != nil && d.whole }

// Admits says whether this client gets the fabrication.
func (d *Decoy) Admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// Profile names the shape, for the status view.
func (d *Decoy) Profile() string {
	if d == nil {
		return ""
	}
	return d.profile.Name
}

// Policy is the record of who has been answered, for the status view.
func (d *Decoy) Policy() *deception.Policy {
	if d == nil {
		return nil
	}
	return d.policy
}

// SetClockForTest fixes the clock the fabricated values move on.
func (d *Decoy) SetClockForTest(now func() time.Time) { d.values.SetClockForTest(now) }

// Tripped says whether a query asks a fabricated resolver for something nothing
// legitimate asks it for.
func (d *Decoy) Tripped(q Question) bool {
	if d == nil {
		return false
	}
	switch q.Type {
	case TypeANY, typeAXFR, typeIXFR, typeDNSKEY, TypeNULL:
		// The zone transfer, the signature set, and the record type that
		// exists to carry arbitrary octets. None of the three has a use
		// against a forwarding resolver at all, which is what makes them
		// worth a line in the log rather than an answer.
		return true
	}
	if len(q.Name) > maxDecoyName {
		return true
	}
	if q.Class != ClassIN {
		// CH and HS are asked for exactly one reason: the fingerprint names
		// below live in CH, and a client asking in another class is not a
		// client resolving a name.
		return true
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if d.trip[name] {
		return true
	}
	// A configured name covers its subdomains, because a tripwire written for
	// a domain that only matched the apex would be a tripwire a subdomain
	// walks past.
	for i := 0; i < len(name); i++ {
		if name[i] == '.' && d.trip[name[i+1:]] {
			return true
		}
	}
	return false
}

// Answer builds the fabricated reply to one query.
//
// It is never called for a query that was going to reach a resolver: the caller
// reaches here only where a refusal would otherwise be written, or on a listener
// that has no resolver behind it. That is the invariant the whole feature rests
// on, and it is a test rather than a comment.
func (d *Decoy) Answer(query []byte, qEnd int, h Header, q Question, tcp, verified bool) []byte {
	recs := d.records(q)
	out := AnswerLocal(query, qEnd, h, q, recs)
	// Not authoritative: this is a forwarding resolver, and one that claimed
	// authority for somebody else's name would be answering a question nobody
	// asked it. AnswerLocal sets the bit for the records a resolver really does
	// own, so it is cleared here rather than there.
	clearAuthoritative(out)
	if tcp || verified {
		return out
	}
	// A datagram from an address nothing has proved. Past the bound the answer
	// is truncated instead: a client that wanted it comes back over TCP, and a
	// spoofed source cannot.
	if len(out) > maxDecoyGrowth*len(query) {
		return Truncate(out, qEnd)
	}
	return out
}

// records is what the fabrication holds for a question.
//
// Four types are answered and everything else is NODATA -- an empty NOERROR,
// which is the commonest truthful answer on this protocol and the one that stops
// a client retrying. Inventing an MX would mean inventing a mail host to go with
// it, and an NS or SOA would be a claim of authority this is not making.
func (d *Decoy) records(q Question) []LocalRecord {
	if q.Class != ClassIN {
		// The fingerprint names live in CH. They are not answered: a resolver
		// that names itself has handed over the list of what it is vulnerable
		// to, and one that names something else is caught by whoever knows
		// what that version actually answers.
		return nil
	}
	switch q.Type {
	case TypeA:
		if !d.profile.V4.IsValid() {
			return nil
		}
		return []LocalRecord{{Name: q.Name, Type: TypeA, TTL: d.ttl, Addr: d.addrFor(q.Name, d.profile.V4)}}
	case TypeAAAA:
		if !d.profile.V6.IsValid() {
			return nil
		}
		return []LocalRecord{{Name: q.Name, Type: TypeAAAA, TTL: d.ttl, Addr: d.addrFor(q.Name, d.profile.V6)}}
	case TypeTXT:
		// The answer a tunnel is waiting for. It carries nothing -- there is
		// no command in it, because this fabrication does not know what the
		// other end's protocol is and will not guess -- but it is the shape a
		// tunnel accepts, and a tunnel that accepts an answer sends the next
		// chunk.
		return []LocalRecord{{Name: q.Name, Type: TypeTXT, TTL: d.ttl, Text: d.text(q.Name)}}
	case TypePTR:
		return []LocalRecord{{Name: q.Name, Type: TypePTR, TTL: d.ttl, Text: d.ptrFor(q.Name)}}
	}
	return nil
}

// addrFor is the address a name is answered with: stable for the name, and
// different for a different name.
//
// That difference is the point. A sinkhole answers one address for everything,
// so a visitor who looks up two blocked names and gets one address has found the
// sinkhole in one extra query. A pool indexed by the name looks like hosting.
func (d *Decoy) addrFor(name string, pfx netip.Prefix) netip.Addr {
	base := pfx.Masked().Addr()
	bits := base.BitLen() - pfx.Bits()
	if bits <= 0 {
		return base
	}
	h := d.hash("addr", name)
	var idx uint64
	switch {
	case bits == 1:
		idx = h & 1
	case bits < 64:
		// The first and last address of a range are the network and the
		// broadcast, and neither is a host anybody is hosted at.
		idx = 1 + h%((uint64(1)<<bits)-2)
	default:
		idx = h | 1
	}
	return addAddr(base, idx)
}

// ptrFor is the name a reverse lookup is answered with, which is the one
// fabricated answer a human reads: it has to look like a host somewhere.
func (d *Decoy) ptrFor(name string) string {
	return fmt.Sprintf("host-%d.static.example.net", 1+d.hash("ptr", name)%9999)
}

// text is the TXT string, which changes between periods because a tunnel that
// received the same answer twice for two different questions would stop.
func (d *Decoy) text(name string) string {
	h := d.hash("txt", name) ^ uint64(d.values.Register(0, addrTextNonce))
	b := make([]byte, 0, maxDecoyText+8)
	for len(b) < maxDecoyText {
		var eight [8]byte
		binary.BigEndian.PutUint64(eight[:], h)
		b = append(b, eight[:]...)
		h = d.hash("txt", string(eight[:]))
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return strings.ToLower(s[:maxDecoyText])
}

// hash is the fabrication's one source of derived values: the seed, a purpose
// and a name. The seed is what makes two listeners answer differently and one
// listener answer the same way after a restart.
func (d *Decoy) hash(purpose, name string) uint64 {
	f := fnv.New64a()
	var eight [8]byte
	binary.BigEndian.PutUint64(eight[:], d.seed)
	_, _ = f.Write(eight[:])
	_, _ = f.Write([]byte(purpose))
	_, _ = f.Write([]byte{0})
	_, _ = f.Write([]byte(strings.ToLower(name)))
	return f.Sum64()
}

// addAddr adds delta to an address, which is arithmetic on the octets because
// netip.Addr is not a number.
func addAddr(base netip.Addr, delta uint64) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := binary.BigEndian.Uint32(b[:]) + uint32(delta) //nolint:gosec // wraps inside the pool by design
		binary.BigEndian.PutUint32(b[:], v)
		return netip.AddrFrom4(b)
	}
	b := base.As16()
	lo := binary.BigEndian.Uint64(b[8:]) + delta
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}

// clearAuthoritative clears the AA bit on a reply.
func clearAuthoritative(out []byte) {
	if len(out) >= 4 {
		out[2] &^= 0x04
	}
}

// Decoy is the fabricated resolver in force, or nil where none is configured.
func (s *Server) Decoy() *Decoy { return s.policy.Load().Decoy }

// deceive answers a query as the fabricated resolver, and reports whether it
// did.
//
// It is called only where the query was not going to reach a resolver: a
// refusal, or a listener with nothing behind it. That is the invariant the whole
// feature rests on -- a query on its way to a resolver is never answered from
// here -- and it is a test rather than a comment.
func (s *Server) deceive(a *asked, p *Policy, query []byte, qEnd int, h Header,
	q Question, why string) ([]byte, bool) {
	d := p.Decoy
	if d == nil || !d.Admits(a.client) {
		return nil, false
	}
	tripped := d.Tripped(q)
	d.policy.Record(a.client, tripped, time.Now())
	s.Deceived.Add(1)
	event := "dns_deceived"
	if tripped {
		s.Tripwire.Add(1)
		event = "dns_tripwire"
	}
	if s.hooks.Event != nil {
		// verified is carried through for the reason every other event on this
		// listener carries it: a datagram proves nothing about its source, so
		// an event from an unverified one must not be attributed -- or banned
		// -- against an address anybody could have written in.
		s.hooks.Event(a.client, event, a.verified, "listener", s.Name, "reason", why,
			"name", q.Name, "type", TypeName(q.Type), "proto", a.proto,
			"mode", decoyMode(d.whole))
	}
	return d.Answer(query, qEnd, h, q, a.stream, a.verified), true
}

func decoyMode(whole bool) string {
	if whole {
		return "decoy"
	}
	return "answer"
}
