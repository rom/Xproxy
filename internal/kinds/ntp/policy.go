package ntp

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ntp"
)

// The policy is written about the two directions separately, because the
// same field means different things in each.
//
// A client's request carries a stratum, a root delay and a root
// dispersion, and all three are noise: the protocol does not ask a client
// to fill them in and nothing should read them. A server's answer carries
// the same fields and they are the whole statement about the time in it.
// So the server-quality rules apply to responses only -- a relay that
// applied them to requests would be refusing clients for fields the
// specification leaves empty.

// Decision is what the policy decided about one packet.
type Decision struct {
	Allow bool
	// Reason is the refusal reason, which is also the label the refusal
	// counters use.
	Reason string
	// Detail is what to put in the security event beside the reason.
	Detail string
	// KoD asks for a kiss-o'-death answer rather than a silent drop: a
	// client that is asking too often is told to slow down, which is
	// what the protocol has for it.
	KoD string
}

var allowed = Decision{Allow: true}

// deny is the refusal constructor, so every refusal has a reason a
// counter can carry.
func deny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail}
}

// Policy is the compiled listener policy.
type Policy struct {
	mode string

	allowClients, denyClients []netip.Prefix
	allowServers              []netip.Prefix
	peers                     []netip.Prefix
	manycastResponders        []netip.Prefix

	versions map[uint8]bool
	modes    map[wire.Mode]bool

	allowV5            bool
	allowManycast      bool
	allowUnknownExt    bool
	refuseAmbiguousMAC bool
	maxExtensions      int
	maxPacket          int

	requireAuth bool
	allowLegacy bool
	keys        wire.Keys
	requireNTS  bool
	ntsMode     string

	// The server-quality bounds, applied to responses.
	maxStratum        uint8
	refuseUnsync      bool
	maxRootDelay      time.Duration
	maxRootDispersion time.Duration
	maxDelay          time.Duration
	maxOffset         time.Duration
	forwardKoD        bool
	interleaved       bool
}

// request is one packet from a client, as the listener reads it.
type request struct {
	client netip.AddrPort
	kind   wire.Kind
	pkt    *wire.Packet
	size   int
}

// response is one packet from a server.
type response struct {
	server netip.AddrPort
	pkt    *wire.Packet
	// offset and delay are the relay's own measurement of this exchange:
	// it knows when it sent the request and when the answer came back,
	// so it can read the answer's own timestamps against its own clock.
	offset, delay time.Duration
	// ntsAsked says the request this answers carried NTS fields, which
	// is what makes a plain answer a downgrade rather than an answer.
	ntsAsked bool
	// authAsked says the request carried a MAC this relay verified.
	authAsked bool
}

// compile builds the policy from the configuration.
func compile(l *config.NTPListener, keys wire.Keys) (*Policy, error) {
	p := &Policy{
		mode:               l.Mode,
		versions:           map[uint8]bool{},
		modes:              map[wire.Mode]bool{},
		allowV5:            l.AllowVersion5,
		allowManycast:      l.AllowManycast,
		maxExtensions:      l.MaxExtensions,
		maxPacket:          l.MaxPacketBytes,
		keys:               keys,
		refuseAmbiguousMAC: true,
		refuseUnsync:       true,
		forwardKoD:         true,
		interleaved:        l.InterleavedAllowed(),
	}
	if p.maxExtensions <= 0 {
		p.maxExtensions = 8
	}
	if p.maxPacket <= 0 {
		p.maxPacket = 1280
	}
	var err error
	if p.allowClients, err = prefixes("allow_clients", l.AllowClients); err != nil {
		return nil, err
	}
	if p.denyClients, err = prefixes("deny_clients", l.DenyClients); err != nil {
		return nil, err
	}
	if p.allowServers, err = prefixes("allow_servers", l.AllowServers); err != nil {
		return nil, err
	}
	if p.peers, err = prefixes("peers", l.Peers); err != nil {
		return nil, err
	}
	if p.manycastResponders, err = prefixes("manycast_responders", l.ManycastResponders); err != nil {
		return nil, err
	}
	// The versions. Empty means the default profile: version 4, and
	// version 3 for the devices that only speak it. Versions 1 and 2 are
	// off unless a listener names them, because a v1 packet has no mode
	// field and a relay that accepted one by default would be guessing
	// what it is.
	if len(l.Versions) == 0 {
		p.versions[4] = true
		p.versions[3] = true
	}
	for _, v := range l.Versions {
		if v < wire.MinVersion || v > wire.MaxVersion {
			return nil, fmt.Errorf("versions: %d is not a version this relay reads", v)
		}
		p.versions[uint8(v)] = true //nolint:gosec // bounded above
	}
	// The modes. Empty means client and server: the association shape
	// every ordinary deployment uses. Symmetric modes and broadcast are
	// relationships rather than requests, so they are named explicitly
	// or not at all.
	if len(l.Modes) == 0 {
		p.modes[wire.ModeClient] = true
		p.modes[wire.ModeServer] = true
	}
	for _, name := range l.Modes {
		m, ok := wire.ModeOf(name)
		if !ok {
			return nil, fmt.Errorf("modes: %q is not a mode", name)
		}
		if m.Management() {
			return nil, fmt.Errorf("modes: %q is not a time service mode and is always refused", name)
		}
		p.modes[m] = true
	}
	if e := l.Extensions; e != nil {
		p.allowUnknownExt = e.AllowUnknown
		if e.RefuseAmbiguousMAC != nil {
			p.refuseAmbiguousMAC = *e.RefuseAmbiguousMAC
		}
		if e.Max > 0 {
			p.maxExtensions = e.Max
		}
	}
	if a := l.Auth; a != nil {
		p.requireAuth = a.Require
		p.allowLegacy = a.AllowLegacyAlgorithms
	}
	if n := l.NTS; n != nil {
		p.ntsMode = n.Mode
		p.requireNTS = n.Require
	}
	if q := l.Quality; q != nil {
		p.maxStratum = uint8(q.MaxStratum) //nolint:gosec // validated 0..16
		if q.RefuseUnsynchronised != nil {
			p.refuseUnsync = *q.RefuseUnsynchronised
		}
		p.maxRootDelay = q.MaxRootDelay.D()
		p.maxRootDispersion = q.MaxRootDispersion.D()
		p.maxDelay = q.MaxDelay.D()
		p.maxOffset = q.MaxOffset.D()
	}
	if k := l.KoD; k != nil && k.Forward != nil {
		p.forwardKoD = *k.Forward
	}
	return p, nil
}

func prefixes(what string, in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a network", what, s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func contains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientAllowed applies the client lists. Deny first, then allow.
func (p *Policy) ClientAllowed(a netip.Addr) bool {
	if contains(p.denyClients, a) {
		return false
	}
	return len(p.allowClients) == 0 || contains(p.allowClients, a)
}

// ServerAllowed applies the egress list to a destination this listener is
// about to use. In a forward deployment it is the whole point: the pool
// says which servers exist and this says which addresses they are allowed
// to be, so a pool whose name resolves somewhere new does not quietly
// become a new egress.
func (p *Policy) ServerAllowed(a netip.Addr) bool {
	return len(p.allowServers) == 0 || contains(p.allowServers, a)
}

// Dispatch decides about a packet from the first octet alone: the version
// and the mode, before any field of the body has been read.
//
// This is the order the refusals have to happen in. A mode 6 or mode 7
// packet is not a time packet with an odd number in it -- it is the
// control protocol and the vendor-private protocol, whose headers are
// not this one, and whose monlist request is the amplifier this port is
// famous for. A version 5 packet is a different layout again. Reading
// any of their bodies with this parser is the mistake, so the dispatch
// refuses them before the parser is reached.
func (p *Policy) Dispatch(k wire.Kind) Decision {
	switch k.Mode {
	case wire.ModeControl:
		return deny("control_mode", "mode 6 is the control protocol, not time")
	case wire.ModePrivate:
		return deny("private_mode", "mode 7 is the vendor-private protocol, not time")
	}
	if k.Version == wire.Version5 {
		if p.allowV5 {
			// Named explicitly, and still not parsed with this parser:
			// version 5 is forwarded as opaque bytes or not at all.
			return Decision{Allow: true, Reason: "version5_passthrough"}
		}
		return deny("version5", "version 5 is experimental and its packet format is not version 4's")
	}
	if k.Version < wire.MinVersion || k.Version > wire.MaxVersion {
		return deny("version", fmt.Sprintf("version %d", k.Version))
	}
	if !p.versions[k.Version] {
		return deny("version_not_allowed", fmt.Sprintf("version %d", k.Version))
	}
	if !p.modes[k.EffectiveMode()] {
		return deny("mode_not_allowed", k.Mode.String())
	}
	return allowed
}

// Request decides about a parsed request.
func (p *Policy) Request(r request) Decision {
	if r.size > p.maxPacket {
		return deny("packet_too_large", fmt.Sprintf("%d octets", r.size))
	}
	pkt := r.pkt
	// A symmetric association is a relationship, not a request: the two
	// ends poll each other and each accepts the other's time. So it is
	// only ever between named peers.
	switch pkt.Mode {
	case wire.ModeSymActive, wire.ModeSymPassive:
		if !contains(p.peers, r.client.Addr()) {
			return deny("not_a_peer", pkt.Mode.String())
		}
	case wire.ModeBroadcast:
		// Broadcast and multicast mode has no round trip, so a listener
		// cannot measure the delay and a client cannot tell a forged
		// packet from a real one by anything but authentication. It is
		// confined to the peers a configuration names.
		if !contains(p.peers, r.client.Addr()) {
			return deny("broadcast_not_allowed", "")
		}
	}
	if len(pkt.Extensions) > p.maxExtensions {
		return deny("too_many_extensions", fmt.Sprintf("%d fields", len(pkt.Extensions)))
	}
	if !p.allowUnknownExt {
		for _, e := range pkt.Extensions {
			if !wire.KnownExtension(e.Type) {
				return deny("unknown_extension", wire.ExtensionName(e.Type))
			}
		}
	}
	if pkt.MACAmbiguous && p.refuseAmbiguousMAC {
		return deny("ambiguous_mac",
			"the tail is both a MAC and a valid extension field, and the two readings differ")
	}
	nts := pkt.NTS()
	if p.requireNTS && !nts.Present {
		return deny("nts_required", "")
	}
	if p.requireAuth {
		switch {
		case pkt.CryptoNAK:
			return deny("auth_required", "a key identifier with no digest")
		case !pkt.HasMAC && !nts.Authenticator:
			// NTS carries its own authentication, so a packet protected
			// by NTS satisfies a requirement for authentication without
			// a symmetric key -- and the relay says plainly that it has
			// not verified it: only the party holding the key can.
			return deny("auth_required", "")
		case pkt.HasMAC:
			if err := p.verify(pkt); err != "" {
				return deny("auth_failed", err)
			}
		}
	} else if pkt.HasMAC && len(p.keys) > 0 {
		// Not required, but a MAC this relay can check is a MAC it does
		// check: a packet whose own authentication fails is not a packet
		// to pass on just because the listener did not insist on one.
		if err := p.verify(pkt); err != "" {
			return deny("auth_failed", err)
		}
	}
	return allowed
}

// verify checks a MAC and returns the empty string when it is good.
func (p *Policy) verify(pkt *wire.Packet) string {
	k, ok := p.keys[pkt.KeyID]
	if !ok {
		return fmt.Sprintf("no key %d", pkt.KeyID)
	}
	if !p.allowLegacy && k.Algorithm != wire.AlgAESCMAC && k.Algorithm != "" {
		return fmt.Sprintf("key %d names %s, which this listener does not accept", pkt.KeyID, k.Algorithm)
	}
	if err := pkt.Verify(p.keys); err != nil {
		return err.Error()
	}
	return ""
}

// Response decides about a server's answer. These are the server-quality
// rules, and they exist here rather than at the client because the client
// is a device that will step its clock to whatever it is told.
func (p *Policy) Response(r response) Decision {
	pkt := r.pkt
	if pkt.Mode != wire.ModeServer && pkt.Mode != wire.ModeSymPassive && pkt.Mode != wire.ModeSymActive {
		return deny("response_mode", pkt.Mode.String())
	}
	if pkt.KissOfDeath() {
		// A kiss-o'-death is not time and not an error: it is the
		// server telling the client something. Forwarding it lets the
		// client back off, which is usually right; not forwarding it
		// hides a rate limit the estate should know about, so it is a
		// choice with a counter either way.
		if p.forwardKoD {
			return Decision{Allow: true, Reason: "kiss_" + pkt.KissCode()}
		}
		return deny("kiss_of_death", pkt.KissCode())
	}
	if p.refuseUnsync && pkt.Unsynchronised() {
		return deny("unsynchronised", "the server says its own clock is not synchronised")
	}
	if p.refuseUnsync && pkt.Stratum >= 16 {
		// Stratum 16 is the protocol's own "unsynchronised", and it is a
		// separate statement from the leap indicator: a server can say
		// either, and both mean do not use this time.
		return deny("unsynchronised_stratum", fmt.Sprintf("stratum %d", pkt.Stratum))
	}
	if p.maxStratum > 0 && pkt.Stratum > p.maxStratum {
		return deny("stratum_too_high", fmt.Sprintf("stratum %d", pkt.Stratum))
	}
	if p.maxRootDelay > 0 && pkt.RootDelay.Duration() > p.maxRootDelay {
		return deny("root_delay", pkt.RootDelay.Duration().String())
	}
	if p.maxRootDispersion > 0 && pkt.RootDispersion.Duration() > p.maxRootDispersion {
		return deny("root_dispersion", pkt.RootDispersion.Duration().String())
	}
	if p.maxDelay > 0 && r.delay > p.maxDelay {
		return deny("delay", r.delay.String())
	}
	if p.maxOffset > 0 && (r.offset > p.maxOffset || r.offset < -p.maxOffset) {
		return deny("offset", r.offset.String())
	}
	if r.ntsAsked && !pkt.NTS().Present {
		// The request was protected and the answer is not. That is a
		// downgrade, and the one thing a relay must never do silently
		// is turn required NTS into plain NTP.
		return deny("nts_stripped", "the request carried NTS fields and the answer carries none")
	}
	if r.authAsked && !pkt.HasMAC && !pkt.CryptoNAK {
		return deny("auth_stripped", "the request was authenticated and the answer is not")
	}
	return allowed
}

// Interleaved says whether an interleaved answer is accepted: one whose
// origin timestamp is the server's own previous transmit timestamp rather
// than the client's. It is how a server hands a client a hardware-quality
// transmit timestamp, so refusing it means refusing the most accurate
// exchange the protocol has -- but it is also a second way for an answer
// to be accepted, so it is a switch rather than an assumption.
func (p *Policy) Interleaved() bool { return p.interleaved }

// NTSMode is the configured NTS handling, for the status view.
func (p *Policy) NTSMode() string {
	if p.ntsMode == "" {
		return "passthrough"
	}
	return p.ntsMode
}
