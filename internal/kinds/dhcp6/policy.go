package dhcp6

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dhcp6"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, which is mostly about answers.
//
// A DHCPv6 request asks for an address and says who is asking; there is not much
// in it to refuse. An answer configures the machine: its addresses, its
// resolvers, its search list, the prefix it will route, the URL it will open, the
// image it will boot, and -- through the S46 options -- where its IPv4 traffic
// goes. So the interesting half of this policy faces upstream, and what it
// mostly does is take things out of replies.
//
// Taking things out rather than refusing the reply is the default on purpose. A
// client that still gets its address and no longer gets a resolver it should not
// have is a client that works; a client refused the whole reply has no address
// at all, and an estate whose DHCP relay refuses replies is an estate that does
// not boot.

// Decision is what the policy says about one message.
type Decision struct {
	Allow bool
	// Rule is the rule that decided, empty for the default.
	Rule string
	// Reason and Detail name the refusal for the log and the counter.
	Reason, Detail string
	// Hard is a refusal a shadow-mode listener still enforces: a bound, a
	// message two parsers would read differently, or a reply from an address
	// that is not a server. The last is the one worth naming: a listener that
	// evaluated the server list without enforcing it would relay a rogue
	// server's answer and write it down.
	Hard bool
	// Strip are the options to remove before forwarding, and StripReason says
	// why each went, for the log line.
	Strip       []uint16
	StripReason map[uint16]string
	// Lease is the valid lifetime to write over a server's own when it is
	// outside the bounds, and Bounded says one was applied.
	Lease   uint32
	Bounded bool
}

func (d *Decision) strip(code uint16, why string) {
	if d.StripReason == nil {
		d.StripReason = map[uint16]string{}
	}
	if _, dup := d.StripReason[code]; dup {
		return
	}
	d.Strip = append(d.Strip, code)
	d.StripReason[code] = why
}

func deny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail}
}

func hard(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}

// request is one message to decide about.
type request struct {
	// from is where the datagram came from, and msg the whole chain.
	from netip.Addr
	msg  *wire.Message
	at   time.Time
}

// inner is the client's own message, which is what a rule matches on.
func (r request) inner() *wire.Message { return r.msg.Innermost() }

// Policy is the compiled configuration.
type Policy struct {
	clients, denyClients []netip.Prefix
	servers              []netip.Prefix
	types                map[wire.MessageType]bool
	denyOpts             map[uint16]bool
	allowOpts            map[uint16]bool
	denyAsked            map[uint16]bool
	resolvers            map[netip.Addr]bool
	domains              []string
	bootURLs             []string
	stripOnDeny          bool
	minLease, maxLease   uint32
	refuseRepeated       bool
	temporary            bool
	reconfigure          bool
	delegating           bool
	pdPrefixes           []netip.Prefix
	pdMin, pdMax         int
	stripClientRelay     bool
	defaultAllow         bool
	rules                []*rule
	now                  func() time.Time
}

type rule struct {
	name    string
	action  string
	clients []netip.Prefix
	duids   []string
	types   map[wire.MessageType]bool
	vendor  []string
	user    []string
	// The per-rule narrowing of the answer policy. A nil map or slice means
	// "the listener's", which is what makes a rule a narrowing rather than a
	// replacement.
	denyOpts  map[uint16]bool
	resolvers map[netip.Addr]bool
	domains   []string
	bootURLs  []string
	maxLease  uint32
	ifID      string
	sched     *schedule.Window
}

func compile(m *config.DHCP6Listener, now func() time.Time) (*Policy, error) {
	p := &Policy{
		stripOnDeny:      m.OnDeniedOption != "deny",
		refuseRepeated:   m.RefusesRepeated(),
		temporary:        m.TemporaryAddresses(),
		reconfigure:      m.AllowReconfigure,
		stripClientRelay: m.OnClientRelayOption != "deny",
		defaultAllow:     m.DefaultAction != "deny",
		delegating:       m.PrefixDelegation.Delegating(),
		now:              now,
	}
	var err error
	if p.clients, err = prefixes(m.AllowClients); err != nil {
		return nil, err
	}
	if p.denyClients, err = prefixes(m.DenyClients); err != nil {
		return nil, err
	}
	if p.servers, err = prefixes(m.AllowServers); err != nil {
		return nil, err
	}
	if p.types, err = types(m.MessageTypes, defaultTypes()); err != nil {
		return nil, err
	}
	if p.denyOpts, err = optSet(m.DenyOptions, defaultDenied()); err != nil {
		return nil, err
	}
	if p.allowOpts, err = optSet(m.AllowOptions, nil); err != nil {
		return nil, err
	}
	if p.denyAsked, err = optSet(m.DenyRequestedOptions, nil); err != nil {
		return nil, err
	}
	if p.resolvers, err = addrSet(m.AllowResolvers); err != nil {
		return nil, err
	}
	p.domains, p.bootURLs = m.AllowDomains, m.AllowBootURLs
	p.minLease, p.maxLease = leaseSeconds(m.MinLeaseTime), leaseSeconds(m.MaxLeaseTime)
	if pd := m.PrefixDelegation; pd != nil {
		if p.pdPrefixes, err = prefixes(pd.Prefixes); err != nil {
			return nil, err
		}
		p.pdMin, p.pdMax = pd.MinLength, pd.MaxLength
	}
	for i := range m.Rules {
		r, err := compileRule(&m.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(c *config.DHCP6Rule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, duids: c.DUIDs,
		vendor: c.VendorClasses, user: c.UserClasses,
		domains: c.AllowDomains, bootURLs: c.AllowBootURLs,
		maxLease: leaseSeconds(c.MaxLeaseTime), ifID: c.InterfaceID}
	if r.action == "" {
		r.action = "allow"
	}
	var err error
	if r.sched, err = schedule.Compile(c.Schedule); err != nil {
		return nil, err
	}
	if r.clients, err = prefixes(c.Clients); err != nil {
		return nil, err
	}
	if len(c.MessageTypes) > 0 {
		if r.types, err = types(c.MessageTypes, nil); err != nil {
			return nil, err
		}
	}
	if len(c.DenyOptions) > 0 {
		if r.denyOpts, err = optSet(c.DenyOptions, nil); err != nil {
			return nil, err
		}
	}
	if len(c.AllowResolvers) > 0 {
		if r.resolvers, err = addrSet(c.AllowResolvers); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// defaultTypes is the ordinary lease cycle: everything a client sends except the
// lease-query family, which is a relay agent's diagnostic and an inventory of
// every lease in the estate to anything else.
func defaultTypes() map[wire.MessageType]bool {
	return map[wire.MessageType]bool{
		wire.Solicit: true, wire.Request: true, wire.Renew: true, wire.Rebind: true,
		wire.Confirm: true, wire.Release: true, wire.Decline: true,
		wire.InformationRequest: true,
	}
}

func defaultDenied() map[uint16]bool {
	out := map[uint16]bool{}
	for _, c := range wire.DangerousOptions {
		out[c] = true
	}
	return out
}

func leaseSeconds(d config.Duration) uint32 {
	secs := int64(d.D().Seconds())
	if secs < 0 {
		return 0
	}
	if secs > 0xffffffff {
		return 0xffffffff
	}
	return uint32(secs) //nolint:gosec // bounded above
}

func prefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("dhcp6: %q is not an address or a network", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.BitLen()))
	}
	return out, nil
}

func addrSet(in []string) (map[netip.Addr]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[netip.Addr]bool{}
	for _, s := range in {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("dhcp6: %q is not an address", s)
		}
		out[a.Unmap()] = true
	}
	return out, nil
}

func types(in []string, def map[wire.MessageType]bool) (map[wire.MessageType]bool, error) {
	if len(in) == 0 {
		return def, nil
	}
	out := map[wire.MessageType]bool{}
	for _, s := range in {
		t, ok := wire.TypeOf(s)
		if !ok {
			return nil, fmt.Errorf("dhcp6: %q is not a message type", s)
		}
		out[t] = true
	}
	return out, nil
}

func optSet(in []string, def map[uint16]bool) (map[uint16]bool, error) {
	if len(in) == 0 {
		return def, nil
	}
	out := map[uint16]bool{}
	for _, s := range in {
		c, ok := wire.OptionOf(s)
		if !ok {
			return nil, fmt.Errorf("dhcp6: %q is not an option", s)
		}
		out[c] = true
	}
	return out, nil
}

// Client says whether a message may arrive from this address.
func (p *Policy) Client(ip netip.Addr) bool {
	for _, n := range p.denyClients {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.clients) == 0 {
		return true
	}
	for _, n := range p.clients {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Server says whether a reply may come from this address.
//
// There is no empty-means-anything here: the list is filled in from the upstream
// pool when the configuration did not write one, because an operator who wrote
// nothing meant "the servers I configured" and a relay that read that as
// "anybody" would have this protection switched off in exactly the deployments
// that did not think about it.
func (p *Policy) Server(ip netip.Addr) bool {
	for _, n := range p.servers {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Decide is the policy on a message from the client side.
func (p *Policy) Decide(req request) Decision {
	in := req.inner()
	if !in.Type.Known() {
		// A type nobody defined is not forwarded on a guess: a relay cannot
		// decide about a message whose meaning is not written down.
		return hard("unknown_message_type", in.Type.String())
	}
	if in.Type.IsRelay() {
		// The chain ends in a client's or a server's message, so a relay
		// message here is a chain with nothing at the bottom.
		return hard("relay_message_inside", in.Type.String())
	}
	if !in.Type.FromClient() {
		// A server's message arriving on the segment side. This is what a rogue
		// server on the relay's own segment looks like from here, and it is
		// worth its own reason: the relay is not the only thing the clients can
		// hear.
		return hard("server_message_from_client_side", in.Type.String())
	}
	if p.refuseRepeated {
		if rep := in.Repeated(); len(rep) > 0 {
			return hard("repeated_option", wire.OptionName(rep[0]))
		}
	}
	if !p.types[in.Type] {
		return deny("message_type_not_allowed", in.Type.String())
	}
	d := p.match(req)
	if !d.Allow {
		return d
	}
	if why := p.asks(in, d.Rule); why != "" {
		return deny("request_not_allowed", why)
	}
	// The relay's own options, arriving from a client. RFC 4649 s3 and RFC 4580
	// s2 both say these are the relay's statement about which circuit a message
	// came from, so one from a client is the client claiming to be somewhere it
	// is not.
	for _, code := range wire.RelayOptions {
		if !in.Has(code) {
			continue
		}
		if !p.stripClientRelay {
			return deny("client_relay_option", wire.OptionName(code))
		}
		d.strip(code, "a relay agent's own option, from a client")
	}
	return d
}

// asks is the policy on what a client's request contains: the identity
// associations it asks for, and the options it asks to be told.
func (p *Policy) asks(in *wire.Message, ruleName string) string {
	ias, err := in.IAs()
	if err != nil {
		return err.Error()
	}
	for _, ia := range ias {
		switch {
		case ia.Code == wire.OptionIATA && !p.temporary:
			return "a temporary address association"
		case ia.Code == wire.OptionIAPD && !p.delegating:
			return "a prefix delegation where none is carried"
		}
		if ia.Code != wire.OptionIAPD {
			continue
		}
		for _, pfx := range ia.Prefixes {
			if why := p.prefixAllowed(pfx.Prefix); why != "" {
				// A client asking for a prefix outside the estate's is asking a
				// real server to give away a segment. It is refused here rather
				// than left to the server's own configuration, because the
				// server's configuration is not what this estate reads.
				return why
			}
		}
	}
	_ = ruleName
	return ""
}

// prefixAllowed is the bound on a delegated prefix: which prefixes it may come
// from, and how long it may be.
func (p *Policy) prefixAllowed(pfx netip.Prefix) string {
	if !pfx.IsValid() {
		return "a prefix that is not one"
	}
	if p.pdMin > 0 && pfx.Bits() < p.pdMin {
		return fmt.Sprintf("a /%d, shorter than the /%d this estate delegates", pfx.Bits(), p.pdMin)
	}
	if p.pdMax > 0 && pfx.Bits() > p.pdMax {
		return fmt.Sprintf("a /%d, longer than the /%d this estate delegates", pfx.Bits(), p.pdMax)
	}
	if len(p.pdPrefixes) == 0 {
		return ""
	}
	// The unspecified prefix is what a client sends to mean "any": RFC 8415
	// s21.22 lets a client send an IA_PREFIX hint of ::/0, and refusing that
	// would be refusing every client that does not already know its prefix.
	if pfx.Addr().IsUnspecified() && pfx.Bits() == 0 {
		return ""
	}
	for _, allowed := range p.pdPrefixes {
		if allowed.Overlaps(pfx) && allowed.Bits() <= pfx.Bits() && allowed.Contains(pfx.Addr()) {
			return ""
		}
	}
	return "the prefix " + pfx.String() + " is outside the estate's"
}

// match runs the rules.
func (p *Policy) match(req request) Decision {
	for _, r := range p.rules {
		if !r.matches(req, p.now()) {
			continue
		}
		switch r.action {
		case "deny":
			return Decision{Rule: r.name, Reason: "rule", Detail: r.name}
		case "observe":
			// Recorded and then still looking, which is how a rule is tried on
			// live traffic before it decides anything.
			continue
		default:
			return Decision{Allow: true, Rule: r.name}
		}
	}
	if !p.defaultAllow {
		return deny("default_deny", "")
	}
	return Decision{Allow: true}
}

func (r *rule) matches(req request, now time.Time) bool {
	in := req.inner()
	if len(r.clients) > 0 && !contains(r.clients, req.from) {
		return false
	}
	if r.types != nil && !r.types[in.Type] {
		return false
	}
	if len(r.duids) > 0 {
		d, ok := req.msg.ClientDUID()
		if !ok || !matchAny(r.duids, d.String()) {
			return false
		}
	}
	if len(r.vendor) > 0 && !matchAny(r.vendor, vendorClass(in)) {
		return false
	}
	if len(r.user) > 0 && !matchAny(r.user, userClass(in)) {
		return false
	}
	if !r.sched.InForce(now) {
		return false
	}
	return true
}

// Answer is the policy on a reply, which is the half that matters.
//
// reqRule is the rule that allowed the request, carried forward so the reply is
// decided under the same rule rather than matched again against a message of a
// different type and without the client's own options in it.
func (p *Policy) Answer(req request, reqRule string) Decision {
	in := req.inner()
	d := Decision{Allow: true, Rule: reqRule}
	if !in.Type.Known() {
		return hard("unknown_message_type", in.Type.String())
	}
	if !in.Type.FromServer() {
		// A client's message arriving from the server side: either a server
		// that is confused or something bouncing traffic back.
		return hard("client_message_from_server_side", in.Type.String())
	}
	if p.refuseRepeated {
		if rep := in.Repeated(); len(rep) > 0 {
			return hard("repeated_option", wire.OptionName(rep[0]))
		}
	}
	if in.Type == wire.Reconfigure && !p.reconfigure {
		// A message to a client that answers nothing, which RFC 8415 s18.3.11
		// requires to be authenticated with a key nobody deploys. A client that
		// accepts one can be made to re-ask a server of the sender's choosing.
		return deny("reconfigure_not_allowed", "")
	}
	r := p.ruleFor(reqRule)
	// The option policy: the allow list if there is one, the deny list
	// otherwise, and the per-rule narrowing on top.
	for _, o := range in.Options {
		if alwaysCarried(o.Code) {
			continue
		}
		switch {
		case p.allowOpts != nil && !p.allowOpts[o.Code]:
			d.strip(o.Code, "not in the allow list")
		case r != nil && r.denyOpts != nil && r.denyOpts[o.Code]:
			d.strip(o.Code, "denied by rule "+r.name)
		case p.allowOpts == nil && p.denyOpts[o.Code]:
			d.strip(o.Code, "an option that carries a configuration")
		}
	}
	// And the addresses and names inside the options that survived, because an
	// option this estate does carry can still name somewhere it does not own.
	p.checkNamed(in, r, &d)
	if why := p.checkIAs(in, &d); why != "" {
		return hard("bad_identity_association", why)
	}
	if len(d.Strip) > 0 && !p.stripOnDeny {
		return deny("denied_option", wire.OptionName(d.Strip[0]))
	}
	return d
}

// checkNamed applies the positive lists: the resolvers, the search domains and
// the boot URLs a reply may name.
//
// These are the more useful half of the answer policy. An estate knows its own
// resolvers, so a reply naming anything else is wrong whoever sent it -- and
// that catches a compromised real server as well as a rogue one, which no
// amount of trusting the source address does.
func (p *Policy) checkNamed(in *wire.Message, r *rule, d *Decision) {
	if d.StripReason == nil {
		d.StripReason = map[uint16]string{}
	}
	if _, gone := d.StripReason[wire.OptionDNSServers]; !gone {
		if allowed := firstAddrs(ruleResolvers(r), p.resolvers); allowed != nil {
			if v, ok := in.Get(wire.OptionDNSServers); ok {
				addrs, err := wire.Addresses(v)
				if err != nil {
					d.strip(wire.OptionDNSServers, "unreadable")
				} else {
					for _, a := range addrs {
						if !allowed[a.Unmap()] {
							d.strip(wire.OptionDNSServers, "names the resolver "+a.String())
							break
						}
					}
				}
			}
		}
	}
	if _, gone := d.StripReason[wire.OptionDomainList]; !gone {
		if pats := firstPats(ruleDomains(r), p.domains); len(pats) > 0 {
			if v, ok := in.Get(wire.OptionDomainList); ok {
				names, err := wire.DomainNames(v)
				if err != nil {
					d.strip(wire.OptionDomainList, "unreadable")
				} else {
					for _, n := range names {
						if !matchAny(pats, n) {
							d.strip(wire.OptionDomainList, "names the domain "+n)
							break
						}
					}
				}
			}
		}
	}
	if _, gone := d.StripReason[wire.OptionBootFileURL]; !gone {
		if pats := firstPats(ruleURLs(r), p.bootURLs); len(pats) > 0 {
			if v, ok := in.Get(wire.OptionBootFileURL); ok {
				if u := string(v); !matchAny(pats, u) {
					d.strip(wire.OptionBootFileURL, "a boot file nobody listed")
				}
			}
		}
	}
}

// checkIAs is the policy on what a reply hands out: the prefixes it delegates
// and the lifetimes it sets.
//
// A prefix outside the estate's is a refusal rather than a strip, because there
// is no useful half of a delegation to keep: an IA_PD with its prefix removed is
// an answer that says nothing, and a client that acted on the rest would be
// routing a prefix the relay decided against.
func (p *Policy) checkIAs(in *wire.Message, d *Decision) string {
	ias, err := in.IAs()
	if err != nil {
		return err.Error()
	}
	for _, ia := range ias {
		if ia.Code == wire.OptionIAPD {
			if !p.delegating {
				return "a delegated prefix where none is carried"
			}
			for _, pfx := range ia.Prefixes {
				if why := p.prefixAllowed(pfx.Prefix); why != "" {
					return why
				}
			}
		}
		if ia.Code == wire.OptionIATA && !p.temporary {
			return "a temporary address association"
		}
		for _, a := range ia.Addresses {
			if lease, ok := p.boundLease(a.Valid); ok {
				d.Lease, d.Bounded = lease, true
			}
		}
		for _, pfx := range ia.Prefixes {
			if lease, ok := p.boundLease(pfx.Valid); ok {
				d.Lease, d.Bounded = lease, true
			}
		}
	}
	return ""
}

// boundLease says what a valid lifetime should be, and whether it had to change.
//
// A valid lifetime of zero is not bounded up to the minimum: zero is how a
// server withdraws an address (RFC 8415 s18.2.10), and rewriting it would turn a
// withdrawal into a lease. Infinity is bounded down like any other number,
// because an infinite lease is a pool exhausted by every device that ever
// visited.
func (p *Policy) boundLease(valid uint32) (uint32, bool) {
	if valid == 0 {
		return 0, false
	}
	if p.maxLease > 0 && valid > p.maxLease {
		return p.maxLease, true
	}
	if p.minLease > 0 && valid < p.minLease {
		return p.minLease, true
	}
	return valid, false
}

// AskDenied removes the options a client may not ask for from its Option Request
// Option, and says which went.
//
// The ask is removed rather than the message refused: a client asking for the
// captive portal URL is a client that will open one if anything offers it, and
// an estate that has decided not to have that can say so without stopping the
// client getting an address.
func (p *Policy) AskDenied(list []byte) ([]byte, []uint16) {
	if len(p.denyAsked) == 0 || len(list)%2 != 0 {
		return list, nil
	}
	out := make([]byte, 0, len(list))
	var gone []uint16
	for i := 0; i+1 < len(list); i += 2 {
		code := uint16(list[i])<<8 | uint16(list[i+1])
		if p.denyAsked[code] {
			gone = append(gone, code)
			continue
		}
		out = append(out, list[i], list[i+1])
	}
	return out, gone
}

// InterfaceFor is the interface identifier a rule wants, or the listener's.
func (p *Policy) InterfaceFor(ruleName, def string) string {
	if r := p.ruleFor(ruleName); r != nil && r.ifID != "" {
		return r.ifID
	}
	return def
}

// StripClientRelayOptions says whether a client's relay option is removed rather
// than refused.
func (p *Policy) StripClientRelayOptions() bool { return p.stripClientRelay }

// Delegating says whether prefix delegation is carried, for the status view.
func (p *Policy) Delegating() bool { return p.delegating }

func (p *Policy) ruleFor(name string) *rule {
	if name == "" {
		return nil
	}
	for _, r := range p.rules {
		if r.name == name {
			return r
		}
	}
	return nil
}

// The per-rule accessors, written so that a nil rule reads as "nothing set" and
// the caller needs no conditional.
func ruleDomains(r *rule) []string {
	if r == nil {
		return nil
	}
	return r.domains
}

func ruleURLs(r *rule) []string {
	if r == nil {
		return nil
	}
	return r.bootURLs
}

func ruleResolvers(r *rule) map[netip.Addr]bool {
	if r == nil {
		return nil
	}
	return r.resolvers
}

func firstAddrs(sets ...map[netip.Addr]bool) map[netip.Addr]bool {
	for _, s := range sets {
		if len(s) > 0 {
			return s
		}
	}
	return nil
}

func firstPats(pats ...[]string) []string {
	for _, p := range pats {
		if len(p) > 0 {
			return p
		}
	}
	return nil
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// matchAny matches a value against shell patterns.
//
// Square brackets are literal here rather than opening a character class, which
// is a deliberate departure from path.Match. Every pattern on this kind is
// matched against a domain name, a URL or a class string, and the one place a
// bracket turns up in any of those is around an IPv6 literal host:
// "tftp://[2001:db8::20]/*" is exactly what an operator writes for a boot
// server. Read as a character class that pattern matches nothing whatsoever,
// and it would fail silently -- an estate would write the list, see the
// validator stop warning, and have allowed no image at all -- on the option
// with the largest consequence in the protocol, which is the file a machine
// boots. Nothing matched here has any use for a character class.
//
// What is kept from path.Match is that * does not cross a /, which is worth
// having: it means a pattern cannot be walked out of with ../ .
func matchAny(pats []string, s string) bool {
	for _, pat := range pats {
		if pat == s {
			return true
		}
		if ok, err := path.Match(literalBrackets(pat), s); err == nil && ok {
			return true
		}
	}
	return false
}

// literalBrackets escapes the bracket characters so path.Match reads them as
// themselves. A pattern that escapes something already is left as it wrote it.
func literalBrackets(pat string) string {
	if !strings.ContainsAny(pat, "[]") {
		return pat
	}
	var b strings.Builder
	b.Grow(len(pat) + 8)
	for i := 0; i < len(pat); i++ {
		switch c := pat[i]; c {
		case '\\':
			b.WriteByte(c)
			if i+1 < len(pat) {
				i++
				b.WriteByte(pat[i])
			}
		case '[', ']':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// vendorClass is the vendor class option's text, past the four octets of
// enterprise number RFC 8415 s21.16 puts in front of it.
func vendorClass(m *wire.Message) string {
	v, ok := m.Get(wire.OptionVendorClass)
	if !ok || len(v) < 4 {
		return ""
	}
	return printable(v[4:])
}

// userClass is the user class option read as text.
//
// RFC 8415 s21.15 makes it a sequence of length-prefixed strings. A rule
// matches the first, which is what every client that sends one sends; a
// length that runs off the end of the option is not read as one, and the
// whole value is rendered instead.
func userClass(m *wire.Message) string {
	v, ok := m.Get(wire.OptionUserClass)
	if !ok {
		return ""
	}
	if len(v) >= 2 {
		if n := int(v[0])<<8 | int(v[1]); len(v) >= 2+n {
			return printable(v[2 : 2+n])
		}
	}
	return printable(v)
}

// printable is a value rendered for a rule to match and a log line to carry.
//
// It is a server's or a client's octets, so anything that is not printable ASCII
// is replaced: a vendor class with a control sequence in it would otherwise be a
// vendor class that moves a terminal's cursor when somebody reads the log.
func printable(v []byte) string {
	var b strings.Builder
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			b.WriteByte('.')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// alwaysCarried are the options a reply cannot be without: the two identifiers
// that pair it with the client and the server, the identity associations that
// carry the addresses, the status code that says what happened, and the relay's
// own message.
//
// Stripping any of them would be answering a client with a message that means
// nothing, which is a worse outcome than the option being carried.
func alwaysCarried(code uint16) bool {
	switch code {
	case wire.OptionClientID, wire.OptionServerID, wire.OptionIANA, wire.OptionIATA,
		wire.OptionIAPD, wire.OptionStatusCode, wire.OptionRelayMsg,
		wire.OptionPreference, wire.OptionRapidCommit, wire.OptionElapsedTime,
		wire.OptionInterfaceID, wire.OptionRemoteID, wire.OptionSubscriberID:
		return true
	}
	return false
}
