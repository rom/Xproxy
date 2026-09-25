package dhcp

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dhcp"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy. It has two halves, and the second is the unusual one.
//
// The *request* half is the ordinary shape: who may send, which message types,
// which hardware addresses, which vendor class. It is thin, because a DHCP
// client has nothing to identify it with.
//
// The *answer* half is where this kind earns its keep. A reply carries a
// machine's configuration -- its route, its resolvers, its proxy, its boot file
// -- and every one of those is checkable against what the estate actually has.
// That check catches a compromised real server as well as a rogue one, which no
// amount of trusting the source address does.

// Decision is what the policy says about one message.
type Decision struct {
	Allow bool
	// Rule is the rule that decided, empty for the default.
	Rule string
	// Reason and Detail name the refusal for the log and the counter.
	Reason, Detail string
	// Hard is a refusal a shadow-mode listener still enforces: a bound, a
	// message two parsers would read differently, or a reply from an address
	// that is not a server. The last of those is the one worth naming: a
	// listener that evaluated the server list without enforcing it would be
	// a listener that relays a rogue server's answer and writes it down.
	Hard bool
	// Strip are the options to remove from a reply before forwarding it, and
	// StripReasons says why each went, for the log line.
	Strip       []uint8
	StripReason map[uint8]string
	// Lease is the lease time to write into the reply when the server's own
	// is outside the bounds, and Bounded says one was applied.
	Lease   uint32
	Bounded bool
}

// stripped records an option to remove.
func (d *Decision) strip(code uint8, why string) {
	if d.StripReason == nil {
		d.StripReason = map[uint8]string{}
	}
	if _, dup := d.StripReason[code]; dup {
		return
	}
	d.Strip = append(d.Strip, code)
	d.StripReason[code] = why
}

// request is one message, as the policy sees it.
type request struct {
	// from is the address the datagram came from. On a segment this is
	// 0.0.0.0 for a client that has no address yet, which is why it is not
	// the main control.
	from netip.Addr
	msg  *wire.Message
	at   time.Time
}

// Policy is a compiled dhcp listener policy.
type Policy struct {
	allow, deny    []netip.Prefix
	servers        []netip.Prefix
	types          map[wire.MessageType]bool
	denyOpts       map[uint8]bool
	allowOpts      map[uint8]bool
	denyAsk        map[uint8]bool
	gateways       map[netip.Addr]bool
	resolvers      map[netip.Addr]bool
	bootServers    map[netip.Addr]bool
	routes         []netip.Prefix
	bootFiles      []string
	stripOnDeny    bool
	stripAgent     bool
	requireIDMatch bool
	refuseHidden   bool
	minLease       uint32
	maxLease       uint32
	rules          []*rule
	allowByDef     bool
	now            func() time.Time
}

// rule is one compiled rule.
type rule struct {
	name        string
	action      string
	clients     []netip.Prefix
	hardware    [][]byte
	types       map[wire.MessageType]bool
	vendor      []string
	user        []string
	denyOpts    map[uint8]bool
	gateways    map[netip.Addr]bool
	resolvers   map[netip.Addr]bool
	bootServers map[netip.Addr]bool
	routes      []netip.Prefix
	bootFiles   []string
	maxLease    uint32
	circuit     string
	sched       *schedule.Window
}

func compile(m *config.DHCPListener, now func() time.Time) (*Policy, error) {
	p := &Policy{now: now, allowByDef: m.DefaultAction != "deny",
		stripOnDeny:    m.OnDeniedOption != "deny",
		stripAgent:     m.OnClientAgentOption != "deny",
		requireIDMatch: m.RequireClientIDMatch,
		refuseHidden:   m.RefuseHiddenOptions == nil || *m.RefuseHiddenOptions,
		bootFiles:      m.BootFiles,
	}
	var err error
	if p.allow, err = prefixes(m.AllowClients); err != nil {
		return nil, fmt.Errorf("dhcp allow_clients: %w", err)
	}
	if p.deny, err = prefixes(m.DenyClients); err != nil {
		return nil, fmt.Errorf("dhcp deny_clients: %w", err)
	}
	if p.servers, err = prefixes(m.AllowServers); err != nil {
		return nil, fmt.Errorf("dhcp allow_servers: %w", err)
	}
	if p.routes, err = prefixes(m.AllowRoutes); err != nil {
		return nil, fmt.Errorf("dhcp allow_routes: %w", err)
	}
	// The default message-type list is the ordinary lease cycle plus inform.
	// It leaves out the lease-query family: that is a relay agent's own
	// diagnostic, and an inventory of every lease in the estate to anything
	// else.
	if p.types, err = types(m.MessageTypes, map[wire.MessageType]bool{
		wire.Discover: true, wire.Request: true, wire.Decline: true,
		wire.Release: true, wire.Inform: true,
	}); err != nil {
		return nil, err
	}
	// The default deny list is the options that carry a configuration rather
	// than a value.
	def := map[uint8]bool{}
	for _, c := range wire.DangerousOptions {
		def[c] = true
	}
	if p.denyOpts, err = optSet(m.DenyOptions, def); err != nil {
		return nil, err
	}
	if p.allowOpts, err = optSet(m.AllowOptions, nil); err != nil {
		return nil, err
	}
	if p.denyAsk, err = optSet(m.DenyRequestedOptions, nil); err != nil {
		return nil, err
	}
	if p.gateways, err = addrSet(m.AllowGateways); err != nil {
		return nil, fmt.Errorf("dhcp allow_gateways: %w", err)
	}
	if p.resolvers, err = addrSet(m.AllowResolvers); err != nil {
		return nil, fmt.Errorf("dhcp allow_resolvers: %w", err)
	}
	if p.bootServers, err = addrSet(m.AllowBootServers); err != nil {
		return nil, fmt.Errorf("dhcp allow_boot_servers: %w", err)
	}
	p.minLease = leaseSeconds(m.MinLeaseTime)
	p.maxLease = leaseSeconds(m.MaxLeaseTime)
	for i := range m.Rules {
		r, err := compileRule(&m.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(c *config.DHCPRule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, vendor: c.VendorClasses,
		user: c.UserClasses, bootFiles: c.BootFiles, circuit: c.CircuitID,
		maxLease: leaseSeconds(c.MaxLeaseTime)}
	if r.action == "" {
		r.action = "allow"
	}
	var err error
	if r.clients, err = prefixes(c.Clients); err != nil {
		return nil, fmt.Errorf("dhcp rule %s clients: %w", c.Name, err)
	}
	if r.routes, err = prefixes(c.AllowRoutes); err != nil {
		return nil, fmt.Errorf("dhcp rule %s allow_routes: %w", c.Name, err)
	}
	for _, h := range c.HardwareAddresses {
		b, err := wire.ParseHardwareAddr(h)
		if err != nil {
			return nil, fmt.Errorf("dhcp rule %s hardware_addresses: %w", c.Name, err)
		}
		r.hardware = append(r.hardware, b)
	}
	if r.types, err = types(c.MessageTypes, nil); err != nil {
		return nil, err
	}
	if r.denyOpts, err = optSet(c.DenyOptions, nil); err != nil {
		return nil, err
	}
	if r.gateways, err = addrSet(c.AllowGateways); err != nil {
		return nil, fmt.Errorf("dhcp rule %s allow_gateways: %w", c.Name, err)
	}
	if r.resolvers, err = addrSet(c.AllowResolvers); err != nil {
		return nil, fmt.Errorf("dhcp rule %s allow_resolvers: %w", c.Name, err)
	}
	if r.bootServers, err = addrSet(c.AllowBootServers); err != nil {
		return nil, fmt.Errorf("dhcp rule %s allow_boot_servers: %w", c.Name, err)
	}
	if r.sched, err = schedule.Compile(c.Schedule); err != nil {
		return nil, err
	}
	return r, nil
}

// leaseSeconds is a configured duration as DHCP's own four-octet second count.
//
// Validation bounds a lease to a year, so the conversion cannot overflow; the
// guard is here rather than in a comment because a bound that moved would
// otherwise turn a long lease into a very short one, which is worse than
// refusing it.
func leaseSeconds(d config.Duration) uint32 {
	secs := int64(d.D() / time.Second)
	if secs <= 0 {
		return 0
	}
	if secs > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(secs)
}

func prefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func addrSet(in []string) (map[netip.Addr]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[netip.Addr]bool, len(in))
	for _, s := range in {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		if !a.Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 address", s)
		}
		out[a] = true
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
			return nil, fmt.Errorf("dhcp message_types: %q is not a message type", s)
		}
		out[t] = true
	}
	return out, nil
}

// optSet compiles an option list. The framing codes and the message type are
// refused here as well as by validation, because a policy built by hand in a
// test is still a policy: an option list that could strip the message type
// would produce a message no rule could be written about.
func optSet(in []string, def map[uint8]bool) (map[uint8]bool, error) {
	if len(in) == 0 {
		return def, nil
	}
	out := map[uint8]bool{}
	for _, s := range in {
		c, ok := wire.OptionOf(s)
		if !ok {
			return nil, fmt.Errorf("dhcp options: %q is not an option", s)
		}
		switch c {
		case wire.OptPad, wire.OptEnd:
			return nil, fmt.Errorf("dhcp options: %q is framing, not an option", s)
		case wire.OptMessageType:
			return nil, fmt.Errorf("dhcp options: the message type cannot be stripped")
		}
		out[c] = true
	}
	return out, nil
}

// Client says whether an address may send at all. Deny is evaluated first, and
// an empty allow list admits everything -- which on a segment is the only thing
// it can do, because a client with no address yet sends from 0.0.0.0.
func (p *Policy) Client(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, n := range p.deny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.allow) == 0 {
		return true
	}
	// The unspecified address is what an on-segment client sends before it has
	// one. A list of networks cannot include it meaningfully, so it is
	// admitted: refusing it would refuse every first-time client, which is
	// every client this listener exists for.
	if ip.IsUnspecified() {
		return true
	}
	for _, n := range p.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Server says whether an address may answer.
//
// This is the rogue-server check, and it is the most valuable line in the
// policy. An empty list means the caller supplies the upstream pool's own
// endpoints, so it is never open by accident: newServer passes them in.
func (p *Policy) Server(ip netip.Addr) bool {
	for _, n := range p.servers {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Decide decides one message from a client.
func (p *Policy) Decide(req request) Decision {
	m := req.msg
	if p.refuseHidden && m.Hidden() {
		// Not shadowable: an option hidden in the boot filename field or split
		// across instances is a message this relay and the server may read
		// differently, and a decision about a message the server reads
		// differently is not a decision.
		return Decision{Reason: "hidden_options", Detail: hiddenDetail(m), Hard: true}
	}
	if p.requireIDMatch {
		if ok, detail := clientIDMatches(m); !ok {
			return Decision{Reason: "client_id_mismatch", Detail: detail}
		}
	}
	if len(p.types) > 0 && !p.types[m.Type] {
		return Decision{Reason: "message_type", Detail: m.Type.String()}
	}
	for _, r := range p.rules {
		if !r.matches(req) {
			continue
		}
		d := Decision{Rule: r.name}
		switch r.action {
		case "deny":
			d.Reason, d.Detail = "rule", m.Type.String()
			return d
		case "observe":
			continue
		}
		d.Allow = true
		return d
	}
	d := Decision{Allow: p.allowByDef}
	if !d.Allow {
		d.Reason, d.Detail = "default_deny", m.Type.String()
	}
	return d
}

// Answer decides one reply from a server, and says what to remove from it.
//
// This is the half that matters. A reply is a configuration: an address, a
// route, a set of resolvers, a proxy, a boot file. Each is checked against what
// the estate has, which is a check that a compromised real server fails as
// surely as a rogue one.
func (p *Policy) Answer(req request, reqRule string) Decision {
	m := req.msg
	d := Decision{Allow: true, Rule: reqRule}
	if p.refuseHidden && m.Hidden() {
		return Decision{Reason: "hidden_options", Detail: hiddenDetail(m), Hard: true, Rule: reqRule}
	}
	if !m.Type.FromServer() {
		// A message type only a client sends, arriving from the server side.
		// The direction and the type disagreeing is itself the finding.
		return Decision{Reason: "wrong_direction", Detail: m.Type.String(), Hard: true, Rule: reqRule}
	}
	r := p.ruleFor(reqRule)
	// A rule that says what an option may *contain* is a rule that allows the
	// option. This is the same turn the attribute policy makes on the LDAP
	// kind: naming the contents is the positive form of the permission, and
	// without it "the build segment may be told a boot server and nothing else
	// may" could not be written -- the listener's own deny list would strip the
	// boot options from the rule's traffic too.
	permitted := r.permits()
	// The option lists: an option that is going to be removed does not need its
	// contents checked.
	for _, o := range m.Options {
		switch {
		case permitted[o.Code]:
			continue
		case p.allowOpts != nil && !p.allowOpts[o.Code] && !alwaysCarried(o.Code):
			d.strip(o.Code, "not_allowed")
		case p.denyOpts[o.Code], r != nil && r.denyOpts[o.Code]:
			d.strip(o.Code, "denied")
		}
	}
	if !m.Type.Assigns() {
		// A NAK or a FORCERENEW carries no configuration to check.
		return p.bound(m, d)
	}
	stripped := func(c uint8) bool { _, ok := d.StripReason[c]; return ok }
	// The addresses. Each is checked only when the estate said what its own
	// are: a list nobody wrote cannot refuse anything, and pretending
	// otherwise would make an empty configuration look like a policy.
	for _, c := range []struct {
		code  uint8
		allow map[netip.Addr]bool
		rule  map[netip.Addr]bool
	}{
		{wire.OptRouter, p.gateways, ruleAddrs(r, wire.OptRouter)},
		{wire.OptDNS, p.resolvers, ruleAddrs(r, wire.OptDNS)},
	} {
		set := c.allow
		if c.rule != nil {
			set = c.rule
		}
		if set == nil || stripped(c.code) {
			continue
		}
		v, ok := m.Get(c.code)
		if !ok {
			continue
		}
		as, err := wire.Addresses(v)
		if err != nil {
			return Decision{Reason: "malformed_option",
				Detail: wire.OptionName(c.code), Hard: true, Rule: reqRule}
		}
		for _, a := range as {
			if !set[a] {
				d.strip(c.code, "address_not_allowed")
				d.Detail = wire.OptionName(c.code) + " " + a.String()
				break
			}
		}
	}
	// The boot server, which is where a machine that boots from the network
	// gets its image. It appears in two places -- option 66 and the siaddr
	// header field -- and a check that looked at only one would be a check
	// with a way round it.
	if set := firstSet(ruleAddrs(r, wire.OptTFTPServer), p.bootServers); set != nil {
		if v, ok := m.Get(wire.OptTFTPServer); ok && !stripped(wire.OptTFTPServer) {
			if a, err := wire.Address(v); err == nil {
				if !set[a] {
					d.strip(wire.OptTFTPServer, "address_not_allowed")
					d.Detail = "tftp_server " + a.String()
				}
			} else if !isName(v) {
				return Decision{Reason: "malformed_option", Detail: "tftp_server",
					Hard: true, Rule: reqRule}
			}
		}
		if m.SIAddr.IsValid() && !m.SIAddr.IsUnspecified() && !set[m.SIAddr] {
			return Decision{Reason: "boot_server_not_allowed",
				Detail: m.SIAddr.String(), Rule: reqRule}
		}
	}
	// The boot filename, which appears in option 67 and in the file field.
	if pats := firstPats(r, p.bootFiles); len(pats) > 0 {
		for _, name := range []string{m.File, optString(m, wire.OptBootFile)} {
			if name == "" || stripped(wire.OptBootFile) {
				continue
			}
			if !matchAny(pats, name) {
				return Decision{Reason: "boot_file_not_allowed",
					Detail: safeName(name), Rule: reqRule}
			}
		}
	}
	// The routes, which are the most direct interception in the protocol. The
	// refusal names the route, because an operator who sees one stopped is
	// owed the route rather than an option number.
	for _, code := range []uint8{wire.OptClasslessRoute, wire.OptMSClasslessRoute} {
		v, ok := m.Get(code)
		if !ok || stripped(code) {
			continue
		}
		rs, err := wire.Routes(v)
		if err != nil {
			return Decision{Reason: "malformed_option", Detail: wire.OptionName(code),
				Hard: true, Rule: reqRule}
		}
		allowed := firstPrefixes(r, p.routes)
		for _, rt := range rs {
			if !containsPrefix(allowed, rt.Dest) {
				d.strip(code, "route_not_allowed")
				d.Detail = rt.String()
				break
			}
		}
	}
	return p.bound(m, d)
}

// bound applies the lease bounds, which are bounds rather than policy: a lease
// of a year is an address pool exhausted by every device that ever visited, and
// a listener in shadow mode should still not relay one.
func (p *Policy) bound(m *wire.Message, d Decision) Decision {
	v, ok := m.Get(wire.OptLeaseTime)
	if !ok {
		return d
	}
	secs, err := wire.Seconds(v)
	if err != nil {
		d.Allow = false
		d.Reason, d.Detail, d.Hard = "malformed_option", "lease_time", true
		return d
	}
	r := p.ruleFor(d.Rule)
	max := p.maxLease
	if r != nil && r.maxLease > 0 {
		max = r.maxLease
	}
	switch {
	case max > 0 && secs > max:
		d.Lease, d.Bounded = max, true
	case p.minLease > 0 && secs < p.minLease:
		d.Lease, d.Bounded = p.minLease, true
	}
	return d
}

// AskDenied are the options a client may not ask for, which are removed from
// its parameter list rather than the message being refused: a client that asked
// for a proxy and is not told about one is a client that works.
func (p *Policy) AskDenied(list []byte) ([]byte, []uint8) {
	if len(p.denyAsk) == 0 || len(list) == 0 {
		return list, nil
	}
	out := make([]byte, 0, len(list))
	var removed []uint8
	for _, c := range list {
		if p.denyAsk[c] {
			removed = append(removed, c)
			continue
		}
		out = append(out, c)
	}
	if len(removed) == 0 {
		return list, nil
	}
	return out, removed
}

// CircuitFor is the circuit identifier a rule named, or the listener's.
func (p *Policy) CircuitFor(ruleName, def string) string {
	if r := p.ruleFor(ruleName); r != nil && r.circuit != "" {
		return r.circuit
	}
	return def
}

// StripAgent says whether a client's own option 82 is stripped rather than the
// message refused.
func (p *Policy) StripAgent() bool { return p.stripAgent }

// StripDenied says whether a denied option is removed rather than the whole
// reply refused.
func (p *Policy) StripDenied() bool { return p.stripOnDeny }

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

// permits are the options a rule allows by saying what they may contain.
//
// A rule with a boot-server list is a rule about machines that boot from the
// network, so the option that names their boot server is not stripped from
// their replies -- it is checked against the list instead. The same for the
// boot filename and for the routes. A nil rule permits nothing extra, which is
// what makes the listener's own lists the default.
func (r *rule) permits() map[uint8]bool {
	if r == nil {
		return nil
	}
	out := map[uint8]bool{}
	if len(r.bootServers) > 0 {
		out[wire.OptTFTPServer] = true
	}
	if len(r.bootFiles) > 0 {
		out[wire.OptBootFile] = true
	}
	if len(r.routes) > 0 {
		out[wire.OptClasslessRoute] = true
		out[wire.OptMSClasslessRoute] = true
	}
	// An option the rule itself denies is denied whatever else the rule says,
	// because a deny somebody wrote is a deny.
	for c := range r.denyOpts {
		delete(out, c)
	}
	return out
}

// matches says whether a rule covers a message.
func (r *rule) matches(req request) bool {
	m := req.msg
	if len(r.clients) > 0 && !contains(r.clients, req.from) {
		return false
	}
	if len(r.types) > 0 && !r.types[m.Type] {
		return false
	}
	if len(r.hardware) > 0 && !hardwareMatches(r.hardware, m.CHAddr) {
		return false
	}
	if len(r.vendor) > 0 && !matchAny(r.vendor, optString(m, wire.OptVendorClass)) {
		return false
	}
	if len(r.user) > 0 && !matchAny(r.user, optString(m, wire.OptUserClass)) {
		return false
	}
	return r.sched.InForce(req.at)
}

// hardwareMatches compares a hardware address against a rule's list, where an
// entry shorter than the address is a vendor prefix: three octets is an OUI,
// which is what a rule about "the telephones" is written with.
func hardwareMatches(list [][]byte, hw []byte) bool {
	for _, want := range list {
		if len(want) > len(hw) {
			continue
		}
		match := true
		for i := range want {
			if want[i] != hw[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// containsPrefix says whether a destination lies inside any allowed prefix. It
// is prefix containment rather than equality, so "10.0.0.0/8" allows a route to
// 10.1.0.0/16 and not one to 0.0.0.0/0.
func containsPrefix(allowed []netip.Prefix, dest netip.Prefix) bool {
	for _, a := range allowed {
		if a.Bits() <= dest.Bits() && a.Contains(dest.Addr()) {
			return true
		}
	}
	return false
}

func ruleAddrs(r *rule, code uint8) map[netip.Addr]bool {
	if r == nil {
		return nil
	}
	switch code {
	case wire.OptRouter:
		return r.gateways
	case wire.OptDNS:
		return r.resolvers
	case wire.OptTFTPServer:
		return r.bootServers
	}
	return nil
}

func firstSet(sets ...map[netip.Addr]bool) map[netip.Addr]bool {
	for _, s := range sets {
		if s != nil {
			return s
		}
	}
	return nil
}

func firstPats(r *rule, def []string) []string {
	if r != nil && len(r.bootFiles) > 0 {
		return r.bootFiles
	}
	return def
}

func firstPrefixes(r *rule, def []netip.Prefix) []netip.Prefix {
	if r != nil && len(r.routes) > 0 {
		return r.routes
	}
	return def
}

func matchAny(pats []string, s string) bool {
	if s == "" {
		return false
	}
	for _, pat := range pats {
		if ok, err := path.Match(pat, s); err == nil && ok {
			return true
		}
	}
	return false
}

// optString reads an option as the text it is, for the options whose values are
// names: the vendor class, the user class, the boot filename.
func optString(m *wire.Message, code uint8) string {
	v, ok := m.Get(code)
	if !ok {
		return ""
	}
	return strings.TrimRight(string(v), "\x00")
}

// isName says whether an option's value looks like a host name rather than an
// address, which option 66 is allowed to be.
func isName(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// alwaysCarried are the options a positive list does not have to name, because
// stripping them would produce a message that is not a DHCP message: the type
// itself, and the server identifier a client must echo in its REQUEST.
func alwaysCarried(code uint8) bool {
	return code == wire.OptMessageType || code == wire.OptServerID
}

// clientIDMatches says whether option 61's Ethernet form names the hardware
// address in the header.
//
// RFC 2132 §9.14 makes the first octet a type, and type 1 means "the rest is a
// hardware address of htype 1". A client whose identifier names a different
// address from its own header is either a badly-written stack or something
// asking for a lease that belongs to somebody else.
func clientIDMatches(m *wire.Message) (bool, string) {
	v, ok := m.Get(wire.OptClientID)
	if !ok || len(v) < 2 || v[0] != wire.HTypeEthernet {
		// No identifier, or one that is not the hardware form. There is
		// nothing to compare, and RFC 2132 explicitly allows any opaque
		// value, so this is not a finding.
		return true, ""
	}
	if string(v[1:]) == string(m.CHAddr) {
		return true, ""
	}
	return false, wire.HardwareAddr(v[1:]) + " in a message from " + wire.HardwareAddr(m.CHAddr)
}

// hiddenDetail says which encoding a message used, for the refusal's log line.
func hiddenDetail(m *wire.Message) string {
	var parts []string
	for _, o := range m.Options {
		if o.Split {
			parts = append(parts, wire.OptionName(o.Code)+" split")
		}
		if o.Where&^wire.InOptions != 0 {
			parts = append(parts, wire.OptionName(o.Code)+" in "+o.Where.String())
		}
	}
	return strings.Join(parts, ", ")
}
