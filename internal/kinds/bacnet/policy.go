// Package bacnet is the kind: bacnet listener: a BACnet/IP relay that
// reads what it forwards.
//
// The protocol has no identity at all -- no user, no session, no
// authentication that anything in the field implements -- so this
// listener's whole job is to decide about a datagram from three things:
// the address it came from, the service it asks for, and the object and
// property it names. Everything below is one of those three, a bound on
// the protocol's own amplification, or the record somebody asks for
// afterwards.
package bacnet

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/schedule"
)

// Decision is one policy answer.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in shadow mode. A bound is hard;
	// a policy choice is not.
	Hard bool
	Rule string
}

func allow(rule string) Decision { return Decision{Allow: true, Rule: rule} }
func denyWith(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail}
}
func hardDeny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}

// The network priorities of clause 6.2.2, by the names a configuration
// file uses.
var priorityNames = map[string]uint8{
	"normal": 0, "urgent": 1, "critical-equipment": 2, "life-safety": 3,
}

var priorityByValue = [4]string{"normal", "urgent", "critical-equipment", "life-safety"}

// request is what the policy decides about: one client's datagram, read
// as far as this relay reads it.
type request struct {
	client netip.Addr
	// fn is the virtual link function, which decides before anything
	// inside it does: a BBMD registration is refused without reading an
	// application layer it does not have.
	fn wire.Function
	// npdu and apdu are present when the message carried them.
	npdu    *wire.NPDU
	apdu    *wire.APDU
	targets []wire.Target
	// located says whether the objects in targets are the ones the
	// request is about, or whether this relay could not find them.
	located bool
	at      time.Time
}

// instanceRange is one rule's bound on object instance numbers.
type instanceRange struct{ low, high uint32 }

func (r instanceRange) holds(n uint32) bool { return n >= r.low && n <= r.high }

type rule struct {
	name    string
	action  string
	observe bool

	clients   []netip.Prefix
	services  map[wire.Service]bool
	objects   map[wire.ObjectType]bool
	denyObj   map[wire.ObjectType]bool
	instances []instanceRange
	props     map[wire.PropertyID]bool
	denyProps map[wire.PropertyID]bool
	networks  map[uint16]bool

	maxPriority int
	sched       *schedule.Window
}

type policy struct {
	allowIPs, denyIPs []netip.Prefix

	services     map[wire.Service]bool
	denyServices map[wire.Service]bool

	objects   map[wire.ObjectType]bool
	denyObj   map[wire.ObjectType]bool
	props     map[wire.PropertyID]bool
	denyProps map[wire.PropertyID]bool
	// objectRules says whether any object or property rule exists at all,
	// which is what makes an unlocated object a refusal rather than a
	// thing nobody asked about.
	objectRules bool

	maxPriority     int
	allowSensitive  bool
	refuseUnlocated bool

	broadcast bool
	bbmd      bool
	forwarded bool
	netMsgs   bool
	routing   bool
	security  bool
	segmented bool

	networks   map[uint16]bool
	maxHop     uint8
	maxNetPrio uint8
	maxWhoIs   int
	needWhoIs  bool
	maxMessage int

	rules []*rule

	allowByDef bool
}

// hopBound narrows the configured hop count to the octet the protocol
// carries it in. The validator refuses one outside the range, and this
// clamps anyway: compile is also called from tests and from wherever a
// future caller puts it, and a bound that wrapped would be a bound that
// raised itself.
func hopBound(n int) uint8 {
	switch {
	case n <= 0:
		return 8
	case n > 255:
		return 255
	}
	return uint8(n) //nolint:gosec // between 1 and 255 by the two lines above
}

// or returns the configured value or a default, which is the idiom every
// sibling kind uses for a bound that has one.
func or[T int | int64 | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// compile turns the configuration into the policy the relay runs. Every
// name is resolved here rather than per datagram, so a listener that
// starts is a listener whose rules were all understood.
func compile(c *config.BACnetListener) (*policy, error) {
	p := &policy{
		maxPriority:     or(c.MaxCommandPriority, 8),
		allowSensitive:  !boolOr(c.DenySensitiveWrites, true),
		refuseUnlocated: boolOr(c.RefuseUnlocatedObjects, true),
		broadcast:       boolOr(c.AllowBroadcast, false),
		bbmd:            boolOr(c.AllowBBMD, false),
		forwarded:       boolOr(c.AllowForwarded, false),
		netMsgs:         boolOr(c.AllowNetworkMessages, false),
		routing:         boolOr(c.AllowRouting, false),
		security:        boolOr(c.AllowSecurityMessages, false),
		segmented:       boolOr(c.AllowSegmented, true),
		maxHop:          hopBound(c.MaxHopCount),
		maxWhoIs:        c.MaxWhoIsRange,
		needWhoIs:       boolOr(c.RequireWhoIsRange, false),
		maxMessage:      or(c.MaxMessageBytes, wire.MaxMessage),
		allowByDef:      c.DefaultAction == "allow",
	}
	var err error
	if p.allowIPs, err = prefixes(c.AllowClients); err != nil {
		return nil, fmt.Errorf("allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("deny_clients: %w", err)
	}
	names := c.Services
	if len(names) == 0 {
		names = wire.DefaultServices()
	}
	if p.services, err = services(names); err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	if p.denyServices, err = services(c.DenyServices); err != nil {
		return nil, fmt.Errorf("deny_services: %w", err)
	}
	if p.objects, err = objectTypes(c.Objects); err != nil {
		return nil, fmt.Errorf("objects: %w", err)
	}
	if p.denyObj, err = objectTypes(c.DenyObjects); err != nil {
		return nil, fmt.Errorf("deny_objects: %w", err)
	}
	if p.props, err = properties(c.Properties); err != nil {
		return nil, fmt.Errorf("properties: %w", err)
	}
	if p.denyProps, err = properties(c.DenyProperties); err != nil {
		return nil, fmt.Errorf("deny_properties: %w", err)
	}
	p.networks = networkSet(c.Networks)
	if p.maxNetPrio, err = priority(c.MaxPriority, 1); err != nil {
		return nil, err
	}
	p.objectRules = len(p.objects) > 0 || len(p.denyObj) > 0 ||
		len(p.props) > 0 || len(p.denyProps) > 0
	for i := range c.Rules {
		r, err := compileRule(&c.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", c.Rules[i].Name, err)
		}
		if len(r.objects) > 0 || len(r.denyObj) > 0 || len(r.props) > 0 ||
			len(r.denyProps) > 0 || len(r.instances) > 0 {
			p.objectRules = true
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(c *config.BACnetRule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, observe: c.Action == "observe",
		maxPriority: c.MaxCommandPriority}
	var err error
	if r.clients, err = prefixes(c.Clients); err != nil {
		return nil, fmt.Errorf("clients: %w", err)
	}
	if r.services, err = services(c.Services); err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	if r.objects, err = objectTypes(c.Objects); err != nil {
		return nil, fmt.Errorf("objects: %w", err)
	}
	if r.denyObj, err = objectTypes(c.DenyObjects); err != nil {
		return nil, fmt.Errorf("deny_objects: %w", err)
	}
	if r.props, err = properties(c.Properties); err != nil {
		return nil, fmt.Errorf("properties: %w", err)
	}
	if r.denyProps, err = properties(c.DenyProperties); err != nil {
		return nil, fmt.Errorf("deny_properties: %w", err)
	}
	if r.instances, err = ranges(c.Instances); err != nil {
		return nil, fmt.Errorf("instances: %w", err)
	}
	r.networks = networkSet(c.Networks)
	if c.Schedule != nil {
		if r.sched, err = schedule.Compile(c.Schedule); err != nil {
			return nil, fmt.Errorf("schedule: %w", err)
		}
	}
	return r, nil
}

// Client reports whether a client may send here at all. Deny is evaluated
// first, and an empty allow list allows any -- which validation advises
// against on this protocol, because the client list is the only identity
// there is.
func (p *policy) Client(ip netip.Addr) bool {
	if contains(p.denyIPs, ip) {
		return false
	}
	return len(p.allowIPs) == 0 || contains(p.allowIPs, ip)
}

// Link decides about the virtual link layer, before anything inside it is
// read. A BBMD registration and a broadcast are decided here because
// neither is about a service: they are about what the link layer is being
// asked to do with the message.
func (p *policy) Link(fn wire.Function) Decision {
	switch {
	case fn.BBMD() && !p.bbmd:
		// Register-Foreign-Device subscribes an address to every broadcast
		// on a network it is not on, and Read-Broadcast-Distribution-Table
		// hands over the estate's BACnet routing. Both from one
		// unauthenticated datagram.
		return denyWith("bbmd_not_allowed", fn.String())
	case fn == wire.FuncForwardedNPDU && !p.forwarded:
		return denyWith("forwarded_not_allowed", fn.String())
	case fn.Broadcast() && fn != wire.FuncForwardedNPDU && !p.broadcast:
		return denyWith("broadcast_not_allowed", fn.String())
	case fn == wire.FuncSecureBVLL && !p.security:
		// A relay cannot read inside a secure wrapper, which is the point
		// of it. Forwarding one would be forwarding a message this
		// listener did not decide about.
		return denyWith("security_not_allowed", fn.String())
	}
	return Decision{Allow: true}
}

// Network decides about the network layer: where a message is being routed
// to, how many hops it may take, what queue it claims, and whether it is
// the routers talking among themselves.
func (p *policy) Network(n wire.NPDU) Decision {
	if n.Priority > p.maxNetPrio {
		// The priority decides what a congested router drops. A client
		// that marks everything life safety has taken a queue from the
		// traffic that is life safety.
		return denyWith("priority_not_allowed", priorityByValue[n.Priority])
	}
	if n.HasDest {
		if len(p.networks) == 0 {
			return denyWith("routing_not_allowed", "network "+strconv.Itoa(int(n.DNET)))
		}
		if !p.networks[n.DNET] {
			return denyWith("network_not_allowed", strconv.Itoa(int(n.DNET)))
		}
	}
	if !n.NetworkMessage {
		return Decision{Allow: true}
	}
	switch {
	case !p.netMsgs:
		return denyWith("network_message_not_allowed", n.MessageType.String())
	case n.MessageType.Routing() && !p.routing:
		// Initialize-Routing-Table rewrites a router's table from an
		// unauthenticated message, which takes a whole BACnet network off
		// the air or puts somebody else's address in front of one.
		return denyWith("routing_message_not_allowed", n.MessageType.String())
	case n.MessageType.Security() && !p.security:
		return denyWith("security_message_not_allowed", n.MessageType.String())
	case !n.MessageType.Known():
		return denyWith("network_message_unknown", n.MessageType.String())
	}
	return Decision{Allow: true}
}

// Decide is the application layer decision: the service, the objects and
// properties it names, and the priority a write asks for.
//
// The order is deliberate. The rule is found first, because a rule can
// widen what its traffic may name and raise the priority it may use, and a
// check run before the rule was known would be checking the wrong bound.
// Then the bounds, before the policy choices -- a bound is never shadowed,
// so a soft refusal found first would hide a hard one behind it and a
// listener in shadow mode would carry a request that violates the bound.
func (p *policy) Decide(r request) Decision {
	a := r.apdu
	if a == nil || !a.HasService {
		// A reply shape with no service choice -- a reject, an abort, a
		// segment acknowledgement. There is nothing here to decide about,
		// and the relay's pairing decides whether it is forwarded.
		return Decision{Allow: true}
	}
	// The rules, in order, first match wins. An observe rule logs and keeps
	// looking, which is how a rule is tried before it decides.
	var ru *rule
	for _, x := range p.rules {
		if !x.matches(r) || x.observe {
			continue
		}
		ru = x
		break
	}
	if d, ok := p.whoIsCheck(a); !ok {
		return d
	}
	if d, ok := p.priorityCheck(a, ru); !ok {
		return d
	}
	if a.Segmented && !p.segmented {
		return denyWith("segmented_not_allowed", a.Service.Name())
	}
	if d, ok := p.serviceCheck(a.Service); !ok {
		return d
	}
	if d, ok := p.objectCheck(r, ru); !ok {
		return d
	}
	switch {
	case ru != nil && ru.action == "deny":
		return Decision{Reason: "rule_denied", Rule: ru.name, Detail: a.Service.Name()}
	case ru != nil:
		return allow(ru.name)
	case p.allowByDef:
		return Decision{Allow: true}
	}
	return denyWith("no_rule_matched", a.Service.Name())
}

// serviceCheck applies the listener's service lists. The deny list wins,
// and a service outside the allow list is refused whatever the rules say:
// a rule widens what a matching request may name, not which services this
// listener carries at all.
func (p *policy) serviceCheck(s wire.Service) (Decision, bool) {
	switch {
	case p.denyServices[s]:
		return denyWith("service_denied", s.Name()), false
	case !s.Known():
		// A choice no edition of the standard defines. It cannot be in an
		// allow list written in names, and letting it through would be
		// deciding by the gap in a table.
		return denyWith("service_unknown", s.Name()), false
	case !p.services[s]:
		return denyWith("service_not_allowed", s.Name()), false
	}
	return Decision{}, true
}

// whoIsCheck bounds the discovery sweep. A Who-Is with no range asks every
// device on the network to answer at once, which is both the protocol's
// amplifier and the first thing anybody does on arriving.
func (p *policy) whoIsCheck(a *wire.APDU) (Decision, bool) {
	if a.Service.Confirmed || a.Service.Choice != wire.WhoIs {
		return Decision{}, true
	}
	low, high, bounded := wire.DeviceRange(*a)
	if !bounded {
		if p.needWhoIs {
			return hardDeny("whois_unbounded", ""), false
		}
		return Decision{}, true
	}
	if p.maxWhoIs > 0 && int(high-low)+1 > p.maxWhoIs {
		return hardDeny("whois_range_too_wide", strconv.Itoa(int(high-low)+1)), false
	}
	return Decision{}, true
}

// priorityCheck applies the command priority bound: the listener's, or a
// rule's own when the matching rule set one.
func (p *policy) priorityCheck(a *wire.APDU, ru *rule) (Decision, bool) {
	want := p.maxPriority
	if ru != nil && ru.maxPriority != 0 {
		// A rule that sets no bound of its own takes the listener's rather
		// than none: a rule is how an exception is written down, and an
		// exception nobody wrote is not one.
		want = ru.maxPriority
	}
	got, ok := wire.CommandPriority(*a)
	if !ok {
		return Decision{}, true
	}
	if int(got) < want {
		// Lower is more privileged. A write at 1 or 2 stands until whoever
		// wrote it relinquishes it, over the management system, the
		// schedules and the operator.
		d := hardDeny("command_priority_too_high", strconv.Itoa(int(got)))
		if ru != nil {
			d.Rule = ru.name
		}
		return d, false
	}
	return Decision{}, true
}

// objectCheck applies the object and property lists, the instance ranges
// of a matching rule, and the sensitive-write refusal.
func (p *policy) objectCheck(r request, ru *rule) (Decision, bool) {
	if !p.objectRules && p.allowSensitive {
		return Decision{}, true
	}
	if !r.located {
		if p.objectRules && p.refuseUnlocated {
			return denyWith("object_unlocatable", r.apdu.Service.Name()), false
		}
		return Decision{}, true
	}
	writes := r.apdu.Service.Writes()
	for _, t := range r.targets {
		if d, ok := p.objectOne(t, writes, ru); !ok {
			return d, false
		}
	}
	return Decision{}, true
}

func (p *policy) objectOne(t wire.Target, writes bool, ru *rule) (Decision, bool) {
	obj, props, deny := p.objects, p.props, p.denyProps
	denyObj := p.denyObj
	if ru != nil {
		if len(ru.objects) > 0 {
			obj = ru.objects
		}
		if len(ru.denyObj) > 0 {
			denyObj = ru.denyObj
		}
		if len(ru.props) > 0 {
			props = ru.props
		}
		if len(ru.denyProps) > 0 {
			deny = ru.denyProps
		}
	}
	name := t.Object.String()
	switch {
	case denyObj[t.Object.Type]:
		return withRule(denyWith("object_denied", name), ru), false
	case len(obj) > 0 && !obj[t.Object.Type]:
		return withRule(denyWith("object_not_allowed", name), ru), false
	}
	if ru != nil && len(ru.instances) > 0 && !inAny(ru.instances, t.Object.Instance) {
		return withRule(denyWith("instance_not_allowed", name), ru), false
	}
	if !t.HasProperty {
		return Decision{}, true
	}
	pn := name + "." + t.Property.String()
	switch {
	case deny[t.Property]:
		return withRule(denyWith("property_denied", pn), ru), false
	case len(props) > 0 && !props[t.Property]:
		return withRule(denyWith("property_not_allowed", pn), ru), false
	case writes && !p.allowSensitive && t.Property.Sensitive():
		// A write to a property whose value is the device's own behaviour.
		// out-of-service is the one that matters: it cuts a point loose
		// from the physical world and leaves every graphics page in the
		// estate reporting whatever was written as the truth.
		return withRule(denyWith("sensitive_write", pn), ru), false
	}
	return Decision{}, true
}

func withRule(d Decision, ru *rule) Decision {
	if ru != nil {
		d.Rule = ru.name
	}
	return d
}

func inAny(rs []instanceRange, n uint32) bool {
	for _, r := range rs {
		if r.holds(n) {
			return true
		}
	}
	return false
}

// matches reports whether a rule covers this request. Every list a rule
// sets has to match; a list it leaves empty matches anything.
func (r *rule) matches(req request) bool {
	if len(r.clients) > 0 && !contains(r.clients, req.client) {
		return false
	}
	if len(r.services) > 0 && (req.apdu == nil || !r.services[req.apdu.Service]) {
		return false
	}
	if len(r.networks) > 0 {
		if req.npdu == nil || !req.npdu.HasDest || !r.networks[req.npdu.DNET] {
			return false
		}
	}
	if r.sched != nil && !r.sched.InForce(req.at) {
		return false
	}
	if len(r.objects) > 0 || len(r.instances) > 0 {
		if !req.located || len(req.targets) == 0 {
			return false
		}
		for _, t := range req.targets {
			if len(r.objects) > 0 && !r.objects[t.Object.Type] {
				return false
			}
			if len(r.instances) > 0 && !inAny(r.instances, t.Object.Instance) {
				return false
			}
		}
	}
	return true
}

// services resolves a list of service names. A name the standard does not
// have is an error at load rather than a rule that matches nothing: the
// second is a policy with a hole in it that nothing reports.
func services(names []string) (map[wire.Service]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.Service]bool, len(names))
	for _, n := range names {
		s, ok := wire.ParseService(strings.TrimSpace(n))
		if !ok {
			return nil, fmt.Errorf("%q is not a BACnet service", n)
		}
		out[s] = true
	}
	return out, nil
}

func objectTypes(names []string) (map[wire.ObjectType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.ObjectType]bool, len(names))
	for _, n := range names {
		t, ok := wire.ParseObjectType(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a BACnet object type", n)
		}
		out[t] = true
	}
	return out, nil
}

func properties(names []string) (map[wire.PropertyID]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.PropertyID]bool, len(names))
	for _, n := range names {
		p, ok := wire.ParseProperty(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a BACnet property", n)
		}
		out[p] = true
	}
	return out, nil
}

func networkSet(ns []int) map[uint16]bool {
	if len(ns) == 0 {
		return nil
	}
	out := make(map[uint16]bool, len(ns))
	for _, n := range ns {
		if n >= 0 && n <= 0xFFFF {
			out[uint16(n)] = true
		}
	}
	return out
}

// priority resolves a network priority name.
func priority(name string, def uint8) (uint8, error) {
	if strings.TrimSpace(name) == "" {
		return def, nil
	}
	v, ok := priorityNames[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("max_priority: %q is not normal, urgent, critical-equipment or life-safety", name)
	}
	return v, nil
}

// ranges parses instance ranges written as 1-100 or as a single number.
func ranges(specs []string) ([]instanceRange, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make([]instanceRange, 0, len(specs))
	for _, s := range specs {
		s = strings.TrimSpace(s)
		lo, hi, found := strings.Cut(s, "-")
		low, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 22)
		if err != nil {
			return nil, fmt.Errorf("%q is not an instance range", s)
		}
		high := low
		if found {
			if high, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 22); err != nil {
				return nil, fmt.Errorf("%q is not an instance range", s)
			}
		}
		if high < low {
			return nil, fmt.Errorf("%q runs backwards", s)
		}
		out = append(out, instanceRange{low: uint32(low), high: uint32(high)})
	}
	return out, nil
}

// prefixes parses a list of CIDR networks, accepting a bare address as a
// host route.
func prefixes(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func contains(ps []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
