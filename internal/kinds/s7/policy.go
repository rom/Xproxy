package s7

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/numrange"
	wire "github.com/rom/xproxy/internal/s7"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, in a plant's own terms.
//
// This protocol has no authentication worth the name. The optional password
// protects a handful of functions on some CPU families and nothing on
// others; an S7-300 with no password accepts a stop from anybody who can
// open a socket to it; and there is no transport security anywhere. So the
// listener is the access control, and it is built on four things in the
// order they are decided.
//
// **Where the client is, and which controller it asked for.** The rack and
// the slot arrive in the COTP connection request, before any S7 request
// exists, so a client that may not reach that CPU is refused before the PLC
// is dialled. The connection *resource* is decided in the same place, and
// it is the cheapest useful line here: `pg` is the programming device
// connection an engineering station opens, `op` is an operator panel, and a
// listener that admits only `op` has said a great deal in one word.
//
// **What the operation is.** The protocol spreads its operations across a
// function code and a user-data group, so `internal/s7` maps both onto one
// vocabulary and the policy is written in it. The default allows what an HMI
// does and nothing that changes the controller -- and an *upload* is off
// with the writes, even though it changes nothing, because reading a block
// out of a PLC is how a plant's control logic leaves the site.
//
// **Which memory it names.** The area, the data block and the byte range,
// checked against the whole span a request covers rather than its first
// byte: a read of two hundred bytes against a range of a hundred is a read
// of bytes the policy does not name.
//
// **Whether the request can be read at all.** A function code nobody has
// documented, a user-data group outside the nine, an item list that does not
// lay out -- each is refused rather than forwarded, because an operation
// with no name is an operation with no policy.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in monitor mode.
	Hard bool
	Rule string
	// Comment is the matched rule's own note, carried into the log for the
	// change record a plant keeps.
	Comment string
}

func hard(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}
func allowed() Decision { return Decision{Allow: true} }

// Session is what the policy knows about a connection.
type Session struct {
	IP netip.Addr
	// Rack, Slot and Resource come from the connection request. Addressed
	// says whether it carried the two octets Siemens puts them in: a TSAP
	// of another length is a legal COTP address and not a Siemens one, and
	// a rule about racks must not match a rack nobody sent.
	Rack, Slot int
	Resource   uint8
	Addressed  bool
	// PDULength is what the two sides negotiated, 0 before they have.
	PDULength int
	At        time.Time
}

type policy struct {
	allowIPs, denyIPs []netip.Prefix
	racks, slots      numrange.Set
	resources         map[uint8]bool

	readOnly            bool
	allowOps, denyOps   map[wire.Op]bool
	namedOps            map[wire.Op]bool
	areas, denyAreas    map[uint8]bool
	dbs                 numrange.Set
	addresses, writeAdr numrange.Set
	blockTypes          map[string]bool

	maxItems, maxRead, maxWrite int
	maxPDU                      int

	rules []*rule

	allowByDef bool
	monitor    bool
	respond    string

	// plus is the S7comm-plus policy: a different protocol on the same
	// stack, with its own vocabulary and much less of it visible.
	plus *commPlus
}

type rule struct {
	name    string
	comment string
	clients []netip.Prefix
	racks   numrange.Set
	slots   numrange.Set
	res     map[uint8]bool
	sched   *schedule.Window
	observe bool
	action  string

	allowOps, denyOps   map[wire.Op]bool
	areas, denyAreas    map[uint8]bool
	dbs                 numrange.Set
	addresses, writeAdr numrange.Set
	blockTypes          map[string]bool
	maxItems            int
}

func compile(c *config.S7Listener) (*policy, error) {
	p := &policy{
		readOnly:   c.ReadOnly,
		maxItems:   c.MaxItems,
		maxRead:    c.MaxReadBytes,
		maxWrite:   c.MaxWriteBytes,
		maxPDU:     c.MaxPDULength,
		monitor:    c.MonitorOnly,
		respond:    c.DenyResponse,
		allowByDef: c.DefaultAction == "allow",
	}
	if c.DefaultAction != "" && c.DefaultAction != "allow" && c.DefaultAction != "deny" {
		return nil, fmt.Errorf("default_action: %q is not allow or deny", c.DefaultAction)
	}
	if p.respond == "" {
		p.respond = "error"
	}
	var err error
	if p.allowIPs, err = prefixes(c.AllowClients); err != nil {
		return nil, fmt.Errorf("s7 allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("s7 deny_clients: %w", err)
	}
	if p.racks, err = numrange.Parse("racks", c.Racks, 7); err != nil {
		return nil, err
	}
	if p.slots, err = numrange.Parse("slots", c.Slots, 31); err != nil {
		return nil, err
	}
	if p.resources, err = resourceSet(c.Resources); err != nil {
		return nil, err
	}
	if p.allowOps, err = opSet(c.Operations, "operations"); err != nil {
		return nil, err
	}
	p.namedOps = p.allowOps
	if p.allowOps == nil {
		p.allowOps = map[wire.Op]bool{}
		for _, o := range wire.DefaultOps() {
			p.allowOps[o] = true
		}
	}
	if p.denyOps, err = opSet(c.DenyOperations, "deny_operations"); err != nil {
		return nil, err
	}
	if p.areas, err = areaSet(c.Areas); err != nil {
		return nil, err
	}
	if p.denyAreas, err = areaSet(c.DenyAreas); err != nil {
		return nil, err
	}
	if p.dbs, err = numrange.Parse("dbs", c.DBs, 65535); err != nil {
		return nil, err
	}
	if p.addresses, err = numrange.Parse("addresses", c.Addresses, 1<<21-1); err != nil {
		return nil, err
	}
	if p.writeAdr, err = numrange.Parse("write_addresses", c.WriteAddresses, 1<<21-1); err != nil {
		return nil, err
	}
	if p.blockTypes, err = blockSet(c.BlockTypes); err != nil {
		return nil, err
	}
	if p.plus, err = compilePlus(c); err != nil {
		return nil, err
	}
	for i := range c.Rules {
		r, err := compileRule(&c.Rules[i], i)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(rc *config.S7Rule, i int) (*rule, error) {
	r := &rule{name: rc.Name, comment: rc.Comment, action: rc.Action, maxItems: rc.MaxItems}
	if r.name == "" {
		r.name = fmt.Sprintf("rules[%d]", i)
	}
	switch rc.Action {
	case "", "allow":
		r.action = "allow"
	case "deny":
	case "observe":
		r.observe = true
	default:
		return nil, fmt.Errorf("rules[%d].action: %q is not allow, deny or observe", i, rc.Action)
	}
	var err error
	if r.clients, err = prefixes(rc.Clients); err != nil {
		return nil, fmt.Errorf("rules[%d].clients: %w", i, err)
	}
	if r.racks, err = numrange.Parse(fmt.Sprintf("rules[%d].racks", i), rc.Racks, 7); err != nil {
		return nil, err
	}
	if r.slots, err = numrange.Parse(fmt.Sprintf("rules[%d].slots", i), rc.Slots, 31); err != nil {
		return nil, err
	}
	if r.res, err = resourceSet(rc.Resources); err != nil {
		return nil, err
	}
	if r.allowOps, err = opSet(rc.Operations, fmt.Sprintf("rules[%d].operations", i)); err != nil {
		return nil, err
	}
	if r.denyOps, err = opSet(rc.DenyOperations, fmt.Sprintf("rules[%d].deny_operations", i)); err != nil {
		return nil, err
	}
	if r.areas, err = areaSet(rc.Areas); err != nil {
		return nil, err
	}
	if r.denyAreas, err = areaSet(rc.DenyAreas); err != nil {
		return nil, err
	}
	if r.dbs, err = numrange.Parse(fmt.Sprintf("rules[%d].dbs", i), rc.DBs, 65535); err != nil {
		return nil, err
	}
	if r.addresses, err = numrange.Parse(fmt.Sprintf("rules[%d].addresses", i), rc.Addresses, 1<<21-1); err != nil {
		return nil, err
	}
	if r.writeAdr, err = numrange.Parse(fmt.Sprintf("rules[%d].write_addresses", i), rc.WriteAddresses, 1<<21-1); err != nil {
		return nil, err
	}
	if r.blockTypes, err = blockSet(rc.BlockTypes); err != nil {
		return nil, err
	}
	if rc.Schedule != nil {
		if r.sched, err = schedule.Compile(rc.Schedule); err != nil {
			return nil, fmt.Errorf("rules[%d].schedule: %w", i, err)
		}
	}
	return r, nil
}

func opSet(in []string, field string) (map[wire.Op]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[wire.Op]bool, len(in))
	for _, s := range in {
		o, ok := wire.OpOf(strings.TrimSpace(s))
		if !ok {
			return nil, fmt.Errorf("%s: %q is not an S7 operation", field, s)
		}
		out[o] = true
	}
	return out, nil
}

func areaSet(in []string) (map[uint8]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[uint8]bool, len(in))
	for _, s := range in {
		a, ok := wire.AreaOf(strings.TrimSpace(s))
		if !ok {
			return nil, fmt.Errorf("%q is not a memory area", s)
		}
		out[a] = true
	}
	return out, nil
}

func resourceSet(in []string) (map[uint8]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[uint8]bool, len(in))
	for _, s := range in {
		r, ok := wire.ResourceOf(strings.TrimSpace(s))
		if !ok {
			return nil, fmt.Errorf("%q is not a connection resource", s)
		}
		out[r] = true
	}
	return out, nil
}

func blockSet(in []string) (map[string]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		k := strings.ToLower(strings.TrimSpace(s))
		switch k {
		case "db", "fb", "fc", "sdb", "sfb", "sfc":
		default:
			return nil, fmt.Errorf("block_types: %q is not a block type", s)
		}
		out[k] = true
	}
	return out, nil
}

// Connect decides about a connection before a single octet is read.
func (p *policy) Connect(se *Session) Decision {
	if contains(p.denyIPs, se.IP) {
		return hard("client_not_allowed", "")
	}
	if len(p.allowIPs) > 0 && !contains(p.allowIPs, se.IP) {
		return hard("client_not_allowed", "")
	}
	return allowed()
}

// Connection decides about the COTP connection request: which controller,
// and what kind of connection.
//
// It is decided before the PLC is dialled, which is the point. A CPU has
// very few connection resources -- an S7-300 has sixteen altogether -- so a
// client that may not reach that rack should never take one of them.
func (p *policy) Connection(se *Session, c *wire.COTP) Decision {
	if c.Type != wire.COTPConnectionRequest {
		// The first frame of a connection is a connection request. Anything
		// else is a client that has not opened one, and forwarding it would
		// be opening a transport connection this relay never decided about.
		return hard("not_a_connection_request", c.TypeName())
	}
	resource, rack, slot, ok := c.Destination()
	if !ok {
		// A TSAP this relay cannot read as a rack and a slot. It is legal
		// COTP and it is not Siemens addressing, so a policy about racks
		// cannot be applied to it -- and a listener with one refuses it
		// rather than guessing at rack zero.
		if len(p.racks) > 0 || len(p.slots) > 0 || p.resources != nil {
			return hard("destination_unreadable", fmt.Sprintf("%x", c.Called))
		}
		return allowed()
	}
	se.Resource, se.Rack, se.Slot, se.Addressed = resource, rack, slot, true
	if p.resources != nil && !p.resources[resource] {
		return hard("resource_not_allowed", wire.ResourceName(resource))
	}
	if len(p.racks) > 0 && !p.racks.Has(rack) {
		return hard("rack_not_allowed", fmt.Sprint(rack))
	}
	if len(p.slots) > 0 && !p.slots.Has(slot) {
		return hard("slot_not_allowed", fmt.Sprint(slot))
	}
	// A rule may narrow it further, and a rule that names racks or a
	// resource is how "this address reaches this CPU and no other" is
	// written.
	r := p.match(se)
	if r != nil {
		if r.res != nil && !r.res[resource] {
			return Decision{Reason: "resource_not_allowed", Detail: wire.ResourceName(resource),
				Hard: true, Rule: r.name, Comment: r.comment}
		}
		if len(r.racks) > 0 && !r.racks.Has(rack) {
			return Decision{Reason: "rack_not_allowed", Detail: fmt.Sprint(rack),
				Hard: true, Rule: r.name, Comment: r.comment}
		}
		if len(r.slots) > 0 && !r.slots.Has(slot) {
			return Decision{Reason: "slot_not_allowed", Detail: fmt.Sprint(slot),
				Hard: true, Rule: r.name, Comment: r.comment}
		}
	}
	return allowed()
}

// Setup decides about the negotiated PDU length.
//
// It is refused rather than rewritten, for the reason the amqp kind gives
// about its frame size: rewriting a negotiation makes the relay a party to
// it, and a connection that agreed a length and then had a request refused
// half way through a transfer is a harder fault to find than one that failed
// at the start.
func (p *policy) Setup(pduLength uint16) Decision {
	if p.maxPDU > 0 && int(pduLength) > p.maxPDU {
		return hard("pdu_length_too_large",
			fmt.Sprintf("%d octets, over the %d this listener allows", pduLength, p.maxPDU))
	}
	return allowed()
}

// Request decides about one S7 request from the client.
func (p *policy) Request(se *Session, pdu *wire.PDU) Decision {
	switch pdu.Type {
	case wire.Job, wire.Userdata:
	default:
		// A client sends jobs and user data. An acknowledgement from the
		// client's side is not a request at all, and forwarding it would be
		// forwarding a message this relay has no policy for.
		return hard("unexpected_message", pdu.Type.String())
	}
	op, known := pdu.Op()
	if !known {
		return hard("operation_unknown", describe(pdu))
	}
	r := p.match(se)

	if p.denyOps[op] || (r != nil && r.denyOps[op]) {
		return p.harden(op, Decision{Reason: "operation_denied", Detail: string(op),
			Rule: ruleName(r), Comment: comment(r)})
	}
	// read_only is before the allow lists and cannot be widened by a rule:
	// a read-only listener that one rule could write through is not a
	// read-only listener.
	if p.readOnly && wire.Writes(op) {
		return hard("read_only", string(op))
	}
	allow := p.allowOps
	if r != nil && r.allowOps != nil {
		allow = r.allowOps
	}
	if !allow[op] {
		return p.harden(op, Decision{Reason: "operation_not_allowed", Detail: string(op),
			Rule: ruleName(r), Comment: comment(r)})
	}

	if d := p.memory(r, op, pdu); !d.Allow {
		return d
	}
	if d := p.block(r, op, pdu); !d.Allow {
		return d
	}

	if r == nil {
		if p.allowByDef {
			return allowed()
		}
		return Decision{Reason: "no_rule_matched", Detail: string(op)}
	}
	if r.observe {
		return Decision{Allow: true, Rule: r.name, Comment: r.comment}
	}
	if r.action == "deny" {
		return Decision{Reason: "rule_denied", Detail: string(op), Rule: r.name, Comment: r.comment}
	}
	if r.sched != nil && !r.sched.InForce(se.At) {
		return Decision{Reason: "outside_schedule", Detail: string(op), Rule: r.name, Comment: r.comment}
	}
	return Decision{Allow: true, Rule: r.name, Comment: r.comment}
}

// memory applies the area, block and address policy to a read or a write.
func (p *policy) memory(r *rule, op wire.Op, pdu *wire.PDU) Decision {
	if op != wire.OpRead && op != wire.OpWrite {
		return allowed()
	}
	items, ok := pdu.Items()
	if !ok {
		// The item list did not lay out. Every address policy rests on it,
		// so this is a refusal rather than a request with fewer items.
		return hard("items_unreadable", string(op))
	}
	writing := op == wire.OpWrite
	if max := p.itemBound(r); max > 0 && len(items) > max {
		return hard("too_many_items", fmt.Sprintf("%d, over %d", len(items), max))
	}
	areas, denyAreas := p.areas, p.denyAreas
	if r != nil && r.areas != nil {
		areas = r.areas
	}
	if r != nil && r.denyAreas != nil {
		denyAreas = r.denyAreas
	}
	dbs := p.dbs
	if r != nil && len(r.dbs) > 0 {
		dbs = r.dbs
	}
	adr := p.addresses
	if r != nil && len(r.addresses) > 0 {
		adr = r.addresses
	}
	if writing {
		if len(p.writeAdr) > 0 {
			adr = p.writeAdr
		}
		if r != nil && len(r.writeAdr) > 0 {
			adr = r.writeAdr
		}
	}
	total := 0
	for _, it := range items {
		if !it.Address {
			// An item whose syntax is not the addressing form: a symbolic
			// or database access this relay cannot place in an area and a
			// byte. With any address policy in force it is refused, because
			// the alternative is letting through the one item the policy
			// could not check.
			if areas != nil || denyAreas != nil || len(dbs) > 0 || len(adr) > 0 {
				return hard("item_not_addressable", fmt.Sprintf("syntax %#x", it.Syntax))
			}
			continue
		}
		if denyAreas[it.Area] {
			return p.hardenArea(Decision{Reason: "area_denied", Detail: wire.AreaName(it.Area),
				Rule: ruleName(r), Comment: comment(r)}, writing)
		}
		if areas != nil && !areas[it.Area] {
			return p.hardenArea(Decision{Reason: "area_not_allowed", Detail: wire.AreaName(it.Area),
				Rule: ruleName(r), Comment: comment(r)}, writing)
		}
		if it.Area == wire.AreaDB && len(dbs) > 0 && !dbs.Has(int(it.DB)) {
			return p.hardenArea(Decision{Reason: "db_not_allowed", Detail: fmt.Sprintf("DB%d", it.DB),
				Rule: ruleName(r), Comment: comment(r)}, writing)
		}
		if len(adr) > 0 && !adr.Covers(it.Byte(), it.Last()) {
			return p.hardenArea(Decision{Reason: "address_not_allowed",
				Detail: fmt.Sprintf("%s byte %d to %d", wire.AreaName(it.Area), it.Byte(), it.Last()),
				Rule:   ruleName(r), Comment: comment(r)}, writing)
		}
		total += it.Bytes()
	}
	bound, name := p.maxRead, "max_read_bytes"
	if writing {
		bound, name = p.maxWrite, "max_write_bytes"
	}
	if bound > 0 && total > bound {
		return hard("too_many_bytes", fmt.Sprintf("%d octets past %s of %d", total, name, bound))
	}
	return allowed()
}

// block applies the block type policy to an upload or a download.
func (p *policy) block(r *rule, op wire.Op, pdu *wire.PDU) Decision {
	if op != wire.OpUpload && op != wire.OpDownload {
		return allowed()
	}
	types := p.blockTypes
	if r != nil && r.blockTypes != nil {
		types = r.blockTypes
	}
	if types == nil {
		return allowed()
	}
	kind, number, ok := pdu.Block()
	if !ok {
		// Only the first PDU of a transfer names the block; the ones that
		// follow carry the data. So a transfer PDU with no name is not a
		// refusal -- the named one was already decided, and refusing the
		// rest would refuse every transfer.
		return allowed()
	}
	if !types[kind] {
		d := Decision{Reason: "block_type_not_allowed",
			Detail: fmt.Sprintf("%s%d", kind, number), Rule: ruleName(r), Comment: comment(r)}
		if op == wire.OpDownload {
			d.Hard = true
		}
		return d
	}
	return allowed()
}

func (p *policy) itemBound(r *rule) int {
	if r != nil && r.maxItems > 0 {
		return r.maxItems
	}
	return p.maxItems
}

// harden marks a refusal monitor mode must not shadow.
//
// The operations that change the controller are the set: a write forwarded so
// that it could be written down is a moved actuator, a stop forwarded is a
// stopped machine, and a download forwarded is a different program running.
// An operator who names one in `operations` has said so, and is not
// overruled -- this is never reached for those.
func (p *policy) harden(op wire.Op, d Decision) Decision {
	if wire.Dangerous(op) {
		d.Hard = true
	}
	return d
}

// hardenArea marks an address refusal on a write as hard, for the same
// reason: the write is what monitor mode must not carry.
func (p *policy) hardenArea(d Decision, writing bool) Decision {
	if writing {
		d.Hard = true
	}
	return d
}

func (p *policy) match(se *Session) *rule {
	for _, r := range p.rules {
		if len(r.clients) > 0 && !contains(r.clients, se.IP) {
			continue
		}
		// A rule that names racks, slots or a resource never matches a
		// connection whose address this relay could not read: it is a rule
		// about a CPU, and there is no CPU number to compare.
		if len(r.racks) > 0 && (!se.Addressed || !r.racks.Has(se.Rack)) {
			continue
		}
		if len(r.slots) > 0 && (!se.Addressed || !r.slots.Has(se.Slot)) {
			continue
		}
		if r.res != nil && (!se.Addressed || !r.res[se.Resource]) {
			continue
		}
		return r
	}
	return nil
}

// describe says what a request was, for a refusal that could not name its
// operation.
func describe(pdu *wire.PDU) string {
	if pdu.Type == wire.Userdata {
		if u, ok := pdu.UserData(); ok {
			return "userdata " + u.Name()
		}
		return "userdata"
	}
	return pdu.FunctionName()
}

func ruleName(r *rule) string {
	if r == nil {
		return ""
	}
	return r.name
}

func comment(r *rule) string {
	if r == nil {
		return ""
	}
	return r.comment
}

func prefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		n, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
