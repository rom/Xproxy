package amqp

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, in a message broker's own terms.
//
// A broker's permissions are per user and per virtual host: RabbitMQ's model
// is three regular expressions -- configure, write, read -- for each user in
// each vhost, administered inside the broker by whoever administers the
// broker. That is more than most brokers offer and less than an estate
// wants, and either way it lives somewhere the estate's own review does not
// reach. This holds the same boundary in the configuration, in front of
// brokers whose model is weaker, and adds the three things a broker's model
// does not have.
//
// **Topology is separated from work.** Declaring an exchange, deleting a
// queue, binding, unbinding and purging are the broker's configuration, and
// an application that publishes to an exchange somebody else declared needs
// none of them. So they are off until named, and a client library that
// declares its own queue on connect becomes a decision rather than a
// default.
//
// **A name is checked wherever it appears.** The exchange of a publish and
// the queue of a consume are the obvious ones. The ones that matter are the
// arguments: `x-dead-letter-exchange` on a queue and `alternate-exchange` on
// an exchange name an exchange the broker will route to, and `reply-to` in a
// message's properties names a queue a responder will deliver to. A policy
// that checked only the obvious fields would let a client have the broker
// reach what the client may not.
//
// **The two versions are one policy.** A client picks 0-9-1 or 1.0 in its
// first eight octets. On 0-9-1 the nouns are in every method; on 1.0 they
// are in the address a link attaches to, which the brokers that serve both
// spell as `/exchange/X/key` and `/queue/Q`. The same exchange and queue
// lists decide both, so an operator writes the boundary once.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in monitor mode.
	Hard bool
	Rule string
}

func deny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail}
}

func hardDeny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}

func allow() Decision { return Decision{Allow: true} }

// names is an allow and a deny list of patterns for one kind of name.
type names struct{ allow, deny []string }

type policy struct {
	allowIPs, denyIPs []netip.Prefix

	requireTLS bool
	versions   map[wire.Version]bool

	allowMechs, denyMechs []string
	requireAuth           bool
	allowUsers, denyUsers []string

	vhosts names

	// allowMethods is the list in force, which is the default application
	// set when the file named none. namedMethods is what the file actually
	// named, which is a different question: a method an operator wrote down
	// is allowed even when its class is off, and the default list is not
	// that kind of statement.
	allowMethods, namedMethods map[string]bool
	denyMethods                map[string]bool
	allowPerfs, denyPerfs      map[string]bool

	topology         bool
	publish, consume bool

	// byKind holds the name lists, keyed by the target kinds of the wire
	// package: exchange, queue, routing_key and address.
	byKind map[string]names

	denyMgmt      bool
	requireUserID bool
	matchUserID   bool
	allowNoAck    bool
	maxPriority   int

	maxFrame, maxChannels, maxLinks int
	maxMessage, maxMethods          int
	requireHeartbeat                bool

	rules []*rule

	allowByDef bool
	nak        bool
	monitor    bool
}

type rule struct {
	name    string
	clients []netip.Prefix
	users   []string
	vhosts  []string
	sched   *schedule.Window
	observe bool
	action  string

	allowMethods, denyMethods map[string]bool
	allowPerfs, denyPerfs     map[string]bool
	byKind                    map[string]names
	topology                  *bool
	publish, consume          *bool
	maxMessage, maxMethods    int
}

func compile(c *config.AMQPListener) (*policy, error) {
	p := &policy{
		requireTLS:       c.RequireTLS == nil || *c.RequireTLS,
		requireAuth:      c.RequireAuth == nil || *c.RequireAuth,
		allowMechs:       upperAll(c.AllowMechanisms),
		denyMechs:        upperAll(c.DenyMechanisms),
		allowUsers:       lowerAll(c.AllowUsers),
		denyUsers:        lowerAll(c.DenyUsers),
		vhosts:           names{allow: c.AllowVhosts, deny: c.DenyVhosts},
		topology:         c.AllowTopology,
		publish:          c.AllowPublish == nil || *c.AllowPublish,
		consume:          c.AllowConsume == nil || *c.AllowConsume,
		denyMgmt:         c.DenyManagementNodes == nil || *c.DenyManagementNodes,
		requireUserID:    c.RequireUserID,
		matchUserID:      c.MatchUserID == nil || *c.MatchUserID,
		allowNoAck:       c.AllowNoAck == nil || *c.AllowNoAck,
		maxPriority:      c.MaxPriority,
		maxFrame:         or(c.MaxFrameBytes, wire.DefaultMaxFrame),
		maxChannels:      or(c.MaxChannels, 256),
		maxLinks:         or(c.MaxLinks, 256),
		maxMessage:       c.MaxMessageBytes,
		maxMethods:       c.MaxMethods,
		requireHeartbeat: c.RequireHeartbeat,
		nak:              c.DenyResponse != "drop",
		monitor:          c.MonitorOnly,
	}
	if len(p.allowMechs) == 0 {
		p.allowMechs = upperAll(wire.SafeMechanisms())
	}
	switch c.DefaultAction {
	case "", "deny":
	case "allow":
		p.allowByDef = true
	default:
		return nil, fmt.Errorf("default_action: %q is not allow or deny", c.DefaultAction)
	}
	var err error
	if p.allowIPs, err = prefixes(c.AllowClients); err != nil {
		return nil, fmt.Errorf("amqp allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("amqp deny_clients: %w", err)
	}
	if p.versions, err = compileVersions(c.Versions); err != nil {
		return nil, err
	}
	if p.allowMethods, err = methodSet(c.AllowMethods, "allow_methods"); err != nil {
		return nil, err
	}
	p.namedMethods = p.allowMethods
	if p.allowMethods == nil {
		set, err := methodSet(wire.DefaultMethods(), "the default method list")
		if err != nil {
			return nil, err
		}
		p.allowMethods = set
	}
	if p.denyMethods, err = methodSet(c.DenyMethods, "deny_methods"); err != nil {
		return nil, err
	}
	if p.allowPerfs, err = perfSet(c.AllowPerformatives, "allow_performatives"); err != nil {
		return nil, err
	}
	if p.denyPerfs, err = perfSet(c.DenyPerformatives, "deny_performatives"); err != nil {
		return nil, err
	}
	p.byKind = map[string]names{
		wire.KindExchange:   {allow: c.AllowExchanges, deny: c.DenyExchanges},
		wire.KindQueue:      {allow: c.AllowQueues, deny: c.DenyQueues},
		wire.KindRoutingKey: {allow: c.AllowRoutingKeys, deny: c.DenyRoutingKeys},
		wire.KindAddress:    {allow: c.AllowAddresses, deny: c.DenyAddresses},
	}
	if err := checkPatterns(p.byKind, p.vhosts); err != nil {
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

func compileRule(rc *config.AMQPRule, i int) (*rule, error) {
	r := &rule{name: rc.Name, users: lowerAll(rc.Users), vhosts: rc.Vhosts,
		action: rc.Action, maxMessage: rc.MaxMessageBytes, maxMethods: rc.MaxMethods}
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
	if r.allowMethods, err = methodSet(rc.AllowMethods, fmt.Sprintf("rules[%d].allow_methods", i)); err != nil {
		return nil, err
	}
	if r.denyMethods, err = methodSet(rc.DenyMethods, fmt.Sprintf("rules[%d].deny_methods", i)); err != nil {
		return nil, err
	}
	if r.allowPerfs, err = perfSet(rc.AllowPerformatives, fmt.Sprintf("rules[%d].allow_performatives", i)); err != nil {
		return nil, err
	}
	if r.denyPerfs, err = perfSet(rc.DenyPerformatives, fmt.Sprintf("rules[%d].deny_performatives", i)); err != nil {
		return nil, err
	}
	r.byKind = map[string]names{
		wire.KindExchange:   {allow: rc.AllowExchanges, deny: rc.DenyExchanges},
		wire.KindQueue:      {allow: rc.AllowQueues, deny: rc.DenyQueues},
		wire.KindRoutingKey: {allow: rc.AllowRoutingKeys, deny: rc.DenyRoutingKeys},
		wire.KindAddress:    {allow: rc.AllowAddresses, deny: rc.DenyAddresses},
	}
	if err := checkPatterns(r.byKind, names{allow: rc.Vhosts}); err != nil {
		return nil, fmt.Errorf("rules[%d]: %w", i, err)
	}
	if rc.AllowTopology != nil {
		v := *rc.AllowTopology
		r.topology = &v
	}
	if rc.AllowPublish != nil {
		v := *rc.AllowPublish
		r.publish = &v
	}
	if rc.AllowConsume != nil {
		v := *rc.AllowConsume
		r.consume = &v
	}
	if rc.Schedule != nil {
		if r.sched, err = schedule.Compile(rc.Schedule); err != nil {
			return nil, fmt.Errorf("rules[%d].schedule: %w", i, err)
		}
	}
	return r, nil
}

// compileVersions reads the version list. Empty allows the two versions
// this relay reads.
func compileVersions(in []string) (map[wire.Version]bool, error) {
	out := map[wire.Version]bool{}
	if len(in) == 0 {
		out[wire.V091] = true
		out[wire.V10] = true
		return out, nil
	}
	for _, v := range in {
		switch strings.TrimSpace(v) {
		case "0-9-1":
			out[wire.V091] = true
		case "1.0":
			out[wire.V10] = true
		default:
			return nil, fmt.Errorf("versions: %q is not 0-9-1 or 1.0", v)
		}
	}
	return out, nil
}

// methodSet folds the names and refuses one the catalogue does not have: a
// policy line naming a method that cannot exist matches nothing, and an
// operator who wrote `queue.del` meant something.
func methodSet(in []string, field string) (map[string]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(in))
	for _, n := range in {
		name := strings.ToLower(strings.TrimSpace(n))
		if _, _, ok := wire.MethodID(name); !ok {
			return nil, fmt.Errorf("%s: %q is not an AMQP 0-9-1 method", field, n)
		}
		out[name] = true
	}
	return out, nil
}

func perfSet(in []string, field string) (map[string]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(in))
	for _, n := range in {
		name := strings.ToLower(strings.TrimSpace(n))
		if _, ok := wire.PerformativeCode(name); !ok {
			return nil, fmt.Errorf("%s: %q is not an AMQP 1.0 performative", field, n)
		}
		out[name] = true
	}
	return out, nil
}

// checkPatterns refuses a pattern that cannot compile, at load rather than
// at the first frame: a malformed pattern matches nothing, and a policy that
// silently matched nothing is one that allows everything or refuses
// everything by accident.
func checkPatterns(byKind map[string]names, vhosts names) error {
	for kind, n := range byKind {
		for _, list := range [][]string{n.allow, n.deny} {
			for _, pat := range list {
				if _, err := path.Match(pat, "x"); err != nil {
					return fmt.Errorf("%s pattern %q: %w", kind, pat, err)
				}
			}
		}
	}
	for _, list := range [][]string{vhosts.allow, vhosts.deny} {
		for _, pat := range list {
			if _, err := path.Match(pat, "x"); err != nil {
				return fmt.Errorf("vhost pattern %q: %w", pat, err)
			}
		}
	}
	return nil
}

// Session is what the policy knows about a connection when it decides.
type Session struct {
	IP      netip.Addr
	Version wire.Version
	User    string
	Vhost   string
	Secure  bool
	Authed  bool
	At      time.Time
}

// Bounds the relay needs.
func (p *policy) MaxFrame() int    { return p.maxFrame }
func (p *policy) MaxChannels() int { return p.maxChannels }
func (p *policy) MaxLinks() int    { return p.maxLinks }

// MaxMessage is the message bound in force for a session.
func (p *policy) MaxMessage(se *Session) int {
	if r := p.match(se); r != nil && r.maxMessage > 0 {
		return r.maxMessage
	}
	return p.maxMessage
}

// MaxMethods is the per-connection method bound in force.
func (p *policy) MaxMethods(se *Session) int {
	if r := p.match(se); r != nil && r.maxMethods > 0 {
		return r.maxMethods
	}
	return p.maxMethods
}

// Connect decides about a connection before a single octet is read.
func (p *policy) Connect(se *Session) Decision {
	if !p.admits(se.IP) {
		return hardDeny("client_not_allowed", "")
	}
	if p.requireTLS && !se.Secure {
		// Hard: the SASL exchange on this connection would put a password
		// on the wire, and so would every message after it.
		return hardDeny("tls_required", "")
	}
	return allow()
}

// Version decides about the protocol header.
//
// The header is the one thing on this protocol that has to be decided before
// anything is forwarded, because it chooses the framing of everything after
// it. Three answers are refusals: a version this relay does not read, a
// version the configuration does not allow, and 1.0's TLS protocol
// identifier -- which asks this relay to negotiate transport security from a
// client's first octet, and the answer to that is a TLS port.
func (p *policy) Version(h wire.Header) Decision {
	v := h.Version()
	switch v {
	case wire.Unknown:
		return hardDeny("protocol_version_unknown", h.String())
	case wire.Legacy:
		return hardDeny("protocol_version_not_allowed", h.String())
	}
	if v == wire.V10 && h.Layer() == wire.ProtoTLS {
		return hardDeny("tls_negotiation_refused", h.String())
	}
	if !p.versions[v] {
		return hardDeny("protocol_version_not_allowed", h.String())
	}
	return allow()
}

// Mechanism decides about the SASL mechanism a client chose.
func (p *policy) Mechanism(mech string) Decision {
	m := strings.ToUpper(strings.TrimSpace(mech))
	if m == "" {
		return hardDeny("mechanism_missing", "")
	}
	if hasFold(p.denyMechs, m) {
		return hardDeny("mechanism_not_allowed", m)
	}
	if len(p.allowMechs) > 0 && !hasFold(p.allowMechs, m) {
		return hardDeny("mechanism_not_allowed", m)
	}
	return allow()
}

// User decides which identity may be attempted.
//
// It is about the attempt, not the outcome: the broker decides whether the
// password is right, and this decides which names may even be tried. The
// same distinction the postgres, mysql and redis kinds draw.
func (p *policy) User(user string) Decision {
	if user == "" {
		// A mechanism whose identity this relay cannot read -- a
		// challenge and response exchange, a broker's own plugin. The
		// mechanism policy has already decided about it; a rule about
		// users simply does not match.
		return allow()
	}
	u := strings.ToLower(user)
	if hasFold(p.denyUsers, u) {
		return deny("user_not_allowed", user)
	}
	if len(p.allowUsers) > 0 && !hasFold(p.allowUsers, u) {
		return deny("user_not_allowed", user)
	}
	return allow()
}

// Vhost decides about the virtual host a connection opens.
//
// This is the broker's own access boundary, and it is decided before the
// exchange and queue lists because an exchange name means something
// different in each vhost.
func (p *policy) Vhost(se *Session, vhost string) Decision {
	r := p.match(se)
	if matchAny(p.vhosts.deny, vhost) {
		return hardDeny("vhost_not_allowed", vhost)
	}
	if len(p.vhosts.allow) > 0 && !matchAny(p.vhosts.allow, vhost) {
		return hardDeny("vhost_not_allowed", vhost)
	}
	if r != nil && len(r.vhosts) > 0 && !matchAny(r.vhosts, vhost) {
		return Decision{Reason: "vhost_not_allowed", Detail: vhost, Hard: true, Rule: r.name}
	}
	return allow()
}

// Tune decides about the bounds the two sides negotiated.
//
// All three are the client's to ask for, and a broker that agrees is a
// broker whose bounds came from the client. A frame bound above what this
// listener reads is refused rather than rewritten: rewriting it would make
// the relay a party to the negotiation, and a connection that agreed a frame
// size and then had a frame refused in the middle of a message is a harder
// fault to find than one that failed at the start.
func (p *policy) Tune(channelMax uint16, frameMax uint32, heartbeat uint16) Decision {
	if frameMax == 0 {
		// Zero means no limit on 0-9-1. A relay that passed it on would
		// be reading frames it has no bound for.
		return hardDeny("frame_max_unbounded", "")
	}
	if int64(frameMax) > int64(p.maxFrame) {
		return hardDeny("frame_max_too_large",
			fmt.Sprintf("%d octets, over the %d this listener reads", frameMax, p.maxFrame))
	}
	// The channel bound is not decided here, deliberately. A broker's own
	// default is a channel-max in the thousands and every client echoes it,
	// so refusing the negotiation would refuse every ordinary connection --
	// and it would be the wrong mechanism anyway: the relay counts the
	// channels that are actually opened, which is what max_channels bounds.
	if p.requireHeartbeat && heartbeat == 0 {
		return hardDeny("heartbeat_disabled", "")
	}
	return allow()
}

// Open decides about an AMQP 1.0 open performative, which carries this
// version's virtual host and its own three bounds.
func (p *policy) Open(se *Session, hostname string, maxFrame uint64) Decision {
	if d := p.Vhost(se, hostname); !d.Allow {
		return d
	}
	if maxFrame > 0 && maxFrame > uint64(p.maxFrame) { //nolint:gosec // maxFrame is a positive int
		return hardDeny("frame_max_too_large",
			fmt.Sprintf("%d octets, over the %d this listener reads", maxFrame, p.maxFrame))
	}
	return allow()
}

// Method decides about one AMQP 0-9-1 method frame from the client.
//
// The order is deliberate, and it is the order the redis and bacnet kinds
// use for the same reasons. The deny lists first, because nothing below may
// take them back. Then what cannot be read, because a frame the relay could
// not lay out is not made safe by a password. Then authentication. Then the
// allow list, the operation classes, and the names -- so that a refusal
// names the narrowest thing that was wrong.
func (p *policy) Method(se *Session, m *wire.Method) Decision {
	r := p.match(se)
	name := m.Name()

	if !m.Known() {
		// A method outside the catalogue. It may be a broker's extension,
		// and it may be a probe; either way this relay cannot say what it
		// names, so forwarding it would be forwarding an operation with
		// no policy at all.
		return hardDeny("method_unknown", name)
	}
	if p.denyMethods[name] {
		return p.harden(name, Decision{Reason: "method_denied", Detail: name})
	}
	if r != nil && r.denyMethods[name] {
		return p.harden(name, Decision{Reason: "method_denied", Detail: name, Rule: r.name})
	}
	if p.requireAuth && !se.Authed && !preAuth091(name) {
		return hardDeny("not_authenticated", name)
	}
	// The class before the name list, because the class is the reason: a
	// listener whose topology is off refuses queue.declare for that and not
	// for a list it was never on.
	if d := p.class(r, name); !d.Allow {
		return d
	}
	if !p.allowedMethod(r, name) {
		return p.harden(name, Decision{Reason: "method_not_allowed", Detail: name, Rule: ruleName(r)})
	}
	targets, known := m.Targets()
	if !known {
		return hardDeny("arguments_unreadable", name)
	}
	if d := p.names(r, targets); !d.Allow {
		return d
	}
	if name == "basic.consume" && !p.allowNoAck {
		if _, noAck, _, ok := m.Consumer(); ok && noAck {
			return Decision{Reason: "no_ack_not_allowed", Detail: name, Rule: ruleName(r)}
		}
	}
	return p.byRule(se, r)
}

// Performative decides about one AMQP 1.0 frame body from the client.
//
// The shape is the same as Method's, and the difference is where the nouns
// are: an attach carries the address, and every transfer after it carries a
// handle. So the relay keeps the handle table (see session.go) and this
// decides the attach.
func (p *policy) Performative(se *Session, pf *wire.Performative) Decision {
	r := p.match(se)
	name := pf.Name()

	if !pf.Known() {
		return hardDeny("performative_unknown", name)
	}
	if p.denyPerfs[name] || (r != nil && r.denyPerfs[name]) {
		return Decision{Reason: "performative_denied", Detail: name, Rule: ruleName(r), Hard: true}
	}
	if p.requireAuth && !se.Authed && !preAuth10(name) {
		return hardDeny("not_authenticated", name)
	}
	allowed := p.allowPerfs
	if r != nil && r.allowPerfs != nil {
		allowed = r.allowPerfs
	}
	if allowed != nil && !allowed[name] {
		return Decision{Reason: "performative_not_allowed", Detail: name, Rule: ruleName(r)}
	}
	if pf.Code == wire.PerfAttach {
		return p.attach(se, r, pf)
	}
	return p.byRule(se, r)
}

// attach decides about a link: which way it goes, and the address at the far
// end of that direction.
//
// A sender is publishing and a receiver is consuming, so the same
// allow_publish and allow_consume that decide basic.publish and
// basic.consume decide an attach -- one policy, two protocols.
func (p *policy) attach(se *Session, r *rule, pf *wire.Performative) Decision {
	_, _, role, source, target, ok := pf.Attach()
	if !ok {
		return hardDeny("arguments_unreadable", "attach")
	}
	addr := target
	class := "publish"
	if role == wire.RoleReceiver {
		addr = source
		class = "consume"
	}
	if class == "publish" && !p.publishAllowed(r) {
		return Decision{Reason: "publish_not_allowed", Detail: addr, Rule: ruleName(r)}
	}
	if class == "consume" && !p.consumeAllowed(r) {
		return Decision{Reason: "consume_not_allowed", Detail: addr, Rule: ruleName(r)}
	}
	// A dynamic link asks the broker to create the node and answer with
	// its name. There is no address to check, and the node the broker
	// makes is this connection's own -- which is how a reply queue is
	// created on this version, so refusing it would refuse request-reply.
	dynSource, dynTarget := pf.Dynamic()
	if (role == wire.RoleReceiver && dynSource) || (role == wire.RoleSender && dynTarget) {
		return p.byRule(se, r)
	}
	if addr == "" {
		return hardDeny("address_missing", role)
	}
	if d := p.names(r, wire.SplitAddress(addr)); !d.Allow {
		return d
	}
	return p.byRule(se, r)
}

// Content decides about a message's own properties, which is where three
// things nothing else names live.
func (p *policy) Content(se *Session, h *wire.ContentHeader) Decision {
	r := p.match(se)
	if max := p.MaxMessage(se); max > 0 && h.BodySize > uint64(max) { //nolint:gosec // max is positive
		// Refused on the declared size, before the body arrives: a
		// message refused after most of it was forwarded is a message the
		// broker held.
		return hardDeny("message_too_large",
			fmt.Sprintf("%d octets, over the %d this listener allows", h.BodySize, max))
	}
	if p.requireUserID && !h.Set["user_id"] {
		return Decision{Reason: "user_id_missing", Rule: ruleName(r)}
	}
	if p.matchUserID && h.Set["user_id"] && se.User != "" && !strings.EqualFold(h.UserID, se.User) {
		// The broker checks this itself when the property is set, so a
		// mismatch is a client that will be refused anyway -- but the
		// refusal is worth making here because it is the one field that
		// ties a message to a person, and a message claiming to be from
		// somebody else is the interesting event.
		return Decision{Reason: "user_id_mismatch", Detail: h.UserID, Rule: ruleName(r)}
	}
	if p.maxPriority > 0 && h.Set["priority"] && int(h.Priority) > p.maxPriority {
		return Decision{Reason: "priority_too_high",
			Detail: fmt.Sprintf("%d, over %d", h.Priority, p.maxPriority), Rule: ruleName(r)}
	}
	// The reply-to is a queue a responder will deliver to, named inside the
	// message rather than in the publish.
	if h.ReplyTo != "" {
		if d := p.names(r, []wire.Target{{Kind: wire.KindQueue, Name: h.ReplyTo}}); !d.Allow {
			d.Reason = "reply_to_not_allowed"
			return d
		}
	}
	return allow()
}

// Delivery decides about what the broker is handing to this client.
//
// Only the deny lists apply, and the difference matters. An allow list says
// what a client may *ask for*; a delivery names where the message came
// from, which the consumer need not be allowed to name -- a queue bound to
// an exchange by somebody else delivers messages carrying that exchange's
// name, and a relay that required it on the allow list would break every
// ordinary consumer. A deny list says something else: this connection must
// never see messages from there, whoever routed them.
func (p *policy) Delivery(se *Session, targets []wire.Target) Decision {
	r := p.match(se)
	for _, t := range targets {
		if matchAny(p.byKind[t.Kind].deny, t.Name) {
			return hardDeny("delivery_denied", t.Kind+" "+t.Name)
		}
		if r != nil && matchAny(r.byKind[t.Kind].deny, t.Name) {
			return Decision{Reason: "delivery_denied", Detail: t.Kind + " " + t.Name,
				Hard: true, Rule: r.name}
		}
	}
	return allow()
}

// allowedMethod says whether a method is on the list in force.
//
// `allow_topology` widens that list, which is what an operator means by it: a
// listener that permits topology permits the methods that do it, without
// having to name nine of them beside the class flag.
func (p *policy) allowedMethod(r *rule, name string) bool {
	allowed := p.allowMethods
	if r != nil && r.allowMethods != nil {
		allowed = r.allowMethods
	}
	if allowed[name] {
		return true
	}
	return wire.Topology(name) && p.topologyAllowed(r)
}

// named says whether the file itself named a method, as opposed to the method
// being on the default list.
//
// It is the difference between "this is the set an application needs" and "an
// operator wrote this down". The second overrides the class flags, the first
// does not: somebody who puts queue.delete in allow_methods has said so, and
// somebody who left the list empty has not said anything about topology.
func (p *policy) named(r *rule, name string) bool {
	if r != nil && r.allowMethods != nil {
		return r.allowMethods[name]
	}
	return p.namedMethods[name]
}

// class decides what an operation reaches: the broker's topology, or
// messages in, or messages out.
func (p *policy) class(r *rule, name string) Decision {
	switch {
	case wire.Topology(name) && !p.topologyAllowed(r) && !p.named(r, name):
		d := Decision{Reason: "topology_not_allowed", Detail: name, Rule: ruleName(r)}
		if wire.Destructive(name) {
			// A purge forwarded so that it could be written down is a
			// queue that is empty, so monitor mode does not shadow it.
			d.Hard = true
		}
		return d
	case wire.Publishes(name) && !p.publishAllowed(r):
		return Decision{Reason: "publish_not_allowed", Detail: name, Rule: ruleName(r)}
	case wire.Consumes(name) && !p.consumeAllowed(r):
		return Decision{Reason: "consume_not_allowed", Detail: name, Rule: ruleName(r)}
	case wire.Administrative(name):
		// connection.update-secret replaces the credential this
		// connection authenticated with, so after it the identity in
		// every log line and every rule match is stale. It is allowed
		// only by being named.
		if !p.named(r, name) {
			return hardDeny("administrative_not_allowed", name)
		}
	}
	return allow()
}

// names applies the name lists to everything an operation named.
func (p *policy) names(r *rule, targets []wire.Target) Decision {
	for _, t := range targets {
		if p.denyMgmt && management(t) {
			return hardDeny("management_node_denied", t.Kind+" "+t.Name)
		}
		lists := p.byKind[t.Kind]
		if r != nil {
			if rl, ok := r.byKind[t.Kind]; ok && (len(rl.allow) > 0 || len(rl.deny) > 0) {
				lists = rl
			}
		}
		if matchAny(lists.deny, t.Name) {
			return Decision{Reason: t.Kind + "_denied", Detail: t.Name, Rule: ruleName(r)}
		}
		if len(lists.allow) > 0 && !matchAny(lists.allow, t.Name) {
			return Decision{Reason: t.Kind + "_not_allowed", Detail: t.Name, Rule: ruleName(r)}
		}
	}
	return allow()
}

// management says whether a name is one a broker keeps for administering
// itself.
//
// `$management` and `$cbs` are the 1.0 node names Azure Service Bus and the
// Qpid tools use for administration and for claims-based authentication, and
// `amq.rabbitmq.*` are RabbitMQ's own exchanges: the log stream, the trace
// stream and the event stream. Each is a way to read or change the broker
// over the same connection an application publishes on.
func management(t wire.Target) bool {
	switch t.Kind {
	case wire.KindAddress:
		n := strings.TrimPrefix(t.Name, "/")
		return strings.HasPrefix(n, "$management") || strings.HasPrefix(n, "$cbs")
	case wire.KindExchange:
		return strings.HasPrefix(t.Name, "amq.rabbitmq.")
	}
	return false
}

func (p *policy) topologyAllowed(r *rule) bool {
	if r != nil && r.topology != nil {
		return *r.topology
	}
	return p.topology
}

func (p *policy) publishAllowed(r *rule) bool {
	if r != nil && r.publish != nil {
		return *r.publish
	}
	return p.publish
}

func (p *policy) consumeAllowed(r *rule) bool {
	if r != nil && r.consume != nil {
		return *r.consume
	}
	return p.consume
}

// byRule is the last word: the matched rule's own action, or the listener's
// default when nothing matched.
func (p *policy) byRule(se *Session, r *rule) Decision {
	if r == nil {
		if p.allowByDef {
			return allow()
		}
		return Decision{Reason: "no_rule_matched"}
	}
	if r.observe {
		return Decision{Allow: true, Rule: r.name}
	}
	if r.action == "deny" {
		return Decision{Reason: "rule_denied", Rule: r.name}
	}
	if r.sched != nil && !r.sched.InForce(se.At) {
		return Decision{Reason: "outside_schedule", Rule: r.name}
	}
	return Decision{Allow: true, Rule: r.name}
}

// harden marks a refusal monitor mode must not shadow.
//
// An explicit allow list still wins: an operator who writes queue.delete
// into allow_methods has said so, and this is never reached for it. What it
// stops is a listener in monitor mode forwarding a delete or a purge because
// nothing is being enforced yet.
func (p *policy) harden(name string, d Decision) Decision {
	if wire.Destructive(name) || wire.Administrative(name) {
		d.Hard = true
	}
	return d
}

// preAuth091 is what a client may send on 0-9-1 before the broker has
// accepted a credential: the handshake itself and nothing else.
//
// Naming them is the point. The alternative -- letting everything through
// until the broker's tune arrives -- is a window an attacker fills with one
// frame.
func preAuth091(name string) bool {
	switch name {
	case "connection.start-ok", "connection.secure-ok", "connection.tune-ok",
		"connection.close", "connection.close-ok":
		return true
	}
	return false
}

// preAuth10 is the same on 1.0: the SASL exchange, and the close that ends
// a connection that got nowhere.
func preAuth10(name string) bool {
	switch name {
	case "sasl-init", "sasl-response", "close":
		return true
	}
	return false
}

func (p *policy) match(se *Session) *rule {
	for _, r := range p.rules {
		if len(r.clients) > 0 && !contains(r.clients, se.IP) {
			continue
		}
		if len(r.users) > 0 && !hasFold(r.users, se.User) {
			continue
		}
		if len(r.vhosts) > 0 && se.Vhost != "" && !matchAny(r.vhosts, se.Vhost) {
			continue
		}
		return r
	}
	return nil
}

func (p *policy) admits(ip netip.Addr) bool {
	if contains(p.denyIPs, ip) {
		return false
	}
	return len(p.allowIPs) == 0 || contains(p.allowIPs, ip)
}

// matchAny is the pattern match the whole name policy rests on.
//
// The patterns are written in the protocol's own topic language, because that
// is the one an operator already knows from writing bindings: a name is words
// separated by dots, `*` is exactly one word and `#` is zero or more. So
// `orders.*` covers `orders.created` and not `orders.eu.created`, which is
// the distinction a routing key policy is about, and `orders.#` covers both.
// Inside a word an ordinary shell glob applies, so `app-?` and `svc-*` mean
// what they look like.
//
// An exact name with no metacharacter matches itself, which is what most of
// these lists hold.
func matchAny(patterns []string, name string) bool {
	for _, pat := range patterns {
		if matchName(pat, name) {
			return true
		}
	}
	return false
}

// matchName matches one pattern.
func matchName(pattern, name string) bool {
	if pattern == name {
		return true
	}
	return matchWords(strings.Split(pattern, "."), strings.Split(name, "."))
}

// matchWords is the word match, greedy with backtracking on `#`.
//
// It is the two-pointer form rather than the recursive one on purpose: a
// pattern holding several `#` against a long routing key would make the
// recursion exponential, and while the patterns come from the configuration
// the names come off the wire.
func matchWords(pat, words []string) bool {
	pi, wi := 0, 0
	star, wStar := -1, 0
	for wi < len(words) {
		switch {
		case pi < len(pat) && pat[pi] == "#":
			star, wStar = pi, wi
			pi++
		case pi < len(pat) && wordMatch(pat[pi], words[wi]):
			pi++
			wi++
		case star >= 0:
			// The last `#` takes one more word.
			wStar++
			wi = wStar
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == "#" {
		pi++
	}
	return pi == len(pat)
}

// wordMatch matches one word, where a `*` on its own is any word and anything
// else is a shell glob over the word's characters.
func wordMatch(pat, word string) bool {
	if pat == "*" {
		return true
	}
	ok, err := path.Match(pat, word)
	return err == nil && ok
}

func ruleName(r *rule) string {
	if r == nil {
		return ""
	}
	return r.name
}

func hasFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func lowerAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

func upperAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToUpper(strings.TrimSpace(s)))
	}
	return out
}

func or(v, def int) int {
	if v > 0 {
		return v
	}
	return def
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
