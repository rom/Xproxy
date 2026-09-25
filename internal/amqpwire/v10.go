package amqpwire

import (
	"fmt"
	"strings"
)

// AMQP 1.0, which is a different protocol wearing the same name.
//
// There are no classes and no methods. A frame body is one described type
// -- a descriptor code and a list of fields -- and there are nine of them
// for the protocol and five for its SASL layer. The thing being authorised
// is not an operation on a named exchange; it is an *attach*, which binds a
// link to an address on the broker and says which way messages will flow.
// Everything after it is a handle.
//
// That changes what a policy has to hold on to. On 0-9-1 every publish
// names its exchange, so a relay can decide each one on its own. On 1.0 the
// name is in the attach and the transfers that follow carry a link handle,
// so a relay that did not remember the attach would be forwarding messages
// to an address it never checked. Deciding the attach -- and keeping the
// handle table that makes the transfers attributable -- is the whole of the
// work on this version.

// The performative descriptors of AMQP 1.0 §2.7, and of its SASL layer
// (§5.3.3).
const (
	PerfOpen        uint64 = 0x10
	PerfBegin       uint64 = 0x11
	PerfAttach      uint64 = 0x12
	PerfFlow        uint64 = 0x13
	PerfTransfer    uint64 = 0x14
	PerfDisposition uint64 = 0x15
	PerfDetach      uint64 = 0x16
	PerfEnd         uint64 = 0x17
	PerfClose       uint64 = 0x18

	PerfSASLMechanisms uint64 = 0x40
	PerfSASLInit       uint64 = 0x41
	PerfSASLChallenge  uint64 = 0x42
	PerfSASLResponse   uint64 = 0x43
	PerfSASLOutcome    uint64 = 0x44
)

// The descriptors of the source and target a link attaches to (§3.5.3 and
// §3.5.4), which is where the address lives.
const (
	descSource uint64 = 0x28
	descTarget uint64 = 0x29
)

var performativeNames = map[uint64]string{
	PerfOpen:           "open",
	PerfBegin:          "begin",
	PerfAttach:         "attach",
	PerfFlow:           "flow",
	PerfTransfer:       "transfer",
	PerfDisposition:    "disposition",
	PerfDetach:         "detach",
	PerfEnd:            "end",
	PerfClose:          "close",
	PerfSASLMechanisms: "sasl-mechanisms",
	PerfSASLInit:       "sasl-init",
	PerfSASLChallenge:  "sasl-challenge",
	PerfSASLResponse:   "sasl-response",
	PerfSASLOutcome:    "sasl-outcome",
}

// Performative is one AMQP 1.0 frame body.
type Performative struct {
	Code uint64
	// Descriptor is the symbol form, for a sender that wrote the
	// descriptor as a name rather than a code. Both forms are legal and
	// both are in use.
	Descriptor string
	Fields     []Value
}

// Performatives is every performative name this package knows, for the
// configuration to validate a policy's spelling against.
func Performatives() []string {
	out := make([]string, 0, len(performativeNames))
	for _, n := range performativeNames {
		out = append(out, n)
	}
	return out
}

// PerformativeCode is the descriptor a name stands for.
func PerformativeCode(name string) (uint64, bool) {
	for c, n := range performativeNames {
		if n == name {
			return c, true
		}
	}
	return 0, false
}

// ParsePerformative reads a 1.0 frame body.
func ParsePerformative(payload []byte) (*Performative, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("an empty frame body is not a performative")
	}
	t := newTypeReader(payload)
	v := t.value(0)
	if t.err != nil {
		return nil, t.err
	}
	if v.Kind != KindDescribed {
		return nil, fmt.Errorf("a frame body that is not a described type is not a performative")
	}
	p := &Performative{Code: v.Descriptor, Descriptor: v.DescriptorName}
	if len(v.Described) > 0 {
		body := v.Described[0]
		switch body.Kind {
		case KindList:
			p.Fields = body.Items
		case KindNull:
			// A performative with no fields at all, which `end` and
			// `close` may legally be.
		default:
			return nil, fmt.Errorf("the fields of %s are not a list", describe(v))
		}
	}
	// A descriptor written as a symbol is resolved to its code, so
	// everything downstream can decide on one form.
	if p.Code == 0 && p.Descriptor != "" {
		if c, ok := symbolCode(p.Descriptor); ok {
			p.Code = c
		}
	}
	return p, nil
}

// symbolCode reads the `amqp:open:list` spelling of a descriptor.
func symbolCode(sym string) (uint64, bool) {
	s := strings.TrimPrefix(sym, "amqp:")
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return PerformativeCode(s)
}

// Name is the performative's name, or its descriptor when this package
// does not know it.
func (p *Performative) Name() string {
	if n, ok := performativeNames[p.Code]; ok {
		return n
	}
	if p.Descriptor != "" {
		return p.Descriptor
	}
	return fmt.Sprintf("%#x", p.Code)
}

// Known says whether this is a performative this package knows.
func (p *Performative) Known() bool { _, ok := performativeNames[p.Code]; return ok }

// SASL says whether this is a performative of the SASL layer, which
// travels in its own frame type and before the connection exists.
func (p *Performative) SASL() bool {
	return p.Code >= PerfSASLMechanisms && p.Code <= PerfSASLOutcome
}

// Open reads an open performative: who is connecting, to which virtual
// host, and the three bounds the connection will run under.
//
// `hostname` is this version's virtual host. It is how a broker that serves
// several tenants tells them apart, and it is the field a relay in front of
// one has to decide on before any link is attached -- an address means
// something different in each.
func (p *Performative) Open() (containerID, hostname string, maxFrame uint64, channelMax uint64, idleTimeout uint64, ok bool) {
	if p.Code != PerfOpen {
		return "", "", 0, 0, 0, false
	}
	containerID = field(p.Fields, 0).Text()
	hostname = field(p.Fields, 1).Text()
	maxFrame, _ = field(p.Fields, 2).Uint()
	channelMax, _ = field(p.Fields, 3).Uint()
	idleTimeout, _ = field(p.Fields, 4).Uint()
	return containerID, hostname, maxFrame, channelMax, idleTimeout, true
}

// The two directions a link can carry messages in, from the point of view
// of the peer that attached it.
const (
	RoleSender   = "sender"
	RoleReceiver = "receiver"
)

// Attach reads an attach performative: the link's name and handle, which
// way it goes, and the addresses at each end.
//
// The role is the field that decides what the link is *for*. A client
// attaching as a sender is publishing; as a receiver it is consuming. The
// address it needs is the one at the far end of that direction -- a
// sender's target, a receiver's source -- and both are returned, because a
// policy that checked the wrong one would be checking the client's own name
// for its link.
func (p *Performative) Attach() (name string, handle uint64, role, source, target string, ok bool) {
	if p.Code != PerfAttach {
		return "", 0, "", "", "", false
	}
	name = field(p.Fields, 0).Text()
	handle, _ = field(p.Fields, 1).Uint()
	role = RoleSender
	if field(p.Fields, 2).Bool() {
		role = RoleReceiver
	}
	source = nodeAddress(field(p.Fields, 5), descSource)
	target = nodeAddress(field(p.Fields, 6), descTarget)
	return name, handle, role, source, target, true
}

// nodeAddress reads the address out of a source or target.
//
// A dynamic link has no address: it asks the broker to make a node and
// answer with its name, which is how a reply queue is created on this
// version. That is reported as the empty address plus the dynamic marker,
// because "no address" and "an address I could not read" must not look the
// same to a policy.
func nodeAddress(v Value, want uint64) string {
	if v.Kind != KindDescribed || (v.Descriptor != want && v.DescriptorName == "") {
		return ""
	}
	if len(v.Described) == 0 {
		return ""
	}
	body := v.Described[0]
	if body.Kind != KindList {
		return ""
	}
	return field(body.Items, 0).Text()
}

// Dynamic says whether an attach asked the broker to create the node
// rather than naming one.
func (p *Performative) Dynamic() (sender, receiver bool) {
	if p.Code != PerfAttach {
		return false, false
	}
	return dynamicFlag(field(p.Fields, 5)), dynamicFlag(field(p.Fields, 6))
}

func dynamicFlag(v Value) bool {
	if v.Kind != KindDescribed || len(v.Described) == 0 {
		return false
	}
	body := v.Described[0]
	if body.Kind != KindList {
		return false
	}
	return field(body.Items, 4).Bool()
}

// Transfer reads a transfer performative: which link, and whether this is
// the whole message.
//
// `more` is what makes a size bound possible on this version. A message can
// be split across transfers, so a relay that bounded each frame would be
// bounding nothing: the sum over a run of transfers with `more` set is the
// message, and that is what has to be counted.
func (p *Performative) Transfer() (handle uint64, deliveryID uint64, settled, more, aborted, ok bool) {
	if p.Code != PerfTransfer {
		return 0, 0, false, false, false, false
	}
	handle, _ = field(p.Fields, 0).Uint()
	deliveryID, _ = field(p.Fields, 1).Uint()
	settled = field(p.Fields, 4).Bool()
	more = field(p.Fields, 5).Bool()
	aborted = field(p.Fields, 9).Bool()
	return handle, deliveryID, settled, more, aborted, true
}

// Handle is the link handle a flow, disposition or detach names, for the
// relay's own table.
func (p *Performative) Handle() (uint64, bool) {
	switch p.Code {
	case PerfFlow:
		v := field(p.Fields, 4) // handle, which a flow about the session omits
		if !v.Present() {
			return 0, false
		}
		h, ok := v.Uint()
		return h, ok
	case PerfDetach:
		h, ok := field(p.Fields, 0).Uint()
		return h, ok
	case PerfTransfer:
		h, ok := field(p.Fields, 0).Uint()
		return h, ok
	}
	return 0, false
}

// SASLMechanisms reads the mechanisms a broker offers. The field is one
// symbol or an array of them, and both forms are in use.
func (p *Performative) SASLMechanisms() ([]string, bool) {
	if p.Code != PerfSASLMechanisms {
		return nil, false
	}
	v := field(p.Fields, 0)
	switch v.Kind {
	case KindSymbol, KindString:
		return []string{v.Str}, true
	case KindArray, KindList:
		out := make([]string, 0, len(v.Items))
		for _, it := range v.Items {
			if s := it.Text(); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

// SASLInit reads the client's chosen mechanism and the identity its
// response carries. As on 0-9-1, the password is stepped over and never
// returned.
func (p *Performative) SASLInit() (mech, user, hostname string, ok bool) {
	if p.Code != PerfSASLInit {
		return "", "", "", false
	}
	mech = field(p.Fields, 0).Text()
	resp := field(p.Fields, 1)
	hostname = field(p.Fields, 2).Text()
	return mech, identityOf(mech, resp.Bin), hostname, true
}

// SASLOutcome reads the broker's verdict: 0 is ok and everything else is a
// refusal (§5.3.3.6).
//
// A relay reads it for the same reason the redis kind reads the reply to an
// AUTH: whether a connection is authenticated is the broker's answer, not
// the client's claim, and a relay that took the attempt for the outcome
// would treat a wrong password as a login.
func (p *Performative) SASLOutcome() (code uint64, ok bool) {
	if p.Code != PerfSASLOutcome {
		return 0, false
	}
	c, had := field(p.Fields, 0).Uint()
	if !had {
		return 0, false
	}
	return c, true
}

// CloseError reads the condition and description of a close, end or detach,
// which is this version's account of why something ended.
func (p *Performative) CloseError() (condition, description string, ok bool) {
	var at int
	switch p.Code {
	case PerfClose, PerfEnd:
		at = 0
	case PerfDetach:
		at = 2
	default:
		return "", "", false
	}
	v := field(p.Fields, at)
	if v.Kind != KindDescribed || len(v.Described) == 0 {
		return "", "", true
	}
	body := v.Described[0]
	if body.Kind != KindList {
		return "", "", true
	}
	return field(body.Items, 0).Text(), field(body.Items, 1).Text(), true
}

// SplitAddress reads a link address into the nouns a policy is written
// about.
//
// On 1.0 an address is a node name and the protocol says nothing about its
// shape, so the address itself is always one of the targets. But the
// brokers that serve both versions give it a shape: RabbitMQ's 1.0 plugin
// reads `/exchange/X/RK`, `/queue/Q`, `/amq/queue/Q` and `/topic/T`, and
// Azure Service Bus and Qpid use a bare node name. Where the shape is
// there, it is read -- so one exchange and queue policy covers both
// versions instead of an operator writing the same boundary twice in two
// vocabularies.
func SplitAddress(addr string) []Target {
	out := []Target{{Kind: KindAddress, Name: addr}}
	if addr == "" {
		return out
	}
	parts := strings.Split(strings.TrimPrefix(addr, "/"), "/")
	switch {
	case len(parts) >= 2 && parts[0] == "exchange":
		out = append(out, Target{Kind: KindExchange, Name: parts[1]})
		if len(parts) >= 3 && parts[2] != "" {
			out = append(out, Target{Kind: KindRoutingKey, Name: strings.Join(parts[2:], "/")})
		}
	case len(parts) >= 2 && parts[0] == "queue":
		out = append(out, Target{Kind: KindQueue, Name: strings.Join(parts[1:], "/")})
	case len(parts) >= 3 && parts[0] == "amq" && parts[1] == "queue":
		out = append(out, Target{Kind: KindQueue, Name: strings.Join(parts[2:], "/")})
	case len(parts) >= 2 && parts[0] == "topic":
		// RabbitMQ routes /topic/KEY through the amq.topic exchange, so
		// the key is the routing key and the exchange is implied.
		out = append(out, Target{Kind: KindExchange, Name: "amq.topic"},
			Target{Kind: KindRoutingKey, Name: strings.Join(parts[1:], "/")})
	}
	return out
}

// KindAddress is the target kind of a 1.0 link address, which is a node
// name and not necessarily an exchange or a queue.
const KindAddress = "address"
