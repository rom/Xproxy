package mqtt

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mqtt"
	"github.com/rom/xproxy/internal/netutil"
)

// Three things about a publication are properties of the *topic* rather
// than of the listener: how large its payload may be, which qualities of
// service it may use, and whether it may be retained.
//
// A command topic wants QoS at least 1 and a payload of tens of octets; a
// firmware topic wants a large payload and retain; telemetry wants QoS 0
// and neither. One bound for the whole listener has to be the loosest of
// the three, which is the same as no bound -- so the bounds are per topic,
// and the listener's own are what a topic no rule names falls back to.

// topicRule is a compiled per-topic rule.
type topicRule struct {
	name    string
	filters []string
	maxLoad int
	minQoS  int
	maxQoS  int
	// hasQoS says a bound was set, because 0 is a real quality of service.
	hasMin, hasMax bool
	retain         *bool
}

// compileTopicRules compiles the per-topic rules. The filters are MQTT
// filters, checked at load: a filter that is not one would silently match
// nothing.
func compileTopicRules(in []config.MQTTTopicRule) ([]topicRule, error) {
	out := make([]topicRule, 0, len(in))
	for i := range in {
		c := &in[i]
		if c.Name == "" {
			return nil, fmt.Errorf("mqtt topics[%d].name: required", i)
		}
		if len(c.Filters) == 0 {
			return nil, fmt.Errorf("mqtt topics[%s].filters: required", c.Name)
		}
		r := topicRule{name: c.Name, maxLoad: c.MaxPayloadBytes, retain: c.AllowRetain}
		for _, f := range c.Filters {
			if err := wire.ValidFilter(f); err != nil {
				return nil, fmt.Errorf("mqtt topics[%s].filters: %q: %w", c.Name, f, err)
			}
			r.filters = append(r.filters, f)
		}
		if c.MinQoS != nil {
			if *c.MinQoS < 0 || *c.MinQoS > 2 {
				return nil, fmt.Errorf("mqtt topics[%s].min_qos: must be 0, 1 or 2", c.Name)
			}
			r.minQoS, r.hasMin = *c.MinQoS, true
		}
		if c.MaxQoS != nil {
			if *c.MaxQoS < 0 || *c.MaxQoS > 2 {
				return nil, fmt.Errorf("mqtt topics[%s].max_qos: must be 0, 1 or 2", c.Name)
			}
			r.maxQoS, r.hasMax = *c.MaxQoS, true
		}
		if r.hasMin && r.hasMax && r.minQoS > r.maxQoS {
			return nil, fmt.Errorf("mqtt topics[%s]: min_qos %d is above max_qos %d", c.Name, r.minQoS, r.maxQoS)
		}
		if c.MaxPayloadBytes < 0 {
			return nil, fmt.Errorf("mqtt topics[%s].max_payload_bytes: must not be negative", c.Name)
		}
		out = append(out, r)
	}
	return out, nil
}

// matchTopic is the first rule whose filters match a topic, or nil.
func matchTopic(rules []topicRule, topic string) *topicRule {
	for i := range rules {
		for _, f := range rules[i].filters {
			if wire.Match(f, topic) {
				return &rules[i]
			}
		}
	}
	return nil
}

// checkPublish applies the payload, QoS and retain bounds to one
// publication and returns the refusal reason, the rule that decided, and
// the empty string when it is allowed.
func (t *server) checkPublish(pub wire.Publish) (reason, rule string) {
	max := t.m.MaxPayloadBytes
	r := matchTopic(t.topics, pub.Topic)
	if r != nil && r.maxLoad > 0 {
		max = r.maxLoad
	}
	if max > 0 && pub.PayloadLen > max {
		if r != nil {
			return "payload_too_large", r.name
		}
		return "payload_too_large", ""
	}
	if r != nil {
		if r.hasMax && int(pub.QoS) > r.maxQoS {
			return "qos_too_high", r.name
		}
		if r.hasMin && int(pub.QoS) < r.minQoS {
			// A command that may be lost is not a command. This is the
			// bound that is about the process rather than the transport,
			// and it is the one an operator has to write down.
			return "qos_too_low", r.name
		}
		if r.retain != nil && pub.Retain && !*r.retain {
			return "retain_refused", r.name
		}
		if r.retain != nil && *r.retain {
			// This rule says retain is allowed here, whatever the
			// listener's own policy is: a configuration topic is the case
			// where a retained message is the point.
			return "", r.name
		}
	}
	if t.maxQoS < 2 && int(pub.QoS) > t.maxQoS {
		return "qos_too_high", ""
	}
	return "", ""
}

// checkSubscribeQoS applies the QoS bound to a subscription. A
// subscription asking for QoS 2 costs the broker the same stored state a
// publication does, so the bound is the same bound.
func (t *server) checkSubscribeQoS(filter string, qos byte) (reason, rule string) {
	if r := matchTopic(t.topics, filter); r != nil && r.hasMax && int(qos) > r.maxQoS {
		return "qos_too_high", r.name
	}
	if t.maxQoS < 2 && int(qos) > t.maxQoS {
		return "qos_too_high", ""
	}
	return "", ""
}

// sparkplugPolicy is the compiled Sparkplug B section.
type sparkplugPolicy struct {
	namespace    string
	requireNS    bool
	types        map[string]bool
	cmdClients   []netip.Prefix
	requireBirth bool
	checkSeq     bool
	maxNodes     int

	mu    sync.Mutex
	edges map[string]*edgeState
	// Dropped counts the edge nodes the bound refused to remember.
	Dropped uint64
}

// edgeState is what has been seen from one edge node.
type edgeState struct {
	born    bool
	seq     uint64
	haveSeq bool
}

func compileSparkplug(c *config.MQTTSparkplug) (*sparkplugPolicy, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	p := &sparkplugPolicy{namespace: c.Namespace, requireNS: c.RequireNamespace,
		requireBirth: c.RequireBirthBeforeData, checkSeq: c.CheckSequence,
		maxNodes: c.MaxNodes, edges: map[string]*edgeState{}}
	if p.namespace == "" {
		p.namespace = wire.SparkplugNamespace
	}
	if p.maxNodes <= 0 || p.maxNodes > 1<<20 {
		p.maxNodes = 8192
	}
	if len(c.AllowMessageTypes) > 0 {
		p.types = map[string]bool{}
		for _, name := range c.AllowMessageTypes {
			if !wire.SparkplugType(name) {
				return nil, fmt.Errorf("mqtt sparkplug.allow_message_types: %q is not a Sparkplug message type", name)
			}
			p.types[name] = true
		}
	}
	for _, c := range c.CommandClients {
		pre, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("mqtt sparkplug.command_clients: %w", err)
		}
		p.cmdClients = append(p.cmdClients, pre.Masked())
	}
	return p, nil
}

// check applies the Sparkplug policy to one publication and returns the
// refusal reason, or the empty string.
//
// The payload is passed rather than copied: the sequence number is two
// varints into a protobuf message, and the metrics are never decoded.
func (p *sparkplugPolicy) check(client netip.Addr, pub wire.Publish, payload []byte) string {
	if p == nil {
		return ""
	}
	sp, ok := wire.ParseSparkplug(pub.Topic)
	if !ok {
		if p.requireNS {
			// A listener declared to carry nothing but Sparkplug: a topic
			// that is not one is not a topic this listener carries.
			return "sparkplug_not_sparkplug"
		}
		return ""
	}
	if sp.Namespace != p.namespace {
		return "sparkplug_namespace"
	}
	if p.types != nil && !p.types[sp.Type] {
		return "sparkplug_message_type"
	}
	if wire.SparkplugCommand(sp.Type) && len(p.cmdClients) > 0 && !netutil.Contains(p.cmdClients, client) {
		// The reason this policy exists: NCMD and DCMD are commands to
		// equipment, and in most estates the publishers with any business
		// sending one are a short and known list.
		return "sparkplug_command_refused"
	}
	if !p.requireBirth && !p.checkSeq {
		return ""
	}
	seq, haveSeq := wire.SparkplugSeq(payload)
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.edges[sp.Edge()]
	if e == nil {
		if len(p.edges) >= p.maxNodes {
			// The table is full. The checks that need it cannot be made
			// for a node it does not hold, and refusing every message
			// from a node because a table is full would be an outage
			// caused by a bound.
			p.Dropped++
			return ""
		}
		e = &edgeState{}
		p.edges[sp.Edge()] = e
	}
	switch {
	case wire.SparkplugBirth(sp.Type):
		// A birth resets the sequence to zero, which is the convention's
		// own rule and the only place a sequence may jump.
		e.born = true
		e.seq, e.haveSeq = seq, haveSeq
		return ""
	case sp.Type == wire.SPNDeath || sp.Type == wire.SPDDeath:
		// A death ends the node. Its sequence is not checked, because a
		// death is published by the broker as the will of a session that
		// is already gone.
		e.born = false
		e.haveSeq = false
		return ""
	}
	if p.requireBirth && wire.SparkplugData(sp.Type) && !e.born {
		return "sparkplug_no_birth"
	}
	if p.checkSeq && haveSeq {
		if e.haveSeq && seq != wire.SparkplugNextSeq(e.seq) {
			// A gap or a repeat: a lost message, a duplicated publisher,
			// or somebody replaying one. The state moves to what arrived,
			// so one gap is one refusal rather than every message after it.
			e.seq = seq
			return "sparkplug_sequence"
		}
		e.seq, e.haveSeq = seq, true
	}
	return ""
}

// Edges is how many edge nodes are remembered, for the status view.
func (p *sparkplugPolicy) Edges() (int, uint64) {
	if p == nil {
		return 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.edges), p.Dropped
}
