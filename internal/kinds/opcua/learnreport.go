package opcua

import (
	"fmt"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
)

// The report: what was seen, and a policy that permits exactly that.
//
// It is written to be argued with. An engineer reads it, strikes out the rows that
// are a contractor's laptop rather than the plant, and adopts the rest — so every
// row has to say enough to be struck out on purpose, and the proposal has to be
// something that can be pasted into a configuration file without editing.

// renderLearnedOPCUA writes the report.
func renderLearnedOPCUA(listener string, subjects []learn.Subject[learnKey, learnObs],
	st learn.Stats) string {
	var b strings.Builder
	b.WriteString(learn.Header("OPC UA", listener, st, time.Now()))
	writeLearnPreamble(&b, subjects)
	writeLearnObserved(&b, subjects)
	b.WriteString("\n# A policy that permits what was seen, and nothing else. Read the two\n")
	b.WriteString("# paragraphs above before adopting it. This is the listener's own\n")
	b.WriteString("# `rules:` list, so it pastes in under the `opcua:` section as it stands.\n")
	b.WriteString("#\n")
	b.WriteString("# The handshake -- open_secure_channel, create_session, activate_session\n")
	b.WriteString("# -- is in none of these rules, and must not be added to them. A client\n")
	b.WriteString("# has sent no identity until it activates, so a rule that named the\n")
	b.WriteString("# identity could not match the messages that establish it. The listener's\n")
	b.WriteString("# own `services:` list is what admits the handshake, and these rules\n")
	b.WriteString("# narrow what an identified client may do once it has one.\n")
	b.WriteString("rules:\n")
	proposeOPCUA(&b, subjects)
	return b.String()
}

// writeLearnPreamble is what a reader has to know before the rows mean anything.
func writeLearnPreamble(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	b.WriteString("#\n")
	b.WriteString("# A subject is one identity -- an application URI and a user -- one class of\n")
	b.WriteString("# service, and one group of nodes. The group and not the node: a `nodes`\n")
	b.WriteString("# pattern is the line an engineer argues about, and a subject per node would\n")
	b.WriteString("# be two thousand rows for one HMI. A string identifier's group is its prefix,\n")
	b.WriteString("# so ns=4;s=Line1/Pump1/Speed groups under Line1/Pump1; a numeric identifier\n")
	b.WriteString("# has no structure to group by, so its group is the namespace and the\n")
	b.WriteString("# identifiers are listed inside it.\n")
	b.WriteString("#\n")
	b.WriteString("# Read three numbers before the proposal. denied_by_policy is what the current\n")
	b.WriteString("# policy refused, or would have. server_faults is what the *server* refused --\n")
	b.WriteString("# a node it does not have, or a user it does not grant -- and a subject with\n")
	b.WriteString("# nothing but faults gets no rule, because a rule for it would permit a thing\n")
	b.WriteString("# that cannot happen. And opaque_messages is the one to read first:\n")

	if opaque, total := opaqueShare(subjects); opaque > 0 {
		fmt.Fprintf(b, "#\n#   %d of %d recorded messages had an encrypted body.\n", opaque, total)
		b.WriteString("#\n")
		b.WriteString("# Under sign_and_encrypt this relay sees the channel, the session and the\n")
		b.WriteString("# sizes and no node identifier at all -- so those messages taught this report\n")
		b.WriteString("# nothing about the address space, and a proposal built from it would be a\n")
		b.WriteString("# policy for the traffic that happened to be readable. A run meant to learn\n")
		b.WriteString("# nodes wants security_modes: [sign] or require_readable_bodies: true for its\n")
		b.WriteString("# duration; mode sign still authenticates every message and still detects\n")
		b.WriteString("# modification, and it leaves the body readable.\n")
	} else {
		b.WriteString("# no message recorded here had an encrypted body, so every node the traffic\n")
		b.WriteString("# named is in this report.\n")
	}
	b.WriteString("#\n")
	b.WriteString("# What this report will not propose: a security policy, a security mode, or\n")
	b.WriteString("# any of the bounds. Seeing a channel in mode none is not a reason to allow\n")
	b.WriteString("# mode none, and a report that proposed the fastest publishing interval it\n")
	b.WriteString("# happened to see would widen the one setting learning must not touch. Those\n")
	b.WriteString("# appear below as observations, under names no rule uses.\n")
	b.WriteString("#\n")
	b.WriteString("# No values are here. A Write's payload is a process value and a method's\n")
	b.WriteString("# arguments are too, and a learning report is a file that gets pasted into a\n")
	b.WriteString("# ticket.\n\n")
}

// opaqueShare is how much of what was recorded taught nothing about nodes.
func opaqueShare(subjects []learn.Subject[learnKey, learnObs]) (opaque, total uint64) {
	for _, s := range subjects {
		opaque += s.Obs.opaque
		total += s.Obs.requests
	}
	return opaque, total
}

func writeLearnObserved(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	b.WriteString("observed:\n")
	if len(subjects) == 0 {
		b.WriteString("  []\n")
		return
	}
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		fmt.Fprintf(b, "  - application_uri: %s\n", learn.Sanitise(k.app))
		fmt.Fprintf(b, "    user: %s\n", learn.Sanitise(k.user))
		fmt.Fprintf(b, "    services: %s\n", k.class)
		if k.ns != "" {
			fmt.Fprintf(b, "    namespace: %s\n", k.ns)
		}
		if k.group != "" {
			fmt.Fprintf(b, "    node_group: %s\n", learn.Sanitise(k.group))
		}
		fmt.Fprintf(b, "    requests: %d\n", o.requests)
		if o.denied > 0 {
			fmt.Fprintf(b, "    denied_by_policy: %d\n", o.denied)
		}
		if o.serverFaults > 0 {
			fmt.Fprintf(b, "    server_faults: %d  # the server itself said no\n", o.serverFaults)
		}
		if o.opaque > 0 {
			fmt.Fprintf(b, "    opaque_messages: %d  # encrypted body; no node was read from these\n",
				o.opaque)
		}
		if c := sortedSet(o.clients); len(c) > 0 {
			fmt.Fprintf(b, "    seen_from: [%s]  # evidence, not policy: an address is what a lease changes\n",
				quoteList(c))
		}
		if nodes := sortedSet(o.nodes); len(nodes) > 0 {
			fmt.Fprintf(b, "    nodes_seen: [%s]\n", quoteList(nodes))
			if o.nodesFull {
				fmt.Fprintf(b, "    nodes_truncated: true  # more than %d under this group\n",
					maxLearnedNodes)
			}
		}
		if m := sortedSet(o.methods); len(m) > 0 {
			fmt.Fprintf(b, "    methods_called: [%s]\n", quoteList(m))
			if o.methodsFull {
				fmt.Fprintf(b, "    methods_truncated: true  # more than %d distinct methods\n",
					maxLearnedMethods)
			}
		}
		if a := sortedSet(o.attrs); len(a) > 0 {
			fmt.Fprintf(b, "    attributes: [%s]\n", strings.Join(a, ", "))
		}
		// The channel's terms, recorded and never proposed.
		if p := sortedSet(o.policies); len(p) > 0 {
			fmt.Fprintf(b, "    security_policies_seen: [%s]  # observation only\n",
				strings.Join(p, ", "))
		}
		if m := sortedSet(o.modes); len(m) > 0 {
			fmt.Fprintf(b, "    security_modes_seen: [%s]  # observation only\n",
				strings.Join(m, ", "))
		}
		if tk := sortedSet(o.tokens); len(tk) > 0 {
			fmt.Fprintf(b, "    token_kinds_seen: [%s]  # observation only\n", strings.Join(tk, ", "))
		}
		// The amplification numbers, under names no rule uses.
		if o.maxOps > 0 {
			fmt.Fprintf(b, "    operations_per_request: %d  # bound, not policy\n", o.maxOps)
		}
		if o.maxItems > 0 {
			fmt.Fprintf(b, "    monitored_items_asked: %d  # bound, not policy\n", o.maxItems)
		}
		if o.maxSubscriptions > 0 {
			fmt.Fprintf(b, "    subscriptions_held: %d  # bound, not policy\n", o.maxSubscriptions)
		}
		if o.minPublishMS > 0 {
			fmt.Fprintf(b, "    fastest_publishing_interval_ms: %.0f  # bound, not policy\n",
				o.minPublishMS)
		}
		if o.minSamplingMS > 0 {
			fmt.Fprintf(b, "    fastest_sampling_interval_ms: %.0f  # bound, not policy\n",
				o.minSamplingMS)
		}
		fmt.Fprintf(b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}
}

// proposal is one rule the report suggests: one identity, the service classes it
// used, and the nodes and methods it touched.
type proposal struct {
	app, user string
	classes   map[serviceClass]bool
	// services are the names seen, and unknownService whether one had no name to
	// propose. They are the services this identity called, not the ones its
	// classes cover.
	services       map[string]bool
	unknownService bool
	// beyondHandshake says some class other than the session's was seen. Without
	// it there is nothing for a rule to permit, because the handshake is not what
	// these rules speak about.
	beyondHandshake bool
	nodes           map[string]bool
	methods         map[string]bool
	attrs           map[string]bool
	// vague is set where a group was truncated, so the pattern proposed for it is
	// a prefix wildcard rather than a list -- and the report says which.
	vague bool
	// onlyFaults is set where every request in every one of the identity's
	// subjects was refused by the server. No rule is proposed for such an
	// identity, because there is nothing it successfully did.
	requests, faults uint64
}

// proposeOPCUA folds the subjects into one rule per identity.
func proposeOPCUA(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	type ident struct{ app, user string }
	byIdent := map[ident]*proposal{}
	var order []ident
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		id := ident{k.app, k.user}
		p, ok := byIdent[id]
		if !ok {
			p = &proposal{app: k.app, user: k.user,
				classes: map[serviceClass]bool{}, services: map[string]bool{},
				nodes:   map[string]bool{},
				methods: map[string]bool{}, attrs: map[string]bool{}}
			byIdent[id] = p
			order = append(order, id)
		}
		p.requests += o.requests
		p.faults += o.serverFaults
		p.classes[k.class] = true
		if k.class != classSession {
			p.beyondHandshake = true
			// The session class is recorded above and proposed never. A rule
			// naming an identity cannot match OpenSecureChannel or CreateSession,
			// because the client has sent no identity yet -- and a rule narrowing
			// CloseSession would refuse a client closing cleanly. The listener's
			// own `services` list admits the handshake; these rules are about what
			// an identified client does with it.
			for svc := range o.services {
				p.services[svc] = true
			}
		}
		if o.unknownService {
			p.unknownService = true
		}
		if o.nodesFull {
			p.vague = true
		}
		// A group's pattern, or the individual nodes where there is no group. A
		// numeric namespace with a handful of identifiers proposes them; one that
		// was truncated proposes the namespace.
		switch {
		case k.group != "" && len(o.nodes) > 1:
			p.nodes[k.ns+";s="+k.group+"/*"] = true
		case o.nodesFull:
			// A numeric namespace whose identifiers were truncated. There is no
			// prefix to wildcard, so the namespace is what the proposal can say —
			// and it says so, because a list of the first twenty-four of an
			// unknown number is worse than a wildcard somebody argues with.
			p.nodes[k.ns+";i=*"] = true
		default:
			// One node under a group, or a handful in a numeric namespace: name
			// them. A group whose nodes were truncated has more than one, so it
			// took the first case.
			for n := range o.nodes {
				p.nodes[n] = true
			}
		}
		for m := range o.methods {
			p.methods[m] = true
		}
		for a := range o.attrs {
			p.attrs[a] = true
		}
	}
	wrote := false
	for _, id := range order {
		p := byIdent[id]
		if p.app == "<no session>" {
			// Messages that arrived before any session existed. There is no
			// identity to write a rule about, and the handshake services are
			// allowed by the listener's own defaults.
			continue
		}
		if !p.beyondHandshake {
			// Only handshake traffic, which the rules do not speak about. The row
			// above says what was seen; there is nothing here to permit.
			fmt.Fprintf(b, "  # %s / %s: nothing but the handshake was seen, so there is\n",
				learn.Sanitise(p.app), learn.Sanitise(p.user))
			b.WriteString("  # no rule to write: the listener's own service list admits that.\n")
			continue
		}
		if p.requests > 0 && p.faults >= p.requests {
			fmt.Fprintf(b, "  # %s / %s: every request was refused by the server, so no rule\n",
				learn.Sanitise(p.app), learn.Sanitise(p.user))
			b.WriteString("  # is proposed -- a rule here would permit a thing that cannot happen.\n")
			continue
		}
		writeProposal(b, p)
		wrote = true
	}
	if !wrote {
		b.WriteString("  []  # nothing was seen that a rule could be written from\n")
	}
}

func writeProposal(b *strings.Builder, p *proposal) {
	fmt.Fprintf(b, "  - name: %s\n", learn.Sanitise(ruleName(p)))
	b.WriteString("    action: allow\n")
	if p.app != "" {
		fmt.Fprintf(b, "    application_uris: [\"%s\"]\n", learn.Sanitise(p.app))
	}
	if named := namedUser(p.user); named != "" {
		fmt.Fprintf(b, "    users: [\"%s\"]\n", learn.Sanitise(named))
	} else {
		fmt.Fprintf(b, "    # no user name was seen (%s), so this rule names none\n",
			learn.Sanitise(p.user))
	}
	if svc := sortedSet(p.services); len(svc) > 0 {
		fmt.Fprintf(b, "    services: [%s]\n", strings.Join(svc, ", "))
	} else {
		// Every service this identity called was one with no configuration name,
		// so the rule names none and the listener's own list still decides. A
		// `services` key naming nothing would deny everything.
		b.WriteString("    # no service seen for this identity has a configuration name\n")
	}
	if p.unknownService {
		b.WriteString("    # and at least one service this build does not name, which is left\n")
		b.WriteString("    # out: a service nobody recognised is not one to allow.\n")
	}
	if nodes := sortedSet(p.nodes); len(nodes) > 0 {
		fmt.Fprintf(b, "    nodes: [%s]\n", quoteList(nodes))
		if p.vague {
			b.WriteString("    # a group held more nodes than were recorded, so its pattern is a\n")
			b.WriteString("    # prefix wildcard rather than a list: narrow it if you can.\n")
		}
	}
	if p.classes[classWrite] {
		if m := sortedSet(p.methods); len(m) > 0 {
			fmt.Fprintf(b, "    methods: [%s]\n", quoteList(m))
		}
		if a := sortedSet(p.attrs); len(a) > 0 {
			fmt.Fprintf(b, "    write_attributes: [%s]\n", strings.Join(a, ", "))
		} else {
			b.WriteString("    # no attribute was recorded for the writes, so write_attributes is\n")
			b.WriteString("    # left to the listener's default of `value` -- which is the line\n")
			b.WriteString("    # between moving an actuator and changing who may move it.\n")
		}
	}
}

// ruleName is a name an engineer can read in a log line.
func ruleName(p *proposal) string {
	app := lastSegment(p.app)
	if named := namedUser(p.user); named != "" {
		return app + "-" + named
	}
	return app
}

// namedUser is the user name where one was seen, and empty for the placeholders.
func namedUser(u string) string {
	if strings.HasPrefix(u, "<") {
		return ""
	}
	return u
}

// lastSegment is the readable tail of an application URI: urn:plant:scada:hmi1
// becomes hmi1.
func lastSegment(s string) string {
	if s == "" {
		return "learned"
	}
	for _, sep := range []string{":", "/"} {
		if i := strings.LastIndex(s, sep); i >= 0 && i+1 < len(s) {
			s = s[i+1:]
		}
	}
	return s
}
