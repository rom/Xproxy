package mms

import (
	"fmt"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/mms"
)

// The report a learning run writes.
//
// It is written to be argued with. An engineer reads it, strikes out the rows that
// are a contractor's laptop rather than the substation, and adopts the rest -- so
// every row has to say enough to be struck out on purpose, and the proposal has to be
// something that pastes into a configuration file without editing.
//
// The order of the file is deliberate. The three findings come before the rows,
// because a reader who adopts the proposal without seeing them has adopted a policy
// for traffic they did not understand: how many associations carried a cleartext
// password, how many requests operated the plant, and how many touched a protection
// setting.

// renderLearnedMMS writes the report.
func renderLearnedMMS(listener string, subjects []learn.Subject[learnKey, learnObs],
	st learn.Stats) string {
	var b strings.Builder
	b.WriteString(learn.Header("IEC 61850 MMS", listener, st, time.Now()))
	writeFindings(&b, subjects)
	writePreamble(&b)
	writeObserved(&b, subjects)
	b.WriteString("\n# A policy that permits what was seen, and nothing else. Read the\n")
	b.WriteString("# findings above before adopting it. This is the listener's own\n")
	b.WriteString("# `rules:` list, so it pastes in under the `mms:` section as it stands.\n")
	b.WriteString("#\n")
	b.WriteString("# The association is in none of these rules: a rule naming an AP-title\n")
	b.WriteString("# cannot match the transport connection or the associate request that\n")
	b.WriteString("# establishes one. The listener's own lists admit those.\n")
	b.WriteString("rules:\n")
	proposeMMS(&b, subjects)
	return b.String()
}

// writeFindings is what a reader has to see before the rows mean anything.
func writeFindings(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	var assoc, plaintext, operates, protects, selects uint64
	for _, s := range subjects {
		plaintext += s.Obs.plaintext
		operates += s.Obs.operates
		protects += s.Obs.protects
		selects += s.Obs.selects
		if s.Key.class == wire.ClassSession {
			assoc += s.Obs.requests
		}
	}
	b.WriteString("#\n# Findings, in the order they matter.\n#\n")
	switch {
	case plaintext == 0 && assoc == 0:
		b.WriteString("# authentication: no association request was recorded, so nothing here\n")
		b.WriteString("#   says how this estate authenticates.\n")
	case plaintext == 0:
		fmt.Fprintf(b,
			"# authentication: none of the %d associations recorded carried a cleartext\n", assoc)
		b.WriteString("#   password, which is what IEC 62351-4 asks for.\n")
	default:
		fmt.Fprintf(b,
			"# authentication: %d of %d associations carried a CLEARTEXT PASSWORD in the\n",
			plaintext, assoc)
		b.WriteString("#   ACSE authentication value. IEC 61850-8-1 specifies that form and\n")
		b.WriteString("#   IEC 62351-4 replaces it. Anything on the path between the client and\n")
		b.WriteString("#   the IED has read it, this relay included -- which is why this relay\n")
		b.WriteString("#   records its length and not its value. refuse_plaintext_passwords\n")
		b.WriteString("#   refuses them, and is the wrong thing to turn on until the clients\n")
		b.WriteString("#   have moved: on most of the installed base that password is the only\n")
		b.WriteString("#   authentication the IED has.\n")
	}
	if operates == 0 {
		b.WriteString("# control: nothing recorded operated the plant, so allow_operate: false\n")
		b.WriteString("#   costs this traffic nothing.\n")
	} else {
		fmt.Fprintf(b,
			"# control: %d requests operated the plant -- a $CO$ Oper, which is a breaker\n", operates)
		b.WriteString("#   or a disconnector moving. The rows below say which identity and which\n")
		b.WriteString("#   object, and those are the two lines to check against the operating\n")
		b.WriteString("#   procedure rather than against the traffic.\n")
		if selects == 0 {
			b.WriteString("#   None of them was preceded by a select, so this estate operates\n")
			b.WriteString("#   directly: require_select_before_operate would refuse every one of\n")
			b.WriteString("#   them as things stand.\n")
		} else {
			fmt.Fprintf(b,
				"#   %d selects were recorded, so select-before-operate is in use and\n", selects)
			b.WriteString("#   require_select_before_operate is a bound this traffic already meets.\n")
		}
	}
	if protects == 0 {
		b.WriteString("# protection: nothing recorded wrote a setting group or a configuration\n")
		b.WriteString("#   attribute, so the SG, SE and CF constraints can stay out of\n")
		b.WriteString("#   write_constraints.\n")
	} else {
		fmt.Fprintf(b,
			"# protection: %d requests wrote a setting group or a configuration attribute.\n", protects)
		b.WriteString("#   Those change what the device does in a FAULT rather than what it is\n")
		b.WriteString("#   doing now, and nothing moves until the fault they were meant to clear:\n")
		b.WriteString("#   a wrong trip characteristic is invisible until the day it matters.\n")
		b.WriteString("#   Put them behind a rule with a schedule, or out of the policy.\n")
	}
	b.WriteString("#\n")
}

// writePreamble explains what a row is.
func writePreamble(b *strings.Builder) {
	b.WriteString("# A subject is one calling identity -- the ACSE AP-title -- one class of\n")
	b.WriteString("# service, and one logical device. Not one object: an `objects` pattern is\n")
	b.WriteString("# the line an engineer argues about, and a subject per object would be four\n")
	b.WriteString("# hundred rows for one bay.\n")
	b.WriteString("#\n")
	b.WriteString("# denied_by_policy is what the current policy refused, or would have.\n")
	b.WriteString("# server_errors is what the *IED* refused -- an object it does not have, a\n")
	b.WriteString("# client it does not grant -- and a subject with nothing but those gets no\n")
	b.WriteString("# rule, because a rule for it would permit a thing that cannot happen.\n")
	b.WriteString("#\n")
	b.WriteString("# What this report will not propose: any of the bounds, and no relaxation of\n")
	b.WriteString("# refuse_plaintext_passwords. A report that proposed max_names from the\n")
	b.WriteString("# largest request it happened to see would widen the one setting a learning\n")
	b.WriteString("# run must not touch. Those appear as observations, under names no rule uses.\n")
	b.WriteString("#\n")
	b.WriteString("# No values are here. A Write's payload is a process value and a control's\n")
	b.WriteString("# ctlVal is a breaker position, and a learning report is a file that gets\n")
	b.WriteString("# pasted into a ticket.\n\n")
}

// writeObserved writes the rows.
func writeObserved(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	if len(subjects) == 0 {
		b.WriteString("observed: []  # nothing crossed this listener\n")
		return
	}
	b.WriteString("observed:\n")
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		fmt.Fprintf(b, "  - identity: %s\n", learn.Sanitise(k.identity))
		fmt.Fprintf(b, "    services: %s\n", k.class)
		if k.domain != "" {
			fmt.Fprintf(b, "    domain: %s\n", learn.Sanitise(k.domain))
		}
		fmt.Fprintf(b, "    requests: %d\n", o.requests)
		if o.denied > 0 {
			fmt.Fprintf(b, "    denied_by_policy: %d\n", o.denied)
		}
		if o.serverErrors > 0 {
			fmt.Fprintf(b, "    server_errors: %d  # the IED itself said no\n", o.serverErrors)
		}
		if c := sortedSet(o.clients); len(c) > 0 {
			fmt.Fprintf(b, "    seen_from: [%s]  # evidence, not policy: an address is what a lease changes\n",
				quoteList(c))
		}
		if v := sortedSet(o.services); len(v) > 0 {
			fmt.Fprintf(b, "    services_called: [%s]\n", strings.Join(v, ", "))
		}
		if v := sortedSet(o.auth); len(v) > 0 {
			fmt.Fprintf(b, "    authentication_seen: [%s]  # observation only\n",
				strings.Join(v, ", "))
		}
		if o.plaintext > 0 {
			fmt.Fprintf(b, "    cleartext_passwords: %d  # see the findings above\n", o.plaintext)
		}
		if v := sortedSet(o.objects); len(v) > 0 {
			fmt.Fprintf(b, "    objects_seen: [%s]\n", quoteList(v))
			if o.objectsFull {
				b.WriteString("    # more objects were seen than were recorded, so the proposal\n")
				b.WriteString("    # below names the constraint rather than the list.\n")
			}
		}
		if v := sortedSet(o.constraints); len(v) > 0 {
			fmt.Fprintf(b, "    constraints: [%s]\n", strings.Join(v, ", "))
		}
		if v := sortedSet(o.files); len(v) > 0 {
			fmt.Fprintf(b, "    files_seen: [%s]\n", quoteList(v))
		}
		if o.writes > 0 {
			fmt.Fprintf(b, "    writes: %d\n", o.writes)
		}
		if o.operates > 0 {
			fmt.Fprintf(b, "    operates: %d  # a breaker or a disconnector moved\n", o.operates)
		}
		if o.protects > 0 {
			fmt.Fprintf(b, "    protection_writes: %d  # a setting group or configuration\n", o.protects)
		}
		if o.selects > 0 {
			fmt.Fprintf(b, "    selects: %d\n", o.selects)
		}
		if o.maxNames > 0 {
			fmt.Fprintf(b, "    names_per_request: %d  # bound, not policy\n", o.maxNames)
		}
		fmt.Fprintf(b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}
}

// proposal is one identity's folded rule.
type proposal struct {
	identity string
	// services are the names called, not the classes' span.
	services map[string]bool
	// beyondAssociation says some class other than the session's was seen, without
	// which there is nothing for a rule to permit.
	beyondAssociation bool
	domains           map[string]bool
	objects           map[string]bool
	// vague is set where a domain's objects were truncated, so the pattern proposed
	// falls back to the constraint.
	vague            bool
	constraints      map[string]bool
	writeConstraints map[string]bool
	files            map[string]bool
	operates         bool
	requests, errors uint64
}

// proposeMMS folds the rows into one rule per identity.
func proposeMMS(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	byIdent := map[string]*proposal{}
	var order []string
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		p, ok := byIdent[k.identity]
		if !ok {
			p = &proposal{identity: k.identity,
				services: map[string]bool{}, domains: map[string]bool{},
				objects: map[string]bool{}, constraints: map[string]bool{},
				writeConstraints: map[string]bool{}, files: map[string]bool{}}
			byIdent[k.identity] = p
			order = append(order, k.identity)
		}
		p.requests += o.requests
		p.errors += o.serverErrors
		if k.class != wire.ClassSession {
			p.beyondAssociation = true
			for s := range o.services {
				p.services[s] = true
			}
		}
		if k.domain != "" {
			p.domains[k.domain] = true
		}
		if o.objectsFull {
			p.vague = true
			// The constraint is the pattern, per domain and per constraint: that is
			// the line an engineer would have written.
			for c := range o.constraints {
				p.objects[objectPattern(k.domain, c)] = true
			}
		} else {
			for obj := range o.objects {
				p.objects[obj] = true
			}
		}
		for c := range o.constraints {
			p.constraints[c] = true
		}
		if o.writes > 0 {
			for c := range o.constraints {
				p.writeConstraints[c] = true
			}
		}
		for f := range o.files {
			p.files[f] = true
		}
		if o.operates > 0 {
			p.operates = true
		}
	}
	wrote := false
	for _, id := range order {
		p := byIdent[id]
		switch {
		case p.identity == "<no association>":
			// Frames that arrived before any association existed: the transport
			// connection. There is no identity to write a rule about.
			continue
		case !p.beyondAssociation:
			fmt.Fprintf(b, "  # %s: nothing but the association was seen, so there is no\n",
				learn.Sanitise(p.identity))
			b.WriteString("  # rule to write: the listener's own lists admit that.\n")
			continue
		case p.requests > 0 && p.errors >= p.requests:
			fmt.Fprintf(b, "  # %s: every request was refused by the IED, so no rule is\n",
				learn.Sanitise(p.identity))
			b.WriteString("  # proposed -- a rule here would permit a thing that cannot happen.\n")
			continue
		}
		writeProposal(b, p)
		wrote = true
	}
	if !wrote {
		b.WriteString("  []  # nothing was seen that a rule could be written from\n")
	}
}

// objectPattern is a domain and a constraint as a glob: `LD0/*$MX$*`.
func objectPattern(domain, fc string) string {
	if domain == "" {
		return "*$" + fc + "$*"
	}
	return domain + "/*$" + fc + "$*"
}

func writeProposal(b *strings.Builder, p *proposal) {
	fmt.Fprintf(b, "  - name: %s\n", learn.Sanitise(ruleName(p.identity)))
	b.WriteString("    action: allow\n")
	if p.identity != "<no ap-title>" {
		fmt.Fprintf(b, "    ap_titles: [\"%s\"]\n", learn.Sanitise(p.identity))
	} else {
		b.WriteString("    # this identity sent no AP-title, so the rule names none: it will\n")
		b.WriteString("    # match every association that sends none. Configure the clients to\n")
		b.WriteString("    # send one, or narrow this rule by clients instead.\n")
	}
	if v := sortedSet(p.services); len(v) > 0 {
		fmt.Fprintf(b, "    services: [%s]\n", strings.Join(v, ", "))
	}
	if v := sortedSet(p.domains); len(v) > 0 {
		fmt.Fprintf(b, "    domains: [%s]\n", quoteList(v))
	}
	if v := sortedSet(p.objects); len(v) > 0 {
		fmt.Fprintf(b, "    objects: [%s]\n", quoteList(v))
		if p.vague {
			b.WriteString("    # a domain held more objects than were recorded, so its pattern is\n")
			b.WriteString("    # the functional constraint rather than a list: narrow it if you can.\n")
		}
	}
	if v := sortedSet(p.constraints); len(v) > 0 {
		fmt.Fprintf(b, "    functional_constraints: [%s]\n", strings.Join(v, ", "))
	}
	if v := sortedSet(p.writeConstraints); len(v) > 0 {
		fmt.Fprintf(b, "    write_constraints: [%s]\n", strings.Join(v, ", "))
	}
	if v := sortedSet(p.files); len(v) > 0 {
		fmt.Fprintf(b, "    files: [%s]\n", quoteList(v))
	}
	if !p.operates {
		// Said explicitly rather than left out. Nothing this identity did operated
		// the plant, and a rule that is silent about it inherits whatever the
		// listener allows -- which is the one default worth overriding per rule.
		b.WriteString("    allow_operate: false  # nothing recorded operated the plant\n")
	}
}

// ruleName is a name an engineer can read in a log line: the last arc of the
// AP-title, which is what distinguishes the clients in an estate that numbers them.
func ruleName(identity string) string {
	if identity == "<no ap-title>" {
		return "unnamed-client"
	}
	if i := strings.LastIndexByte(identity, '.'); i >= 0 && i+1 < len(identity) {
		return "client-" + identity[i+1:]
	}
	return "client-" + identity
}
