// Package admit is the two questions every listener kind asks about a client
// before it carries anything for it: do the imported lists know this address,
// and does the estate's authorisation policy allow it here.
//
// It exists because those two questions were answered in two places for two
// kinds and nowhere for the rest. The HTTP gateway asked the lists about the
// client and the forward proxy asked them about the destination; no other kind
// asked them at all, so a cidr feed did nothing on an SSH, Modbus or syslog
// listener. The authorisation policy had the same shape of gap. Both belong at
// the same point in a kind -- the moment it has a client and has not yet carried
// anything for it -- and a kind that has one admission point rather than two is a
// kind where the order cannot drift.
//
// # What it is not
//
// It is not the ban list. A ban is this proxy's own finding about this client
// and applies to everything, including the health endpoint. A list is an import,
// and an import with one wrong line in it must not take the endpoint an operator
// watches an outage with -- which is why this is not in the accept path either:
// the HTTP gateway's per-route exemption and the challenge action both need the
// request, and an accept-path check cannot see one.
//
// It is not each kind's own policy. What a Modbus write to holding register
// 40001 means is the modbus kind's business, and nothing here could say it.
package admit

import (
	"context"
	"net/netip"

	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/intel"
	"github.com/rom/xproxy/internal/logging"
)

// Reason is the deny reason an imported list's refusal carries. The policy's own
// is authorization.Reason; the two are separate because they are separate
// findings, and an operator reading a refusal needs to know whether it was their
// rule or somebody else's feed.
const Reason = "threat_intel"

// QuarantineReason is the deny reason a behaviour pack's quarantine carries.
//
// A separate reason from everything else here on purpose. An operator reading a
// refused session needs to know it was this proxy's own detection holding the
// address out for a window rather than a feed, a rule or a ban -- because the
// three are undone in three different places, and a quarantine is undone by
// waiting or by `xproxyctl packs release`.
const QuarantineReason = "pack_quarantine"

// Gate is what a listener kind lends this package so a refusal made here is
// counted, logged and banned on exactly as one the kind made itself.
//
// It is the same shape as authorization.Gate, and for the same reason: the kinds
// spell their counters and events differently, and the part that must not differ
// between them is the order, which is Client's job below.
type Gate struct {
	// Shadowing reports whether this listener is in shadow mode.
	Shadowing func() bool
	// Record writes a refusal that is not being enforced, with the rule or the
	// list that decided in its own field.
	Record func(reason, rule, detail string)
	// Deny counts and logs an enforced refusal. It may be nil for a kind whose
	// caller counts the reason it is handed.
	Deny func(reason, rule, detail string)
	// Quarantine counts and logs an enforced pack quarantine without feeding
	// the listener's ordinary denial path. In particular, implementations must
	// not submit this refusal to the automatic-ban ladder.
	Quarantine func(reason, rule, detail string)
}

// Deps are the process-wide facilities the two questions need. A kind passes
// what its host gives it; either may be nil, and a nil one asks nothing.
type Deps struct {
	Lists  *intel.Set
	Policy *authorization.Policy
	Logs   *logging.Logs
	// Matched and Blocked count what the lists did, so an operator can see a
	// feed working before anything is refused by it.
	Matched, Blocked func()
	// Observe, where a kind passes one, writes the admission to the
	// cross-listener window: this client was on this listener, and whether
	// it was let through.
	//
	// It is the kind's business whether to pass one, because the frequency
	// is: a stream kind admits a client once per connection, and a
	// datagram kind would be writing a fact per packet. The ones that
	// admit per datagram record from their own session tables instead.
	Observe func(correlate.Fact)
	// Quarantined reports whether a behaviour pack is holding this address
	// out, and which pack. Nil asks nothing, which is what a daemon with no
	// pack directory passes.
	//
	// It is asked here for the reason the lists and the policy are: a tool
	// refused on Modbus tries S7 next, so a detection that held an actor on
	// one listener only would be a detection somebody walks around.
	Quarantined func(netip.Addr) (string, bool)
}

// Client asks both questions about one client and reports the reason to refuse,
// or "" to carry on.
//
// The lists come first and the policy second, deliberately. A list is an import
// about an address and says nothing about this estate's intentions; the policy is
// what the estate wrote. Asking the import first means a refusal names the feed
// rather than a rule the operator would then go looking for and not find -- and
// it means a client the estate has no rule about is refused as "not in the
// policy" rather than as "on somebody's list", which is the truer of the two.
//
// A list whose action is not block is not a refusal here. An estate's challenge
// action needs a request to serve a challenge into, and these kinds have none, so
// a list asking for one is recorded like a log list rather than escalated into a
// block -- which would be a policy the operator did not write.
func Client(d Deps, sub authorization.Subject, g Gate) string {
	reason := ask(d, sub, g)
	note(d, sub, reason)
	return reason
}

// ask is the questions themselves.
func ask(d Deps, sub authorization.Subject, g Gate) string {
	// The quarantine first. It is this proxy's own finding about this address,
	// made minutes ago from its own traffic, so a session refused for it should
	// say so rather than being attributed to whichever import or rule would
	// have refused it next. It obeys shadow mode like everything else here: a
	// listener recording what it would have refused records this too.
	if d.Quarantined != nil {
		if pack, held := d.Quarantined(sub.Client); held {
			detail := pack + " " + sub.Client.String()
			if g.Shadowing != nil && g.Shadowing() {
				g.Record(QuarantineReason, pack, detail)
			} else {
				if g.Quarantine != nil {
					g.Quarantine(QuarantineReason, pack, detail)
				} else if d.Logs != nil {
					// Ordinary deny callbacks may also submit the actor to the
					// automatic-ban ladder. A quarantine is deliberately bounded
					// by its pack window, so report it directly when the kind has
					// no non-escalating callback.
					d.Logs.SecurityEvent(context.Background(), "deny", QuarantineReason,
						"listener", sub.Listener, "proto", sub.Kind,
						"client_ip", sub.Client.String(), "pack", pack,
						"detail", detail)
				}
				return QuarantineReason
			}
		}
	}
	if list := listed(d, sub); list != "" {
		detail := list + " " + sub.Client.String()
		if g.Shadowing != nil && g.Shadowing() {
			g.Record(Reason, list, detail)
		} else {
			if d.Blocked != nil {
				d.Blocked()
			}
			if g.Deny != nil {
				g.Deny(Reason, list, detail)
			}
			return Reason
		}
	}
	return d.Policy.Ask(sub, sub.User, authorization.Gate{
		Shadowing: g.Shadowing,
		Record:    g.Record,
		Deny:      g.Deny,
	})
}

// note writes the admission to the cross-listener window.
//
// It is here rather than in each kind because this is the one point every
// kind passes through with a client in hand and nothing carried yet, which
// makes it the one place where "this address was on this listener" is
// recorded the same way for all of them. The cross-kind questions -- one
// host on Modbus, then S7, then IEC 104 -- are answered from these facts,
// and a kind that recorded its own would be a kind that could spell the
// class differently from its siblings.
func note(d Deps, sub authorization.Subject, reason string) {
	if d.Observe == nil {
		return
	}
	f := correlate.Fact{
		Class:    correlate.ClassSession,
		Kind:     sub.Kind,
		Listener: sub.Listener,
		Identity: sub.User,
	}
	if reason != "" {
		f.Class = correlate.ClassRefused
		f.Detail = reason
	}
	d.Observe(f)
}

// listed asks the imported lists about the client and returns the name of the
// list that asks for a refusal, or "".
//
// Only the client address and its TLS fingerprint are offered. A domain, a URL
// or a payload digest is not something these kinds have: a Modbus frame names no
// host, and a list asked a question it has no entries for would answer it.
func listed(d Deps, sub authorization.Subject) string {
	if d.Lists == nil || !sub.Client.IsValid() {
		return ""
	}
	hit, ok := d.Lists.Match(intel.Subject{IP: sub.Client})
	if !ok {
		return ""
	}
	if d.Matched != nil {
		d.Matched()
	}
	if hit.Action == intel.ActionBlock {
		return hit.List
	}
	if d.Logs != nil && d.Lists.Logs() {
		// A list that only logs still says so: a list nobody can see matching is
		// a list nobody can tune.
		d.Logs.SecurityEvent(context.Background(), "allow", "threat_intel",
			"listener", sub.Listener, "proto", sub.Kind,
			"client_ip", sub.Client.String(), "list", hit.List,
			"kind", hit.Kind, "action", hit.Action)
	}
	return ""
}

// Addr is the client address a kind hands in, for the kinds whose sessions are
// datagrams and carry an AddrPort rather than an Addr.
func Addr(ap netip.AddrPort) netip.Addr { return ap.Addr().Unmap() }
