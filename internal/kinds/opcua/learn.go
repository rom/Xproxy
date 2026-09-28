package opcua

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/opcua"
)

// Learning mode for OPC UA.
//
// Nobody knows what an estate's OPC UA traffic is. A server's address space has
// thousands of nodes and its own documentation lists all of them; the traffic uses a
// few dozen. A policy written from the documentation allows everything, and one
// written from a guess refuses the half nobody wrote down — which on a plant means
// an HMI screen that stops updating during a shift, and a security control that gets
// switched off and stays off.
//
// Three things shape what is recorded.
//
// **A subject is one identity and one node group, not one node.** The line an
// engineer argues about is a `nodes` pattern, and a subject per node would be a
// report with two thousand rows for one HMI. A string node identifier has structure
// — `ns=4;s=Line1/Pump1/Speed` — so its group is the prefix, exactly as the TFTP
// report groups by directory; a numeric identifier has none, so its group is the
// namespace and the identifiers inside it are listed as a bounded set.
//
// **A channel that encrypts its bodies teaches nothing about nodes.** Under
// sign_and_encrypt this relay sees the channel, the session and the sizes and no
// node identifier at all. A run over such a channel produces subjects with an
// identity and no address space, and the report says so — per subject and in its
// header — rather than leaving an operator to conclude the plant reads almost
// nothing. It is the one finding a reader of an OPC UA learning report has to see
// first.
//
// **What is recorded and never proposed is the part that bounds amplification.**
// The publishing and sampling intervals, the operations per request and the
// monitored items per subscription appear as observations under names no rule uses,
// because a report that proposed the fastest interval it happened to see would widen
// the one setting learning must not touch. Nor is a security policy or mode ever
// proposed: seeing a channel in mode none is not a reason to allow mode none, and no
// run proposes allow_deprecated_policies.
//
// What is never recorded is a value. A Write's payload is a process value and a
// method's arguments are too, and a learning report is a file that gets pasted into
// a ticket.

const (
	// maxLearnedNodes bounds the node identifiers remembered per subject. A
	// prefix group with more than this many nodes under it is a group a pattern
	// should cover rather than a list somebody reads.
	maxLearnedNodes = 24
	// maxLearnedMethods bounds the methods remembered per subject. A handful is
	// the real number; past it there is no policy to write from a list.
	maxLearnedMethods = 16
	// maxLearnedTerms bounds each of the small sets: the security policies, the
	// modes, the token kinds, the attributes.
	maxLearnedTerms = 8
	// maxLearnedServices bounds the service names remembered per subject. A
	// subject is one class of service, so the real number is a handful; the bound
	// is the whole table's worth, past which the names say nothing.
	maxLearnedServices = 24
)

// serviceClass is how a subject groups services, because a report with a row per
// service identifier would be a row per call and a policy is not written that way.
//
// The classes are the four decisions an engineer makes: may this client read, may it
// browse, may it subscribe, may it change something. Everything that changes the
// plant is one class on purpose — a report that separated Write from Call would
// invite a rule that allowed one and not the other on the same nodes, which is not
// a distinction the address space supports.
type serviceClass string

const (
	classSession   serviceClass = "session"
	classRead      serviceClass = "read"
	classBrowse    serviceClass = "browse"
	classSubscribe serviceClass = "subscribe"
	classWrite     serviceClass = "write"
	classOther     serviceClass = "other"
)

// classOf places a service in its class.
func classOf(s wire.Service) serviceClass {
	switch s {
	case wire.SvcFindServers, wire.SvcGetEndpoints, wire.SvcOpenChannel,
		wire.SvcCloseChannel, wire.SvcCreateSession, wire.SvcActivateSession,
		wire.SvcCloseSession, wire.SvcCancel:
		return classSession
	case wire.SvcRead, wire.SvcHistoryRead:
		return classRead
	case wire.SvcBrowse, wire.SvcBrowseNext, wire.SvcTranslatePaths,
		wire.SvcRegisterNodes, wire.SvcUnregisterNodes:
		return classBrowse
	case wire.SvcCreateSubscription, wire.SvcModifySubscription,
		wire.SvcSetPublishingMode, wire.SvcDeleteSubscriptions,
		wire.SvcCreateMonitored, wire.SvcModifyMonitored, wire.SvcSetMonitoringMode,
		wire.SvcSetTriggering, wire.SvcDeleteMonitored, wire.SvcPublish,
		wire.SvcRepublish:
		return classSubscribe
	}
	if s.Writes() {
		return classWrite
	}
	return classOther
}

// learnKey identifies one subject.
//
// The identity is the application URI and the user rather than the address, because
// on this protocol those are what a rule names and an address is what a DHCP lease
// changes. The address is recorded inside the observation instead, where it is
// evidence rather than the subject.
type learnKey struct {
	app   string
	user  string
	class serviceClass
	// ns is the namespace index the nodes were in, and group the prefix of a
	// string identifier within it. Both are empty for a subject with no node at
	// all: a session service, or a message whose body the channel encrypted.
	ns    string
	group string
}

// learnObs is what was seen of one subject.
type learnObs struct {
	first, last time.Time
	requests    uint64
	// denied counts what the policy refused, or would have refused on a listener
	// learning without enforcement.
	denied uint64
	// serverFaults counts what the *server* refused: a node it does not have, or
	// a user it does not grant. Those belong out of the policy rather than in it,
	// and a subject with nothing but faults gets no rule proposed.
	serverFaults uint64
	// opaque counts the messages whose body the channel encrypted, which are the
	// messages this subject taught nothing about.
	opaque uint64
	// clients are the addresses the identity was seen from, which is evidence
	// rather than policy: an address is what a lease changes.
	clients map[string]bool
	// services are the service names seen, in the configuration's own
	// vocabulary. They are recorded rather than derived from the subject's class,
	// because a class covers more services than any one subject called: a
	// proposal built from the class would allow HistoryRead to an identity that
	// only ever read a live value.
	services map[string]bool
	// unknownService is set where a service this package does not name was seen.
	// It has no configuration name to propose, so the report says so instead.
	unknownService bool
	// nodes are the identifiers seen inside the group, methods the methods
	// called, attrs the attributes named.
	nodes, methods, attrs   map[string]bool
	nodesFull, methodsFull  bool
	policies, modes, tokens map[string]bool
	// The amplification observations, recorded and never proposed.
	maxOps           int
	maxItems         int
	minPublishMS     float64
	minSamplingMS    float64
	maxSubscriptions int
}

type learner = learn.Run[learnKey, learnObs]

// learnConfig is the part of the configuration the learner needs.
type learnConfig struct {
	enabled     bool
	listener    string
	file        string
	interval    time.Duration
	maxSubjects int
}

func newLearner(c *learnConfig) *learner {
	if c == nil || !c.enabled {
		return nil
	}
	return learn.New(learn.Options[learnKey, learnObs]{
		Kind:     "opcua",
		Listener: c.listener,
		Path:     c.file,
		Interval: c.interval,
		Max:      c.maxSubjects,
		Render:   renderLearnedOPCUA,
		Less:     learnLessOPCUA,
		Clone:    cloneOPCUAObs,
	})
}

func learnLessOPCUA(a, b learnKey) bool {
	if a.app != b.app {
		return a.app < b.app
	}
	if a.user != b.user {
		return a.user < b.user
	}
	if a.class != b.class {
		return a.class < b.class
	}
	if a.ns != b.ns {
		return a.ns < b.ns
	}
	return a.group < b.group
}

func cloneOPCUAObs(o learnObs) learnObs {
	out := o
	out.services = cloneSet(o.services)
	out.clients = cloneSet(o.clients)
	out.nodes = cloneSet(o.nodes)
	out.methods = cloneSet(o.methods)
	out.attrs = cloneSet(o.attrs)
	out.policies = cloneSet(o.policies)
	out.modes = cloneSet(o.modes)
	out.tokens = cloneSet(o.tokens)
	return out
}

func cloneSet(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// identity is how a subject names who it was, falling back in the order the
// protocol establishes things: the user if the session activated, the application if
// it got as far as CreateSession, and otherwise nothing.
//
// The fallbacks are labelled rather than left empty. A report whose `user` column is
// blank for half its rows reads as missing data; one that says `<no session>` says
// the truth, which is that those messages arrived before any session existed.
func identityOf(s Session) (app, user string) {
	app, user = s.ApplicationURI, s.User
	if app == "" {
		app = "<no session>"
	}
	if !s.Activated {
		user = "<not activated>"
	} else if user == "" {
		// An anonymous or certificate token names no user name. Saying which
		// rather than leaving it blank is what lets a reader tell an anonymous
		// session from a missing observation.
		user = "<" + s.TokenKind.String() + ">"
	}
	return app, user
}

// groupOf splits a node identifier into the namespace and the group a pattern would
// cover.
//
// A string identifier's group is everything up to its last separator, which is what
// makes `ns=4;s=Line1/Pump1/*` a sentence somebody can write. A numeric identifier
// has no structure to group by, so the namespace is the group and the identifiers
// are listed inside it — which is the honest answer rather than inventing a prefix
// from digits.
func groupOf(n NodeRef) (ns, group string) {
	ns = fmt.Sprintf("ns=%d", n.Namespace)
	_, ident, ok := strings.Cut(n.Key, ";")
	if !ok {
		return ns, ""
	}
	kind, rest, ok := strings.Cut(ident, "=")
	if !ok || kind != "s" {
		return ns, ""
	}
	i := strings.LastIndexByte(rest, '/')
	if i <= 0 {
		return ns, ""
	}
	return ns, rest[:i]
}

// observeRequest records one service call and what the policy said about it.
//
// ops may be empty, which is the ordinary case for a session service and the only
// case for a message whose body the channel encrypted. Then one subject is recorded
// for the identity and the class, with no node at all — because the alternative is
// recording nothing, and a run that recorded nothing for an encrypted channel would
// look like a run over an idle listener.
// The subjects a request was recorded under are remembered against its request
// identifier, so a fault the server answers it with lands on the same rows.
func (t *server) observeRequest(c *conn, s Session, reqID uint32, svc wire.Service,
	ops []Operation, allowed, opaque bool, now time.Time) {
	if t.learner == nil {
		return
	}
	app, user := identityOf(s)
	class := classOf(svc)
	note := func(k learnKey, add func(*learnObs)) {
		t.learner.Observe(k, func(o *learnObs, first bool) {
			if first {
				o.first = now
				o.services = map[string]bool{}
				o.clients = map[string]bool{}
				o.nodes = map[string]bool{}
				o.methods = map[string]bool{}
				o.attrs = map[string]bool{}
				o.policies = map[string]bool{}
				o.modes = map[string]bool{}
				o.tokens = map[string]bool{}
			}
			o.last = now
			o.requests++
			switch {
			case svc.Known():
				addBounded(o.services, svc.String(), maxLearnedServices)
			case svc != 0:
				o.unknownService = true
			}
			if !allowed {
				o.denied++
			}
			if opaque {
				o.opaque++
			}
			if s.IP.IsValid() {
				addBounded(o.clients, s.IP.String(), maxLearnedTerms)
			}
			if s.Secured {
				addBounded(o.policies, s.Policy.Short(), maxLearnedTerms)
				addBounded(o.modes, s.Mode.String(), maxLearnedTerms)
			}
			if s.Activated {
				addBounded(o.tokens, s.TokenKind.String(), maxLearnedTerms)
			}
			if n := len(ops); n > o.maxOps {
				o.maxOps = n
			}
			if add != nil {
				add(o)
			}
		})
	}
	if len(ops) == 0 {
		k := learnKey{app: app, user: user, class: class}
		note(k, nil)
		c.recordSubjects(reqID, []learnKey{k})
		return
	}
	// One subject per node group the request touched, so a Read of twenty nodes
	// under two prefixes is two rows rather than twenty.
	seen := map[learnKey][]Operation{}
	var order []learnKey
	for _, op := range ops {
		ns, group := groupOf(op.Node)
		k := learnKey{app: app, user: user, class: class, ns: ns, group: group}
		if _, ok := seen[k]; !ok {
			order = append(order, k)
		}
		seen[k] = append(seen[k], op)
	}
	for _, k := range order {
		group := seen[k]
		note(k, func(o *learnObs) {
			for _, op := range group {
				if !addBounded(o.nodes, op.Node.Key, maxLearnedNodes) {
					o.nodesFull = true
				}
				if op.Attr != 0 {
					addBounded(o.attrs, op.Attr.String(), maxLearnedTerms)
				}
				if op.Method != nil {
					if !addBounded(o.methods, op.Method.Key, maxLearnedMethods) {
						o.methodsFull = true
					}
				}
			}
		})
	}
	c.recordSubjects(reqID, order)
}

// observeSubscription records what a subscription asked for, against the identity
// that asked. These are the amplification numbers and they are never proposed.
func (t *server) observeSubscription(s Session, intervalMS float64, now time.Time) {
	if t.learner == nil {
		return
	}
	app, user := identityOf(s)
	t.learner.Observe(learnKey{app: app, user: user, class: classSubscribe},
		func(o *learnObs, first bool) {
			if first {
				o.first = now
				o.services = map[string]bool{}
				o.clients = map[string]bool{}
			}
			o.last = now
			if intervalMS > 0 && (o.minPublishMS == 0 || intervalMS < o.minPublishMS) {
				o.minPublishMS = intervalMS
			}
			if s.Subscriptions+1 > o.maxSubscriptions {
				o.maxSubscriptions = s.Subscriptions + 1
			}
		})
}

// observeMonitoredItems records the fan-out of a CreateMonitoredItems.
func (t *server) observeMonitoredItems(s Session, items int, samplingMS float64, now time.Time) {
	if t.learner == nil {
		return
	}
	app, user := identityOf(s)
	t.learner.Observe(learnKey{app: app, user: user, class: classSubscribe},
		func(o *learnObs, first bool) {
			if first {
				o.first = now
				o.services = map[string]bool{}
				o.clients = map[string]bool{}
			}
			o.last = now
			if items > o.maxItems {
				o.maxItems = items
			}
			if samplingMS > 0 && (o.minSamplingMS == 0 || samplingMS < o.minSamplingMS) {
				o.minSamplingMS = samplingMS
			}
		})
}

// observeServerFault records the server refusing something this relay allowed.
//
// It is the number a learning run wants most, because a rule proposed for it would
// permit a thing that cannot happen: on this protocol a fault usually means the
// server does not grant this user what the listener does, and a report that
// proposed the node anyway would be a report that made the disagreement permanent.
//
// ObserveExisting rather than Observe: the request is what created the subject, and
// a response may not invent one — a fault for a request this relay never saw is a
// fault for a subject that does not exist.
// The subjects are the rows the request itself was recorded under: a Read of three
// nodes under two prefixes made two rows, and a fault answering it belongs to both,
// because the identity asked for nothing the server granted. A request that was
// never recorded — the learner is off, or the in-flight bound dropped it — has
// none, and the fault is then not counted rather than counted against a row it did
// not come from.
func (t *server) observeServerFault(subjects []learnKey) {
	if t.learner == nil {
		return
	}
	for _, k := range subjects {
		t.learner.ObserveExisting(k, func(o *learnObs) { o.serverFaults++ })
	}
}

// addBounded adds to a set and says whether there was room.
func addBounded(m map[string]bool, v string, max int) bool {
	if m == nil || v == "" {
		return true
	}
	if m[v] {
		return true
	}
	if len(m) >= max {
		return false
	}
	m[learn.Sanitise(v)] = true
	return true
}

func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func quoteList(in []string) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, "\""+s+"\"")
	}
	return strings.Join(out, ", ")
}
