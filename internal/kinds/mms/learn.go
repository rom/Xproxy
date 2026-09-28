package mms

import (
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/mms"
)

// Learning mode, in the vocabulary a substation's own engineers use.
//
// Nobody writes a correct object list from an SCL file. The file says which data
// objects exist; the traffic says which of them the control centre actually polls,
// which report control blocks the HMI enables, which file an engineering laptop
// fetched last Tuesday and which logical device nobody remembers commissioning. A
// policy written from the drawings refuses half the traffic on the first shift, which
// is how a security control gets turned off and stays off.
//
// A **subject** is one calling identity, one class of service, and one logical
// device. Not one object: an `objects` pattern is the line an engineer argues about,
// and a subject per object would be four hundred rows for one bay. The objects seen
// inside a subject are recorded so the proposal can name them, and where there are
// too many the proposal falls back to the constraint -- which is the pattern an
// engineer would have written anyway: `LD0/MMXU1$MX$*`.

// The bounds on what is remembered per subject. They exist because a learning run is
// a table a peer fills.
const (
	// maxLearnedObjects bounds the object names remembered per subject. A bay's
	// worth is a few dozen; past that a list is not a policy anybody reads.
	maxLearnedObjects = 32
	// maxLearnedFiles bounds the file paths.
	maxLearnedFiles = 16
	// maxLearnedTerms bounds each of the small sets: the constraints, the clients,
	// the services.
	maxLearnedTerms = 16
)

// learnKey is one row's identity.
type learnKey struct {
	// identity is the calling AP-title, or a placeholder saying which part is
	// missing rather than a blank column.
	identity string
	// class is what the services in this row do.
	class wire.Class
	// domain is the logical device, or empty for a request that addressed none.
	domain string
}

// learnObs is what was seen of one subject.
type learnObs struct {
	first, last time.Time
	requests    uint64
	// denied counts what the policy refused, or would have on a run that is not
	// enforcing.
	denied uint64
	// serverErrors counts what the *IED* refused: an object it does not have, or a
	// client it does not grant. A subject with nothing but those gets no rule,
	// because a rule for it would permit a thing that cannot happen.
	serverErrors uint64
	// clients are the addresses the identity was seen from, which is evidence
	// rather than policy: an address is what a lease changes.
	clients map[string]bool
	// services are the service names seen, in the configuration's own vocabulary.
	// They are recorded rather than derived from the class, because a class covers
	// more services than any one subject called.
	services map[string]bool
	// objects are the object names seen, constraints the functional constraints,
	// files the file paths.
	objects, constraints, files map[string]bool
	objectsFull, filesFull      bool
	// writes counts the requests that changed something, operates those that
	// operated the plant, and protects those that touched a setting group or the
	// configuration. The last two are the numbers a reader of this report needs
	// before any of the rows mean anything.
	writes, operates, protects uint64
	// selects counts the select-before-operate exchanges, which says whether the
	// estate uses them at all.
	selects uint64
	// auth is the authentication form seen, and plaintext how many associations
	// carried a password in the clear.
	auth      map[string]bool
	plaintext uint64
	// maxNames is the largest name count one request carried, which is a bound and
	// never a proposal.
	maxNames int
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
		Kind:     "mms",
		Listener: c.listener,
		Path:     c.file,
		Interval: c.interval,
		Max:      c.maxSubjects,
		Render:   renderLearnedMMS,
		Less:     learnLessMMS,
		Clone:    cloneMMSObs,
	})
}

// learnLessMMS orders the rows, so that two runs over the same traffic produce the
// same file and a diff between two weeks means something.
func learnLessMMS(a, b learnKey) bool {
	if a.identity != b.identity {
		return a.identity < b.identity
	}
	if a.class != b.class {
		return a.class < b.class
	}
	return a.domain < b.domain
}

func cloneMMSObs(o learnObs) learnObs {
	out := o
	out.clients = cloneSet(o.clients)
	out.services = cloneSet(o.services)
	out.objects = cloneSet(o.objects)
	out.constraints = cloneSet(o.constraints)
	out.files = cloneSet(o.files)
	out.auth = cloneSet(o.auth)
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

// observeAssociation records the connection, before any identity exists. It is what
// makes a listener that saw traffic and learned nothing distinguishable from an idle
// one.
func (t *server) observeAssociation(c *conn) {
	if t.learner == nil {
		return
	}
	a := c.assoc()
	t.learner.Observe(learnKey{identity: a.Identity(), class: wire.ClassSession},
		func(o *learnObs, first bool) {
			initObs(o, time.Now(), first)
			o.last = time.Now()
			if a.IP.IsValid() {
				addBounded(o.clients, a.IP.String(), maxLearnedTerms)
			}
		})
}

// observeAssociate records the ACSE association: the identity, and what authenticated
// it.
func (t *server) observeAssociate(c *conn, allowed bool) {
	if t.learner == nil {
		return
	}
	a := c.assoc()
	n := time.Now()
	t.learner.Observe(learnKey{identity: a.Identity(), class: wire.ClassSession},
		func(o *learnObs, first bool) {
			initObs(o, n, first)
			o.last = n
			o.requests++
			if !allowed {
				o.denied++
			}
			addBounded(o.auth, a.Auth.String(), maxLearnedTerms)
			if a.Auth == wire.AuthPassword {
				o.plaintext++
			}
			if a.IP.IsValid() {
				addBounded(o.clients, a.IP.String(), maxLearnedTerms)
			}
		})
}

// observeRequest records one confirmed request and what the policy said about it.
//
// One subject per logical device the request touched, so a Read of twenty objects on
// one device is one row rather than twenty.
func (t *server) observeRequest(c *conn, a Association, m *wire.Message,
	ops []Operation, allowed bool, at time.Time) {
	if t.learner == nil {
		return
	}
	svc := m.Service
	class := svc.Class()
	var order []learnKey
	byDomain := map[learnKey][]Operation{}
	for _, op := range ops {
		k := learnKey{identity: a.Identity(), class: class, domain: op.Name.Domain}
		if _, ok := byDomain[k]; !ok {
			order = append(order, k)
		}
		byDomain[k] = append(byDomain[k], op)
	}
	if len(order) == 0 {
		// A request addressing no object: a domain service, a file, an
		// enumeration. Its own domain is the row.
		order = append(order, learnKey{identity: a.Identity(), class: class, domain: m.Domain})
	}
	for _, k := range order {
		group := byDomain[k]
		t.learner.Observe(k, func(o *learnObs, first bool) {
			initObs(o, at, first)
			o.last = at
			o.requests++
			if !allowed {
				o.denied++
			}
			if svc.Known() {
				addBounded(o.services, svc.String(), maxLearnedTerms)
			}
			if a.IP.IsValid() {
				addBounded(o.clients, a.IP.String(), maxLearnedTerms)
			}
			if svc.Changes() {
				o.writes++
			}
			if n := len(group); n > o.maxNames {
				o.maxNames = n
			}
			if m.FileName != "" {
				if !addBounded(o.files, m.FileName, maxLearnedFiles) {
					o.filesFull = true
				}
			}
			for _, op := range group {
				if !addBounded(o.objects, op.Name.Key(), maxLearnedObjects) {
					o.objectsFull = true
				}
				if !op.Name.Parsed {
					continue
				}
				addBounded(o.constraints, string(op.Name.FC), maxLearnedTerms)
				if op.Write && op.Name.Operates() {
					o.operates++
				}
				if op.Write && op.Name.FC.Protects() {
					o.protects++
				}
				if op.Name.Selects() {
					o.selects++
				}
			}
		})
	}
	c.rememberSubjects(order)
}

// observeServerError counts the IED refusing a request, against the rows the request
// itself made.
func (t *server) observeServerError(subjects []learnKey) {
	if t.learner == nil {
		return
	}
	for _, k := range subjects {
		t.learner.ObserveExisting(k, func(o *learnObs) { o.serverErrors++ })
	}
}

// rememberSubjects and lastSubjects carry the rows a request was recorded under from
// the observer to the in-flight table.
//
// They go through the connection rather than being returned, because the observer is
// called from the decision path and the table is written after it: a return value
// would mean every caller of observeRequest carrying a value it does not use.
func (c *conn) rememberSubjects(keys []learnKey) {
	c.mu.Lock()
	c.lastSubjects = keys
	c.mu.Unlock()
}

func (t *server) lastSubjects(c *conn) []learnKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSubjects
}

// initObs prepares a fresh observation's maps.
func initObs(o *learnObs, at time.Time, first bool) {
	if !first {
		return
	}
	o.first = at
	o.clients = map[string]bool{}
	o.services = map[string]bool{}
	o.objects = map[string]bool{}
	o.constraints = map[string]bool{}
	o.files = map[string]bool{}
	o.auth = map[string]bool{}
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

// quoteList renders a list of names as a YAML flow sequence's contents.
func quoteList(in []string) string {
	q := make([]string, 0, len(in))
	for _, s := range in {
		q = append(q, `"`+s+`"`)
	}
	return strings.Join(q, ", ")
}
