// Package mms is the kind: mms listener: an IEC 61850 relay in front of substation
// IEDs on TCP 102.
package mms

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, in the terms a substation's own drawings use.
//
// It decides in three places, in the order an association reaches them.
//
// **The connection.** Which networks may reach the listener at all, and the bounds.
//
// **The association.** An ACSE associate request names a calling AP-title and an
// AE-qualifier, and where the estate configured one it carries an authentication
// value that is a password in the clear. None of the three is a credential this
// relay can verify -- nothing proves an AP-title -- but they are what an SCL file
// configured and what the IEDs themselves check, so they are the fields an estate's
// own rules are written in. Treat them as an address, which is what they are, and do
// not pretend the password is authentication.
//
// **The request.** Which service, which logical device, which object, and above all
// which **functional constraint**. That last one is what makes this listener
// different from every other relay kind in this tree: the protocol's own names carry
// the semantics. In front of Modbus the relay has to be told which register is a
// setpoint; here `XCBR1$CO$Pos$Oper` says it operates a breaker and
// `PTOC1$SG$StrVal$setMag$f` says it changes a trip characteristic. A useful policy
// can therefore be written for an estate whose SCL files nobody has read.
//
// One decision this policy makes that the devices may not: **select before
// operate**. IEC 61850 leaves it to each object's `ctlModel`, `ctlModel` lives in
// `$CF$`, and `$CF$` is writable -- so a client with configuration access can turn
// the interlock off and then operate directly. A listener that tracks the selection
// itself has put the interlock somewhere the configuration cannot reach.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in monitor or shadow mode: a client the
	// lists refuse, a message the relay could not read, a bound, and every
	// service that changes the substation -- because a Write forwarded so that it
	// could be written down is a moved breaker.
	Hard bool
	Rule string
	// Comment is the matched rule's own note, carried into the log for the change
	// record a substation keeps.
	Comment string
	// Error is the MMS error class and code a refusal answers with, so the
	// client's own library reports what an IED would have said rather than a
	// timeout.
	ErrorClass, ErrorCode int
}

func hard(reason, detail string, class, code int) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true,
		ErrorClass: class, ErrorCode: code}
}

func refuse(reason, detail string, class, code int) Decision {
	return Decision{Reason: reason, Detail: detail, ErrorClass: class, ErrorCode: code}
}

func allowed() Decision { return Decision{Allow: true} }

// The MMS error classes and the codes this relay uses (ISO 9506-2 Annex A). A
// refusal answers with the class an IED would have used for the same refusal, so
// that a client's own diagnostics say something true.
const (
	// ErrClassAccess is access, whose codes cover a denied object.
	ErrClassAccess = 3
	// ErrClassService is service, for a service the device will not perform.
	ErrClassService = 8
	// ErrClassDefinition is definition, for a name the device does not have.
	ErrClassDefinition = 5
	// ErrClassResource is resource, for a bound.
	ErrClassResource = 6
	// ErrCodeObjectAccessDenied is access/object-access-denied.
	ErrCodeObjectAccessDenied = 3
	// ErrCodeObjectNonExistent is definition/object-non-existent.
	ErrCodeObjectNonExistent = 1
	// ErrCodeServiceNotSupported is service/other.
	ErrCodeServiceNotSupported = 0
	// ErrCodeCapabilityUnavailable is resource/capability-unavailable.
	ErrCodeCapabilityUnavailable = 1
)

// Association is what the policy knows about one association, built up as the
// handshake goes and then fixed.
type Association struct {
	IP netip.Addr
	// Called and Calling are the transport selectors, kept for the log rather than
	// for a decision: on IEC 61850 they are a convention.
	Called, Calling []byte
	// APTitle and AEQualifier are the calling identity, where the peer sent them.
	APTitle      string
	AEQualifier  int
	HasQualifier bool
	// Auth is which form of authentication value the association carried, and
	// AuthLength how long it was. The value is deliberately not here: on the
	// charstring form it is a password, and this relay does not hold one.
	Auth       wire.AuthKind
	AuthLength int
	// Associated says the ACSE exchange completed, Initiated that the MMS
	// initiate did.
	Associated, Initiated bool
	// Contexts is the presentation context list the association agreed, which is
	// how a data value's syntax is known.
	Contexts wire.Contexts
	// Selected are the control objects this association currently holds a
	// selection on, and when each expires. It is what require_select_before_operate
	// consults.
	Selected map[string]time.Time
	// Requests is how many confirmed requests it has sent.
	Requests int
	At       time.Time
}

// Identity is the association's identity as a log line and a learning subject name
// it: the AP-title, or a placeholder saying which part is missing rather than a
// blank column.
func (a Association) Identity() string {
	if !a.Associated {
		return "<no association>"
	}
	if a.APTitle == "" {
		return "<no ap-title>"
	}
	return a.APTitle
}

// policy is the compiled configuration.
type policy struct {
	clients, denyClients []netip.Prefix

	apTitles, denyAPTitles []string
	qualifiers             numrange.Set
	requireAPTitle         bool

	refusePlaintext bool

	services, denyServices  map[wire.Service]bool
	classes, denyClasses    map[wire.Class]bool
	domains, denyDomains    []string
	objects, denyObjects    []string
	writeObjects            []string
	files, denyFiles        []string
	constraints             map[wire.FC]bool
	writeConstraints        map[wire.FC]bool
	denyConstraints         map[wire.FC]bool
	allowOperate            bool
	requireSelect           bool
	selectTimeout           time.Duration
	readOnly                bool
	allowDomainServices     bool
	maxNames, maxWriteNames int
	defaultAllow            bool
	rules                   []*rule
}

// rule is one compiled rule.
type rule struct {
	name, comment string
	action        string

	clients       []netip.Prefix
	apTitles      []string
	qualifiers    numrange.Set
	hasQualifiers bool

	services, denyServices map[wire.Service]bool
	classes, denyClasses   map[wire.Class]bool
	domains, denyDomains   []string
	objects, denyObjects   []string
	writeObjects           []string
	files, denyFiles       []string
	constraints            map[wire.FC]bool
	writeConstraints       map[wire.FC]bool
	denyConstraints        map[wire.FC]bool
	allowOperate           *bool
	maxNames               int
	window                 *schedule.Window
}

// defaultServices is what a control centre and an HMI do: read, browse, subscribe to
// reports and write the constraints that move the plant now. It excludes every domain
// service, every file write and every program-invocation control, because those
// replace what is inside an IED rather than telling it what to do.
var defaultClasses = map[wire.Class]bool{
	wire.ClassSession: true,
	wire.ClassBrowse:  true,
	wire.ClassRead:    true,
	wire.ClassWrite:   true,
	wire.ClassReport:  true,
	wire.ClassDataSet: true,
	wire.ClassFile:    true,
}

// defaultWriteConstraints is what an HMI and a control centre write: status,
// measurands, setpoints, substituted values, blocking and control. Not SG, SE or CF,
// because those change what the device will do in a fault rather than what it is
// doing now.
var defaultWriteConstraints = map[wire.FC]bool{
	wire.FCStatus:       true,
	wire.FCMeasurand:    true,
	wire.FCSetpoint:     true,
	wire.FCSubstitution: true,
	wire.FCBlock:        true,
	wire.FCControl:      true,
}

// compile turns the configuration into the policy.
func compile(c *config.MMSListener) (*policy, error) {
	q, err := numrange.Parse("ae_qualifier", c.AEQualifiers, 65535)
	if err != nil {
		return nil, err
	}
	p := &policy{
		clients:             netutil.ParsePrefixes(c.AllowClients),
		denyClients:         netutil.ParsePrefixes(c.DenyClients),
		apTitles:            c.APTitles,
		denyAPTitles:        c.DenyAPTitles,
		qualifiers:          q,
		requireAPTitle:      c.RequireAPTitle,
		refusePlaintext:     c.RefusePlaintextPasswords,
		services:            serviceSet(c.Services),
		denyServices:        serviceSet(c.DenyServices),
		classes:             classSet(c.ServiceClasses),
		denyClasses:         classSet(c.DenyServiceClasses),
		domains:             c.Domains,
		denyDomains:         c.DenyDomains,
		objects:             c.Objects,
		denyObjects:         c.DenyObjects,
		writeObjects:        c.WriteObjects,
		files:               c.Files,
		denyFiles:           c.DenyFiles,
		constraints:         fcSet(c.FunctionalConstraints),
		writeConstraints:    fcSet(c.WriteConstraints),
		denyConstraints:     fcSet(c.DenyConstraints),
		allowOperate:        c.AllowOperate == nil || *c.AllowOperate,
		requireSelect:       c.RequireSelectBeforeOperate,
		selectTimeout:       c.SelectTimeout.D(),
		readOnly:            c.ReadOnly,
		allowDomainServices: c.AllowDomainServices,
		maxNames:            c.MaxNames,
		maxWriteNames:       c.MaxWriteNames,
		defaultAllow:        c.DefaultAction == "allow",
	}
	if p.selectTimeout <= 0 {
		// IEC 61850-7-2's own default for sboTimeout.
		p.selectTimeout = 30 * time.Second
	}
	if len(p.classes) == 0 {
		p.classes = defaultClasses
		if p.allowDomainServices {
			// The knob and the class list have to agree, or turning the knob on
			// would leave the services it names refused by the default list --
			// which reads as the knob not working.
			p.classes = make(map[wire.Class]bool, len(defaultClasses)+1)
			for c := range defaultClasses {
				p.classes[c] = true
			}
			p.classes[wire.ClassDomain] = true
		}
	}
	if len(p.writeConstraints) == 0 {
		p.writeConstraints = defaultWriteConstraints
	}
	for i := range c.Rules {
		r, err := compileRule(&c.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(c *config.MMSRule) (*rule, error) {
	q, err := numrange.Parse("ae_qualifier", c.AEQualifiers, 65535)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", c.Name, err)
	}
	r := &rule{
		name:             c.Name,
		comment:          c.Comment,
		action:           c.Action,
		clients:          netutil.ParsePrefixes(c.Clients),
		apTitles:         c.APTitles,
		qualifiers:       q,
		hasQualifiers:    len(c.AEQualifiers) > 0,
		services:         serviceSet(c.Services),
		denyServices:     serviceSet(c.DenyServices),
		classes:          classSet(c.ServiceClasses),
		denyClasses:      classSet(c.DenyServiceClasses),
		domains:          c.Domains,
		denyDomains:      c.DenyDomains,
		objects:          c.Objects,
		denyObjects:      c.DenyObjects,
		writeObjects:     c.WriteObjects,
		files:            c.Files,
		denyFiles:        c.DenyFiles,
		constraints:      fcSet(c.FunctionalConstraints),
		writeConstraints: fcSet(c.WriteConstraints),
		denyConstraints:  fcSet(c.DenyConstraints),
		allowOperate:     c.AllowOperate,
		maxNames:         c.MaxNames,
	}
	if r.action == "" {
		r.action = "allow"
	}
	if c.Schedule != nil {
		w, err := schedule.Compile(c.Schedule)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", c.Name, err)
		}
		r.window = w
	}
	return r, nil
}

func serviceSet(names []string) map[wire.Service]bool {
	if len(names) == 0 {
		return nil
	}
	out := make(map[wire.Service]bool, len(names))
	for _, n := range names {
		if s, ok := wire.ServiceOf(n); ok {
			out[s] = true
		}
	}
	return out
}

func classSet(names []string) map[wire.Class]bool {
	if len(names) == 0 {
		return nil
	}
	out := make(map[wire.Class]bool, len(names))
	for _, n := range names {
		if c, ok := classOf(n); ok {
			out[c] = true
		}
	}
	return out
}

// classOf reads a class back from its configuration name.
func classOf(name string) (wire.Class, bool) {
	for _, c := range []wire.Class{
		wire.ClassBrowse, wire.ClassRead, wire.ClassWrite, wire.ClassReport,
		wire.ClassDataSet, wire.ClassControl, wire.ClassDomain, wire.ClassFile,
		wire.ClassSession,
	} {
		if c.String() == name {
			return c, true
		}
	}
	return wire.ClassUnknown, false
}

func fcSet(names []string) map[wire.FC]bool {
	if len(names) == 0 {
		return nil
	}
	out := make(map[wire.FC]bool, len(names))
	for _, n := range names {
		out[wire.FC(n)] = true
	}
	return out
}

// Connect decides about a connection before anything is read.
func (p *policy) Connect(a Association) Decision {
	if netutil.Contains(p.denyClients, a.IP) {
		return hard("client_denied", a.IP.String(), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if len(p.clients) > 0 && !netutil.Contains(p.clients, a.IP) {
		return hard("client_not_allowed", a.IP.String(), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	return allowed()
}

// Associate decides about an ACSE associate request.
func (p *policy) Associate(a Association) Decision {
	if p.requireAPTitle && a.APTitle == "" {
		return refuse("no_ap_title", "", ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if a.APTitle != "" {
		if matchedGlob(p.denyAPTitles, a.APTitle) {
			return hard("ap_title_denied", a.APTitle, ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		if len(p.apTitles) > 0 && !matchedGlob(p.apTitles, a.APTitle) {
			return refuse("ap_title_not_allowed", a.APTitle,
				ErrClassAccess, ErrCodeObjectAccessDenied)
		}
	}
	if len(p.qualifiers) > 0 {
		if !a.HasQualifier {
			return refuse("no_ae_qualifier", "", ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		if !p.qualifiers.Has(a.AEQualifier) {
			return refuse("ae_qualifier_not_allowed", fmt.Sprint(a.AEQualifier),
				ErrClassAccess, ErrCodeObjectAccessDenied)
		}
	}
	if p.refusePlaintext && a.Auth == wire.AuthPassword {
		// A hard refusal, because the point of turning it on is that such an
		// association must not reach the IED at all: a shadow listener that
		// forwarded it would have forwarded the password.
		return hard("plaintext_password", fmt.Sprintf("%d octets", a.AuthLength),
			ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	return allowed()
}

// Operation is one thing a request asked of one object.
type Operation struct {
	Name wire.Name
	// Write says the operation changes the object.
	Write bool
}

// Request decides about a confirmed request's service, before its objects.
func (p *policy) Request(a Association, svc wire.Service) Decision {
	if !svc.Known() {
		// A service this relay has not classified. Forwarding it would be
		// forwarding something to a substation with no policy applied at all.
		return hard("service_unknown", svc.String(), ErrClassService, ErrCodeServiceNotSupported)
	}
	if p.readOnly && svc.Changes() {
		return hard("read_only", svc.String(), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if svc.Class() == wire.ClassDomain && svc.Changes() && !p.allowDomainServices {
		// Separate from the service list on purpose: a download replaces what is
		// inside a protection relay, and the decision to carry one should be
		// stated where a reviewer reads it rather than inferred from a list of
		// eighty names.
		return hard("domain_services_not_allowed", svc.String(),
			ErrClassService, ErrCodeServiceNotSupported)
	}
	if p.denyServices[svc] {
		return hard("service_denied", svc.String(), ErrClassService, ErrCodeServiceNotSupported)
	}
	if p.denyClasses[svc.Class()] {
		return hard("service_class_denied", svc.Class().String(),
			ErrClassService, ErrCodeServiceNotSupported)
	}
	if len(p.services) > 0 {
		if !p.services[svc] {
			return refuse("service_not_allowed", svc.String(),
				ErrClassService, ErrCodeServiceNotSupported)
		}
		return allowed()
	}
	if !p.classes[svc.Class()] {
		return refuse("service_class_not_allowed", svc.Class().String(),
			ErrClassService, ErrCodeServiceNotSupported)
	}
	return allowed()
}

// Bounds decides about the size of a request.
func (p *policy) Bounds(svc wire.Service, ops []Operation, truncated bool) Decision {
	if truncated {
		// More names than the reader kept. A policy that allowed the request on
		// the names it could see would be allowing the ones it could not.
		return hard("too_many_names", "past the reader's own bound",
			ErrClassResource, ErrCodeCapabilityUnavailable)
	}
	bound := p.maxNames
	if svc == wire.SvcWrite && p.maxWriteNames > 0 {
		bound = p.maxWriteNames
	}
	if bound > 0 && len(ops) > bound {
		return hard("too_many_names", fmt.Sprintf("%d names, bound %d", len(ops), bound),
			ErrClassResource, ErrCodeCapabilityUnavailable)
	}
	return allowed()
}

// Operations decides about every object a request addressed, and returns the first
// refusal. A request is one decision: a Read of twenty objects where one is refused
// is a refused Read, because an IED that answered nineteen would leave the client
// believing it had read twenty.
func (p *policy) Operations(a Association, svc wire.Service, ops []Operation) Decision {
	r := p.match(a, svc, ops)
	if r != nil && r.action == "deny" {
		return refuse("rule_denied", r.name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	for _, op := range ops {
		if d := p.operation(r, op); !d.Allow {
			if r != nil {
				d.Rule, d.Comment = r.name, r.comment
			}
			return d
		}
	}
	if r == nil && !p.defaultAllow && len(ops) > 0 {
		return refuse("no_rule", describe(ops), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if r != nil {
		return Decision{Allow: true, Rule: r.name, Comment: r.comment}
	}
	return allowed()
}

// operation decides about one object.
func (p *policy) operation(r *rule, op Operation) Decision {
	key := op.Name.Key()
	// The deny lists first, and no rule overrides them.
	if matchedGlob(p.denyObjects, key) {
		return hard("object_denied", key, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if op.Name.Domain != "" && matchedGlob(p.denyDomains, op.Name.Domain) {
		return hard("domain_denied", op.Name.Domain, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if op.Name.Parsed && p.denyConstraints[op.Name.FC] {
		return hard("constraint_denied", string(op.Name.FC),
			ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if r != nil {
		if matchedGlob(r.denyObjects, key) {
			return refuse("object_denied", key, ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		if op.Name.Domain != "" && matchedGlob(r.denyDomains, op.Name.Domain) {
			return refuse("domain_denied", op.Name.Domain,
				ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		if op.Name.Parsed && r.denyConstraints[op.Name.FC] {
			return refuse("constraint_denied", string(op.Name.FC),
				ErrClassAccess, ErrCodeObjectAccessDenied)
		}
	}
	if d := p.domainAllowed(r, op.Name); !d.Allow {
		return d
	}
	if d := p.objectAllowed(r, op); !d.Allow {
		return d
	}
	return p.constraintAllowed(r, op)
}

func (p *policy) domainAllowed(r *rule, n wire.Name) Decision {
	if n.Domain == "" {
		return allowed()
	}
	list := p.domains
	if r != nil && len(r.domains) > 0 {
		list = r.domains
	}
	if len(list) > 0 && !matchedGlob(list, n.Domain) {
		return refuse("domain_not_allowed", n.Domain, ErrClassDefinition, ErrCodeObjectNonExistent)
	}
	return allowed()
}

func (p *policy) objectAllowed(r *rule, op Operation) Decision {
	key := op.Name.Key()
	if op.Write {
		if list := p.writeList(r); len(list) > 0 {
			if !matchedGlob(list, key) {
				return refuse("write_object_not_allowed", key,
					ErrClassAccess, ErrCodeObjectAccessDenied)
			}
			return allowed()
		}
	}
	list := p.objects
	if r != nil && len(r.objects) > 0 {
		list = r.objects
	}
	if len(list) > 0 && !matchedGlob(list, key) {
		return refuse("object_not_allowed", key, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	return allowed()
}

// writeList is the effective write-object list: the rule's own, then the
// listener's.
func (p *policy) writeList(r *rule) []string {
	if r != nil && len(r.writeObjects) > 0 {
		return r.writeObjects
	}
	return p.writeObjects
}

// constraintAllowed is where this protocol's semantics are decided.
func (p *policy) constraintAllowed(r *rule, op Operation) Decision {
	n := op.Name
	if !n.Parsed {
		// A name with no functional constraint in it: a device's own well-known
		// variable, or a client's named variable list. The constraint rules say
		// nothing about it, and a listener that treated an unparsed name as
		// though it carried the constraint the rule allows would be allowing
		// something else.
		if op.Write && p.constraintsNarrowed(r) {
			return refuse("constraint_unknown", n.Item,
				ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		return allowed()
	}
	if !n.FC.Known() {
		return refuse("constraint_unknown", string(n.FC),
			ErrClassDefinition, ErrCodeObjectNonExistent)
	}
	if list := p.constraintList(r); len(list) > 0 && !list[n.FC] {
		return refuse("constraint_not_allowed", string(n.FC),
			ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if !op.Write {
		return allowed()
	}
	if !p.writeConstraintList(r)[n.FC] {
		return refuse("write_constraint_not_allowed", string(n.FC),
			ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if n.Operates() && !p.operateAllowed(r) {
		return refuse("operate_not_allowed", n.Key(),
			ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	return allowed()
}

func (p *policy) constraintList(r *rule) map[wire.FC]bool {
	if r != nil && len(r.constraints) > 0 {
		return r.constraints
	}
	return p.constraints
}

func (p *policy) writeConstraintList(r *rule) map[wire.FC]bool {
	if r != nil && len(r.writeConstraints) > 0 {
		return r.writeConstraints
	}
	return p.writeConstraints
}

// constraintsNarrowed says a write-constraint list is in force that is narrower than
// everything, which is what makes an unparsed name's write worth refusing.
func (p *policy) constraintsNarrowed(r *rule) bool {
	return len(p.writeConstraintList(r)) > 0
}

func (p *policy) operateAllowed(r *rule) bool {
	if r != nil && r.allowOperate != nil {
		return *r.allowOperate
	}
	return p.allowOperate
}

// Operate decides whether an operate may proceed given what this association has
// selected, which is the check the devices may not make.
func (p *policy) Operate(a Association, n wire.Name, now time.Time) Decision {
	if !p.requireSelect || !n.Operates() {
		return allowed()
	}
	until, ok := a.Selected[selectKey(n)]
	if !ok {
		return refuse("not_selected", n.Key(), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if now.After(until) {
		return refuse("selection_expired", n.Key(), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	return allowed()
}

// selectKey is what a selection is remembered against: the object, without the
// control attribute, because a select names SBOw and the operate that follows names
// Oper on the same object.
func selectKey(n wire.Name) string {
	if n.Domain == "" {
		return n.LogicalNode + "$" + n.DataObject
	}
	return n.Domain + "/" + n.LogicalNode + "$" + n.DataObject
}

// SelectTimeout is how long a selection stays good.
func (p *policy) SelectTimeout() time.Duration { return p.selectTimeout }

// RequiresSelect says the listener is tracking selections.
func (p *policy) RequiresSelect() bool { return p.requireSelect }

// File decides about a file service's path.
func (p *policy) File(a Association, svc wire.Service, name string) Decision {
	r := p.match(a, svc, nil)
	if r != nil && r.action == "deny" {
		return refuse("rule_denied", r.name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if name == "" {
		// A file service whose path this relay could not read. Forwarding it
		// would be forwarding a path with no policy applied.
		return hard("file_unreadable", svc.String(), ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if matchedGlob(p.denyFiles, name) {
		return hard("file_denied", name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if r != nil && matchedGlob(r.denyFiles, name) {
		return refuse("file_denied", name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	list := p.files
	if r != nil && len(r.files) > 0 {
		list = r.files
	}
	if len(list) > 0 && !matchedGlob(list, name) {
		return refuse("file_not_allowed", name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if r == nil && !p.defaultAllow {
		return refuse("no_rule", name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if r != nil {
		return Decision{Allow: true, Rule: r.name, Comment: r.comment}
	}
	return allowed()
}

// Domain decides about a service that names a logical device rather than an object:
// a download, a delete, an enumeration.
func (p *policy) Domain(a Association, svc wire.Service, domain string) Decision {
	r := p.match(a, svc, nil)
	if r != nil && r.action == "deny" {
		return refuse("rule_denied", r.name, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if domain != "" {
		if matchedGlob(p.denyDomains, domain) {
			return hard("domain_denied", domain, ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		if r != nil && matchedGlob(r.denyDomains, domain) {
			return refuse("domain_denied", domain, ErrClassAccess, ErrCodeObjectAccessDenied)
		}
		list := p.domains
		if r != nil && len(r.domains) > 0 {
			list = r.domains
		}
		if len(list) > 0 && !matchedGlob(list, domain) {
			return refuse("domain_not_allowed", domain,
				ErrClassDefinition, ErrCodeObjectNonExistent)
		}
	}
	if r == nil && !p.defaultAllow {
		return refuse("no_rule", domain, ErrClassAccess, ErrCodeObjectAccessDenied)
	}
	if r != nil {
		return Decision{Allow: true, Rule: r.name, Comment: r.comment}
	}
	return allowed()
}

// match finds the first rule that selects this request, in order.
func (p *policy) match(a Association, svc wire.Service, ops []Operation) *rule {
	for _, r := range p.rules {
		if !r.selects(a, svc, ops) {
			continue
		}
		if r.action == "observe" {
			// Logged and counted by the caller, and then the search continues:
			// that is what lets a rule be tried on live traffic before it decides
			// anything.
			continue
		}
		return r
	}
	return nil
}

// selects says a rule applies to this request.
func (r *rule) selects(a Association, svc wire.Service, ops []Operation) bool {
	if len(r.clients) > 0 && !netutil.Contains(r.clients, a.IP) {
		return false
	}
	if len(r.apTitles) > 0 && !matchedGlob(r.apTitles, a.APTitle) {
		return false
	}
	if r.hasQualifiers && (!a.HasQualifier || !r.qualifiers.Has(a.AEQualifier)) {
		return false
	}
	if len(r.services) > 0 && !r.services[svc] {
		return false
	}
	if len(r.classes) > 0 && !r.classes[svc.Class()] {
		return false
	}
	if r.window != nil && !r.window.InForce(time.Now()) {
		return false
	}
	// A rule that names objects selects only requests that touch one of them. A
	// rule naming objects and a request naming none -- a domain service, a file --
	// is not this rule's traffic.
	if len(r.objects) > 0 || len(r.domains) > 0 {
		if len(ops) == 0 {
			return len(r.domains) > 0
		}
		for _, op := range ops {
			if len(r.objects) > 0 && matchedGlob(r.objects, op.Name.Key()) {
				return true
			}
			if len(r.domains) > 0 && op.Name.Domain != "" &&
				matchedGlob(r.domains, op.Name.Domain) {
				return true
			}
		}
		return false
	}
	return true
}

// ObserveRules reports the observe rules a request matched, for the caller to log.
func (p *policy) ObserveRules(a Association, svc wire.Service, ops []Operation) []*rule {
	var out []*rule
	for _, r := range p.rules {
		if r.action == "observe" && r.selects(a, svc, ops) {
			out = append(out, r)
		}
	}
	return out
}

// Name is the rule's name, for the caller's log line.
func (r *rule) Name() string { return r.name }

// Comment is the rule's note.
func (r *rule) Comment() string { return r.comment }

// matchedGlob says one of the patterns matches.
//
// The patterns are shell globs over the whole string, which is the form an IEC 61850
// name is written in: `AA1J1Q01A1LD0/MMXU1$MX$*`. A pattern that will not compile
// matches nothing, which is refused by validation before it gets here and treated as
// no match if it somehow does.
func matchedGlob(pats []string, s string) bool {
	for _, pat := range pats {
		if pat == s {
			return true
		}
		if !strings.ContainsAny(pat, "*?[") {
			continue
		}
		if ok, err := path.Match(pat, s); err == nil && ok {
			return true
		}
	}
	return false
}

// describe names the objects a refusal was about, bounded so that a log line stays a
// log line.
func describe(ops []Operation) string {
	if len(ops) == 0 {
		return ""
	}
	if len(ops) == 1 {
		return ops[0].Name.Key()
	}
	return fmt.Sprintf("%s and %d more", ops[0].Name.Key(), len(ops)-1)
}
