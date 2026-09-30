// Package packs is behaviour packs as data: a versioned, signed document that
// says "these signals, from this actor, inside this window, are this ATT&CK
// technique", and nothing else.
//
// # Why data and not code
//
// The first behaviour packs in this project were example listener
// configurations: a `modbus` policy written against the published behaviour of
// FrostyGoop, an `iec104` policy written against Industroyer. They are worth
// having and they are still in examples/ot/packs, because a policy is what
// actually refuses a program download. But they are the wrong shape for the
// thing an estate needs to update.
//
// A detection that ships as a configuration to copy has to be merged by hand
// into a policy somebody has already tuned, which means it is merged once and
// never again. A detection that ships as *code* has to be released as a
// binary, which means an estate that cannot take a new binary this quarter
// cannot take the detection either -- and a plant is exactly such an estate.
//
// So a pack is a file. It is versioned, so a build can refuse one it does not
// understand instead of reading it wrong. It is signed, so a file in a
// directory a process reads at start is not a way into that process. And it is
// *declarative*: a pack cannot call anything, cannot reach a socket, cannot
// name a Go symbol. The whole vocabulary is below, and a pack naming something
// outside it fails to load rather than being ignored.
//
// # What a pack decides about
//
// Not a frame. Every kind in this project already decides about frames, and it
// does it with a policy an engineer wrote and can argue with. A pack sits one
// level up, on the stream of security events those decisions produce: the
// refusal reasons, the behavioural findings, the engineering operations. That
// is the layer where the named tooling is actually visible -- none of it
// exploited a protocol, so there is nothing in a frame to match on, and what
// distinguishes Industroyer from a control centre is the *shape* of a sequence
// across a quarter of an hour.
//
// Working from the event stream has a second property worth more than it
// looks: the vocabulary is closed and already documented. A pack names
// refusal reasons, and every reason this build can emit is in
// internal/attack's table. A pack naming one that is not fails to load. So a
// pack cannot claim a detection this build cannot make, which is the same rule
// docs/ATTACK.md is held to.
//
// # What a pack may do
//
// Every pack declares the most it may do: `alert`, or `deny`. A pack that says
// `alert` can never refuse anything, whatever an operator configures -- which
// is the right declaration for every detection derived from novelty, because
// the first legitimate thing a plant does after a quiet year looks exactly like
// the first illegitimate one. `deny` is for the shapes where the sequence
// itself is the evidence, and even then the operator has to turn it on.
//
// A pack's deny is bounded and is *not the ban ladder*. It quarantines one
// actor from the OT listeners for the rest of the pack's own window, and it
// expires by itself. OT detections have never fed the ban ladder in this
// project and they still do not: banning a plant's master takes the process
// away from the control room, which is worse than what is being guarded
// against.
package packs

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/attack"
	"github.com/rom/xproxy/internal/listener"
)

// Format is the pack format version this build reads.
//
// It is the first field of every pack and the first thing checked. A pack from
// a later format is refused by name rather than read with its unknown fields
// dropped: a detection half of which was ignored is worse than one that did
// not load, because the second is visible.
const Format = 1

// Severity is how much a match is worth to somebody triaging.
//
// It is the pack author's judgement and it is in the pack rather than in the
// configuration, because an operator who has to assign severities to
// detections they did not write ends up assigning them all the same one.
type Severity string

// The severities, least to most.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities are the severities in order, for validation and for a view that
// sorts by them.
func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh,
		SeverityCritical}
}

// Rank is the severity's place in the order, for sorting a report.
func (s Severity) Rank() int {
	for i, v := range Severities() {
		if v == s {
			return i
		}
	}
	return -1
}

// Enforcement is the most a pack may do, declared by the pack itself.
type Enforcement string

const (
	// EnforceAlert is a pack that may only report. No configuration can make
	// it refuse anything.
	EnforceAlert Enforcement = "alert"
	// EnforceDeny is a pack that an operator may allow to quarantine the
	// actor for the rest of its window. It still only alerts until they do.
	EnforceDeny Enforcement = "deny"
)

// Enforcements are the two, for validation.
func Enforcements() []Enforcement { return []Enforcement{EnforceAlert, EnforceDeny} }

// Signal is one thing a pack looks for in the event stream.
//
// A signal is a conjunction: an event matches it when the event's reason is one
// of Reasons, its kind is one of Kinds (or Kinds is empty), and its action is
// one of Actions (or Actions is empty). Count says how many such events the
// window needs before the signal is satisfied.
//
// There is no negation and no regular expression, on purpose. A signal that
// could say "and not X" is a signal whose behaviour depends on what else the
// estate happens to emit, and a pack is meant to be readable by the person
// woken up by it.
type Signal struct {
	// Name is what this step is called in the finding, so an alert can say
	// which half of a pack fired first.
	Name string `yaml:"name"`
	// Reasons are the security-event reasons that satisfy it. At least one,
	// and each must be a reason internal/attack knows -- which is every
	// reason this build tags, and a pack may not name any other.
	Reasons []string `yaml:"reasons"`
	// Kinds narrows the signal to those listener kinds. Empty means any of
	// the pack's own kinds.
	Kinds []string `yaml:"kinds"`
	// Actions narrows it to those actions (`deny`, `alert`, `engineering`).
	// Empty means any.
	Actions []string `yaml:"actions"`
	// Count is how many matching events satisfy the signal. Default 1.
	Count int `yaml:"count"`
}

// Detect is a pack's condition.
type Detect struct {
	// Window is how long the signals have to arrive within; 1s..24h.
	Window time.Duration `yaml:"window"`
	// Signals are the steps. All of them must be satisfied.
	Signals []Signal `yaml:"signals"`
	// Ordered says the signals must be satisfied in the order written. It is
	// what separates a sequence from a set: "read the program, then write
	// one" is a different statement from "read the program and write one",
	// and on this protocol the first is the tool and the second is a day's
	// work.
	Ordered bool `yaml:"ordered"`
	// AcrossKinds requires the actor to have produced matching events on at
	// least this many distinct listener kinds. 0 means it does not matter.
	//
	// It is the one thing here that is not about a single protocol, and it is
	// the cheapest true statement in the file: one host on three control
	// protocols in ten minutes is not a control system.
	AcrossKinds int `yaml:"across_kinds"`
	// Refire is how long after a match the same actor's next match is
	// reported. Default: the window. A campaign should be one alert and not
	// one per frame.
	Refire time.Duration `yaml:"refire"`
}

// Pack is one pack, as the file spells it.
type Pack struct {
	// Format is the pack format version. Must be Format.
	Format int `yaml:"pack"`
	// ID is the pack's stable identifier, lower case, `[a-z0-9-]`. It is what
	// the finding's reason is built from and what an operator enables or
	// suppresses by name, so it never changes -- a corrected pack keeps its
	// identifier and takes a higher Revision.
	ID string `yaml:"id"`
	// Revision is the pack's own version, increasing. Where a directory holds
	// two files with one identifier the higher revision wins and the fact is
	// reported, which is how an estate drops an update in beside what it has.
	Revision int `yaml:"revision"`
	// Name is the human title, and Summary one paragraph of what the pack is
	// about. Both reach the finding.
	Name    string `yaml:"name"`
	Summary string `yaml:"summary"`
	// Technique is the ATT&CK identifier this pack is a detection for. It
	// must be one internal/attack has, in either matrix.
	Technique string `yaml:"technique"`
	// Kinds are the listener kinds the pack applies to. Each must be a kind
	// this build serves.
	Kinds []string `yaml:"kinds"`
	// Severity is the pack author's judgement of what a match is worth.
	Severity Severity `yaml:"severity"`
	// Enforcement is the most this pack may do.
	Enforcement Enforcement `yaml:"enforcement"`
	// References are where the behaviour was published. They are not used for
	// anything; they are in the file because a detection nobody can trace
	// back to an analysis is one nobody can argue with.
	References []string `yaml:"references"`
	// Detect is the condition.
	Detect Detect `yaml:"detect"`

	// Source is the file this pack was read from, and Signer the key that
	// signed it -- both filled in by the loader, not by the file.
	Source string `yaml:"-"`
	Signer string `yaml:"-"`
}

// Reason is the security-event reason a match is reported under:
// `pack_<id>`, with the dashes of the identifier kept, so a SIEM query can
// name one pack.
func (p *Pack) Reason() string { return "pack_" + p.ID }

// Technique returns the technique this pack detects, and whether this build
// has it. A loaded pack always has one: Check refuses a pack whose technique
// is unknown.
func (p *Pack) TechniqueOf() (attack.Technique, bool) { return attack.Get(p.Technique) }

// Covers reports whether the pack applies to a listener kind.
func (p *Pack) Covers(kind string) bool {
	for _, k := range p.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// MayDeny reports whether the pack's own declaration allows a refusal at all.
// An operator's configuration can narrow this and can never widen it.
func (p *Pack) MayDeny() bool { return p.Enforcement == EnforceDeny }

// idRunes is the identifier's alphabet. It is narrow because the identifier
// becomes a metric label, a log reason and a command-line argument.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// knownReason reports whether a reason is one this build can emit -- which is
// to say one internal/attack's table carries, since every reason worth a
// technique is in it. It is the check that stops a pack claiming a detection
// the build cannot make.
func knownReason(reason string) bool {
	if len(attack.OfEvent(reason)) > 0 {
		return true
	}
	// A reason mapped on some kind but reached here without one: OfEvent
	// looks the whole table up, so this is only for the shapes with a
	// detail after a colon, which OfEvent already handles. Kept as the
	// explicit second half so the rule reads as one thing.
	for _, m := range attack.Mappings() {
		if m.Reason == reason {
			return true
		}
	}
	return false
}

// SignalKinds are the listener kinds a signal's events may come from: the ones
// it names, or the pack's own where it names none.
func (p *Pack) SignalKinds(s Signal) []string {
	if len(s.Kinds) > 0 {
		out := make([]string, len(s.Kinds))
		copy(out, s.Kinds)
		sort.Strings(out)
		return out
	}
	out := make([]string, len(p.Kinds))
	copy(out, p.Kinds)
	sort.Strings(out)
	return out
}

// Emits reports whether a listener kind can produce a reason -- which is to say
// whether internal/attack's table has the two together.
//
// It is what makes a pack's reasons more than spelling: a Modbus-only pack that
// named `object_not_allowed` would name a real reason no Modbus listener has
// ever emitted, and would sit in a directory looking like a detection.
func Emits(kind, reason string) bool {
	return len(attack.Of(kind, bareReason(kind, reason))) > 0
}

// EmittingKinds are the kinds among a signal's own that can produce a reason.
func (p *Pack) EmittingKinds(s Signal, reason string) []string {
	var out []string
	for _, k := range p.SignalKinds(s) {
		if Emits(k, reason) {
			out = append(out, k)
		}
	}
	return out
}

// Check validates a pack and fills in its defaults. A pack that does not pass
// is refused by the loader with the file named: a detection that loaded
// half-read is worse than one that did not load.
func (p *Pack) Check() error {
	if p.Format != Format {
		return fmt.Errorf("pack format %d: this build reads %d", p.Format, Format)
	}
	if !validID(p.ID) {
		return fmt.Errorf("id %q: lower case letters, digits and dashes, 1..64, not starting or ending with a dash", p.ID)
	}
	if p.Revision < 1 {
		return fmt.Errorf("revision %d: 1 or more, and higher than the pack it replaces", p.Revision)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name: a pack with no title is one nobody can act on")
	}
	if strings.TrimSpace(p.Summary) == "" {
		return fmt.Errorf("summary: what this pack is about, in a paragraph, because it reaches the alert")
	}
	if !attack.Known(p.Technique) {
		return fmt.Errorf("technique %q: not one this build can observe; docs/ATTACK.md has the catalogue", p.Technique)
	}
	if len(p.Kinds) == 0 {
		return fmt.Errorf("kinds: a pack that applies to no listener kind detects nothing")
	}
	seenKind := map[string]bool{}
	for _, k := range p.Kinds {
		if _, ok := listener.RoleOf(k); !ok {
			return fmt.Errorf("kinds: %q is not a listener kind this build serves", k)
		}
		if seenKind[k] {
			return fmt.Errorf("kinds: %q twice", k)
		}
		seenKind[k] = true
	}
	if p.Severity == "" {
		p.Severity = SeverityMedium
	}
	if p.Severity.Rank() < 0 {
		return fmt.Errorf("severity %q: one of info, low, medium, high, critical", p.Severity)
	}
	if p.Enforcement == "" {
		// The safe default, and the one most packs want: a detection that
		// could refuse without its author having said so is how a plant
		// loses a shift to a detection somebody dropped in a directory.
		p.Enforcement = EnforceAlert
	}
	if p.Enforcement != EnforceAlert && p.Enforcement != EnforceDeny {
		return fmt.Errorf("enforcement %q: alert or deny", p.Enforcement)
	}
	return p.Detect.check(p)
}

func (d *Detect) check(p *Pack) error {
	if d.Window == 0 {
		d.Window = 15 * time.Minute
	}
	if d.Window < time.Second || d.Window > 24*time.Hour {
		return fmt.Errorf("detect.window %s: 1s..24h", d.Window)
	}
	if d.Refire == 0 {
		d.Refire = d.Window
	}
	if d.Refire < time.Second || d.Refire > 24*time.Hour {
		return fmt.Errorf("detect.refire %s: 1s..24h", d.Refire)
	}
	if len(d.Signals) == 0 {
		return fmt.Errorf("detect.signals: a pack with no signal matches everything or nothing, and which is not worth finding out at runtime")
	}
	if len(d.Signals) > 16 {
		return fmt.Errorf("detect.signals: %d, at most 16 -- a pack nobody can read is a pack nobody maintains", len(d.Signals))
	}
	if d.AcrossKinds < 0 || d.AcrossKinds > len(p.Kinds) {
		return fmt.Errorf("detect.across_kinds %d: 0..%d, the kinds this pack names",
			d.AcrossKinds, len(p.Kinds))
	}
	names := map[string]bool{}
	for i := range d.Signals {
		s := &d.Signals[i]
		if err := s.check(p); err != nil {
			return fmt.Errorf("detect.signals[%d]: %w", i, err)
		}
		if names[s.Name] {
			return fmt.Errorf("detect.signals[%d]: two signals called %q, so a finding could not say which fired", i, s.Name)
		}
		names[s.Name] = true
	}
	return nil
}

func (s *Signal) check(p *Pack) error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("name: each signal is named, because the finding says which one fired")
	}
	if len(s.Reasons) == 0 {
		return fmt.Errorf("reasons: at least one")
	}
	seen := map[string]bool{}
	for _, r := range s.Reasons {
		if !knownReason(r) {
			return fmt.Errorf("reasons: %q is not a reason this build emits; "+
				"docs/ATTACK.md lists them per kind, and a pack naming one that does not exist "+
				"is a detection that would never fire", r)
		}
		if seen[r] {
			return fmt.Errorf("reasons: %q twice", r)
		}
		seen[r] = true
	}
	for _, k := range s.Kinds {
		if !p.Covers(k) {
			return fmt.Errorf("kinds: %q is not one of the pack's own kinds", k)
		}
	}
	// Every reason has to be one some kind of this signal actually emits.
	// Checked after the kinds so the message can name them.
	for _, r := range s.Reasons {
		if len(p.EmittingKinds(*s, r)) == 0 {
			return fmt.Errorf("reasons: no listener kind of this signal (%s) emits %q, "+
				"so the signal would never be satisfied; docs/ATTACK.md lists the reasons per kind",
				strings.Join(p.SignalKinds(*s), ", "), r)
		}
	}
	for _, a := range s.Actions {
		switch a {
		case "deny", "alert", "engineering", "would_deny":
		default:
			return fmt.Errorf("actions: %q is not an action a security event carries", a)
		}
	}
	if s.Count == 0 {
		s.Count = 1
	}
	if s.Count < 1 || s.Count > 100000 {
		return fmt.Errorf("count %d: 1..100000", s.Count)
	}
	return nil
}

// bareReason is a reason without the kind prefix some kinds put on theirs and
// without the detail some append after a colon.
//
// It exists because the log spellings are not uniform and a pack author should
// not have to know which kinds prefix: a Modbus read refused on a read-only
// listener reaches the log as `modbus_read_only` and the ATT&CK table calls it
// `read_only`, and a pack naming either means the same thing. The WAF's
// `waf:942100` is the colon case.
func bareReason(kind, reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		reason = reason[:i]
	}
	if kind != "" {
		reason = strings.TrimPrefix(reason, kind+"_")
	}
	return reason
}

// matches reports whether an event satisfies the signal.
func (s *Signal) matches(e Event) bool {
	want := bareReason(e.Kind, e.Reason)
	found := false
	for _, r := range s.Reasons {
		if bareReason(e.Kind, r) == want {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if len(s.Kinds) > 0 && !contains(s.Kinds, e.Kind) {
		return false
	}
	if len(s.Actions) > 0 && !contains(s.Actions, e.Action) {
		return false
	}
	return true
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// Event is one security event, as the engine sees it. It is deliberately the
// fields a pack can name and no more: a pack cannot reach a payload, a user
// name or a register value, so nothing a peer chose ever reaches a comparison.
type Event struct {
	Action   string
	Reason   string
	Kind     string
	Listener string
	Actor    netip.Addr
	At       time.Time
}

// Finding is one pack match.
type Finding struct {
	Pack      string
	Name      string
	Technique string
	Severity  Severity
	Actor     netip.Addr
	// Kinds are the listener kinds the signals came from, sorted, so the
	// alert says where the sequence was seen.
	Kinds []string
	// Signals are the signal names in the order they were satisfied.
	Signals []string
	// Denied says the actor was quarantined as well as reported.
	Denied bool
	At     time.Time
}

// Reason is the security-event reason this finding is reported under. It is
// here rather than at the call site so that the log, the counter, the metric
// and the documentation cannot disagree about the spelling.
func (f Finding) Reason() string { return "pack_" + f.Pack }

// Detail is the finding in one line, for a log attribute.
func (f Finding) Detail() string {
	parts := make([]string, 0, 2)
	if len(f.Signals) > 0 {
		parts = append(parts, strings.Join(f.Signals, " then "))
	}
	if len(f.Kinds) > 0 {
		ks := make([]string, len(f.Kinds))
		copy(ks, f.Kinds)
		sort.Strings(ks)
		parts = append(parts, "on "+strings.Join(ks, ", "))
	}
	return strings.Join(parts, " ")
}
