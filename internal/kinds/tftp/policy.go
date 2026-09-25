package tftp

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/tftp"
)

// The policy. A TFTP request carries a filename, a mode and a direction, and
// that is the whole of what there is to decide about -- so each of the three
// is a decision of its own, and the address it came from stands in for the
// identity the protocol does not have.

// Decision is what the policy says about one request.
type Decision struct {
	Allow bool
	// Rule is the rule that decided, empty for the default.
	Rule string
	// Reason and Detail name the refusal for the log and the counter.
	Reason, Detail string
	// Hard is a refusal a shadow-mode listener still enforces.
	//
	// The line is the same one every kind here draws. A policy -- which
	// paths, which direction, which mode -- is what shadow mode is for: an
	// operator runs it on live traffic and reads what it would have refused.
	// A *bound* is not policy, and neither is a filename this relay and the
	// server read differently: shadowing the first leaves a working
	// amplifier, and shadowing the second means forwarding a request nobody
	// decided about.
	Hard bool
	// The bounds this request runs under, after the rule that matched has
	// had its say.
	MaxBytes  int64
	MaxBlock  int
	MaxWindow int
}

// request is one request, as the policy sees it.
type request struct {
	client netip.Addr
	op     wire.Op
	path   wire.Path
	mode   string
	at     time.Time
}

// Policy is a compiled tftp listener policy.
type Policy struct {
	allow, deny []netip.Prefix
	ops         map[wire.Op]bool
	modes       map[string]bool
	classes     map[wire.Class]bool
	dirs        []string
	denyDirs    []string
	pats        []string
	denyPats    []string
	maxDepth    int
	maxName     int
	maxBytes    int64
	maxBlock    int
	maxWindow   int
	rules       []*rule
	allowByDef  bool
	now         func() time.Time
}

// rule is one compiled rule.
type rule struct {
	name     string
	action   string
	clients  []netip.Prefix
	ops      map[wire.Op]bool
	modes    map[string]bool
	classes  map[wire.Class]bool
	dirs     []string
	denyDirs []string
	pats     []string
	denyPats []string

	maxBytes  int64
	maxBlock  int
	maxWindow int
	sched     *schedule
}

func compile(m *config.TFTPListener, now func() time.Time) (*Policy, error) {
	p := &Policy{now: now, allowByDef: m.DefaultAction == "allow",
		maxDepth: 8, maxName: 256, maxBytes: 64 << 20,
		maxBlock: 1468, maxWindow: 4}
	var err error
	if p.allow, err = prefixes(m.AllowClients); err != nil {
		return nil, fmt.Errorf("tftp allow_clients: %w", err)
	}
	if p.deny, err = prefixes(m.DenyClients); err != nil {
		return nil, fmt.Errorf("tftp deny_clients: %w", err)
	}
	// Read only by default. A write is a device putting a file onto the
	// server, and a protocol with no authentication is not how that should
	// happen unless somebody wrote it down.
	if p.ops, err = ops(m.Operations, map[wire.Op]bool{wire.OpRead: true}); err != nil {
		return nil, err
	}
	// mail is left out of the default: RFC 1350 removed it, and a server
	// that still implements it delivers the file as mail to the address in
	// the filename field.
	p.modes = modes(m.Modes, map[string]bool{wire.ModeOctet: true, wire.ModeNetASCII: true})
	if p.classes, err = classes(m.AllowPathClasses); err != nil {
		return nil, err
	}
	p.dirs, p.denyDirs = m.Directories, m.DenyDirectories
	p.pats, p.denyPats = m.Filenames, m.DenyFilenames
	if m.MaxDepth > 0 {
		p.maxDepth = m.MaxDepth
	}
	if m.MaxFilenameBytes > 0 {
		p.maxName = m.MaxFilenameBytes
	}
	if m.MaxTransferBytes != 0 {
		p.maxBytes = m.MaxTransferBytes
	}
	if m.MaxBlockSize > 0 {
		p.maxBlock = m.MaxBlockSize
	}
	if m.MaxWindowSize != 0 {
		p.maxWindow = m.MaxWindowSize
	}
	for i := range m.Rules {
		r, err := compileRule(&m.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(c *config.TFTPRule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, dirs: c.Directories,
		denyDirs: c.DenyDirectories, pats: c.Filenames, denyPats: c.DenyFilenames,
		maxBytes: c.MaxTransferBytes, maxBlock: c.MaxBlockSize, maxWindow: c.MaxWindowSize}
	if r.action == "" {
		r.action = "allow"
	}
	var err error
	if r.clients, err = prefixes(c.Clients); err != nil {
		return nil, fmt.Errorf("tftp rule %s clients: %w", c.Name, err)
	}
	if r.ops, err = ops(c.Operations, nil); err != nil {
		return nil, err
	}
	r.modes = modes(c.Modes, nil)
	if r.classes, err = classes(c.AllowPathClasses); err != nil {
		return nil, err
	}
	if r.sched, err = compileSchedule(c.Schedule); err != nil {
		return nil, err
	}
	return r, nil
}

func prefixes(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func ops(in []string, def map[wire.Op]bool) (map[wire.Op]bool, error) {
	if len(in) == 0 {
		return def, nil
	}
	out := map[wire.Op]bool{}
	for _, s := range in {
		op, ok := wire.OpOf(s)
		if !ok || !op.Request() {
			return nil, fmt.Errorf("tftp operations: %q is not read or write", s)
		}
		out[op] = true
	}
	return out, nil
}

func modes(in []string, def map[string]bool) map[string]bool {
	if len(in) == 0 {
		return def
	}
	out := map[string]bool{}
	for _, s := range in {
		out[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return out
}

// classes compiles a path-class list. The three a configuration may not name
// are refused here as well as by validation, because a policy built by hand
// in a test is still a policy and the bound is not one it may cross.
func classes(in []string) (map[wire.Class]bool, error) {
	out := map[wire.Class]bool{}
	for _, s := range in {
		c, ok := wire.ClassOf(s)
		if !ok {
			return nil, fmt.Errorf("tftp allow_path_classes: %q is not a path class", s)
		}
		if c.Hard() {
			return nil, fmt.Errorf("tftp allow_path_classes: %q can never be allowed", s)
		}
		if c == wire.ClassPlain {
			return nil, fmt.Errorf("tftp allow_path_classes: %q is every ordinary path and is always allowed", s)
		}
		out[c] = true
	}
	return out, nil
}

// Client says whether an address may send at all. Deny is evaluated first,
// and an empty allow list admits everything -- which validation warns about,
// because on this protocol the client list is the only identity there is.
func (p *Policy) Client(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, n := range p.deny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.allow) == 0 {
		return true
	}
	for _, n := range p.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Decide decides one request.
//
// The order is deliberate. The name's shape comes first, because a name this
// relay and the server read differently cannot be decided about at all. Then
// the bounds on the name, then the listener's own lists -- which no rule can
// widen -- and only then the rules, which narrow.
func (p *Policy) Decide(req request) Decision {
	if d, refused := p.shape(req); refused {
		return d
	}
	if d, refused := p.lists(req); refused {
		return d
	}
	base := Decision{MaxBytes: p.maxBytes, MaxBlock: p.maxBlock, MaxWindow: p.maxWindow}
	for _, r := range p.rules {
		if !r.matches(req, p) {
			continue
		}
		d := base
		d.Rule = r.name
		switch r.action {
		case "deny":
			d.Reason, d.Detail = "rule", req.path.Clean
			return d
		case "observe":
			// An observing rule logs and counts and then keeps looking,
			// which is how a rule is tried on live traffic before it decides
			// anything.
			continue
		}
		if r.maxBytes != 0 {
			d.MaxBytes = r.maxBytes
		}
		if r.maxBlock > 0 {
			d.MaxBlock = r.maxBlock
		}
		if r.maxWindow != 0 {
			d.MaxWindow = r.maxWindow
		}
		d.Allow = true
		return d
	}
	d := base
	// No rule matched, so the class list that applies is the listener's own.
	// This is the soft half of the shape check, held back until here: a rule
	// that widened the list has already had its chance, and one that did not
	// leaves the listener's answer standing.
	if c := req.path.Class; c != wire.ClassPlain && !p.classes[c] {
		d.Reason, d.Detail = "path_"+c.String(), req.path.Detail
		return d
	}
	d.Allow = p.allowByDef
	if !d.Allow {
		d.Reason, d.Detail = "default_deny", req.path.Clean
	}
	return d
}

// shape refuses a filename for what it is rather than for what it names.
//
// Only the classes nothing may allow, and the bounds, are refused here. A
// class a configuration *could* allow is left to the end of Decide, because a
// rule may widen the list for its own traffic and a refusal before the rules
// were read would make that impossible.
func (p *Policy) shape(req request) (Decision, bool) {
	c := req.path.Class
	if c.Hard() {
		// Not shadowable: this relay and the server are reading different
		// names, so there is nothing a policy could be evaluated against.
		return Decision{Reason: "path_" + c.String(), Detail: req.path.Detail, Hard: true}, true
	}
	if n := len(req.path.Name); p.maxName > 0 && n > p.maxName {
		// A bound, so it holds in shadow mode too.
		return Decision{Reason: "filename_too_long", Detail: itoa(n), Hard: true}, true
	}
	if p.maxDepth > 0 && req.path.Depth > p.maxDepth {
		return Decision{Reason: "path_too_deep", Detail: itoa(req.path.Depth), Hard: true}, true
	}
	return Decision{}, false
}

// lists applies the listener's own allow and deny lists, which no rule can
// widen: a deny list one rule could override is not a deny list.
func (p *Policy) lists(req request) (Decision, bool) {
	if under(req.path, p.denyDirs) {
		return Decision{Reason: "directory_denied", Detail: req.path.Clean}, true
	}
	if matches(req.path, p.denyPats) {
		return Decision{Reason: "filename_denied", Detail: req.path.Clean}, true
	}
	if len(p.dirs) > 0 && !under(req.path, p.dirs) {
		return Decision{Reason: "directory_not_allowed", Detail: req.path.Clean}, true
	}
	if len(p.pats) > 0 && !matches(req.path, p.pats) {
		return Decision{Reason: "filename_not_allowed", Detail: req.path.Clean}, true
	}
	if len(p.ops) > 0 && !p.ops[req.op] {
		return Decision{Reason: "operation_not_allowed", Detail: req.op.String()}, true
	}
	if len(p.modes) > 0 && !p.modes[req.mode] {
		return Decision{Reason: "mode_not_allowed", Detail: req.mode}, true
	}
	return Decision{}, false
}

// matches says whether a rule covers a request.
func (r *rule) matches(req request, p *Policy) bool {
	if len(r.clients) > 0 && !contains(r.clients, req.client) {
		return false
	}
	if len(r.ops) > 0 && !r.ops[req.op] {
		return false
	}
	if len(r.modes) > 0 && !r.modes[req.mode] {
		return false
	}
	// A rule's class list widens the listener's for its own traffic, which is
	// how one legacy server that really does serve absolute paths is written
	// down. It cannot widen past the classes nothing may allow, because
	// compilation refuses those.
	if c := req.path.Class; c != wire.ClassPlain && !p.classes[c] && !r.classes[c] {
		return false
	}
	if under(req.path, r.denyDirs) {
		return false
	}
	if matches(req.path, r.denyPats) {
		return false
	}
	if len(r.dirs) > 0 && !under(req.path, r.dirs) {
		return false
	}
	if len(r.pats) > 0 && !matches(req.path, r.pats) {
		return false
	}
	return r.sched.inForce(req.at)
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// under says whether a path lies inside any of the directories.
func under(pa wire.Path, dirs []string) bool {
	for _, d := range dirs {
		if pa.Under(d) {
			return true
		}
	}
	return false
}

// matches says whether a path matches any of the patterns.
//
// The pattern is matched against the cleaned path and against the last
// element, so both "firmware/*.bin" and "*.bin" say what an operator means by
// them. path.Match's error is the pattern's, and validation has already
// refused a pattern that has one.
func matches(pa wire.Path, pats []string) bool {
	for _, pat := range pats {
		if ok, err := path.Match(pat, pa.Clean); err == nil && ok {
			return true
		}
		if ok, err := path.Match(pat, path.Base(pa.Clean)); err == nil && ok {
			return true
		}
	}
	return false
}
