package proxy

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/listener"
)

// The listener inventory: what this daemon is serving, on which address,
// in which mode, with which of the protocol's own guards switched on.
//
// It exists because the status view was a map of name to address, which
// answers "is it listening" and nothing after that. Every question an
// operator actually asks of a proxy that speaks thirty-four protocols --
// which of them am I running, which are enforcing and which are only
// watching, which have anomaly detection or a learning run going, what
// has each one refused and what would it have refused -- needs the kind
// and the mode beside the address. So does every per-protocol view in the
// web interface, which is why this is one report rather than three fields
// bolted onto the status.
//
// It covers this daemon's listeners. A shared estate configuration names
// the other roles' as well and each daemon takes out the ones it does not
// own before the engine sees them (internal/daemon.own), so a listener
// missing from here belongs to a sibling: ask its socket, or read
// /v1/fleet for the estate. The report says which daemon owns each kind it
// does serve, so a reader can tell the difference between "not configured"
// and "configured somewhere else".

// ListenerView is one accepting socket.
type ListenerView struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Role is edge, gate, relay or ot; Daemon the program that binds a
	// listener of this kind -- which for the seven kinds two daemons
	// serve is the one this listener named.
	Role   string `json:"role"`
	Daemon string `json:"daemon"`
	// Address is the accept socket's own, after binding, so a listener
	// configured on port 0 reports the port it actually got. Extra holds
	// the further addresses a kind took, under the suffix it chose: an
	// HTTP/3 endpoint, a datagram port beside a stream one.
	Address string            `json:"address"`
	Extra   map[string]string `json:"extra_addresses,omitempty"`
	// Mode is enforce, shadow (the policy is evaluated and nothing is
	// refused for it) or monitor (the kind's own monitor_only). It is the
	// one field a status view must not get wrong: a listener an operator
	// believes is enforcing and is not is worse than no listener.
	Mode string `json:"mode"`
	// TLS reports a tls section on the listener itself. A kind that
	// starts in the clear and upgrades -- STARTTLS, an NTS key exchange
	// -- says so in its own section, not here.
	TLS       bool     `json:"tls"`
	Protocols []string `json:"protocols,omitempty"`
	// ProxyProtocol parses PROXY protocol on accepted connections.
	ProxyProtocol bool `json:"proxy_protocol,omitempty"`
	// Bound reports that this listener holds its socket. A configured
	// listener that is not bound is either one that failed to bind or one
	// a reload has only just installed, and both are worth seeing.
	Bound bool `json:"bound"`
	// Configured reports a section of the kind's own on this listener.
	// Without one the kind runs on its defaults, which for a policy
	// enforcement point usually means it is relaying and watching rather
	// than restricting anything.
	Configured bool `json:"configured"`
	// Authorises reports that this kind consults the estate's
	// authorization section (internal/listener.Authorises).
	Authorises bool `json:"authorises"`
	// RateLimited reports a connection_rate or connection_rate_per_source
	// of this listener's own, replacing the server-wide accept gate.
	RateLimited bool `json:"rate_limited,omitempty"`
	// Features are the protocol guards this kind supports, each with
	// whether it is on. A kind reports only its own: there is no mfa row
	// on a Modbus listener, because Modbus has nobody to ask.
	Features []FeatureView `json:"features,omitempty"`
	// Egress is the forward proxy's rule policy, where the listener has
	// one: the count the feature row carries, how many of those rules
	// need a visible request, and whether this listener reads the
	// requests inside the tunnels it decrypts. Absent for every other
	// kind, and for a forward listener with no rules.
	Egress *EgressStatus `json:"egress,omitempty"`
}

// FeatureView is one guard of a listener's own section, in the name the
// configuration and the documentation use for it.
type FeatureView struct {
	// Name is the section key: learn, anomaly, engineering, deception,
	// recording, mfa, yara or icap.
	Name string `json:"name"`
	// Enabled is the guard's state. A section with an enabled flag says
	// so itself; a section written down without one is on by having been
	// written; an absent section is off, except for the one guard whose
	// default is on (see listenerFeatures).
	Enabled bool `json:"enabled"`
	// Mode is what the guard does where it says: the section's action
	// (alert or deny), or enforce and observe for a learning run.
	Mode string `json:"mode,omitempty"`
}

// KindActivity is one listener kind's decisions, which is where the
// refusal counters live: they are kept per kind and per reason, not per
// listener, so two Modbus listeners share one row. Listeners says how
// many are sharing it, because a count read as one listener's when it is
// two listeners' is the kind of mistake a status view should not invite.
type KindActivity struct {
	Kind      string `json:"kind"`
	Role      string `json:"role"`
	Daemon    string `json:"daemon"`
	Listeners int    `json:"listeners"`
	// Refused is what this kind refused, WouldRefuse what its listeners
	// in shadow mode recorded instead of refusing. Two totals from two
	// tables, never added together.
	Refused     uint64 `json:"refused"`
	WouldRefuse uint64 `json:"would_refuse"`
	// Reasons and ShadowReasons are the same two tables broken down,
	// heaviest first.
	Reasons       []ReasonCount `json:"reasons,omitempty"`
	ShadowReasons []ReasonCount `json:"shadow_reasons,omitempty"`
}

// ReasonCount is one refusal reason and its count.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

// ListenersReport is GET /v1/listeners.
type ListenersReport struct {
	Generated  time.Time `json:"generated"`
	Generation uint64    `json:"generation"`
	// Daemon is the program answering, and Role its role, so a reader
	// with three sockets open can tell the reports apart.
	Daemon string `json:"daemon"`
	Role   string `json:"role"`
	// Enforcing and Shadowing count the listeners in each mode, which is
	// the number an operator wants on a dashboard: "four of my
	// twenty-one listeners are not enforcing".
	Enforcing  int `json:"enforcing"`
	Shadowing  int `json:"shadowing"`
	Monitoring int `json:"monitoring"`
	// Learning counts the listeners recording a baseline without
	// enforcing, which is the third way a listener can be deciding
	// nothing and the one this report used to leave out.
	Learning  int            `json:"learning"`
	Listeners []ListenerView `json:"listeners"`
	Kinds     []KindActivity `json:"kinds,omitempty"`
}

// feature is one row of the guard table.
type feature struct {
	name string
	// defaultOn marks a guard that needs no section. An engineering
	// operation is reported on a listener of a kind that recognises one
	// whether or not anybody configured it, so an absent block means on
	// -- and a view that showed it off would be wrong about the most
	// consequential event class the plant has.
	defaultOn bool
}

// listenerFeatures is the guards a kind's section may carry, in the order
// a status view reads best: what the listener has learned and what it
// decides, then what it records, then what it scans.
//
// The kinds are matched by their yaml key rather than listed per kind, so
// a kind that grows an `anomaly:` section tomorrow appears here without
// this file being edited -- which is the only way a thirty-four kind
// inventory stays true. What is not generic is the default, so that is in
// the table above, named and explained.
var listenerFeatures = []feature{
	{name: "learn"},
	{name: "anomaly"},
	{name: "engineering", defaultOn: true},
	{name: "deception"},
	{name: "recording"},
	{name: "mfa"},
	{name: "yara"},
	{name: "icap"},
	{name: "rules"},
}

// ListenersReport is the inventory of this daemon's listeners with the
// decisions their kinds have taken.
//
// It is built from the configuration and then overlaid with what is bound,
// rather than read off the bound sockets: a listener that failed to bind,
// or one in a configuration a reload has installed but whose socket is
// still coming up, is exactly the listener somebody is looking for. Bound
// says which is which, and Address is the socket's own once there is one.
func (s *Server) ListenersReport() ListenersReport {
	cfg := s.cfg()
	out := ListenersReport{
		Generated:  time.Now().UTC(),
		Generation: s.Generation(),
	}
	refusals := s.stats.RefusalCounts()
	shadow := s.stats.WouldRefusalCounts()

	s.mu.Lock()
	bound := make(map[string]*boundListener, len(s.listeners))
	for _, bl := range s.listeners {
		bound[bl.cfg.Name] = bl
	}
	s.mu.Unlock()

	perKind := make(map[string]int, len(cfg.Server.Listeners))
	for _, lc := range cfg.Server.Listeners {
		v := listenerView(lc)
		if bl := bound[lc.Name]; bl != nil {
			v.Bound = true
			if bl.ln != nil {
				v.Address = bl.ln.Addr().String()
			}
			if r, ok := bl.inst.(EgressReporter); ok {
				v.Egress = r.EgressStatus()
			}
			if a, ok := bl.inst.(ExtraAddrs); ok {
				if extra := a.Addrs(); len(extra) > 0 {
					v.Extra = make(map[string]string, len(extra))
					for suffix, addr := range extra {
						v.Extra[suffix] = addr
					}
				}
			}
		}
		perKind[v.Kind]++
		switch v.Mode {
		case "shadow":
			out.Shadowing++
		case "monitor":
			out.Monitoring++
		case "learn":
			out.Learning++
		default:
			out.Enforcing++
		}
		if out.Role == "" {
			out.Role, out.Daemon = v.Role, v.Daemon
		}
		out.Listeners = append(out.Listeners, v)
	}
	sort.Slice(out.Listeners, func(i, j int) bool {
		if out.Listeners[i].Kind != out.Listeners[j].Kind {
			return out.Listeners[i].Kind < out.Listeners[j].Kind
		}
		return out.Listeners[i].Name < out.Listeners[j].Name
	})

	kinds := make([]string, 0, len(perKind))
	for k := range perKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		role, _ := listener.RoleOf(k)
		a := KindActivity{
			Kind:          k,
			Role:          string(role),
			Daemon:        role.Daemon(),
			Listeners:     perKind[k],
			Reasons:       reasonCounts(refusals[k]),
			ShadowReasons: reasonCounts(shadow[k]),
		}
		for _, r := range a.Reasons {
			a.Refused += r.Count
		}
		for _, r := range a.ShadowReasons {
			a.WouldRefuse += r.Count
		}
		out.Kinds = append(out.Kinds, a)
	}
	return out
}

// reasonCounts sorts one kind's table heaviest first, and by reason where
// two are equal so the order does not move between reads.
func reasonCounts(m map[string]uint64) []ReasonCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]ReasonCount, 0, len(m))
	for reason, n := range m {
		out = append(out, ReasonCount{Reason: reason, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// listenerView is everything about a listener that comes from its
// configuration; the caller fills in the bound address.
func listenerView(l config.Listener) ListenerView {
	kind := l.Kind
	if kind == "" {
		kind = "http"
	}
	role, _ := listener.Owner(kind, l.Daemon)
	v := ListenerView{
		Name:          l.Name,
		Kind:          kind,
		Role:          string(role),
		Daemon:        role.Daemon(),
		Address:       l.Address,
		Mode:          "enforce",
		TLS:           l.TLS != nil,
		ProxyProtocol: l.ProxyProtocol,
		Authorises:    listener.Authorises(kind),
		RateLimited:   l.ConnectionRate != nil || l.ConnectionRatePerSource != nil,
	}
	for _, p := range l.Protocols {
		v.Protocols = append(v.Protocols, string(p))
	}
	sec := kindSection(l, kind)
	v.Configured = sec.IsValid()
	v.Mode = config.Enforcement{
		Shadow:       l.Shadowing(),
		MonitorOnly:  monitorOnly(sec),
		Learning:     learning(sec),
		LearnEnforce: learnEnforces(sec),
	}.Mode()
	v.Features = featureViews(kind, sec)
	return v
}

// yamlKey is a struct tag's key, without the options after it.
func yamlKey(tag string) string {
	if i := strings.IndexByte(tag, ','); i >= 0 {
		return tag[:i]
	}
	return tag
}

// sectionType is the type of the listener field holding a kind's own
// section -- the field whose yaml key is the kind's name -- and whether
// the kind has one at all. http has none: its policy is the routes.
func sectionType(kind string) (reflect.Type, bool) {
	t := reflect.TypeOf(config.Listener{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if yamlKey(f.Tag.Get("yaml")) != kind {
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() != reflect.Struct {
			return nil, false
		}
		return ft, true
	}
	return nil, false
}

// kindSection is the listener's own section as a struct value, or the
// zero Value where the kind has none or the listener did not write one.
func kindSection(l config.Listener, kind string) reflect.Value {
	v := reflect.ValueOf(l)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if yamlKey(t.Field(i).Tag.Get("yaml")) != kind {
			continue
		}
		f := v.Field(i)
		if f.Kind() == reflect.Pointer {
			if f.IsNil() {
				return reflect.Value{}
			}
			f = f.Elem()
		}
		if f.Kind() != reflect.Struct {
			return reflect.Value{}
		}
		return f
	}
	return reflect.Value{}
}

// fieldByYAML finds a struct field by its yaml key.
func fieldByYAML(t reflect.Type, key string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if yamlKey(f.Tag.Get("yaml")) == key {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// monitorOnly reads a kind section's monitor_only.
func monitorOnly(sec reflect.Value) bool {
	if !sec.IsValid() {
		return false
	}
	f, ok := fieldByYAML(sec.Type(), "monitor_only")
	if !ok {
		return false
	}
	v := sec.FieldByIndex(f.Index)
	return v.Kind() == reflect.Bool && v.Bool()
}

// learning and learnEnforces read a kind section's learn.enabled and
// learn.enforce.
//
// The third reason a listener may not be enforcing, and the one the view used to
// miss: a learning run is observe-only unless it says otherwise, so a listener
// recording a baseline reported mode "enforce" while its policy decided nothing.
// That is the one field a status view must not get wrong.
func learning(sec reflect.Value) bool { return learnFlag(sec, "enabled") }

func learnEnforces(sec reflect.Value) bool { return learnFlag(sec, "enforce") }

func learnFlag(sec reflect.Value, key string) bool {
	if !sec.IsValid() {
		return false
	}
	f, ok := fieldByYAML(sec.Type(), "learn")
	if !ok {
		return false
	}
	l := sec.FieldByIndex(f.Index)
	for l.Kind() == reflect.Ptr {
		if l.IsNil() {
			return false
		}
		l = l.Elem()
	}
	if l.Kind() != reflect.Struct {
		return false
	}
	g, ok := fieldByYAML(l.Type(), key)
	if !ok {
		return false
	}
	v := l.FieldByIndex(g.Index)
	return v.Kind() == reflect.Bool && v.Bool()
}

// featureViews is the guard rows for one kind: one per guard the kind's
// section type has a field for, whether or not the listener wrote the
// section, so the answer to "does this protocol do anomaly detection" is
// the same shape as the answer to "is it switched on here".
func featureViews(kind string, sec reflect.Value) []FeatureView {
	t, ok := sectionType(kind)
	if !ok {
		return nil
	}
	out := make([]FeatureView, 0, len(listenerFeatures))
	for _, f := range listenerFeatures {
		sf, ok := fieldByYAML(t, f.name)
		if !ok {
			continue
		}
		var fv reflect.Value
		if sec.IsValid() {
			fv = sec.FieldByIndex(sf.Index)
		}
		out = append(out, f.view(fv))
	}
	return out
}

// view reads one guard's state from its field.
func (f feature) view(fv reflect.Value) FeatureView {
	out := FeatureView{Name: f.name, Enabled: f.defaultOn}
	if !fv.IsValid() {
		return out
	}
	if fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			return out
		}
		fv = fv.Elem()
	}
	// A guard written as a list of rules rather than a section: it is on when
	// it has rules, and how many there are is the one thing worth saying about
	// it in a table this wide. Which rules, and what each has decided, is the
	// kind's own report.
	if fv.Kind() == reflect.Slice {
		out.Enabled = fv.Len() > 0
		if out.Enabled {
			out.Mode = strconv.Itoa(fv.Len())
		}
		return out
	}
	if fv.Kind() != reflect.Struct {
		return out
	}
	out.Enabled = enabledOf(fv)
	out.Mode = modeOf(fv)
	return out
}

// enabledOf reads a section's own enabled flag: a bool means what it
// says, a *bool left out means the default the section documents (on --
// nobody writes a block to leave it off), and a section with no flag at
// all is on by having been written down.
func enabledOf(sec reflect.Value) bool {
	f, ok := fieldByYAML(sec.Type(), "enabled")
	if !ok {
		return true
	}
	v := sec.FieldByIndex(f.Index)
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Pointer:
		return v.IsNil() || v.Elem().Bool()
	}
	return true
}

// modeOf reads what a guard does on a match: its action where it has one,
// otherwise enforce or observe for a section that only decides whether
// what it learned is applied.
func modeOf(sec reflect.Value) string {
	if f, ok := fieldByYAML(sec.Type(), "action"); ok {
		if v := sec.FieldByIndex(f.Index); v.Kind() == reflect.String && v.String() != "" {
			return v.String()
		}
	}
	if f, ok := fieldByYAML(sec.Type(), "enforce"); ok {
		if v := sec.FieldByIndex(f.Index); v.Kind() == reflect.Bool {
			if v.Bool() {
				return "enforce"
			}
			return "observe"
		}
	}
	// A section that requires a grant and does not name an action takes
	// the default its own documentation gives: refuse what has no grant
	// open for it, and where nothing is required, report and allow. Said
	// here rather than left blank because "the block does not say" is not
	// an answer to "does this listener refuse a program download".
	if f, ok := fieldByYAML(sec.Type(), "require_grant"); ok {
		if v := sec.FieldByIndex(f.Index); v.Kind() == reflect.Bool {
			if v.Bool() {
				return "deny"
			}
			return "alert"
		}
	}
	return ""
}
