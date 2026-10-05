// Package simulate answers one question: what would this configuration
// decide about this traffic?
//
// It answers it by running the engine. Not a model of the engine, not a
// reimplementation of the policy in simpler terms -- the same listener kinds,
// the same WAF, the same command policies, the same admission path, driven
// with the traffic and watched. A simulator that reimplemented the decision
// would be a second policy engine to keep in step with the first, and the day
// they disagreed the operator would have trusted the wrong one. So the only
// thing this package does is take the estate out of the loop: the upstreams
// are replaced by a sink in this process, the state files are copied rather
// than opened, and everything that reaches outward is switched off.
//
// What it is for: introducing a WAF rule, or an OT command restriction,
// without finding out in production. Run last week's traffic through the
// configuration you have and the configuration you are proposing, and read the
// requests whose decision changed. That list is usually short, and it is the
// only part worth arguing about.
package simulate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// treatment is what a simulation does with one configuration section.
type treatment int

const (
	// keepPolicy is a section the simulation must keep exactly: it decides
	// something, and changing it would make the answer a different question.
	keepPolicy treatment = iota
	// copyState is a section naming a file the engine reads *and* writes.
	// The file is copied into the simulation's own directory, so the run
	// starts from the estate's state and writes nowhere near it. A grant in
	// the ledger has to be there or an engineering decision changes.
	copyState
	// switchOff is a section whose only effect reaches outside this process:
	// another node, an origin, a collector, a disk the estate reads. There is
	// nothing to simulate in it and a great deal to get wrong.
	switchOff
	// replaced is a section the simulation supplies itself.
	replaced
)

// sections is every top-level configuration section and what a simulation does
// with it.
//
// It is a table rather than a sequence of ifs because it is the security
// argument of this package, and an argument has to be readable. A reviewer
// asking "does simulating my configuration touch my cluster" reads one line.
//
// TestEverySectionHasATreatment fails when the configuration grows a section
// this table does not mention, which is the only way a table like this stays
// true.
var sections = map[string]treatment{
	// The policy. All of it is kept, because all of it decides something.
	"version":         keepPolicy,
	"includes":        keepPolicy, // already expanded by the loader
	"server":          keepPolicy, // rewritten in place: see bindLocally
	"trusted_proxies": keepPolicy,
	"rate_limits":     keepPolicy,
	"upstreams":       replaced, // every endpoint becomes the sink
	"routes":          keepPolicy,
	"policy":          keepPolicy,
	"waf":             keepPolicy,
	"virtual_patches": keepPolicy,
	"security_txt":    keepPolicy,
	"honeytokens":     keepPolicy,
	"handshake":       keepPolicy,
	"degradation":     keepPolicy,

	"correlation":   keepPolicy,
	"packs":         keepPolicy, // signed files on disk, read only
	"shedding":      keepPolicy,
	"maintenance":   keepPolicy,
	"challenge":     keepPolicy,
	"jwt":           keepPolicy,
	"filters":       keepPolicy,
	"geoip":         keepPolicy, // a database file, read only
	"cache":         keepPolicy,
	"compression":   keepPolicy,
	"authorization": keepPolicy,
	"fips":          keepPolicy,
	"secrets":       keepPolicy, // resolved the same way, from the same place

	// State the engine reads and writes. Copied in, so a run starts from what
	// the estate has and writes nowhere near it.
	"bans":            copyState, // bans.state_file: a banned address must stay banned
	"access":          copyState, // the grants and work orders a decision depends on
	"asset_inventory": copyState, // a device already in it is not a new device
	"api_inventory":   copyState, // an endpoint already in it is not a shadow endpoint

	// Outward. Nothing here changes a decision, and all of it would touch
	// something real.
	"cluster":      switchOff, // would gossip this run's bans to the estate
	"fleet":        switchOff, // would report a simulation as a node
	"acme":         switchOff, // would ask a CA for a certificate
	"tracing":      switchOff, // would send spans for traffic nobody served
	"metrics":      switchOff, // would push a simulation's numbers
	"icap":         switchOff, // would send bodies to a scanner
	"scim":         switchOff, // would serve provisioning
	"ingress":      switchOff, // would watch a Kubernetes API
	"capture":      switchOff, // would write pcapng of synthetic traffic
	"threat_intel": switchOff, // would fetch lists over the network
	"sandbox":      switchOff, // landlock in a simulator locks the simulator

	// Supplied by the simulation.
	"management": replaced, // no control plane: there is nothing to control
	"logging":    replaced, // the simulation is the reader of these events
}

// Report is what a simulation says it did to a configuration before running
// it. It is printed, because an operator is entitled to know what was taken
// out of the thing they asked to be simulated.
type Report struct {
	// SwitchedOff are the sections that were present and were disabled.
	SwitchedOff []string `json:"switched_off,omitempty"`
	// Copied are the state files copied into the simulation's directory,
	// as "section: path".
	Copied []string `json:"copied,omitempty"`
	// Listeners are the listeners the simulation bound, by name.
	Listeners []string `json:"listeners,omitempty"`
	// Notes are the things worth saying that are neither: a TLS listener
	// given a throwaway certificate, a kind the simulator cannot drive.
	Notes []string `json:"notes,omitempty"`
}

// Offline rewrites a configuration so that running it touches nothing but the
// directory it is given.
//
// dir must exist and be writable, and is where the copied state and the
// throwaway certificates go. The returned configuration is a copy; the one
// passed in is not modified, because a caller holding the estate's real
// configuration should not find it altered by having asked a question about it.
func Offline(in *config.Config, dir string) (*config.Config, Report, error) {
	if in == nil {
		return nil, Report{}, fmt.Errorf("no configuration")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, Report{}, fmt.Errorf("simulation directory: %w", err)
	}
	if !st.IsDir() {
		return nil, Report{}, fmt.Errorf("simulation directory %s: not a directory", dir)
	}
	// A real copy, so everything below may rewrite what it likes: see clone.go.
	cfg := clone(in)
	var rep Report

	// Outward: switched off, and said so.
	off := func(name string, present bool, clear func()) {
		if !present {
			return
		}
		clear()
		rep.SwitchedOff = append(rep.SwitchedOff, name)
	}
	off("cluster", cfg.Cluster != nil, func() { cfg.Cluster = nil })
	off("fleet", cfg.Fleet != nil, func() { cfg.Fleet = nil })
	off("acme", cfg.ACME != nil, func() { cfg.ACME = nil })
	off("tracing", cfg.Tracing != nil, func() { cfg.Tracing = nil })
	off("icap", cfg.ICAP != nil, func() { cfg.ICAP = nil })
	off("scim", cfg.SCIM != nil, func() { cfg.SCIM = nil })
	off("ingress", cfg.Ingress != nil, func() { cfg.Ingress = nil })
	off("capture", cfg.Capture != nil, func() { cfg.Capture = nil })
	off("threat_intel", cfg.ThreatIntel != nil, func() { cfg.ThreatIntel = nil })
	off("metrics", cfg.Metrics.OTLP != nil, func() { cfg.Metrics.OTLP = nil })
	off("sandbox", cfg.Sandbox.Enabled != nil && *cfg.Sandbox.Enabled, func() { cfg.Sandbox = config.Sandbox{} })

	// The control plane has nothing to control here, and a second daemon
	// binding the estate's management socket would be a real collision.
	cfg.Management = config.Management{}
	// The logs are the simulation's own: it reads the decisions off them.
	cfg.Logging = config.Logging{}

	// State the engine reads and writes: copied, so the run starts from what
	// the estate has and writes nowhere near it.
	state := func(name, into string, get func() string, set func(string)) error {
		from := get()
		if from == "" {
			return nil
		}
		path, err := copyIn(dir, into, from)
		if err != nil {
			return err
		}
		set(path)
		rep.Copied = append(rep.Copied, name+": "+from)
		return nil
	}
	if b := cfg.Bans; b != nil {
		if err := state("bans.state_file", "bans.state",
			func() string { return b.StateFile }, func(p string) { b.StateFile = p }); err != nil {
			return nil, rep, err
		}
	}
	if a := cfg.Access; a != nil {
		if err := state("access.ledger", "access.jsonl",
			func() string { return a.Ledger }, func(p string) { a.Ledger = p }); err != nil {
			return nil, rep, err
		}
	}
	// The inventories are state and not output: a device already in the
	// inventory is not a new device, and an API already seen is not a shadow
	// endpoint, so a simulation that started from an empty one would report
	// findings the daemon would not. Copied in like the rest, which also keeps
	// what this run invents out of the estate's file.
	if k := cfg.AssetInventory; k != nil {
		if err := state("asset_inventory.state_file", "assets.json",
			func() string { return k.StateFile }, func(p string) { k.StateFile = p }); err != nil {
			return nil, rep, err
		}
	}
	if a := cfg.APIInventory; a != nil {
		if err := state("api_inventory.state_file", "apis.json",
			func() string { return a.StateFile }, func(p string) { a.StateFile = p }); err != nil {
			return nil, rep, err
		}
	}

	// Everything else the engine writes is output rather than state, and goes
	// into the simulation's directory too: see writes.go.
	if err := redirectWrites(cfg, dir, &rep); err != nil {
		return nil, rep, err
	}

	sort.Strings(rep.SwitchedOff)
	sort.Strings(rep.Copied)
	return cfg, rep, nil
}

// copyIn copies a state file into the simulation's directory, or notes that
// there was none to copy. A missing file is not an error: an estate that has
// not banned anybody yet has no ban state, and the simulation starts as the
// daemon would.
func copyIn(dir, name, from string) (string, error) {
	to := filepath.Join(dir, name)
	b, err := os.ReadFile(from) //nolint:gosec // a state file path from the configuration being simulated
	switch {
	case os.IsNotExist(err):
		return to, nil
	case err != nil:
		return "", fmt.Errorf("copying %s for the simulation: %w", from, err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		return "", fmt.Errorf("copying %s for the simulation: %w", from, err)
	}
	return to, nil
}

// sectionNames is the table's keys, for the completeness test and for a
// message that has to list them.
func sectionNames() []string {
	out := make([]string, 0, len(sections))
	for k := range sections {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// String names a treatment, for a test failure that has to be readable.
func (t treatment) String() string {
	switch t {
	case keepPolicy:
		return "kept"
	case copyState:
		return "copied"
	case switchOff:
		return "switched off"
	case replaced:
		return "replaced"
	}
	return "unknown"
}

// summary is the one-line form of a Report, for the command.
func (r Report) summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d listeners", len(r.Listeners))
	if len(r.SwitchedOff) > 0 {
		fmt.Fprintf(&b, ", switched off: %s", strings.Join(r.SwitchedOff, " "))
	}
	if len(r.Copied) > 0 {
		fmt.Fprintf(&b, ", copied: %d state file(s)", len(r.Copied))
	}
	return b.String()
}
