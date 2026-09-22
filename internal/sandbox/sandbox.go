// Package sandbox applies in-process hardening once the daemon has opened
// everything it needs: listeners, log files, state files and the
// management socket. On Linux it installs Landlock file system rules
// derived from the configuration, a seccomp system call deny list, clears
// every capability set, sets no_new_privs and makes the process non
// dumpable. On macOS it denies debugger attachment and core dumps; the
// file system and system call confinement come from the launchd and
// sandbox-exec profiles shipped in deploy/macos. Each mechanism reports
// whether it was applied, was unavailable or failed, so the status is
// visible over the management socket (GET /v1/sandbox, xproxyctl sandbox).
package sandbox

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/paths"
)

// State of one mechanism.
const (
	StateApplied     = "applied"
	StateDisabled    = "disabled"
	StateUnavailable = "unavailable"
	StateFailed      = "failed"
)

// Mechanism is one hardening measure and what became of it.
type Mechanism struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// Status is the management view of the sandbox.
type Status struct {
	Platform  string      `json:"platform"`
	Enabled   bool        `json:"enabled"`
	Strict    bool        `json:"strict"`
	AppliedAt time.Time   `json:"applied_at,omitempty"`
	Mechanism []Mechanism `json:"mechanisms"`
	// ReadPaths and WritePaths are the Landlock rules in force, when
	// Landlock was applied.
	ReadPaths  []string `json:"read_paths,omitempty"`
	WritePaths []string `json:"write_paths,omitempty"`
	// LandlockABI is the kernel's Landlock ABI version, 0 without.
	LandlockABI int `json:"landlock_abi,omitempty"`
	// Denied is the number of system calls the seccomp filter refuses.
	Denied int `json:"seccomp_denied,omitempty"`
	// Landlocked reports whether file system rules are in force, which
	// makes Check meaningful.
	Landlocked bool `json:"landlocked"`
	// MissingPaths are configured or system paths that did not exist when
	// the rules were applied; a file created there later is reachable
	// only if its directory was admitted.
	MissingPaths []string `json:"missing_paths,omitempty"`
}

// Rules are the file system paths a configuration needs after start.
type Rules struct {
	Read  []string
	Write []string
}

// ErrOutsideRules is returned by Check when a configuration names a path
// the running sandbox does not admit.
var ErrOutsideRules = errors.New("outside the sandbox rules applied at start; restart to apply")

// Apply hardens the process for cfg, which was loaded from cfgPath. The
// returned status is never nil; err is set only when the configuration is
// strict and a mechanism was unavailable or failed, or when a mechanism
// failed in a way that leaves the process in an undefined state.
func Apply(cfg *config.Config, cfgPath string, log *slog.Logger) (*Status, error) {
	st := &Status{Platform: paths.Platform, Enabled: cfg.Sandbox.On(), Strict: cfg.Sandbox.Strict, Mechanism: []Mechanism{}}
	if !st.Enabled {
		log.Warn("sandbox disabled by configuration")
		return st, nil
	}
	rules := Derive(cfg, cfgPath)
	apply(&cfg.Sandbox, rules, st, log)
	st.AppliedAt = time.Now()
	var problems []string
	for _, m := range st.Mechanism {
		switch m.State {
		case StateApplied:
			log.Info("sandbox "+m.Name, "state", m.State, "detail", m.Detail)
		case StateDisabled:
			log.Info("sandbox "+m.Name, "state", m.State)
		default:
			log.Warn("sandbox "+m.Name, "state", m.State, "detail", m.Detail)
			problems = append(problems, m.Name+": "+m.Detail)
		}
	}
	if st.Strict && len(problems) > 0 {
		return st, fmt.Errorf("sandbox: strict mode and %s", strings.Join(problems, "; "))
	}
	return st, nil
}

// Check reports whether a candidate configuration stays within the file
// system rules applied at start. Without Landlock in force every
// configuration passes.
func (st *Status) Check(cfg *config.Config, cfgPath string) error {
	if st == nil || !st.Landlocked {
		return nil
	}
	r := Derive(cfg, cfgPath)
	var bad []string
	for _, p := range r.Read {
		if !beneathAny(p, st.ReadPaths) && !beneathAny(p, st.WritePaths) {
			bad = append(bad, p+" (read)")
		}
	}
	for _, p := range r.Write {
		if !beneathAny(p, st.WritePaths) {
			bad = append(bad, p+" (write)")
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("sandbox: %s %w", strings.Join(bad, ", "), ErrOutsideRules)
}

// beneathAny reports whether p equals or lies under one of roots.
func beneathAny(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

// systemReadPaths are what the Go runtime and the standard library open
// after start: name resolution files, the trusted certificate stores,
// time zones and the kernel interfaces the net package consults.
var systemReadPaths = []string{
	"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/services", "/etc/protocols",
	"/etc/localtime", "/usr/share/zoneinfo", "/etc/ssl", "/etc/pki", "/etc/ca-certificates",
	"/usr/share/ca-certificates", "/usr/local/share/ca-certificates", "/etc/crypto-policies",
	"/proc/sys/net", "/proc/self", "/sys/kernel/mm/transparent_hugepage", "/dev/null", "/dev/urandom",
	"/private/etc/hosts", "/private/etc/resolv.conf", "/var/run/resolv.conf",
}

// isSystemPath reports whether p is one of the well known system paths
// rather than an operator configured one; a missing system path is
// normal (not every distribution has every trust store directory).
func isSystemPath(p string) bool {
	for _, s := range systemReadPaths {
		if p == s {
			return true
		}
	}
	return false
}

// Derive computes the paths cfg needs after start. Files are represented
// by their directory so that a reload can pick up a replaced file (new
// inode, same directory) without widening the rules.
func Derive(cfg *config.Config, cfgPath string) Rules {
	read := map[string]bool{}
	write := map[string]bool{}
	addRead := func(p string, isDir bool) {
		p = clean(p)
		if p == "" {
			return
		}
		if !isDir {
			p = filepath.Dir(p)
		}
		read[p] = true
	}
	addWrite := func(p string, isDir bool) {
		p = clean(p)
		if p == "" {
			return
		}
		if !isDir {
			p = filepath.Dir(p)
		}
		write[p] = true
	}
	for _, p := range systemReadPaths {
		read[p] = true
	}
	if cfgPath != "" {
		addRead(cfgPath, false)
	}
	for _, pat := range cfg.Includes {
		addRead(globBase(pat), true)
	}
	for _, f := range cfg.IncludedFiles {
		addRead(f, false)
	}
	walk(cfg, func(key, value string) {
		if !strings.HasPrefix(value, "/") {
			return
		}
		switch key {
		case "state_dir", "cert_dir", "history_dir":
			addWrite(value, true)
		case "state_file", "file":
			addWrite(value, false)
		case "root", "dir":
			addRead(value, true)
		default:
			addRead(value, false)
		}
	})
	// Log streams without a file setting go to the log directory; the
	// management socket is the one socket the process creates; the fleet
	// agent writes bundles into its directory.
	if d := cfg.Logging.Directory; d != "" {
		addWrite(d, true)
	}
	// The capture directory is written to, not read: the proxy creates a
	// file in it for each recording window. Without this rule a capture
	// that is configured and switched on writes nothing under the
	// sandbox, which is on by default.
	if c := cfg.Capture; c != nil && c.Enabled {
		addWrite(c.Directory, true)
	}
	if f := cfg.Fleet; f != nil && f.Applies() {
		d := f.Dir
		if d == "" {
			d = filepath.Dir(cfgPath)
		}
		addWrite(d, true)
	}
	addWrite(cfg.Management.Socket, false)
	// A local cluster binds its own socket and connects to its
	// siblings', which are in the same directory: the whole directory
	// has to be reachable, not only the one path this node creates.
	if cl := cfg.Cluster; cl != nil && cl.IsLocal() {
		if path, ok := config.UnixSocket(cl.Listen); ok {
			addWrite(path, false)
		}
		for _, p := range cl.Peers {
			if path, ok := config.UnixSocket(p); ok {
				addWrite(path, false)
			}
		}
	}
	for _, p := range cfg.Sandbox.Landlock.ReadPaths {
		addRead(p, true)
	}
	for _, p := range cfg.Sandbox.Landlock.WritePaths {
		addWrite(p, true)
	}
	// A directory that is writable is readable as well; drop the
	// duplicate read rule.
	for w := range write {
		delete(read, w)
	}
	return Rules{Read: sorted(read), Write: sorted(write)}
}

func clean(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	return filepath.Clean(p)
}

// globBase returns the longest directory prefix of a glob pattern that
// contains no wildcard.
func globBase(pat string) string {
	if i := strings.IndexAny(pat, "*?["); i >= 0 {
		pat = pat[:i]
	}
	if strings.HasSuffix(pat, "/") {
		return filepath.Clean(pat)
	}
	return filepath.Dir(pat)
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
