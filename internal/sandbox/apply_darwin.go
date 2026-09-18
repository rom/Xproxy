package sandbox

import (
	"log/slog"
	"os"

	"golang.org/x/sys/unix"

	"github.com/rom/xproxy/internal/config"
)

// apply on macOS: debugger denial and no core files in process; file
// system and system call confinement come from the sandbox-exec profile
// the launchd job runs the daemon under (deploy/macos/xproxy.sb), which
// the job advertises through XPROXY_SEATBELT so the status can show it.
func apply(sb *config.Sandbox, _ Rules, st *Status, _ *slog.Logger) {
	m := Mechanism{Name: "debuggable"}
	switch {
	case sb.Debuggable:
		m.State = StateDisabled
	default:
		if err := unix.PtraceDenyAttach(); err != nil {
			m.State, m.Detail = StateFailed, "PT_DENY_ATTACH: "+err.Error()
		} else if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
			m.State, m.Detail = StateFailed, "RLIMIT_CORE: "+err.Error()
		} else {
			m.State, m.Detail = StateApplied, "debugger attachment denied, core size 0"
		}
	}
	st.Mechanism = append(st.Mechanism, m)
	seatbelt := Mechanism{Name: "seatbelt", State: StateUnavailable, Detail: "not running under the sandbox-exec profile (deploy/macos/xproxy.sb)"}
	if p := os.Getenv("XPROXY_SEATBELT"); p != "" {
		seatbelt.State, seatbelt.Detail = StateApplied, "profile "+p+" reported by the launcher"
	}
	st.Mechanism = append(st.Mechanism, seatbelt)
	for _, name := range []string{"landlock", "seccomp", "capabilities"} {
		st.Mechanism = append(st.Mechanism, Mechanism{Name: name, State: StateUnavailable, Detail: "Linux only; see docs/HARDENING_MACOS.md"})
	}
}
