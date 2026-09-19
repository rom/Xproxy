package sandbox

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"

	"github.com/rom/xproxy/internal/config"
)

// apply runs the Linux mechanisms in dependency order: the debugging
// controls first (cheap and independent), then capabilities, then
// no_new_privs (required by Landlock and by seccomp without
// CAP_SYS_ADMIN), then Landlock, and the system call filter last so that
// nothing it refuses is still needed.
func apply(sb *config.Sandbox, rules Rules, st *Status, log *slog.Logger) {
	st.Mechanism = append(st.Mechanism, debuggable(sb))
	st.Mechanism = append(st.Mechanism, dropCapabilities(sb))
	nnp := noNewPrivs(sb)
	st.Mechanism = append(st.Mechanism, nnp)
	st.Mechanism = append(st.Mechanism, landlock(sb, rules, st, nnp.State == StateApplied || nnp.State == StateDisabled, log))
	st.Mechanism = append(st.Mechanism, seccomp(sb, st))
}

// debuggable makes the process non dumpable and forbids core files unless
// the configuration keeps it debuggable.
func debuggable(sb *config.Sandbox) Mechanism {
	m := Mechanism{Name: "debuggable"}
	if sb.Debuggable {
		m.State = StateDisabled
		return m
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		m.State, m.Detail = StateFailed, "PR_SET_DUMPABLE: "+err.Error()
		return m
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		m.State, m.Detail = StateFailed, "RLIMIT_CORE: "+err.Error()
		return m
	}
	m.State, m.Detail = StateApplied, "non dumpable, core size 0"
	return m
}

// noNewPrivs sets PR_SET_NO_NEW_PRIVS. It is idempotent: systemd's
// NoNewPrivileges=yes sets it before exec.
func noNewPrivs(sb *config.Sandbox) Mechanism {
	m := Mechanism{Name: "no_new_privs"}
	if sb.NoNewPrivs != nil && !*sb.NoNewPrivs {
		m.State = StateDisabled
		return m
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		m.State, m.Detail = StateFailed, err.Error()
		return m
	}
	m.State = StateApplied
	return m
}

// errnoDetail renders a system call failure.
func errnoDetail(call string, err error) string { return fmt.Sprintf("%s: %v", call, err) }
