//go:build !linux && !darwin

package sandbox

import (
	"log/slog"

	"github.com/rom/xproxy/internal/config"
)

// apply on other platforms reports every mechanism as unavailable.
func apply(_ *config.Sandbox, _ Rules, st *Status, _ *slog.Logger) {
	for _, name := range []string{"debuggable", "capabilities", "no_new_privs", "landlock", "seccomp"} {
		st.Mechanism = append(st.Mechanism, Mechanism{Name: name, State: StateUnavailable, Detail: "not implemented on this platform"})
	}
}
