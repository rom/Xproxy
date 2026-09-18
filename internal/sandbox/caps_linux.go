package sandbox

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rom/xproxy/internal/config"
)

// lastCap reads the highest capability number the kernel knows, falling
// back to the compile time value.
func lastCap() int {
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n >= 0 && n < 64 {
			return n
		}
	}
	return unix.CAP_LAST_CAP
}

// dropCapabilities clears the ambient set, drops every capability from
// the bounding set that is still in it, and clears the effective,
// permitted and inheritable sets. Under the shipped unit all of them are
// already empty and every step is a no-op that still verifies the state.
func dropCapabilities(sb *config.Sandbox) Mechanism {
	m := Mechanism{Name: "capabilities"}
	if sb.Capabilities.Drop != nil && !*sb.Capabilities.Drop {
		m.State = StateDisabled
		return m
	}
	// Ambient capabilities cannot exist without permitted ones, but the
	// call is cheap and independent of state.
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		m.State, m.Detail = StateFailed, errnoDetail("capget", err)
		return m
	}
	hadPermitted := data[0].Permitted != 0 || data[1].Permitted != 0
	last := lastCap()
	dropped, remaining := 0, 0
	for c := 0; c <= last; c++ {
		in, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0) //nolint:gosec // 0..63
		if err != nil || in == 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil { //nolint:gosec // 0..63
			// Dropping needs CAP_SETPCAP; without it the bounding set is
			// whatever the parent left, which is reported below.
			remaining++
			continue
		}
		dropped++
	}
	var empty [2]unix.CapUserData
	if err := unix.Capset(&hdr, &empty[0]); err != nil {
		m.State, m.Detail = StateFailed, errnoDetail("capset", err)
		return m
	}
	if remaining > 0 {
		m.State = StateFailed
		m.Detail = fmt.Sprintf("%d capabilities remain in the bounding set (no CAP_SETPCAP to drop them); sets cleared", remaining)
		return m
	}
	m.State = StateApplied
	switch {
	case hadPermitted:
		m.Detail = fmt.Sprintf("sets cleared, %d dropped from the bounding set", dropped)
	case dropped > 0:
		m.Detail = fmt.Sprintf("%d dropped from the bounding set", dropped)
	default:
		m.Detail = "already empty"
	}
	return m
}
