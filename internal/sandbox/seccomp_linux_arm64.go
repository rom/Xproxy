package sandbox

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_AARCH64
	x32Check  = false
)

// deniedArchitecture: nothing beyond the common list on arm64.
var deniedArchitecture = []int{}
