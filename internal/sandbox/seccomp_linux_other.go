//go:build linux && !amd64 && !arm64

package sandbox

// The filter is built for amd64 and arm64; other architectures report
// seccomp as unavailable and keep the remaining mechanisms.
const (
	auditArch = 0
	x32Check  = false
)

var deniedArchitecture = []int{}
