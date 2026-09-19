//go:build !linux && !darwin

package paths

import "runtime"

const (
	ConfigFile = "/etc/xproxy/xproxy.yaml"
	ConfigDir  = "/etc/xproxy"
	UsersFile  = "/etc/xproxy/admin-users"
	Socket     = "/run/xproxy/mgmt.sock"
	LogDir     = "/var/log/xproxy"
	StateDir   = "/var/lib/xproxy"
)

// Platform names the operating system in status output.
var Platform = runtime.GOOS
