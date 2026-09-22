// Package paths holds the platform default locations of the configuration
// file, the management socket, the log directory and the state directory.
// Linux follows the file system hierarchy standard under /etc, /run,
// /var/log and /var/lib; macOS keeps everything under /usr/local, where a
// third party daemon belongs and where the system integrity protection
// does not interfere.
package paths

import "path/filepath"

// ConfigFileFor is a daemon's default configuration file. The three
// daemons run side by side, so each reads a file of its own: a shared
// file cannot give them different management sockets, metrics addresses
// or log directories, and those are exactly the things two processes
// cannot share. What is common between them belongs in an include the
// three files pull in.
func ConfigFileFor(daemon string) string {
	if daemon == "" || daemon == "xproxy" {
		return ConfigFile
	}
	return filepath.Join(ConfigDir, daemon+".yaml")
}
