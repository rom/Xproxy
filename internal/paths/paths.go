// Package paths holds the platform default locations of the configuration
// file, the management socket, the log directory and the state directory.
// Linux follows the file system hierarchy standard under /etc, /run,
// /var/log and /var/lib; macOS keeps everything under /usr/local, where a
// third party daemon belongs and where the system integrity protection
// does not interfere.
package paths
