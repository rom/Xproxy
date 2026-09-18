// Package version holds build-time version information for xproxy binaries.
package version

// These are overridden at link time via -ldflags "-X ...".
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a single-line human readable version string.
func String() string {
	return Version + " (" + Commit + ", " + BuildDate + ")"
}
