//go:build !linux

package daemon

// monotonicUSec is only meaningful to systemd.
func monotonicUSec() int64 { return 0 }
