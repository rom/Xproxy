//go:build !linux

package main

// monotonicUSec is only meaningful to systemd.
func monotonicUSec() int64 { return 0 }
