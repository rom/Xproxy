package main

import "golang.org/x/sys/unix"

// monotonicUSec is CLOCK_MONOTONIC in microseconds, which systemd wants in
// the RELOADING notification of a Type=notify-reload service.
func monotonicUSec() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return ts.Sec*1_000_000 + ts.Nsec/1000
}
