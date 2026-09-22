package proxy

import (
	"os"
	goruntime "runtime"
	"runtime/metrics"
)

type runtimeStats struct {
	goroutines, heapAlloc, sys, gcCycles float64
}

// runtimeSample reads a few runtime metrics without stopping the world
// (runtime/metrics, not runtime.ReadMemStats).
func runtimeSample() runtimeStats {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/gc/cycles/total:gc-cycles"},
	}
	metrics.Read(samples)
	f := func(s metrics.Sample) float64 {
		switch s.Value.Kind() {
		case metrics.KindUint64:
			return float64(s.Value.Uint64())
		case metrics.KindFloat64:
			return s.Value.Float64()
		}
		return 0
	}
	return runtimeStats{
		goroutines: float64(goruntime.NumGoroutine()),
		heapAlloc:  f(samples[0]),
		sys:        f(samples[1]),
		gcCycles:   f(samples[2]),
	}
}

// openFDs counts entries in /proc/self/fd; -1 when unavailable.
// OpenFDs is the process's open descriptor count, for the gauge and
// for a test that watches it grow.
func OpenFDs() int { return openFDs() }

func openFDs() int {
	f, err := os.Open("/proc/self/fd")
	if err != nil {
		return -1
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return -1
	}
	return len(names) - 1 // minus the directory handle itself
}
