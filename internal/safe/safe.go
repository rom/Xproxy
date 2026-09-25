// Package safe is the last line of defence against a panic on a
// goroutine that serves one connection, one datagram or one request.
//
// Go ends the whole process on an unrecovered panic, whichever goroutine
// raised it. A proxy parses attacker-controlled bytes on a goroutine per
// flow, so a single malformed datagram that reaches an unchecked index
// would take every other connection down with it: a denial of service
// out of one packet. Every such goroutine defers Guard, which contains
// the damage to the flow that caused it and records the stack for the
// operator.
//
// Guard is defence in depth, not a licence to skip bounds checks. A
// recovered panic is a bug: it is counted and logged at error level so
// that it is found and fixed, never silently absorbed.
package safe

import (
	"runtime"
	"sync/atomic"
)

// panics counts recovered panics across the process, for the metric of
// the same name.
var panics atomic.Uint64

// Panics reports how many panics have been contained since start.
func Panics() uint64 { return panics.Load() }

// Reporter receives a contained panic: what was running, the recovered
// value and the stack of the goroutine that raised it.
type Reporter func(what string, value any, stack []byte)

// report is the installed sink, held atomically.
//
// It is atomic because "set once at start-up" is not quite true: a reload
// builds a second Server while the first is still serving, so the sink is
// written while flow goroutines are running and could be reading it. A
// contained panic during a reload is exactly when an operator most wants
// the stack, and a torn function pointer is the one way to turn a
// contained panic back into a process that stops.
var report atomic.Pointer[Reporter]

// SetReport installs the sink for contained panics. A sink that has not
// been set drops the detail but still counts the panic.
func SetReport(f Reporter) {
	if f == nil {
		report.Store(nil)
		return
	}
	report.Store(&f)
}

// Guard recovers a panic on the calling goroutine. Use it as the first
// deferred call of a goroutine that handles one flow:
//
//	go func() {
//		defer safe.Guard("dns udp query")
//		...
//	}()
//
// It must not be used to wrap work whose caller depends on the result:
// the goroutine simply stops where it panicked, so anything the flow
// still owed (a reply, a closed socket) is abandoned. Every current use
// is a goroutine whose own deferred cleanup runs afterwards.
func Guard(what string) {
	v := recover()
	if v == nil {
		return
	}
	panics.Add(1)
	f := report.Load()
	if f == nil {
		return
	}
	buf := make([]byte, 16<<10)
	buf = buf[:runtime.Stack(buf, false)]
	(*f)(what, v, buf)
}
