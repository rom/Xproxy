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

// Report receives a contained panic: what was running, the recovered
// value and the stack of the goroutine that raised it. It is set once at
// start-up, before any listener runs. A nil Report drops the detail but
// still counts the panic.
var Report func(what string, value any, stack []byte)

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
	if Report == nil {
		return
	}
	buf := make([]byte, 16<<10)
	buf = buf[:runtime.Stack(buf, false)]
	Report(what, v, buf)
}
