// Package relay copies bytes between two connections.
//
// Every listener kind ends up doing this, and the parts that are easy
// to get wrong are the same every time: a deadline on the write as well
// as the read, because a peer that stops reading holds the write open
// for as long as it likes and the flow would keep its goroutines, its
// sockets, its connection-limiter slot and its endpoint's active count
// until the process ended; and a half close rather than a close when
// one direction ends, so the other can still drain.
//
// Watch is the same with a hook per direction, which is how a kind
// scans what it relays without writing the copy loop again.
package relay

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Splice copies in both directions until one side ends or the idle
// timeout passes with no bytes either way. It returns bytes client to
// upstream and upstream to client.
func Splice(client, up net.Conn, idle time.Duration) (in, out int64) {
	return Watch(client, up, idle, nil, nil)
}

// Watch is Splice with an optional watcher per direction. A
// watcher sees each read before it is written on and returns false to
// end the copy.
func Watch(client, up net.Conn, idle time.Duration, toUpstream, toClient func([]byte) bool) (in, out int64) {
	var wg sync.WaitGroup
	// The idle timeout is a property of the connection, not of one
	// direction, and the difference is not academic: plenty of relayed
	// protocols have one side that speaks rarely while the other is
	// busy -- a database connection, a mail session holding IDLE, an
	// interactive session carried at layer 4. Timing out each direction
	// on its own read deadline would half close such a connection while
	// it was working, leaving the busy side sending into a path with no
	// return, which is worse than closing it. So a read deadline that
	// expires while the other direction has been active is not an idle
	// connection: the deadline is reset and the read goes again.
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	copyDir := func(dst, src net.Conn, n *int64, watch func([]byte) bool) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			r, err := src.Read(buf)
			if r > 0 {
				last.Store(time.Now().UnixNano())
				if watch != nil && !watch(buf[:r]) {
					break
				}
				// The write needs its own deadline. A peer that stops
				// reading (a zero receive window) blocks this write for
				// as long as it likes, and the idle timeout above only
				// covers the read: the flow would hold its goroutines,
				// its sockets, its connection-limiter slot and its
				// endpoint's active count until the process ended.
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
				w, werr := dst.Write(buf[:r])
				*n += int64(w)
				if werr != nil {
					break
				}
			}
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() &&
					time.Since(time.Unix(0, last.Load())) < idle {
					continue // the other direction was active
				}
				break
			}
		}
		// Half close where possible so the other direction can drain.
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go copyDir(up, client, &in, toUpstream)
	go copyDir(client, up, &out, toClient)
	wg.Wait()
	_ = client.Close()
	_ = up.Close()
	return in, out
}

// Limits bound one relayed connection beyond the idle timeout: an
// absolute lifetime and a byte bound per direction.
//
// They exist for the listeners with no parser in the path -- kind: tcp,
// and a forward tunnel -- where nothing else in the proxy can say what
// a connection is doing or when it has done enough. A protocol-aware
// listener bounds a session in its own terms (a command count, a
// transfer size, a channel policy); a relay has only time and bytes,
// so it should at least have those.
type Limits struct {
	// Idle ends a connection with no bytes in either direction.
	Idle time.Duration
	// Lifetime ends a connection however active. 0 is no bound.
	Lifetime time.Duration
	// BytesIn bounds client to upstream, BytesOut upstream to client.
	// 0 is no bound. The bound is on what is relayed, so the direction
	// that reaches it is the direction named in the reason.
	BytesIn, BytesOut int64
}

// End is how a relayed connection ended: "" for a peer closing it,
// otherwise the bound that ended it.
const (
	EndLifetime = "session_timeout"
	EndBytesIn  = "max_bytes_in"
	EndBytesOut = "max_bytes_out"
)

// Bounded is Watch with Limits, returning the bound that ended the
// connection, or "" where a peer ended it.
//
// A byte bound is enforced on what has been relayed rather than on what
// was read, and it ends the connection rather than truncating the
// stream: a relay that silently stopped forwarding would look to both
// peers like a network that had gone quiet, which is the hardest
// failure there is to diagnose.
func Bounded(client, up net.Conn, l Limits, toUpstream, toClient func([]byte) bool) (in, out int64, end string) {
	var reason atomic.Pointer[string]
	stop := func(r string) {
		reason.CompareAndSwap(nil, &r)
		// Closing both is what ends the other direction's blocking read
		// as well as this one's.
		_ = client.Close()
		_ = up.Close()
	}
	if l.Lifetime > 0 {
		t := time.AfterFunc(l.Lifetime, func() { stop(EndLifetime) })
		defer t.Stop()
	}
	bound := func(limit *int64, counted *int64, r string) func([]byte) bool {
		if *limit <= 0 {
			return nil
		}
		return func(b []byte) bool {
			if atomic.AddInt64(counted, int64(len(b))) > *limit {
				stop(r)
				return false
			}
			return true
		}
	}
	var seenIn, seenOut int64
	chain := func(a, b func([]byte) bool) func([]byte) bool {
		switch {
		case a == nil:
			return b
		case b == nil:
			return a
		}
		return func(p []byte) bool { return a(p) && b(p) }
	}
	in, out = Watch(client, up, l.Idle,
		chain(bound(&l.BytesIn, &seenIn, EndBytesIn), toUpstream),
		chain(bound(&l.BytesOut, &seenOut, EndBytesOut), toClient))
	if r := reason.Load(); r != nil {
		return in, out, *r
	}
	return in, out, ""
}
