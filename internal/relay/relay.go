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
	"net"
	"sync"
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
	copyDir := func(dst, src net.Conn, n *int64, watch func([]byte) bool) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			r, err := src.Read(buf)
			if r > 0 {
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
