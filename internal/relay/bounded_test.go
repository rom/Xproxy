package relay

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// pair returns two connected sockets over a real TCP loopback, because
// what this package is about -- deadlines, half close, a peer that
// stops reading -- is only true of a real socket.
func pair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		done <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-done
	if b == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// relayed runs Bounded between two pairs and gives the test the ends it
// drives: what a client writes arrives at the upstream and back.
func relayed(t *testing.T, l Limits) (client, upstream net.Conn, result chan [3]any) {
	t.Helper()
	clientEnd, proxyClient := pair(t)
	proxyUp, upEnd := pair(t)
	result = make(chan [3]any, 1)
	go func() {
		in, out, end := Bounded(proxyClient, proxyUp, l, nil, nil)
		result <- [3]any{in, out, end}
	}()
	return clientEnd, upEnd, result
}

// A connection ends on the byte bound of the direction that reached it,
// and the reason names that direction.
func TestBoundedByBytesIn(t *testing.T) {
	client, up, result := relayed(t, Limits{Idle: 5 * time.Second, BytesIn: 16})
	go func() { _, _ = io.Copy(io.Discard, up) }()
	if _, err := client.Write([]byte(strings.Repeat("x", 64))); err != nil {
		t.Fatal(err)
	}
	r := <-result
	if end := r[2].(string); end != EndBytesIn {
		t.Fatalf("ended %q, want %q", end, EndBytesIn)
	}
	if in := r[0].(int64); in > 64 {
		t.Errorf("relayed %d bytes past a bound of 16", in)
	}
}

func TestBoundedByBytesOut(t *testing.T) {
	client, up, result := relayed(t, Limits{Idle: 5 * time.Second, BytesOut: 16})
	go func() { _, _ = io.Copy(io.Discard, client) }()
	if _, err := up.Write([]byte(strings.Repeat("y", 64))); err != nil {
		t.Fatal(err)
	}
	r := <-result
	if end := r[2].(string); end != EndBytesOut {
		t.Fatalf("ended %q, want %q", end, EndBytesOut)
	}
}

// The lifetime ends a connection that is busy, which is the whole point
// of it: an idle timeout never fires on one.
func TestBoundedByLifetime(t *testing.T) {
	client, up, result := relayed(t, Limits{Idle: time.Minute, Lifetime: 300 * time.Millisecond})
	go func() { _, _ = io.Copy(io.Discard, up) }()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := client.Write([]byte("busy")); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	select {
	case r := <-result:
		if end := r[2].(string); end != EndLifetime {
			t.Fatalf("ended %q, want %q", end, EndLifetime)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a busy connection outlived its lifetime bound")
	}
}

// A connection a peer closes ends with no reason: the bounds are for
// saying that the proxy ended it, and an ordinary close is not that.
func TestUnboundedConnectionReportsNoReason(t *testing.T) {
	// A short idle timeout, because after the client's close the other
	// direction has nothing to end it but that timeout, and waiting out
	// a realistic one is waiting for nothing.
	client, up, result := relayed(t, Limits{Idle: 200 * time.Millisecond})
	go func() { _, _ = io.Copy(io.Discard, up) }()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	r := <-result
	if end := r[2].(string); end != "" {
		t.Fatalf("a peer's close reported %q", end)
	}
}

// Splice still behaves as it did: the bounds are additions, and the
// callers that pass none must be unaffected.
func TestSpliceStillCopiesBothWays(t *testing.T) {
	clientEnd, proxyClient := pair(t)
	proxyUp, upEnd := pair(t)
	done := make(chan struct{})
	go func() { Splice(proxyClient, proxyUp, 200*time.Millisecond); close(done) }()
	go func() {
		buf := make([]byte, 64)
		n, err := upEnd.Read(buf)
		if err != nil {
			return
		}
		_, _ = upEnd.Write([]byte("re:" + string(buf[:n])))
	}()
	if _, err := clientEnd.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientEnd.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "re:ping" {
		t.Fatalf("got %q", got)
	}
	_ = clientEnd.Close()
	<-done
}

// TestIdleIsAPropertyOfTheConnection is the regression for a bug the
// byte bounds turned up: the idle timeout was applied to each
// direction's own read deadline, so a connection whose server side
// speaks rarely -- a database session, a mail session holding IDLE, an
// interactive session carried at layer 4 -- was half closed while it
// was working. The busy side went on sending into a path with no
// return, which is worse than a close, because nothing tells it.
func TestIdleIsAPropertyOfTheConnection(t *testing.T) {
	clientEnd, proxyClient := pair(t)
	proxyUp, upEnd := pair(t)
	done := make(chan struct{})
	go func() { Splice(proxyClient, proxyUp, 300*time.Millisecond); close(done) }()

	// The upstream reads and says nothing for several idle timeouts,
	// then finally answers.
	go func() {
		buf := make([]byte, 64)
		total := 0
		for {
			n, err := upEnd.Read(buf)
			if err != nil {
				return
			}
			total += n
			if total >= 40 { // after a good many client writes
				_, _ = upEnd.Write([]byte("finally"))
				return
			}
		}
	}()
	go func() {
		for i := 0; i < 40; i++ {
			if _, err := clientEnd.Write([]byte("tick")); err != nil {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	buf := make([]byte, 64)
	_ = clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientEnd.Read(buf)
	if err != nil {
		t.Fatalf("the return path died while the client was busy: %v", err)
	}
	if got := string(buf[:n]); got != "finally" {
		t.Fatalf("got %q", got)
	}
	_ = clientEnd.Close()
	<-done
}

// A connection that is genuinely idle in both directions still ends.
func TestIdleStillEndsASilentConnection(t *testing.T) {
	clientEnd, proxyClient := pair(t)
	proxyUp, _ := pair(t)
	done := make(chan struct{})
	go func() { Splice(proxyClient, proxyUp, 200*time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a silent connection was never closed")
	}
	_ = clientEnd.Close()
}
