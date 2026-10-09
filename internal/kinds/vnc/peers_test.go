package vnc

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rfb"
)

// A peer that is not there. Every security type is a sequence of reads
// and writes with the client or the desktop, and each of those can fail
// for the dullest reason there is: the other end has gone. What must
// not happen is a leg that reports success anyway -- that would be an
// authenticated session nobody authenticated -- or one that blocks on a
// socket whose peer has gone for good.
//
// Each type is driven directly here rather than through a listener,
// because a socket cannot be asked to fail at the fourth write of a
// handshake from the outside.

// peer returns a connection whose far end reads everything and answers
// nothing, and a function that drops the far end. Not net.Pipe: that is
// synchronous, so an unread write there blocks for ever instead of
// failing.
func peer(t *testing.T) (ours net.Conn, drop func()) {
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
			done <- nil
			return
		}
		done <- c
		_, _ = io.Copy(io.Discard, c)
	}()
	ours, err = net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	far := <-done
	if far == nil {
		t.Fatal("the far end never arrived")
	}
	t.Cleanup(func() { _ = far.Close(); _ = ours.Close() })
	return ours, func() {
		_ = far.Close()
		// The close has to be seen before the leg reads, and a read
		// deadline in the past is the only way to say that from here
		// without a sleep.
		_ = ours.SetReadDeadline(time.Now().Add(-time.Second))
	}
}

// legs is every security type's two halves, as the thing to run and
// what the session needs to have settled before running it.
func legs(t *testing.T) []struct {
	name  string
	build func(*testing.T) *session
	run   func(*session) string
	// toUp says which leg this one talks on, so the test knows which
	// connection to hand it.
	toUp bool
	// resultLater marks a half that ends before the peer has said yes
	// or no: the desktop's security result is read by the caller, so
	// finishing against a peer that answered nonsense is the right
	// outcome there and the refusal comes one step later.
	resultLater bool
} {
	t.Helper()
	host := engine(t)
	pw := secret(t, "pw", "desktop-secret\n", 0o600)
	k := key(t)

	build := func(cfg func(*server)) func(*testing.T) *session {
		return func(t *testing.T) *session {
			v := &config.VNCListener{UpstreamUser: "service", UpstreamRSAFingerprint: "aa:bb"}
			srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: v,
				password: "desktop-secret", upPassword: "desktop-secret", rsaKey: k,
				tlsCfg:   &tls.Config{MinVersion: tls.VersionTLS12},
				subtypes: []uint32{rfb.VeNCryptX509Plain, rfb.VeNCryptX509None},
			}
			if cfg != nil {
				cfg(srv)
			}
			return &session{t: srv, target: "desk.lab.test:5900",
				clientVersion: rfb.V38, upVersion: rfb.V38}
		}
	}
	_ = pw
	return []struct {
		name        string
		build       func(*testing.T) *session
		run         func(*session) string
		toUp        bool
		resultLater bool
	}{
		{name: "vncauth, the client's half", build: build(nil), run: (*session).clientVNCAuth},
		{name: "vencrypt, the client's half", build: build(nil), run: (*session).clientVeNCrypt},
		{name: "vencrypt plain, the credential", build: build(nil), run: (*session).clientPlain},
		{name: "anonymous TLS, the client's half", build: build(nil), run: (*session).clientAnonTLS},
		{name: "mslogon2, the client's half", build: build(nil), run: (*session).clientMSLogon},
		{
			name:  "rsa-aes, the client's half",
			build: build(func(s *server) {}),
			run: func(se *session) string {
				se.clientSec = rfb.SecRSAAES
				return se.clientRSAAES()
			},
		},
		{name: "tight, the client's half", build: build(nil), run: (*session).clientTight},
		{name: "ard, the client's half", build: build(nil), run: (*session).clientARD},

		{name: "vncauth, the desktop's half", build: build(nil), run: (*session).upstreamVNCChallenge, toUp: true, resultLater: true},
		{
			name: "vencrypt, the desktop's half",
			build: build(func(s *server) {
				s.v.UpstreamTLSMode = "vencrypt"
				s.upTLS = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // the handshake never completes here
			}),
			run: (*session).upstreamVeNCrypt, toUp: true,
		},
		{name: "mslogon2, the desktop's half", build: build(nil), run: (*session).upstreamMSLogon, toUp: true},
		{
			name:  "rsa-aes, the desktop's half",
			build: build(nil),
			run: func(se *session) string {
				se.upSec = rfb.SecRSAAES
				return se.upstreamRSAAES()
			},
			toUp: true,
		},
		// A Tight server offering no tunnels and no authentication
		// types is a Tight server asking for nothing, which is legal
		// and is what a run of zero octets spells.
		{name: "tight, the desktop's half", build: build(nil), run: (*session).upstreamTight, toUp: true, resultLater: true},
		{name: "ard, the desktop's half", build: build(nil), run: (*session).upstreamARD, toUp: true},
	}
}

// With the peer already gone, the first thing the leg does fails.
func TestEveryTypeEndsWhenThePeerIsAlreadyGone(t *testing.T) {
	for _, c := range legs(t) {
		t.Run(c.name, func(t *testing.T) {
			se := c.build(t)
			conn, drop := peer(t)
			drop()
			_ = conn.Close()
			if c.toUp {
				se.up = conn
			} else {
				se.client = conn
			}
			if reason := c.run(se); reason == "" {
				t.Error("the leg reported success against a peer that is not there")
			}
		})
	}
}

// And with a peer that takes everything and answers nothing, the first
// read fails instead -- the case a half-open socket makes, where the
// writes all succeed into the kernel and nothing ever comes back.
func TestEveryTypeEndsWhenThePeerAnswersNothing(t *testing.T) {
	for _, c := range legs(t) {
		t.Run(c.name, func(t *testing.T) {
			se := c.build(t)
			conn, drop := peer(t)
			if c.toUp {
				se.up = conn
			} else {
				se.client = conn
			}
			done := make(chan string, 1)
			go func() { done <- c.run(se) }()
			// The writes go through, and then the leg waits for an
			// answer; dropping the far end is what it gets instead.
			time.Sleep(20 * time.Millisecond)
			drop()
			select {
			case reason := <-done:
				if reason == "" {
					t.Error("the leg reported success against a peer that said nothing")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the leg is still waiting on a peer that has gone")
			}
		})
	}
}

// babble returns a connection whose far end answers everything with
// the same octet and reads whatever it is sent. This is the other
// failure a peer can be: not absent but wrong, so every read succeeds
// and nothing it returns means anything. A leg that takes those
// answers for a completed authentication is the serious version of
// this bug.
func babble(t *testing.T, fill byte) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		go func() { _, _ = io.Copy(io.Discard, c) }()
		noise := make([]byte, 4096)
		for i := range noise {
			noise[i] = fill
		}
		for {
			if _, err := c.Write(noise); err != nil {
				return
			}
		}
	}()
	ours, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ours.Close() })
	// A leg that waits for something it will never recognise must not
	// wait for ever here.
	_ = ours.SetDeadline(time.Now().Add(10 * time.Second))
	return ours
}

func TestEveryTypeEndsWhenThePeerAnswersNonsense(t *testing.T) {
	for _, fill := range []byte{0x00, 0xff} {
		for _, c := range legs(t) {
			t.Run(c.name+filler(fill), func(t *testing.T) {
				se := c.build(t)
				conn := babble(t, fill)
				if c.toUp {
					se.up = conn
				} else {
					se.client = conn
				}
				done := make(chan string, 1)
				go func() { done <- c.run(se) }()
				select {
				case reason := <-done:
					if reason == "" && !c.resultLater {
						t.Error("the leg authenticated a peer that answered nonsense")
					}
				case <-time.After(20 * time.Second):
					t.Fatal("the leg is still reading nonsense")
				}
			})
		}
	}
}

func filler(b byte) string {
	const digits = "0123456789abcdef"
	return ", answered 0x" + string([]byte{digits[b>>4], digits[b&0xf]})
}
