package vnc_test

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/rfb"
)

// A peer that dies in the middle of the handshake. Every read and write
// in that negotiation is a place where the other end can go away, and a
// gateway that mishandles one of them either hangs holding a session or
// carries on with a half-negotiated one. The two directions are
// separate: the client's leg is settled first, so a desktop that dies
// can only be noticed after the client has been told its own leg is
// open.

// ended waits for the gateway to let go of every session it had, which
// is the observable fact about a session that has ended.
func ended(t *testing.T, stats func() int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for stats() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the gateway is still holding a session whose peer died")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A desktop that stops writing partway through the handshake. The cut
// points walk the negotiation: nothing at all, half a version, the
// version and no security list, half a list, no security result, and a
// ServerInit that stops in the middle.
func TestADesktopThatDiesMidHandshakeDoesNotHangTheGateway(t *testing.T) {
	for _, cut := range []int{-1, 6, 12, 13, 14, 16, 18, 30, 50} {
		t.Run(name(cut), func(t *testing.T) {
			tg := startTarget(t, &target{cutAfter: cut, security: []uint8{rfb.SecNone}})
			s, addr := gateway(t, tg, "        security_types: [none]")
			cl := dial(t, addr)
			// The client's own leg is negotiated before the desktop is
			// dialled at all, so all of this succeeds whatever the
			// desktop does.
			cl.version(rfb.V38)
			if list := cl.offered(); !contains(list, rfb.SecNone) {
				t.Fatalf("none was not offered: %v", list)
			}
			cl.write([]byte{rfb.SecNone})
			if ok, why := cl.result(); !ok {
				t.Fatalf("the gateway refused its own client: %s", why)
			}
			cl.write(rfb.ClientInit{Shared: true}.Encode())
			// And now the desktop's leg fails, so the client is let go
			// rather than left waiting for a ServerInit that cannot
			// come.
			_ = cl.c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(cl.c, make([]byte, 24)); err == nil {
				t.Error("the gateway answered with a ServerInit of its own invention")
			}
			ended(t, func() int64 { return s.Stats().VNCSessionsOpen })
		})
	}
}

func name(cut int) string {
	switch {
	case cut < 0:
		return "nothing at all"
	default:
		return "after " + itoa(cut) + " octets"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A desktop that announces a version this gateway cannot speak, and one
// that refuses the gateway at the security result. Neither is a reason
// to tell the client anything but no.
func TestADesktopTheGatewayCannotNegotiateWith(t *testing.T) {
	t.Run("a version from before the protocol", func(t *testing.T) {
		tg := startTarget(t, &target{version: rfb.Version{Major: 2, Minor: 0}})
		s, addr := gateway(t, tg, "        security_types: [none]")
		clientLegUpTo(t, addr)
		ended(t, func() int64 { return s.Stats().VNCSessionsOpen })
	})

	t.Run("a desktop that refuses the gateway", func(t *testing.T) {
		tg := startTarget(t, &target{resultFails: true})
		s, addr := gateway(t, tg, "        security_types: [none]")
		clientLegUpTo(t, addr)
		// The gateway's own credential being refused is the desktop's
		// decision, not a refusal this gateway made, so it is logged
		// and ends the session rather than counted against the client.
		ended(t, func() int64 { return s.Stats().VNCSessionsOpen })
	})

	t.Run("a desktop offering nothing the gateway can use", func(t *testing.T) {
		// 19 is not a type this gateway speaks, so there is nothing to
		// pick and the session ends before the client sees a desktop.
		tg := startTarget(t, &target{security: []uint8{19}})
		s, addr := gateway(t, tg, "        security_types: [none]")
		clientLegUpTo(t, addr)
		ended(t, func() int64 { return s.Stats().VNCSessionsOpen })
	})
}

// clientLegUpTo drives the client's side through to ClientInit and
// asserts that no ServerInit follows, which is the shape of every
// session whose desktop leg failed.
func clientLegUpTo(t *testing.T, addr string) {
	t.Helper()
	cl := dial(t, addr)
	cl.version(rfb.V38)
	if list := cl.offered(); !contains(list, rfb.SecNone) {
		t.Fatalf("none was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecNone})
	if ok, why := cl.result(); !ok {
		t.Fatalf("the gateway refused its own client: %s", why)
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	_ = cl.c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(cl.c, make([]byte, 24)); err == nil {
		t.Error("the gateway answered with a ServerInit of its own invention")
	}
}

// A client that dies in its own handshake. None of this reaches the
// desktop -- it is never dialled -- so what matters is that the gateway
// lets the session go rather than waiting on a socket nobody is holding.
func TestAClientThatDiesMidHandshakeIsNotWaitedFor(t *testing.T) {
	for _, c := range []struct {
		name string
		send []byte
	}{
		{"nothing at all", nil},
		{"half a version", []byte("RFB 003.")},
		{"a version and no choice", []byte("RFB 003.008\n")},
		{"a version from before the protocol", []byte("RFB 002.000\n")},
		{"a version that is not one", []byte("NOT A VERSION\n")},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := startTarget(t, &target{})
			s, addr := gateway(t, tg, "        security_types: [none]")
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			// The gateway writes its own version first; reading it
			// makes sure the session has started before we leave.
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(conn, make([]byte, 12)); err != nil {
				t.Fatal(err)
			}
			if len(c.send) > 0 {
				if _, err := conn.Write(c.send); err != nil {
					t.Fatal(err)
				}
			}
			_ = conn.Close()
			ended(t, func() int64 { return s.Stats().VNCSessionsOpen })
			// And the desktop was never troubled with any of it.
			if len(tg.seen()) != 0 {
				t.Errorf("the desktop was sent %d octets for a client that never finished", len(tg.seen()))
			}
		})
	}
}

// The same walk through every security type the gateway speaks towards
// a desktop. Each type is a different sequence of reads and writes on
// that leg -- a challenge, a key, a tunnel, a credential -- and a
// desktop can go away at any point in it. Nothing here should end as
// anything but a session that closed: a gateway that carried on would
// be relaying a stream it never authenticated.
func TestADesktopThatDiesInEachUpstreamTypeDoesNotHangTheGateway(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "target.pw")
	write(t, pw, "desktop-secret")
	cert, _, srvTLS, _ := serverTLS(t, "target.test")
	keyFile, _ := rsaKeyFile(t)
	_, targetKey := rsaKeyFile(t)
	pub, err := rfb.OwnRSAAESKey(&targetKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// The cut points are per type because the negotiations are
	// different lengths: a DES challenge is sixteen octets and an RSA
	// key is a few hundred, so one list of offsets would walk the whole
	// of one and only the opening of another. Every offset here is
	// inside its own negotiation.
	for _, c := range []struct {
		name  string
		extra string
		cuts  []int
		// tg builds the desktop afresh for each run rather than being
		// one to copy: a target carries the lock its own session takes.
		tg func() *target
	}{
		{
			name:  "vncauth",
			cuts:  []int{15, 20, 31, 36, 50, 65},
			extra: "        upstream_password_file: " + pw,
			tg:    func() *target { return &target{security: []uint8{rfb.SecVNCAuth}, password: "desktop-secret"} },
		},
		{
			name:  "vencrypt",
			cuts:  []int{15, 17, 20, 23, 60, 200, 600},
			extra: "        upstream_tls_mode: vencrypt\n        upstream_tls: {ca_file: " + cert + ", server_name: target.test}",
			tg:    func() *target { return &target{security: []uint8{rfb.SecVeNCrypt}, serverTLS: srvTLS} },
		},
		{
			name:  "mslogon2",
			cuts:  []int{15, 20, 30, 40, 48, 60},
			extra: "        upstream_security: mslogon2\n        upstream_user: service\n        upstream_password_file: " + pw,
			tg:    func() *target { return &target{security: []uint8{rfb.SecMSLogon2}, password: "desktop-secret"} },
		},
		{
			name:  "ard",
			cuts:  []int{15, 20, 30, 60, 100, 160},
			extra: "        upstream_security: ard\n        upstream_user: service\n        upstream_password_file: " + pw,
			tg:    func() *target { return &target{security: []uint8{rfb.SecARD}, password: "desktop-secret"} },
		},
		{
			name:  "tight",
			cuts:  []int{15, 18, 22, 30, 45, 60},
			extra: "        upstream_password_file: " + pw,
			tg: func() *target {
				return &target{security: []uint8{rfb.SecTight}, password: "desktop-secret", tightAuth: true}
			},
		},
		{
			name: "rsa-aes",
			cuts: []int{15, 20, 60, 140, 270, 285, 300, 320, 340},
			extra: "        rsa_key_file: " + keyFile + "\n        upstream_security: rsa-aes\n" +
				"        upstream_user: service\n        upstream_password_file: " + pw +
				"\n        upstream_rsa_fingerprint: " + rfb.RSAAESFingerprint(pub),
			tg: func() *target {
				return &target{security: []uint8{rfb.SecRSAAES}, rsaKey: targetKey, password: "desktop-secret"}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Uncut first, so a case that never worked cannot pass by
			// failing the way a cut one does.
			whole := c.tg()
			whole.desktop = "whole-" + c.name
			tg := startTarget(t, whole)
			_, addr := gateway(t, tg, "        security_types: [none]\n"+c.extra)
			if si := dial(t, addr).open(true); si.Name != whole.desktop {
				t.Fatalf("the uncut desktop answered %q", si.Name)
			}
			for _, cut := range c.cuts {
				t.Run(name(cut), func(t *testing.T) {
					cv := c.tg()
					cv.cutAfter = cut
					tg := startTarget(t, cv)
					s, addr := gateway(t, tg, "        security_types: [none]\n"+c.extra)
					clientLegUpTo(t, addr)
					ended(t, func() int64 { return s.Stats().VNCSessionsOpen })
				})
			}
		})
	}
}
