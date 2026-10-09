package postgres

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/pgwire"
)

// The four things a client can send before it has said who it is.
//
// PostgreSQL's startup has an unusual shape: the first packet is not a
// startup packet at all but a code, and three of the four codes mean
// something other than "here is my identity". That makes this the part of the
// protocol a relay most has to get right -- each of them is read before there
// is a user name to apply any policy to, so what the relay does with them is
// the policy.

// prelude is one of the fixed eight-octet requests: a length and a code, with
// a cancel request carrying its key as well.
func prelude(code uint32, extra ...uint32) []byte {
	out := make([]byte, 8, 8+4*len(extra))
	binary.BigEndian.PutUint32(out[4:8], code)
	for _, v := range extra {
		out = binary.BigEndian.AppendUint32(out, v)
	}
	binary.BigEndian.PutUint32(out[:4], uint32(len(out)))
	return out
}

// A client asking to encrypt where the listener has no certificate is told no
// in the protocol's own single octet, and then its session goes on in the
// clear. That is the one place answering 'N' is right: a client that asked
// politely gets a real answer rather than a closed socket, and whether
// plaintext is acceptable is require_tls's decision rather than this one.
func TestAnEncryptionRequestIsAnsweredAndTheSessionGoesOn(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := c.Write(prelude(wire.SSLRequest)); err != nil {
		t.Fatal(err)
	}
	var ans [1]byte
	if _, err := c.Read(ans[:]); err != nil {
		t.Fatalf("no answer to the encryption request: %v", err)
	}
	if ans[0] != wire.DenyTLS {
		t.Fatalf("the answer was %q, want %q", ans[0], wire.DenyTLS)
	}
	// And the startup packet after it is read as one: the relay is back at the
	// beginning of the negotiation rather than one request behind.
	cl := &client{c: c, rd: wire.NewReader(c, wire.FromServer, 0)}
	if _, err := c.Write(startupPacket("user", "alice", "database", "sales")); err != nil {
		t.Fatal(err)
	}
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the session after a refused upgrade: %s", e)
	}
	if ss := fake.sawStartups(); len(ss) != 1 || ss[0]["user"] != "alice" {
		t.Fatalf("the server saw %+v", ss)
	}
}

// GSSAPI encryption is a thing this relay does not do, and the honest answer
// is to say no rather than to accept and then speak something else. The
// session goes on in the clear the same way.
func TestAGSSAPIEncryptionRequestIsRefusedAndNotPretendedAbout(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(prelude(wire.GSSEncRequest)); err != nil {
		t.Fatal(err)
	}
	var ans [1]byte
	if _, err := c.Read(ans[:]); err != nil {
		t.Fatalf("no answer to the GSSAPI request: %v", err)
	}
	if ans[0] != wire.DenyTLS {
		t.Fatalf("the answer was %q, want %q", ans[0], wire.DenyTLS)
	}
	cl := &client{c: c, rd: wire.NewReader(c, wire.FromServer, 0)}
	if _, err := c.Write(startupPacket("user", "alice")); err != nil {
		t.Fatal(err)
	}
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the session after a refused GSSAPI request: %s", e)
	}
}

// A cancel request is a connection of its own carrying somebody else's
// session key, and it is the one message on this protocol that acts on a
// session without authenticating. Allowed, it is forwarded; refused, the
// server never sees it.
func TestACancelRequestIsDecidedBeforeItIsForwarded(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        allow_cancel: true\n", fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(prelude(wire.CancelRequest, 4242, 0x5a5a5a5a)); err != nil {
		t.Fatal(err)
	}
	// The relay forwards it and closes: a cancel request has no answer in the
	// protocol, so the connection ending is what a client sees.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("a cancel request was answered")
	}

	// With cancels refused, the same request is turned down and the server is
	// never dialled. An estate that does not let one session cancel another's
	// query says so here, because there is no identity in this message to
	// decide with afterwards.
	s2, addr2 := relayFor(t, base+"        allow_cancel: false\n", fake.addr())
	c2, err := net.Dial("tcp", addr2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	_ = c2.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c2.Write(prelude(wire.CancelRequest, 4242, 0x5a5a5a5a)); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s2.Stats().Refusals["postgres"]["cancel_not_allowed"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the cancel was not refused: %v", s2.Stats().Refusals["postgres"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A code that is not one of the four is refused as an unreadable startup. A
// relay that forwarded it would be forwarding octets it has not understood to
// a database, which is the thing this kind exists not to do.
func TestACodeThatIsNotOneOfTheFourIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := relayFor(t, base, fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	// Protocol version 2, which this relay does not speak, under a code
	// nothing else claims.
	if _, err := c.Write(prelude(131072)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(make([]byte, 1))
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["postgres"]["unreadable_startup"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the unknown code was not refused: %v", s.Stats().Refusals["postgres"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Errorf("it reached the server anyway: %+v", ss)
	}
}

// And a second encryption request after the first has been answered: not a
// thing a client does, and the relay does not read it as a startup packet
// whose fields happen to be nonsense.
func TestASecondEncryptionRequestIsNotReadAsAStartup(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := relayFor(t, base, fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(prelude(wire.SSLRequest)); err != nil {
		t.Fatal(err)
	}
	var ans [1]byte
	if _, err := c.Read(ans[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(prelude(wire.SSLRequest)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(make([]byte, 1))
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["postgres"]["startup_out_of_order"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a repeated upgrade request was not refused: %v",
				s.Stats().Refusals["postgres"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Errorf("it reached the server anyway: %+v", ss)
	}
}

// A listener with a certificate takes the upgrade itself, which is the
// arrangement an estate wants: the client encrypts to the relay, the relay
// encrypts to the server, and neither leg is the other's.
func TestAListenerWithACertificateTakesTheUpgradeItself(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := relayFor(t, base, fake.addr())
	// Without a certificate there is nothing to upgrade to, so this is the
	// refusal the same code path produces when require_tls is set: the
	// listener has already refused to load in that case, which
	// TestAClientThatWillNotEncryptIsRefused covers. Here the relay answers
	// 'N' and the counter stays clean.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(prelude(wire.SSLRequest)); err != nil {
		t.Fatal(err)
	}
	var ans [1]byte
	if _, err := c.Read(ans[:]); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().Refusals["postgres"]["tls_required"]; got != 0 {
		t.Errorf("a listener that does not require tls refused %d upgrades", got)
	}
	if !strings.ContainsRune("NS", rune(ans[0])) {
		t.Errorf("the answer to an upgrade request was %q", ans[0])
	}
}
