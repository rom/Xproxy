package radius

import (
	"net"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/radius"
)

// The table that pairs an answer with its question, on a protocol that
// gives a relay eight bits to pair with.
//
// It is worth its own test because the two modes are different security
// properties rather than two settings. With a secret the relay allocates an
// identifier of its own and translates it back, so two switches that both
// use identifier 7 cannot be confused; without one it forwards the client's
// own, and then the same pair is a collision it has to refuse rather than
// resolve -- because resolving it means delivering one switch's
// Access-Accept to the other.

func addr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func exch(t *testing.T, clientID uint8, server string) *exchange {
	t.Helper()
	return &exchange{client: from("10.0.0.5"), from: addr(t, "10.0.0.5:4000"),
		server: server, clientID: clientID, code: wire.CodeAccessRequest, user: "bob"}
}

// Without a secret the relay cannot re-sign, so it cannot translate, so the
// client's own identifier is what goes out -- and a second client using the
// same one at the same time is refused.
func TestWithoutASecretTheIdentifierIsTheClientsAndACollisionIsRefused(t *testing.T) {
	p := newPending(256, time.Minute, false)
	now := noon

	id, ok := p.add(exch(t, 7, "10.1.1.1:1812"), now)
	if !ok || id != 7 {
		t.Fatalf("add returned %d, %v, want the client's own identifier", id, ok)
	}
	if _, ok := p.add(exch(t, 7, "10.1.1.1:1812"), now); ok {
		t.Fatal("a second exchange took identifier 7 while the first was outstanding")
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("%d requests are outstanding, want 1", n)
	}
	// A different identifier is free, and the first one is free again once
	// its answer has been claimed.
	if _, ok := p.add(exch(t, 8, "10.1.1.1:1812"), now); !ok {
		t.Fatal("identifier 8 was refused while only 7 was outstanding")
	}
	if e, expired := p.take(7, "10.1.1.1:1812", now); e == nil || expired {
		t.Fatalf("take(7) returned %v, expired=%v", e, expired)
	}
	if _, ok := p.add(exch(t, 7, "10.1.1.1:1812"), now); !ok {
		t.Fatal("identifier 7 was still held after its answer was claimed")
	}
}

// With a secret it allocates its own identifier, which is what keeps two
// switches using the same one apart.
func TestWithASecretTheRelayAllocatesItsOwnIdentifier(t *testing.T) {
	p := newPending(256, time.Minute, true)
	now := noon

	first := exch(t, 7, "10.1.1.1:1812")
	second := exch(t, 7, "10.1.1.1:1812")
	second.from = addr(t, "10.0.0.6:4000")
	a, ok := p.add(first, now)
	if !ok {
		t.Fatal("the first exchange was refused")
	}
	b, ok := p.add(second, now)
	if !ok {
		t.Fatal("the second exchange using the same client identifier was refused")
	}
	if a == b {
		t.Fatalf("both exchanges were given identifier %d, so one switch's answer goes to the other", a)
	}
	// And each one's answer comes back to its own exchange, with the
	// client's own identifier to put back on it.
	got, _ := p.take(b, "10.1.1.1:1812", now)
	if got != second {
		t.Fatal("the answer was paired with the wrong exchange")
	}
	if got.clientID != 7 {
		t.Errorf("the exchange remembers client identifier %d", got.clientID)
	}
}

// An answer carrying the right identifier from the wrong host is the shape
// of answer spoofing on a datagram protocol, and it is the one check that
// does not need the secret.
func TestAnAnswerFromTheWrongServerIsNotThisExchangesAnswer(t *testing.T) {
	p := newPending(256, time.Minute, true)
	id, _ := p.add(exch(t, 7, "10.1.1.1:1812"), noon)

	if e, _ := p.take(id, "10.9.9.9:1812", noon); e != nil {
		t.Fatal("an answer from another host claimed the exchange")
	}
	// And the exchange is still there for the server it was sent to, which
	// is what makes the check a refusal rather than a denial of the real
	// answer.
	if e, _ := p.take(id, "10.1.1.1:1812", noon); e == nil {
		t.Fatal("the real server's answer was lost with the spoofed one")
	}
	// An identifier nobody is waiting on is not an exchange either.
	if e, _ := p.take(200, "10.1.1.1:1812", noon); e != nil {
		t.Fatal("an unsolicited answer found an exchange")
	}
}

// An answer that arrives after the slot's lifetime is reported as late
// rather than silently carried: the client has given up and retried, and
// the retry has its own slot.
func TestALateAnswerIsClaimedAndReportedAsLate(t *testing.T) {
	p := newPending(256, time.Second, true)
	id, _ := p.add(exch(t, 7, "10.1.1.1:1812"), noon)

	e, expired := p.take(id, "10.1.1.1:1812", noon.Add(2*time.Second))
	if e == nil || !expired {
		t.Fatalf("take returned %v, expired=%v for an answer past the deadline", e, expired)
	}
}

// An exchange that has expired must not hold its identifier against the
// next request, so the scan runs on every add rather than on a timer.
func TestAnExpiredExchangeDoesNotHoldItsIdentifier(t *testing.T) {
	p := newPending(2, time.Second, true)
	first, _ := p.add(exch(t, 7, "10.1.1.1:1812"), noon)
	if _, ok := p.add(exch(t, 8, "10.1.1.1:1812"), noon); !ok {
		t.Fatal("the second of two slots was refused")
	}
	if _, ok := p.add(exch(t, 9, "10.1.1.1:1812"), noon); ok {
		t.Fatal("a third exchange was admitted against max_pending: 2")
	}
	// A minute later both have expired, and the next request is admitted
	// without anybody having swept the table.
	later := noon.Add(time.Minute)
	if _, ok := p.add(exch(t, 9, "10.1.1.1:1812"), later); !ok {
		t.Fatal("the expired exchanges still held their slots")
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("%d requests are outstanding after the expiry, want 1", n)
	}
	if e, _ := p.take(first, "10.1.1.1:1812", later); e != nil {
		t.Error("an expired exchange was still claimable")
	}
}

// Every identifier outstanding is a different fact from the table being
// full, and on a translating listener it is the one that says the servers
// have stopped answering.
func TestATranslatingListenerRunsOutOfIdentifiersBeforeItsBound(t *testing.T) {
	p := newPending(1000, time.Minute, true)
	for i := 0; i < 256; i++ {
		if _, ok := p.add(exch(t, uint8(i), "10.1.1.1:1812"), noon); !ok {
			t.Fatalf("exchange %d was refused below the identifier space", i)
		}
	}
	if n := p.outstanding(); n != 256 {
		t.Fatalf("%d requests are outstanding, want the whole identifier space", n)
	}
	if _, ok := p.add(exch(t, 0, "10.1.1.1:1812"), noon); ok {
		t.Fatal("a 257th exchange was given an identifier")
	}
}

// drop gives an identifier back for a request that never left, which is the
// path a refused forward takes: the slot was taken before the write and the
// write failed.
func TestDropGivesTheIdentifierBack(t *testing.T) {
	p := newPending(256, time.Minute, false)
	id, _ := p.add(exch(t, 7, "10.1.1.1:1812"), noon)
	p.drop(id)
	if n := p.outstanding(); n != 0 {
		t.Errorf("%d requests are outstanding after the drop", n)
	}
	if _, ok := p.add(exch(t, 7, "10.1.1.1:1812"), noon); !ok {
		t.Fatal("the dropped identifier was still held")
	}
}
