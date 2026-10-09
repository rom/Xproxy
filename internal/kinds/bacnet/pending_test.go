package bacnet

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func clientAt(port int) net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

func exch(port int, clientID uint8, device string) *exchange {
	return &exchange{client: netip.MustParseAddr("127.0.0.1"), from: clientAt(port),
		device: device, clientID: clientID, service: "readProperty"}
}

// The invoke-identifier table, which is what keeps two clients' answers
// apart on a protocol where the only thing tying an answer to a request
// is one octet.
//
// There are two hundred and fifty-six identifiers and no handshake. The
// table has to refuse rather than reuse when they run out -- reusing one
// would deliver somebody else's answer to whoever holds it now -- and it
// has to refuse an answer that carries the right identifier from the
// wrong device, which on a datagram protocol is the shape of an answer
// somebody else sent first.
func TestTheInvokeIdentifierTableNeverReusesOrMisdelivers(t *testing.T) {
	now := time.Now()
	p := newPending(8, 2, time.Minute)

	id, ok := p.add(exch(5000, 1, "10.0.0.9:47808"), now)
	if !ok {
		t.Fatal("the first exchange was refused")
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("outstanding = %d, want 1", n)
	}

	// An answer carrying the right identifier from an address this
	// exchange was never sent to is not this exchange's answer.
	if got, expired := p.take(id, "10.0.0.99:47808", true, now); got != nil || expired {
		t.Error("an answer from the wrong device was matched to the exchange")
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("the exchange was forgotten anyway: %d", n)
	}

	// A segment, which keeps the exchange and renews its deadline: a
	// segmented reply is one exchange however many datagrams it takes.
	if got, _ := p.take(id, "10.0.0.9:47808", false, now.Add(time.Second)); got == nil {
		t.Fatal("a segment did not match the exchange")
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("a segment ended the exchange: %d", n)
	}
	// And the last segment ends it.
	if got, expired := p.take(id, "10.0.0.9:47808", true, now.Add(2*time.Second)); got == nil || expired {
		t.Error("the last segment did not end the exchange")
	}
	if n := p.outstanding(); n != 0 {
		t.Errorf("outstanding = %d after the answer", n)
	}

	// The same client reusing its own identifier while one is
	// outstanding: the old exchange is the one that is over, and both
	// entries for it go, or the table keeps a row nothing will take.
	first, _ := p.add(exch(5000, 7, "10.0.0.9:47808"), now)
	second, ok := p.add(exch(5000, 7, "10.0.0.9:47808"), now)
	if !ok || second == first {
		t.Fatalf("the retransmission got %d, the first had %d", second, first)
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("both exchanges are outstanding: %d", n)
	}
	if got, _ := p.take(first, "10.0.0.9:47808", true, now); got != nil {
		t.Error("the replaced exchange is still in the table")
	}

	// The client knows the exchange by the identifier it chose, which is
	// what a segment acknowledgement travelling the other way carries, so
	// that direction has to be translated too.
	if mine, ok := p.translate(clientAt(5000), 7, now); !ok || mine != second {
		t.Errorf("translate got %d, %v, want %d", mine, ok, second)
	}
	if _, ok := p.translate(clientAt(5000), 8, now); ok {
		t.Error("an identifier nobody is waiting on was translated")
	}
	if _, ok := p.translate(clientAt(5000), 7, now.Add(2*time.Minute)); ok {
		t.Error("an exchange past its deadline was translated")
	}
	if got, _ := p.take(second, "10.0.0.9:47808", true, now); got == nil {
		t.Error("the retransmission's own answer did not match it")
	}
	if n := p.outstanding(); n != 0 {
		t.Errorf("outstanding = %d after both exchanges ended", n)
	}

	// An answer nobody waited for, after the exchange expired: the
	// expired flag is what tells "somebody asked and stopped waiting"
	// from "nobody asked this", which are different events.
	late, _ := p.add(exch(5001, 3, "10.0.0.9:47808"), now)
	got, expired := p.take(late, "10.0.0.9:47808", true, now.Add(2*time.Minute))
	if got == nil || !expired {
		t.Errorf("a late answer: %+v, expired %v", got, expired)
	}

	// A request that never left releases its identifier.
	dropped, _ := p.add(exch(5002, 4, "10.0.0.9:47808"), now)
	p.drop(dropped)
	if n := p.outstanding(); n != 0 {
		t.Errorf("drop left %d outstanding", n)
	}
	p.drop(dropped) // and again, which is not an error
}

// The table is bounded, and the bound is a refusal.
//
// A listener with every identifier outstanding is a listener whose
// devices are not answering; allocating anyway would mean reuse, and
// reuse on this protocol is a misdelivered answer.
func TestTheInvokeIdentifierTableRefusesRatherThanReuse(t *testing.T) {
	now := time.Now()
	small := newPending(1, 1, time.Minute)
	if _, ok := small.add(exch(6000, 1, "10.0.0.9:47808"), now); !ok {
		t.Fatal("the first exchange was refused")
	}
	if _, ok := small.add(exch(6001, 2, "10.0.0.9:47808"), now); ok {
		t.Error("an exchange past the bound was allocated an identifier")
	}

	// With room for more than the identifier space, the search skips the
	// ones in use rather than handing out a duplicate.
	wide := newPending(300, 1, time.Minute)
	ids := map[uint8]bool{}
	for i := 0; i < 255; i++ {
		id, ok := wide.add(exch(7000+i, uint8(i), "10.0.0.9:47808"), now)
		if !ok {
			t.Fatalf("exchange %d was refused", i)
		}
		if ids[id] {
			t.Fatalf("identifier %d was handed out twice", id)
		}
		ids[id] = true
	}
	// The next allocation wraps the search onto identifiers that are in
	// use and has to walk past them.
	if id, ok := wide.add(exch(7999, 200, "10.0.0.9:47808"), now); !ok || ids[id] {
		t.Errorf("the wrapped search gave %d, ok %v", id, ok)
	}
}

// The broadcast budget, which is this protocol's amplification bound: a
// Who-Is is one datagram and every device on the network answers it.
func TestTheBroadcastBudgetIsSpentAndBounded(t *testing.T) {
	now := time.Now()
	p := newPending(8, 2, time.Minute)
	if !p.addBroadcast(&broadcast{from: clientAt(8000), left: 2, deadline: now.Add(time.Minute)}, now) {
		t.Fatal("the first broadcast was refused")
	}
	if !p.addBroadcast(&broadcast{from: clientAt(8001), left: 1, deadline: now.Add(time.Minute)}, now) {
		t.Fatal("the second broadcast was refused")
	}
	// The third is past the bound: a client cannot fill this table by
	// broadcasting.
	if p.addBroadcast(&broadcast{from: clientAt(8002), left: 1, deadline: now.Add(time.Minute)}, now) {
		t.Error("a broadcast past the bound was recorded")
	}

	// Each answer spends one reply from each waiting client, and a client
	// whose budget is gone is dropped rather than looked at again.
	if got := p.broadcastTargets(now); len(got) != 2 {
		t.Fatalf("the first answer reached %d clients", len(got))
	}
	if got := p.broadcastTargets(now); len(got) != 1 {
		t.Fatalf("the second answer reached %d clients, want only the one with budget left", len(got))
	}
	if got := p.broadcastTargets(now); len(got) != 0 {
		t.Errorf("a third answer reached %d clients", len(got))
	}

	// And a broadcast whose window has passed is forgotten.
	p.addBroadcast(&broadcast{from: clientAt(8003), left: 5, deadline: now.Add(time.Second)}, now)
	if got := p.broadcastTargets(now.Add(2 * time.Second)); len(got) != 0 {
		t.Errorf("an expired broadcast still took answers: %d", len(got))
	}
}

// Every list in a bacnet section that can hold a name this build does
// not know, refused at compile with the field named.
//
// These are the lists a policy is written in, so a name nobody checked
// would be a rule that quietly covers nothing -- and on this protocol
// that is a write nobody refused.
func TestEveryBACnetListIsCheckedAtCompile(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   *config.BACnetListener
		says string
	}{
		{"deny_clients", &config.BACnetListener{Upstream: "d", DenyClients: []string{"not a cidr"}}, "deny_clients"},
		{"objects", &config.BACnetListener{Upstream: "d", Objects: []string{"not-an-object"}}, "objects"},
		{"deny_objects", &config.BACnetListener{Upstream: "d", DenyObjects: []string{"not-an-object"}}, "deny_objects"},
		{"properties", &config.BACnetListener{Upstream: "d", Properties: []string{"not-a-property"}}, "properties"},
		{"deny_properties", &config.BACnetListener{Upstream: "d", DenyProperties: []string{"not-a-property"}}, "deny_properties"},
		{"services", &config.BACnetListener{Upstream: "d", Services: []string{"notAService"}}, "services"},
		{"deny_services", &config.BACnetListener{Upstream: "d", DenyServices: []string{"notAService"}}, "deny_services"},
		{
			"a rule's own lists",
			&config.BACnetListener{Upstream: "d", Rules: []config.BACnetRule{
				{Name: "r", Action: "allow", Services: []string{"notAService"}},
			}},
			"services",
		},
	} {
		_, err := compile(tc.in)
		if err == nil {
			t.Errorf("%s: compiled", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: error %v, want it to name the field", tc.name, err)
		}
	}
}
