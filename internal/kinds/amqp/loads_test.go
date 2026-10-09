package amqp

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// What this listener refuses to start with, and what a refusal writes down.
//
// The first half is the configurations that cannot work. A broker relay that
// started anyway would be one that looks healthy and protects nothing, which
// is worse than one that did not start: an operator watching a deploy sees a
// failure, and nobody watches a listener that came up.

func TestTheConfigurationsTheBrokerRelayWillNotStartWith(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	for _, tc := range []struct {
		name, section, want string
	}{
		// require_tls with nothing to offer: every client would be refused
		// for the one thing it cannot fix.
		// Caught by validation, which says it better than the listener's own
		// guard behind it: AMQP has no in-protocol upgrade, so the port is
		// either TLS or it is not, and there is nothing a client could do.
		{name: "require_tls with no certificate",
			section: "        upstream: br\n        require_tls: true\n",
			want:    "the listener has no tls section"},
		// An upstream TLS block naming a CA file that is not there. The
		// error names upstream_tls, because a certificate problem at the
		// other end reads exactly like one at this end until it is said.
		{name: "an upstream CA file that is not there",
			section: "        upstream: br\n        require_tls: false\n" +
				"        upstream_tls_mode: require\n" +
				"        upstream_tls: {ca_file: /nonexistent/ca.pem}\n",
			want: "upstream_tls"},
		// The mode vocabulary, because a value that looks right and is not
		// would otherwise be a listener talking in the clear to a broker
		// somebody thought was protected.
		{name: "an upstream TLS mode nothing defines",
			section: "        upstream: br\n        require_tls: false\n" +
				"        upstream_tls_mode: tls\n",
			want: "is not require, prefer or disable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := proxytest.StartError(t, fmt.Sprintf(amqpYAML, tc.section, b.addr()))
			if err == nil {
				t.Fatal("started")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want one about %q", err, tc.want)
			}
		})
	}
}

// A rate limit with no burst beside it takes the limit as its burst, which
// is the reading that makes `rate_limit: 10` mean what an operator writing it
// means -- ten a second, not ten a second after a burst of nothing. The bound
// is per request rather than per connection, so a login spends from it.
func TestARateLimitWithNoBurstTakesTheLimitAsItsBurst(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := relayFor(t, base+"        rate_limit: 1\n", b.addr())

	// The login spends from the bound, so the handshake is driven by hand
	// rather than through the helper, which fails the test on a close.
	cl := dial091(t, addr)
	cl.expect("connection.start")
	cl.send(wire.ClassConnection, 11, 0, emptyTable(), sstr("PLAIN"),
		lstr([]byte("\x00orders\x00secret")), sstr("en_US"))
	cl.send(wire.ClassConnection, 31, 0, u16(2047), u32(131072), u16(60))
	cl.send(wire.ClassConnection, 40, 0, sstr("/"), sstr(""), bitsOf(false))
	awaitAMQP(t, s, "the rate limit", func(sn proxy.Snapshot) bool {
		return sn.Refusals["amqp"]["rate_limited"] >= 1
	})
}

// A client outside allow_clients is refused before the handshake, which is
// the cheapest refusal this listener makes: no AMQP exchange at all.
func TestAClientOutsideTheListNeverHandshakes(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := relayFor(t, base+"        allow_clients: [10.0.0.0/8]\n", b.addr())

	cl := dial091(t, addr)
	_ = cl.closed()
	awaitAMQP(t, s, "the refusal", func(sn proxy.Snapshot) bool {
		return sn.Refusals["amqp"]["client_not_allowed"] >= 1
	})
	if b.got("connection.open") {
		t.Error("the client reached the broker")
	}
}

// What a refusal writes down.
//
// The event is the product of this listener: a relay that refused a
// queue.delete and said only "amqp_topology_not_allowed" would leave an
// operator to work out which client, which user and which queue. So the
// attributes are asserted, not just the counter.
func TestARefusalNamesTheClientTheUserAndWhatWasRefused(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := relayFor(t, base, b.addr())
	cap := &amqpEvents{}
	s.Logs().Watch(cap)

	cl := dial091(t, addr)
	cl.handshake("orders", "/production")
	cl.send(wire.ClassQueue, 40, 1, u16(0), sstr("work"), bitsOf(false, false, false))
	_ = cl.closed()

	ev := cap.find(t, "amqp_topology_not_allowed")
	for _, want := range []struct{ key, value string }{
		{"proto", "amqp"},
		{"client_ip", "127.0.0.1"},
		{"amqp_user", "orders"},
		{"vhost", "/production"},
	} {
		if got := fmt.Sprint(ev.attrs[want.key]); got != want.value {
			t.Errorf("%s is %q, want %q", want.key, got, want.value)
		}
	}
	// what says which method, which is the field that turns the event into a
	// sentence somebody can act on.
	if got := fmt.Sprint(ev.attrs["what"]); !strings.Contains(got, "queue.delete") {
		t.Errorf("what is %q, want the method", got)
	}
	if _, ok := ev.attrs["secure"]; !ok {
		t.Error("the event does not say whether the connection was secure")
	}
	if _, ok := ev.attrs["authed"]; !ok {
		t.Error("the event does not say whether the client had logged in")
	}
}

// In shadow mode the same refusal is counted apart and the method goes
// through. The two tables are kept separate on purpose: an operator reading
// the refusal count of a listener being trialled would otherwise see
// enforcement that is not happening.
func TestAShadowListenerCountsTheRefusalApartAndForwards(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
policy: {mode: shadow}
server:
  listeners:
    - name: broker
      address: "127.0.0.1:0"
      kind: amqp
      amqp:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: br, endpoints: [{address: %q}]}
`, base+"        allow_exchanges: [orders]\n", b.addr()))
	addr := proxytest.Addr(t, s, "broker")

	cl := dial091(t, addr)
	cl.handshake("orders", "/")
	// A publish to an exchange the policy does not list. That refusal is
	// soft, which is what shadow mode is for -- the hard ones (a topology
	// change, a denied vhost) stand whatever the mode, because a listener
	// that forwarded a queue.delete so it could be written down would have
	// deleted the queue.
	cl.send(wire.ClassBasic, 40, 1, u16(0), sstr("payments"), sstr("k"),
		bitsOf(false, false))

	awaitAMQP(t, s, "the shadow record", func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["amqp"]["exchange_not_allowed"] >= 1
	})
	if n := s.Stats().Refusals["amqp"]["exchange_not_allowed"]; n != 0 {
		t.Errorf("a shadow listener counted %d real refusals", n)
	}
}

// awaitAMQP waits for a counter condition.
func awaitAMQP(t *testing.T, s *proxy.Server, what string, ok func(proxy.Snapshot) bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s never happened; refusals %v, would-refuse %v", what,
		s.Stats().Refusals["amqp"], s.Stats().WouldRefusals["amqp"])
}

// amqpEvents collects the security log.
type amqpEvents struct {
	mu     sync.Mutex
	events []amqpEvent
}

type amqpEvent struct {
	action, reason string
	attrs          map[string]any
}

func (c *amqpEvents) SecurityEvent(action, reason string, attrs []any) {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	c.mu.Lock()
	c.events = append(c.events, amqpEvent{action: action, reason: reason, attrs: m})
	c.mu.Unlock()
}

func (c *amqpEvents) find(t *testing.T, reason string) amqpEvent {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		c.mu.Lock()
		for _, e := range c.events {
			if e.reason == reason {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("no %s event; saw %+v", reason, c.events)
	return amqpEvent{}
}

func (c *amqpEvents) seen(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.reason == reason {
			return true
		}
	}
	return false
}
