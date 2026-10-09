package radius

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/radius"
)

// The behavioural models, the request log, and the bound on a datagram.
//
// What an estate's RADIUS traffic looks like is unusually stable: the clients
// are a list written once and changed by a change request, each one
// authenticates the same way every day, and the realms are fixed. That makes
// novelty worth acting on here in a way it is not on a protocol anybody can
// speak -- a new address authenticating against the directory is worth a line
// in a log whatever the address lists say.

// relayTop is relay() with a section at the top of the file as well, for the
// estate-wide settings the radius section does not carry.
func relayTop(t *testing.T, section, listener, top, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: auth
      address: "127.0.0.1:0"
      kind: radius
%s
      radius:
        upstream: servers
        secret_file: %q
%s
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, listener, secretFile(t, theSecret), section, top, serverAddr))
	return s, proxytest.Addr(t, s, "auth")
}

func awaitReason(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if refusals(s, reason) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["radius"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The novelty models report and the request is still carried: a client that
// has not been seen before is novel, and so is the one that was quiet over a
// long weekend.
func TestTheModelsNoticeTheClientTheMethodAndTheRealm(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, `        default_action: allow
        log_requests: true
        anomaly:
          enabled: true
          settle: 0s
          talkers: {enabled: true, ready_after: 1s}
`, "", srv.addr())

	c := dial(t, addr)
	if rep := c.send(request(1, "alice@corp.example", true,
		attr(wire.AttrNASIdentifier, []byte("switch-3")...))); rep == nil {
		t.Fatal("a request with the models on got no answer")
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(s.Stats().Refusals["radius"]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the models reported nothing with settle: 0s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The request reached the server: a behavioural finding on this kind is a
	// signal, not a refusal.
	if seen := srv.requests(); len(seen) == 0 {
		t.Error("the request the models reported on did not reach the server")
	}
}

// With the alerts turned off the finding is still counted. An estate that has
// turned the record down has said it reads the counters; it has not said to
// stop noticing.
func TestAFindingIsCountedWithTheAlertsOff(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, `        default_action: allow
        alert_on_deny: false
        anomaly: {enabled: true, settle: 0s}
`, "", srv.addr())
	c := dial(t, addr)
	c.send(request(2, "bob@corp.example", true))
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(s.Stats().Refusals["radius"]) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the finding was not counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// In shadow mode a model told to refuse says what it would have done and the
// request is carried. That is how a behavioural policy is turned on in front
// of an estate's own authentication: a model that has not settled refuses the
// traffic the estate runs on, so the report is read for a week first.
func TestInShadowModeTheModelsSayWhatTheyWouldHaveRefused(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relayTop(t, `        default_action: allow
        anomaly: {enabled: true, settle: 0s, action: deny}
`, "      policy: {mode: shadow}", "", srv.addr())
	c := dial(t, addr)
	if rep := c.send(request(3, "carol@corp.example", true)); rep == nil {
		t.Fatal("shadow mode refused the request")
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(s.Stats().WouldRefusals["radius"]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the would-be refusal was not recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rep := s.Shadow().Report()
	if len(rep) == 0 {
		t.Fatal("the shadow report is empty")
	}
	for _, e := range rep {
		if e.Kind != "radius" || e.Listener != "auth" {
			t.Errorf("the shadow report: %+v", e)
		}
	}
}

// What the access log carries about a request and about the answer, and where
// a refusal goes besides the counter.
//
// The two lines are the audit trail of an estate's authentication: the request
// line says who asked for what and how, and the reply line says what was
// granted, which is the half that matters when a privilege level is being
// argued about afterwards.
func TestTheRequestAndTheReplyAreBothLogged(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true, reply: func(p *wire.Packet) (wire.Code, [][]byte) {
		return wire.CodeAccessAccept, [][]byte{
			attr(wire.AttrServiceType, 0, 0, 0, 6), // administrative
			vsa(9, 1, []byte("priv-lvl=15")...),    // Cisco AV pair
		}
	}})
	s, addr := relayTop(t, `        default_action: allow
        log_requests: true
        max_privilege_level: 15
        realms: [corp.example]
`, "", "bans:\n  action: reject\n  state_file: "+
		filepath.Join(t.TempDir(), "bans.state"), srv.addr())

	c := dial(t, addr)
	rep := c.send(request(4, "dave@corp.example", true,
		attr(wire.AttrNASIdentifier, []byte("switch-7")...),
		attr(wire.AttrUserPassword, make([]byte, 16)...)))
	if rep == nil || rep.Code != wire.CodeAccessAccept {
		t.Fatalf("the answer: %+v", rep)
	}

	// And a request from a realm the listener does not carry is refused, with
	// the refusal reaching the ban ladder.
	if got := c.send(request(5, "eve@elsewhere.example", true)); got == nil ||
		got.Code != wire.CodeAccessReject {
		t.Fatalf("a request from a realm off the list: %+v", got)
	}
	awaitReason(t, s, "realm_not_allowed")
}

// A datagram over the bound is refused unread. Reading it to find out what it
// asked for is the work the bound exists to avoid, and on a protocol carried
// over UDP the length in the header is whatever the sender wrote.
func TestADatagramOverTheBoundIsRefusedUnread(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, "        default_action: allow\n        max_message_bytes: 512\n",
		"", srv.addr())
	c := dial(t, addr)
	big := request(6, "frank@corp.example", true,
		attr(wire.AttrReplyMessage, make([]byte, 200)...),
		attr(wire.AttrReplyMessage, make([]byte, 200)...),
		attr(wire.AttrReplyMessage, make([]byte, 200)...))
	if rep := c.send(big); rep != nil {
		t.Errorf("an oversize datagram was answered: %+v", rep)
	}
	awaitReason(t, s, "message_too_large")
	if seen := srv.requests(); len(seen) != 0 {
		t.Errorf("the oversize datagram reached the server: %d", len(seen))
	}
}

// What the listener refuses to load with. A shared secret is the whole of this
// protocol's security, so a file that is not a secret has to stop the start
// rather than leave a relay running with one nobody set.
func TestWhatTheListenerRefusesToLoadWith(t *testing.T) {
	dir := t.TempDir()
	// A file holding nothing but a line ending, which is what an operator
	// who meant to paste a secret and did not leaves behind.
	empty := filepath.Join(dir, "empty.secret")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, &fakeServer{})
	for _, tc := range []struct{ name, section, secret, want string }{
		{"a secret file with nothing in it", "", empty, "is empty"},
		{"an upstream secret that is not there",
			"        upstream_secret_file: " + filepath.Join(dir, "never-written") + "\n",
			secretFile(t, theSecret), "upstream_secret_file"},
	} {
		yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: auth
      address: "127.0.0.1:0"
      kind: radius
      radius:
        upstream: servers
        secret_file: %q
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, tc.secret, tc.section, srv.addr())
		err := proxytest.StartError(t, yaml)
		if err == nil {
			t.Errorf("%s: loaded", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say what was wrong", tc.name, err)
		}
	}
}

// The per-client request rate, which is this protocol's amplification and
// flood control: a RADIUS server answers every request it is sent, so a relay
// with no bound is a relay that will reflect a flood at the directory an
// estate logs in with.
func TestTheRequestRateIsBoundedPerClient(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, `        default_action: allow
        rate_limit: 1
`, "", srv.addr())
	c := dial(t, addr)
	for i := range 6 {
		c.send(request(uint8(10+i), "grace@corp.example", true))
	}
	awaitReason(t, s, "rate_limited")
}
