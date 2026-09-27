package http

import (
	"fmt"
	"testing"
)

// authzYAML is a gateway with two pools and the estate's authorisation policy
// over it. The policy names one pool and one network, which is the shape a rule
// on this kind takes: there is no identity here for it to decide about.
const authzYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging: {access: {enabled: false}}
upstreams:
  - {name: public, endpoints: [{address: "%s"}]}
  - {name: internal, endpoints: [{address: "%s"}]}
routes:
  - {name: pub, paths: [/pub], upstream: public}
  - {name: int, paths: [/int], upstream: internal}
%s
`

// The estate's policy decides which pool a client may reach, above the route.
//
// This is what the HTTP gateway had no way to be told. A route decides what may be
// done with it; the authz filter decides what a verified identity may do with one
// request; neither can say "this network reaches the public pool and not the
// internal one", because a route is one of the things being decided about and the
// filter needs an identity the client has not offered.
//
// The rule names a target, which is why the question is asked after routing: before
// it there is no pool for targets to name.
func TestThePolicyDecidesWhichPoolAClientMayReach(t *testing.T) {
	pub, in := newBackend(t, "public"), newBackend(t, "internal")
	s, base := startServer(t, fmt.Sprintf(authzYAML, pub.addr(), in.addr(), `authorization:
  rules:
    - {name: loopback-to-public, allow: true, networks: ["127.0.0.0/8"], targets: [public]}`))

	if resp, _ := get(t, base+"/pub"); resp.StatusCode != 200 {
		t.Errorf("the allowed pool answered %d, want 200", resp.StatusCode)
	}
	// The same client, the same listener, a pool no rule covers.
	resp, _ := get(t, base+"/int")
	if resp.StatusCode != 403 {
		t.Errorf("a pool no rule covers answered %d, want 403", resp.StatusCode)
	}
	if n := in.hits.Load(); n != 0 {
		t.Errorf("the internal backend saw %d requests from a refused client", n)
	}
	if n := s.Stats().Refusals["http"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["http"])
	}
}

// A refusal is a 403 rather than a dropped connection, because a client library
// reports a status and hangs on a socket that went away -- and because on this kind
// there is a response to write, which is the whole reason the section is asked here
// rather than at the accept.
func TestARefusedRequestIsAnsweredRatherThanDropped(t *testing.T) {
	pub, in := newBackend(t, "public"), newBackend(t, "internal")
	_, base := startServer(t, fmt.Sprintf(authzYAML, pub.addr(), in.addr(), `authorization:
  rules:
    - {name: nowhere, allow: true, networks: ["10.0.0.0/8"]}`))

	resp, body := get(t, base+"/pub")
	if resp.StatusCode != 403 {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if body == "" {
		t.Error("a refusal with no body: a client library has nothing to report")
	}
}

// A rule naming users matches nobody here, and the reference says so. The gateway
// does establish identities, but per route and in the filter chain, and the authz
// filter is what decides what one may do -- so the section deciding on a user as
// well would be two answers to one question.
//
// The consequence is worth a test rather than a sentence: a policy written only
// about people refuses every request on this kind, fail-closed, exactly as it does
// on a Modbus or syslog listener.
func TestARuleAboutPeopleMatchesNobodyOnTheGateway(t *testing.T) {
	pub, in := newBackend(t, "public"), newBackend(t, "internal")
	_, base := startServer(t, fmt.Sprintf(authzYAML, pub.addr(), in.addr(), `authorization:
  rules:
    - {name: staff, allow: true, users: [alice]}`))

	if resp, _ := get(t, base+"/pub"); resp.StatusCode != 403 {
		t.Errorf("a policy written only about people answered %d on a gateway with "+
			"no identity at this point, want 403", resp.StatusCode)
	}
}

// Shadow mode records and carries, on this kind as on every other. A gateway is
// where an operator is least willing to guess, so the trial has to work here.
func TestShadowModeCarriesTheRequestOnTheGateway(t *testing.T) {
	pub, in := newBackend(t, "public"), newBackend(t, "internal")
	s, base := startServer(t, fmt.Sprintf(authzYAML, pub.addr(), in.addr(), `authorization:
  shadow: true
  rules:
    - {name: nowhere, allow: true, networks: ["10.0.0.0/8"]}`))

	if resp, _ := get(t, base+"/pub"); resp.StatusCode != 200 {
		t.Fatalf("a listener in shadow mode answered %d, want the request carried", resp.StatusCode)
	}
	st := s.Stats()
	if n := st.Refusals["http"]["authorization"]; n != 0 {
		t.Errorf("shadow mode counted %d refusals it did not make", n)
	}
	if n := st.WouldRefusals["http"]["authorization"]; n != 1 {
		t.Errorf("would-refusals %d, want 1: %v", n, st.WouldRefusals["http"])
	}
}

// The listener's own shadow switch, which is a different switch from the section's
// and has to work on this kind too.
//
// It gets its own test because the section switch above cannot stand in for it:
// four relays were found reading only their own monitor_only and never
// config.Listener.Shadowing(), so an operator who trialled those policies the way
// the reference documents got enforcement. A mutation that ignored this switch on
// the gateway survived the section test, which is exactly how those four went
// unnoticed.
func TestTheListenersOwnShadowSwitchCarriesTheRequest(t *testing.T) {
	pub, in := newBackend(t, "public"), newBackend(t, "internal")
	yaml := `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0", policy: {mode: shadow}}
trusted_proxies: [127.0.0.0/8]
logging: {access: {enabled: false}}
upstreams:
  - {name: public, endpoints: [{address: "%s"}]}
  - {name: internal, endpoints: [{address: "%s"}]}
routes:
  - {name: pub, paths: [/pub], upstream: public}
  - {name: int, paths: [/int], upstream: internal}
authorization:
  rules:
    - {name: nowhere, allow: true, networks: ["10.0.0.0/8"]}
`
	s, base := startServer(t, fmt.Sprintf(yaml, pub.addr(), in.addr()))

	if resp, _ := get(t, base+"/pub"); resp.StatusCode != 200 {
		t.Fatalf("a listener in policy: {mode: shadow} answered %d, want the "+
			"request carried", resp.StatusCode)
	}
	st := s.Stats()
	if n := st.Refusals["http"]["authorization"]; n != 0 {
		t.Errorf("a listener in shadow mode counted %d refusals it did not make", n)
	}
	if n := st.WouldRefusals["http"]["authorization"]; n != 1 {
		t.Errorf("would-refusals %d, want 1: %v", n, st.WouldRefusals["http"])
	}
}

// And a gateway with no section is a gateway that pays nothing: the question
// returns before it looks at anything, which is what makes a per-request ask
// acceptable on the busiest kind here.
func TestNoSectionIsNoDecision(t *testing.T) {
	pub, in := newBackend(t, "public"), newBackend(t, "internal")
	s, base := startServer(t, fmt.Sprintf(authzYAML, pub.addr(), in.addr(), ""))

	if resp, _ := get(t, base+"/int"); resp.StatusCode != 200 {
		t.Fatalf("status %d without a policy, want 200", resp.StatusCode)
	}
	if s.Stats().Authz != nil {
		t.Error("a gateway with no authorization section reported a policy summary")
	}
}
