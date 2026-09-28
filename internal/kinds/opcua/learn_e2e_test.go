package opcua

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/proxy"
)

// Learning mode end to end: real traffic through the real engine, and the report
// that comes out of it.
//
// The assertions are about what the report *says*, because the report is the
// product. A learning mode that recorded perfectly and rendered a file nobody can
// adopt has done nothing, so every test here reads the YAML.

// learnRelay starts a listener learning into a file under the test's own directory
// and returns the server, its address and the report's path.
func learnRelay(t *testing.T, section string, up *fakeServer) (*proxy.Server, string, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "opcua-learn.yaml")
	s, addr := relayFor(t, section+
		"        learn:\n"+
		"          enabled: true\n"+
		"          file: "+file+"\n"+
		"          interval: 10s\n", up.addr())
	return s, addr, file
}

// report shuts the listener down, which is what writes the file, and hands back
// what it says. The client is closed first: shutdown waits for the connections it
// is relaying, and a test that left one open would wait out the whole bound.
func report(t *testing.T, s *proxy.Server, cl *client, file string) string {
	t.Helper()
	_ = cl.c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	return string(b)
}

// A run over ordinary traffic: the report names the identity, the node group and a
// rule that permits what was seen.
func TestALearningRunProposesWhatWasSeen(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:scada:hmi1", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "p", rsaOaep))
	// Two nodes under one prefix and one under another, so the grouping is
	// visible in the report rather than inferred from a single row.
	cl.service(wire.SvcRead, readBody(
		op("ns=4;s=Line1/Pump1/Speed", wire.AttrValue),
		op("ns=4;s=Line1/Pump1/Pressure", wire.AttrValue),
		op("ns=4;s=Line2/Conveyor/Rate", wire.AttrValue)))
	up.await(t, 4, "the session and the read")

	out := report(t, s, cl, file)
	t.Log("\n" + out)
	for _, want := range []string{
		"application_uri: urn:plant:scada:hmi1",
		"user: operator",
		"services: read",
		"node_group: Line1/Pump1",
		"node_group: Line2/Conveyor",
		"attributes: [value]",
		// The channel's terms are recorded and marked as observations.
		"security_policies_seen: [Basic256Sha256]  # observation only",
		"security_modes_seen: [sign]  # observation only",
		// And the proposal is a rule somebody can paste in.
		"- name: hmi1-operator",
		"action: allow",
		`application_uris: ["urn:plant:scada:hmi1"]`,
		`users: ["operator"]`,
		`nodes: ["ns=4;s=Line1/Pump1/*", "ns=4;s=Line2/Conveyor/Rate"]`,
		// Under the listener's own key, so the proposal pastes in as it stands.
		"rules:\n",
		// And the services are the ones called, not the class's whole span: this
		// identity read a live value and never asked for history.
		"services: [read]",
		// The handshake is not in the rule, and the report says why rather than
		// leaving somebody to paste it and lock every client out.
		"# The handshake -- open_secure_channel, create_session, activate_session",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q", want)
		}
	}
	// And it proposes none of the things learning must not widen.
	for _, never := range []string{
		"security_policies:", "security_modes:", "allow_deprecated_policies",
		"min_publishing_interval", "min_sampling_interval", "max_operations",
		// And never a service the class covers but the identity never called.
		"history_read", "browse_next", "republish",
	} {
		if strings.Contains(out, never) {
			t.Errorf("the report proposes %q, which a learning run must never widen", never)
		}
	}
}

// The finding a reader of an OPC UA report has to see first: an encrypted channel
// teaches nothing about nodes, and the report says so rather than looking idle.
func TestAReportSaysWhenTheBodiesWereEncrypted(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSignAndEncrypt)
	cl.service(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue)))
	up.await(t, 2, "the channel and the read")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"opaque_messages:",
		"recorded messages had an encrypted body",
		"security_modes: [sign] or require_readable_bodies: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q", want)
		}
	}
	// No node was read from those messages, so none is proposed.
	if strings.Contains(out, "ns=3;i=1") {
		t.Error("the report names a node it could not have read")
	}
}

// A subject the server refused everything for gets no rule: a rule for it would
// permit a thing that cannot happen.
func TestAnIdentityTheServerAlwaysRefusedGetsNoRule(t *testing.T) {
	up := startServer(t, &fakeServer{fault: wire.StatusBadUserAccessDenied})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:tool", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "contractor", "p", rsaOaep))
	cl.service(wire.SvcRead, readBody(op("ns=4;s=Line1/Pump1/Speed", wire.AttrValue)))
	up.await(t, 4, "the refused traffic")

	out := report(t, s, cl, file)
	if !strings.Contains(out, "the server itself said no") {
		t.Error("the report does not say the server refused it")
	}
	// And on the row the read made, not on a row with no node in it: that is what
	// decides whether a rule is proposed at all.
	if !strings.Contains(out, "node_group: Line1/Pump1") ||
		!strings.Contains(out, "server_faults: 1") {
		t.Errorf("the fault was not counted against the row the read made:\n%s", out)
	}
	// And on the session row too, which has no node in it at all: a refused
	// ActivateSession is the one a reader of this report most needs to see, since
	// it is the server saying this identity is not one it grants.
	rest, ok := cut(out, "services: session")
	if !ok {
		t.Fatalf("the report has no row for the session services:\n%s", out)
	}
	if !strings.Contains(firstLines(rest, 8), "server_faults:") {
		t.Errorf("the session row does not carry its fault:\n%s", out)
	}
	if !strings.Contains(out, "every request was refused by the server, so no rule") {
		t.Errorf("the report proposed a rule for an identity the server always refused:\n%s", out)
	}
}

// Learning is observe-only unless it says otherwise, which is what stops a run being
// left on by accident.
func TestALearningRunDoesNotEnforceUnlessAsked(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr, _ := learnRelay(t, base+"        nodes: [\"ns=3;i=*\"]\n", up)
	cl := session(t, addr)

	// A node the policy does not name. It is recorded as a would-be refusal and
	// forwarded, because the run is measuring rather than deciding.
	cl.service(wire.SvcRead, readBody(op(n(9, 1), wire.AttrValue)))
	until(t, s, wouldRefuse("node_not_allowed"), "the would-be refusal")
	up.await(t, 2, "the forwarded read")
	if got := s.Stats().Refusals["opcua"]["node_not_allowed"]; got != 0 {
		t.Errorf("a learning run counted %d real refusals", got)
	}
}

// And enforces where the configuration says so, because a run on a live plant may
// need the policy in force while it measures.
func TestALearningRunEnforcesWhenAsked(t *testing.T) {
	up := startServer(t, &fakeServer{})
	file := filepath.Join(t.TempDir(), "opcua-learn.yaml")
	s, addr := relayFor(t, base+
		"        nodes: [\"ns=3;i=*\"]\n"+
		"        learn:\n"+
		"          enabled: true\n"+
		"          enforce: true\n"+
		"          file: "+file+"\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcRead, readBody(op(n(9, 1), wire.AttrValue)))
	until(t, s, refused("node_not_allowed"), "the refusal")
	if up.sawService(wire.SvcRead) {
		t.Errorf("an enforcing learning run forwarded the read: %v", up.seen())
	}
	// And the refusal is in the report, because a run wants to know the policy and
	// the traffic disagree.
	out := report(t, s, cl, file)
	if !strings.Contains(out, "denied_by_policy") {
		t.Error("the report does not record the refusal")
	}
}

// The subscription numbers are recorded and never proposed: they are the bound that
// stops a thousand values a millisecond.
func TestTheSubscriptionNumbersAreRecordedAndNotProposed(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr, file := learnRelay(t, base, up)
	cl := session(t, addr)

	cl.service(wire.SvcCreateSubscription, subscriptionBody(250))
	cl.service(wire.SvcCreateMonitored, monitoredBody(500, n(3, 1), n(3, 2)))
	up.await(t, 3, "the subscription and the items")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"fastest_publishing_interval_ms: 250  # bound, not policy",
		"fastest_sampling_interval_ms: 500  # bound, not policy",
		"monitored_items_asked: 2  # bound, not policy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q", want)
		}
	}
}

// A numeric namespace has no prefix to group by, so the identifiers are listed and
// the proposal names them rather than inventing a pattern out of digits.
func TestNumericNodesAreListedRatherThanGrouped(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:hist", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "historian", "p", rsaOaep))
	cl.service(wire.SvcRead, readBody(
		op(n(3, 1001), wire.AttrValue), op(n(3, 1002), wire.AttrValue)))
	up.await(t, 4, "the read")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"namespace: ns=3",
		`nodes_seen: ["ns=3;i=1001", "ns=3;i=1002"]`,
		`nodes: ["ns=3;i=1001", "ns=3;i=1002"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q", want)
		}
	}
	if strings.Contains(out, "node_group:") {
		t.Error("the report invented a group for numeric identifiers")
	}
}

// A session that never activated has no user to name, and the report says which
// rather than leaving the column blank.
func TestAnUnactivatedSessionIsLabelledRatherThanBlank(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr, file := learnRelay(t, base, up)
	cl := session(t, addr)
	cl.service(wire.SvcRead, readBody(op("ns=4;s=Line1/Pump1/Speed", wire.AttrValue)))
	up.await(t, 2, "the read")

	out := report(t, s, cl, file)
	if !strings.Contains(out, "user: <not activated>") {
		t.Errorf("the report does not label the missing user:\n%s", out)
	}
	if !strings.Contains(out, "application_uri: <no session>") {
		t.Error("the report does not label the missing application")
	}
	// No rule is proposed for a subject with no identity: the handshake services
	// are the listener's own defaults, and there is nothing to name.
	if strings.Contains(out, "- name:") {
		t.Errorf("a rule was proposed for a subject with no identity:\n%s", out)
	}
}

// The writes: the attributes are recorded, and a write with no attribute recorded
// leaves write_attributes to the listener's default rather than widening it.
func TestAWriteRecordsItsAttributeAndItsMethods(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, baseServices+
		"        services: [open_secure_channel, create_session, activate_session,"+
		" read, write, call]\n", up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:tia", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "engineer", "p", rsaOaep))
	cl.service(wire.SvcWrite,
		writeBody(wr("ns=4;s=Line1/Setpoints/Speed", wire.AttrValue, 72.5)))
	cl.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	up.await(t, 5, "the write and the call")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"services: write",
		"attributes: [value]",
		`methods_called: ["ns=4;s=Line1/Pump1/Reset"]`,
		`methods: ["ns=4;s=Line1/Pump1/Reset"]`,
		"write_attributes: [value]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
}

// A service this build cannot name must not reach the proposal by the name it
// prints. `service(31337)` in a `services:` list is a configuration that will not
// load, so somebody who pasted the proposal would find that out at the next
// restart of a listener in front of a plant.
func TestAnUnnameableServiceIsNotProposedByItsPrintedName(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:odd", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "p", rsaOaep))
	// Refused, because a service with no name has no policy -- and recorded, because
	// a learning run wants to know a client is sending one.
	if _, err := cl.serviceQuiet(wire.Service(31337), nil); err == nil {
		t.Log("the relay answered rather than closing, which the response policy allows")
	}
	until(t, s, refused("service_unknown"), "the refusal")

	out := report(t, s, cl, file)
	if strings.Contains(out, "service(") {
		t.Errorf("the report names a service by a name no configuration accepts:\n%s", out)
	}
	if !strings.Contains(out, "at least one service this build does not name") {
		t.Errorf("the report does not say a service was left out:\n%s", out)
	}
}

// A fault answers the whole request, so it belongs to every row the request made.
// A Read across two node groups that the server refuses is two rows the server
// refused; counting the fault against only the first would leave the second reading
// as traffic the server accepted, and a rule would be proposed for it.
func TestAFaultIsCountedAgainstEveryRowTheRequestMade(t *testing.T) {
	up := startServer(t, &fakeServer{fault: wire.StatusBadNodeIDUnknown})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:ghost", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "p", rsaOaep))
	// One request, two groups, and the server has neither.
	cl.service(wire.SvcRead, readBody(
		op("ns=4;s=Cell1/Pump/Speed", wire.AttrValue),
		op("ns=4;s=Cell2/Pump/Speed", wire.AttrValue)))
	up.await(t, 4, "the refused read")

	out := report(t, s, cl, file)
	for _, group := range []string{"Cell1/Pump", "Cell2/Pump"} {
		rest, ok := cut(out, "node_group: "+group)
		if !ok {
			t.Fatalf("the report has no row for %s:\n%s", group, out)
		}
		if !strings.Contains(firstLines(rest, 6), "server_faults: 1") {
			t.Errorf("the row for %s does not carry the fault:\n%s", group, out)
		}
	}
	// And so no rule, because nothing this identity asked for happened.
	if strings.Contains(out, "- name: ghost-operator") {
		t.Errorf("a rule was proposed for an identity the server refused:\n%s", out)
	}
}

// The in-flight table is bounded, and a bound whose entries are never released is
// a bound reached once and never left: the sixty-fifth request would then be
// unattributable for the rest of a session that a plant keeps open for months.
func TestTheInFlightTableIsReleasedAsAnswersArrive(t *testing.T) {
	up := startServer(t, &fakeServer{fault: wire.StatusBadUserAccessDenied})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:poller", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "p", rsaOaep))
	// Comfortably past MaxPendingRequests, one at a time: each answer arrives
	// before the next request goes out, so nothing is ever in flight but one.
	const reads = MaxPendingRequests + 8
	for range reads {
		cl.service(wire.SvcRead, readBody(op("ns=4;s=Line9/Tank/Level", wire.AttrValue)))
	}
	up.await(t, 3+reads, "every read")

	out := report(t, s, cl, file)
	if want := fmt.Sprintf("server_faults: %d", reads); !strings.Contains(out, want) {
		t.Errorf("the report is missing %q, so answers stopped being attributed:\n%s",
			want, out)
	}
}

// A numeric namespace with more identifiers than are remembered proposes the
// namespace, not the first two dozen of an unknown number. The first two dozen
// would read as a complete list and be adopted as one.
func TestATruncatedNumericNamespaceProposesTheNamespace(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:hist2", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "historian", "p", rsaOaep))
	ops := make([][2]any, 0, maxLearnedNodes+6)
	for i := range maxLearnedNodes + 6 {
		ops = append(ops, op(n(3, uint32(2000+i)), wire.AttrValue))
	}
	cl.service(wire.SvcRead, readBody(ops...))
	up.await(t, 4, "the read")

	out := report(t, s, cl, file)
	if !strings.Contains(out, `nodes: ["ns=3;i=*"]`) {
		t.Errorf("the proposal does not fall back to the namespace:\n%s", out)
	}
	if !strings.Contains(out, "a group held more nodes than were recorded") {
		t.Error("the report does not say the list was truncated")
	}
}

// cut splits at the first occurrence of sep and says whether it was there.
func cut(s, sep string) (string, bool) {
	_, after, ok := strings.Cut(s, sep)
	return after, ok
}

// firstLines is the first n lines of s, which is how a row's own fields are read
// out of a report without parsing the YAML.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// The handshake is recorded and never proposed, and the two have to be checked
// apart: the observed rows are where "this identity's activation was refused" lives,
// and the proposal is what somebody pastes. A proposal carrying create_session would
// contradict the paragraph above it in the same file.
func TestTheHandshakeIsObservedAndNeverProposed(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:hmi2", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "p", rsaOaep))
	cl.service(wire.SvcRead, readBody(op("ns=4;s=Line5/Mixer/Speed", wire.AttrValue)))
	up.await(t, 4, "the session and the read")

	out := report(t, s, cl, file)
	// Observed: the session class is a row of its own, so a refused activation has
	// somewhere to be counted.
	if !strings.Contains(out, "services: session") {
		t.Errorf("the handshake was not recorded at all:\n%s", out)
	}
	// Proposed: not there.
	_, rules, ok := strings.Cut(out, "\nrules:\n")
	if !ok {
		t.Fatalf("the report proposes nothing:\n%s", out)
	}
	for _, never := range []string{
		"create_session", "activate_session", "open_secure_channel",
		"close_secure_channel", "close_session", "get_endpoints",
	} {
		if strings.Contains(rules, never) {
			t.Errorf("the proposal names %q, which no rule matching an identity can decide", never)
		}
	}
	// And the rule that is there is about what the client did with the session.
	if !strings.Contains(rules, "services: [read]") {
		t.Errorf("the proposal does not name the read:\n%s", rules)
	}
}

// A client that only connected gets no rule. Writing one for it would be writing
// an allow rule with nothing narrowed: no `services` key means the listener's own
// list, so the rule permits more than the traffic ever asked for.
func TestAnIdentityThatOnlyHandshookGetsNoRule(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:idle", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "watcher", "p", rsaOaep))
	up.await(t, 3, "the session")

	out := report(t, s, cl, file)
	// Recorded, with the activation distinguishable from the CreateSession: the
	// row for the named user is the activation's.
	rest, ok := cut(out, "user: watcher")
	if !ok || !strings.Contains(firstLines(rest, 3), "services: session") {
		t.Errorf("the activation was not recorded against the user it named:\n%s", out)
	}
	if !strings.Contains(out, "token_kinds_seen: [username]") {
		t.Errorf("the activation's token kind was not recorded:\n%s", out)
	}
	// And no rule.
	if strings.Contains(out, "- name:") {
		t.Errorf("a rule was proposed for a client that only connected:\n%s", out)
	}
	if !strings.Contains(out, "nothing but the handshake was seen") {
		t.Errorf("the report does not say why there is no rule:\n%s", out)
	}
}

// A handshake the policy refuses is a refusal the report has to carry, because the
// whole point of a run that is not enforcing is to find out what a policy would
// have broken -- and a CreateSession refused on its application URI breaks
// everything that client does.
func TestARefusedHandshakeIsCountedAgainstItsIdentity(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr, file := learnRelay(t,
		head+"        default_action: allow\n"+services+
			"        application_uris: [\"urn:plant:known\"]\n", up)

	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:stranger", "s", nil))
	until(t, s, wouldRefuse("application_not_allowed"), "the would-be refusal")
	up.await(t, 2, "the forwarded session")

	out := report(t, s, cl, file)
	rest, ok := cut(out, "application_uri: urn:plant:stranger")
	if !ok {
		t.Fatalf("the report has no row for the refused application:\n%s", out)
	}
	if !strings.Contains(firstLines(rest, 6), "denied_by_policy: 1") {
		t.Errorf("the refused handshake was recorded as allowed:\n%s", out)
	}
}

// Two runs over the same traffic have to produce the same file, or a diff between
// two weeks means nothing. The rows and the rules are therefore ordered by the
// identity, not by which client happened to connect first.
func TestTheReportIsOrderedByIdentityAndNotByArrival(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr, file := learnRelay(t, base, up)

	// Deliberately the later name first.
	for _, who := range []struct{ app, user string }{
		{"urn:plant:zulu", "zoe"}, {"urn:plant:alpha", "alice"},
	} {
		cl := dial(t, addr)
		cl.handshake("opc.tcp://127.0.0.1:4840")
		cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
		cl.service(wire.SvcCreateSession, createSessionBody(who.app, "s", nil))
		cl.service(wire.SvcActivateSession,
			activateBody(wire.TokenUserName, who.user, "p", rsaOaep))
		cl.service(wire.SvcRead, readBody(op("ns=4;s=Cell/Thing/Value", wire.AttrValue)))
		_ = cl.c.Close()
	}
	up.await(t, 8, "both clients")

	cl := dial(t, addr)
	out := report(t, s, cl, file)
	_, rules, ok := strings.Cut(out, "\nrules:\n")
	if !ok {
		t.Fatalf("the report proposes nothing:\n%s", out)
	}
	alpha, zulu := strings.Index(rules, "alpha"), strings.Index(rules, "zulu")
	if alpha < 0 || zulu < 0 {
		t.Fatalf("both identities should have a rule:\n%s", rules)
	}
	if alpha > zulu {
		t.Errorf("the rules are in arrival order rather than by identity:\n%s", rules)
	}
}
