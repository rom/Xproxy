package snmp

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/snmp"
)

// The outstanding-request table publishes its size, because an operator
// watching a relay wants to see the table filling up rather than only seeing
// the bound refuse.
func TestTheOutstandingCountIsPublished(t *testing.T) {
	var seen []int
	p := newPending(4, time.Second)
	p.onChange = func(n int) { seen = append(seen, n) }
	now := time.Now()
	p.add(&exchange{requestID: 1}, now)
	p.add(&exchange{requestID: 2}, now)
	p.take(1, netip.Addr{}, now)
	if want := []int{1, 2, 1}; len(seen) != len(want) {
		t.Fatalf("the table reported %v", seen)
	}
	for i, n := range []int{1, 2, 1} {
		if seen[i] != n {
			t.Errorf("report %d was %d, wanted %d", i, seen[i], n)
		}
	}
	// A table nobody asked about does not panic on the way past.
	q := newPending(2, time.Second)
	q.add(&exchange{requestID: 1}, now)
	q.take(1, netip.Addr{}, now)
}

// The pending table. It is bounded and it expires, because the entries come
// off the network -- and a full table refuses the new request rather than
// forgetting an old one, because forgetting would make the pairing that
// detects an unsolicited response unreliable.
func TestTheTableRefusesRatherThanForgets(t *testing.T) {
	now := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	p := newPending(2, 5*time.Second)
	for i := int64(1); i <= 2; i++ {
		if !p.add(&exchange{requestID: i}, now) {
			t.Fatalf("request %d was refused below the bound", i)
		}
	}
	if p.add(&exchange{requestID: 3}, now) {
		t.Error("a third request was admitted past a bound of two")
	}
	if n, dropped := p.status(); n != 2 || dropped != 1 {
		t.Errorf("status: %d outstanding, %d dropped", n, dropped)
	}
	// The first request is still there: nothing was forgotten to make room.
	if e, ok := p.take(1, netip.Addr{}, now); !ok || e.requestID != 1 {
		t.Errorf("the first request was forgotten: %v %v", e, ok)
	}
	// Once it has expired, its slot is reusable -- and an answer arriving
	// against it is not forwarded, because the manager stopped waiting and
	// has since reused the identifier.
	later := now.Add(6 * time.Second)
	if e, ok := p.take(2, netip.Addr{}, later); ok || e == nil {
		t.Errorf("a late answer was forwarded: %v %v", e, ok)
	}
	if !p.add(&exchange{requestID: 4}, later) {
		t.Error("an expired entry did not free its slot")
	}
	// An answer to a question nobody asked has no entry at all, which is
	// what separates it from a late one.
	if e, ok := p.take(999, netip.Addr{}, later); ok || e != nil {
		t.Errorf("an unsolicited answer matched something: %v %v", e, ok)
	}
	// And the defaults, for a listener that set neither.
	d := newPending(0, 0)
	if d.max != 32 || d.ttl != 5*time.Second {
		t.Errorf("defaults: %d %s", d.max, d.ttl)
	}
}

// The framing reader on a stream: RFC 3430 has no framing of its own, so
// the length in the message is the whole of it -- and the length is chosen
// by whoever sent it.
func TestTheStreamReaderDecidesAboutALengthBeforeReadingIt(t *testing.T) {
	first := v2c("public", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0))
	second := v2c("public", get(2, 1, 3, 6, 1, 2, 1, 1, 2, 0))
	rd := newStreamReader(bytes.NewReader(append(append([]byte{}, first...), second...)), 8192)
	got, err := rd.next()
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("the first message: % x (%v)", got, err)
	}
	got, err = rd.next()
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("the second message: % x (%v)", got, err)
	}
	if _, err := rd.next(); !errors.Is(err, io.EOF) {
		t.Errorf("the end of the stream read as %v", err)
	}

	// A length past the bound, with none of the octets it claims sent. A
	// reader that waited for them would be doing the work the bound exists
	// to avoid.
	rd = newStreamReader(bytes.NewReader([]byte{0x30, 0x82, 0xea, 0x60}), 600)
	if _, err := rd.next(); !errors.Is(err, errTooLong) {
		t.Errorf("an oversize length read as %v", err)
	}
	// Five length octets: legal in BER for a length no SNMP message has.
	rd = newStreamReader(bytes.NewReader([]byte{0x30, 0x85, 1, 1, 1, 1, 1}), 8192)
	if _, err := rd.next(); !errors.Is(err, errTooLong) {
		t.Errorf("a five-octet length read as %v", err)
	}
	// The indefinite length, which would make a message's extent depend on
	// finding an end-of-contents pair inside a payload this relay does not
	// interpret.
	rd = newStreamReader(bytes.NewReader([]byte{0x30, 0x80, 0x02, 0x01, 0x01}), 8192)
	if _, err := rd.next(); !errors.Is(err, errFraming) {
		t.Errorf("an indefinite length read as %v", err)
	}
	// Not a SEQUENCE at all.
	rd = newStreamReader(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")), 8192)
	if _, err := rd.next(); !errors.Is(err, errFraming) {
		t.Errorf("an HTTP request read as %v", err)
	}
	// A truncated body: an end of stream, not a framing error, because the
	// sender may simply have gone away mid-message.
	rd = newStreamReader(bytes.NewReader([]byte{0x30, 0x10, 0x02}), 8192)
	if _, err := rd.next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a truncated body read as %v", err)
	}
	// And the bound has a default, because a reader with no bound is not a
	// reader this relay would use.
	if got := newStreamReader(bytes.NewReader(nil), 0).max; got != 8192 {
		t.Errorf("the default bound is %d", got)
	}
}

// The listener's defaults: every one of these is a number an operator can
// leave out, so every one of them has to be a number this relay would have
// chosen.
func TestTheDefaultsAreTheOnesTheDocumentationNames(t *testing.T) {
	s := &server{m: &config.SNMPListener{}}
	for what, got := range map[string]int{
		"max_pending":        s.maxPending(),
		"max_message_bytes":  s.maxMessage(),
		"max_response_bytes": s.maxResponse(),
		"max_response_ratio": s.maxRatio(),
	} {
		if got == 0 {
			t.Errorf("%s has no default", what)
		}
	}
	if got := s.maxPending(); got != 32 {
		t.Errorf("max_pending %d", got)
	}
	if got := s.maxMessage(); got != 8192 {
		t.Errorf("max_message_bytes %d", got)
	}
	if got := s.maxRatio(); got != 50 {
		t.Errorf("max_response_ratio %d", got)
	}
	if got := s.requestTimeout(); got != 5*time.Second {
		t.Errorf("request_timeout %s", got)
	}
	if got := s.idleTimeout(); got != time.Minute {
		t.Errorf("idle_timeout %s", got)
	}
	if !s.alerts() {
		t.Error("alert_on_deny is off by default")
	}
	// And what an operator wrote wins over all of them.
	no := false
	s = &server{m: &config.SNMPListener{MaxPending: 4, MaxMessageBytes: 1472,
		MaxResponseBytes: 2048, MaxResponseRatio: 3, AlertOnDeny: &no,
		RequestTimeout: config.Duration(2 * time.Second), IdleTimeout: config.Duration(30 * time.Second)}}
	if s.maxPending() != 4 || s.maxMessage() != 1472 || s.maxResponse() != 2048 || s.maxRatio() != 3 {
		t.Error("a configured bound was ignored")
	}
	if s.requestTimeout() != 2*time.Second || s.idleTimeout() != 30*time.Second {
		t.Error("a configured timeout was ignored")
	}
	if s.alerts() {
		t.Error("alert_on_deny: false was ignored")
	}
}

// The upgrade, decided per message rather than per listener: what can be
// rewritten, what cannot, and why.
func TestWhatCanAndCannotBeRewritten(t *testing.T) {
	s := &server{m: &config.SNMPListener{UpstreamCommunity: "switch-secret"}, upgrade: wire.V1}

	// v2c to v1: neither has any integrity to invalidate.
	in := parse(v2c("nms-only", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	out, changed, err := s.applyUpgrade(in.Raw, in)
	if err != nil || !changed {
		t.Fatalf("a v2c request was not downgraded: %v %v", changed, err)
	}
	got := parse(out)
	if got.Version != wire.V1 || got.Community != "switch-secret" {
		t.Errorf("the rewritten request is %s %q", got.Version, got.Community)
	}

	// A v3 request: its answer would have to be authenticated.
	in = parse(v3(0x05, "monitor", "", get(2, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if _, changed, err := s.applyUpgrade(in.Raw, in); changed || !errors.Is(err, errUnanswerable) {
		t.Errorf("a v3 request was downgraded: %v %v", changed, err)
	}
	// A v3 notification: nothing comes back, so there is nothing to
	// authenticate.
	in = parse(v3(0x05, "device-a", "", trap(3, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3)))
	if out, changed, err := s.applyUpgrade(in.Raw, in); err != nil || !changed {
		t.Errorf("a v3 trap was not downgraded: %v %v", changed, err)
	} else if parse(out).Version != wire.V1 {
		t.Error("the downgraded trap is not v1")
	}
	// An encrypted payload: there is no PDU to put in an envelope.
	in = parse(v3(0x07, "monitor", "", get(4, 1, 3, 6, 1)))
	if _, changed, err := s.applyUpgrade(in.Raw, in); changed || !errors.Is(err, errSealed) {
		t.Errorf("an encrypted message was rewritten: %v %v", changed, err)
	}
	// A listener that rewrites nothing rewrites nothing.
	s.upgrade = -1
	in = parse(v2c("public", get(5, 1, 3, 6, 1)))
	if _, changed, _ := s.applyUpgrade(in.Raw, in); changed {
		t.Error("a listener with no upgrade_version rewrote a message")
	}
}

// Lowering the repetition count, and the one shape that has to be refused
// instead.
func TestTheRepetitionCountIsLoweredOrTheRequestIsRefused(t *testing.T) {
	m := &config.SNMPListener{MaxRepetitions: 25}
	p, err := compile(m, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{m: m, policy: p, upgrade: -1}

	// Below the bound: nothing is rewritten, because a request that is
	// already within the bound is not this relay's to edit.
	in := parse(v2c("public", bulk(1, 10, 1, 3, 6, 1, 2, 1)))
	if out, lowered, refuse := s.lowerRepetitions(in, Decision{Allow: true}); lowered || refuse || out != nil {
		t.Errorf("a walk within the bound was rewritten: %v %v", lowered, refuse)
	}
	// Past it: lowered.
	in = parse(v2c("public", bulk(2, 10000, 1, 3, 6, 1, 2, 1)))
	out, lowered, refuse := s.lowerRepetitions(in, Decision{Allow: true})
	if !lowered || refuse {
		t.Fatalf("a walk past the bound: lowered %v refuse %v", lowered, refuse)
	}
	if got := parse(out); got.PDU.MaxRepetitions != 25 {
		t.Errorf("lowered to %d", got.PDU.MaxRepetitions)
	}
	// A *negative* count, which is past the bound rather than under it.
	//
	// RFC 3416 gives max-repetitions the range 0..2147483647, so this is
	// malformed -- and malformed in the direction that matters: compared as the
	// signed value it is, it sits under any bound and was forwarded unlowered;
	// read by an agent that puts it in an unsigned or a narrower counter it is an
	// enormous repetition count, which is the amplification this bound exists to
	// remove. The devices behind this relay are the ones that cannot be patched,
	// so their conformance is not the thing to rely on.
	//
	// A fuzz target on the wire package found it: -839632 against a bound of 25.
	in = parse(v2c("public", bulk(9, -839632, 1, 3, 6, 1, 2, 1)))
	out, lowered, refuse = s.lowerRepetitions(in, Decision{Allow: true})
	if !lowered || refuse {
		t.Fatalf("a walk with a negative count: lowered %v refuse %v -- it was "+
			"forwarded with the bound unenforced", lowered, refuse)
	}
	if got := parse(out).PDU.MaxRepetitions; got != 25 {
		t.Errorf("the negative count was rewritten to %d, not the bound", got)
	}

	// An authenticated v3 walk: refused, because the digest covers the
	// whole message and this relay has no key to compute a new one with.
	in = parse(v3(0x05, "monitor", "", bulk(3, 10000, 1, 3, 6, 1, 2, 1)))
	if _, lowered, refuse := s.lowerRepetitions(in, Decision{Allow: true}); lowered || !refuse {
		t.Errorf("an authenticated v3 walk: lowered %v refuse %v", lowered, refuse)
	}
	// And a noAuthNoPriv one, which nothing signed but which this relay
	// still will not forge a v3 envelope for.
	in = parse(v3(0x04, "monitor", "", bulk(4, 10000, 1, 3, 6, 1, 2, 1)))
	if _, lowered, refuse := s.lowerRepetitions(in, Decision{Allow: true}); lowered || !refuse {
		t.Errorf("a noAuthNoPriv v3 walk: lowered %v refuse %v", lowered, refuse)
	}
	// A rule may raise the bound for the traffic it covers.
	m.Rules = []config.SNMPRule{{Name: "walks", Action: "allow", MaxRepetitions: 5000}}
	if p, err = compile(m, time.Now); err != nil {
		t.Fatal(err)
	}
	s.policy = p
	in = parse(v2c("public", bulk(5, 1000, 1, 3, 6, 1, 2, 1)))
	if _, lowered, refuse := s.lowerRepetitions(in, Decision{Allow: true, Rule: "walks"}); lowered || refuse {
		t.Errorf("a walk inside the rule's own bound was rewritten: %v %v", lowered, refuse)
	}
	// A GET has no repetition count at all.
	in = parse(v2c("public", get(6, 1, 3, 6, 1, 2, 1)))
	if _, lowered, refuse := s.lowerRepetitions(in, Decision{Allow: true}); lowered || refuse {
		t.Errorf("a GET was treated as a walk: %v %v", lowered, refuse)
	}
}

// Restoring the version on the way back, which is the other half of the
// downgrade: the manager is owed the version it asked in.
func TestTheAnswerIsRestoredToTheVersionTheQuestionUsed(t *testing.T) {
	s := &server{m: &config.SNMPListener{}, upgrade: wire.V1}
	answer := v1msg("legacy-switch", response(7, 8, 1, 3, 6, 1, 2, 1, 1, 1, 0))
	in := parse(answer)
	e := &exchange{requestID: 7, version: wire.V2c, community: "nms-only"}
	out, restored := s.restore(answer, in, e)
	if !restored {
		t.Fatal("the answer was not restored")
	}
	got := parse(out)
	if got.Version != wire.V2c || got.Community != "nms-only" {
		t.Errorf("the restored answer is %s %q", got.Version, got.Community)
	}
	if got.PDU.RequestID != 7 {
		t.Errorf("the request identifier moved: %d", got.PDU.RequestID)
	}
	// An answer already in the right version is left exactly as it arrived.
	e.version = wire.V1
	if out, restored := s.restore(answer, in, e); restored || !bytes.Equal(out, answer) {
		t.Error("an answer in the right version was rewritten")
	}
	// A v3 answer is never restored, because a v3 request is never
	// downgraded.
	e.version = wire.V3
	if out, restored := s.restore(answer, in, e); restored || !bytes.Equal(out, answer) {
		t.Error("a v3 answer was rebuilt")
	}
	// And with no exchange there is nothing to restore it to.
	if out, restored := s.restore(answer, in, nil); restored || !bytes.Equal(out, answer) {
		t.Error("an answer with no question was rewritten")
	}
}

// The refusal a listener sends, per deny_response.
func TestTheRefusalRespectsDenyResponse(t *testing.T) {
	in := parse(v2c("public", set(8, "x", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	if answer := refusalFor(in); answer == nil {
		t.Fatal("there was no refusal to send")
	} else if parse(answer).PDU.ErrorStatus != wire.StatusNoAccess {
		t.Error("the refusal does not say noAccess")
	}
}

// deny prefixes the kind's own name once and only once, because the counters
// and the security log have to agree about what a reason is called.
func TestAReasonIsNamedTheSameWayWhereverItIsWritten(t *testing.T) {
	s := &server{m: &config.SNMPListener{}, cfg: config.Listener{Name: "poll"}}
	_ = s
	for in, want := range map[string]string{
		"malformed":      "snmp_malformed",
		"snmp_malformed": "snmp_malformed",
		"snmp":           "snmp_snmp",
	} {
		name := in
		if len(name) < 5 || name[:5] != "snmp_" {
			name = "snmp_" + name
		}
		if name != want {
			t.Errorf("%q became %q", in, name)
		}
	}
}

// itoa is the formatter the hot path uses, and a detail field that formats a
// number wrongly is an audit trail that lies.
func TestTheNumberFormatterIsCorrect(t *testing.T) {
	for in, want := range map[int]string{0: "0", 7: "7", 42: "42", 1472: "1472", 65507: "65507"} {
		if got := itoa(in); got != want {
			t.Errorf("%d formatted as %q", in, got)
		}
	}
}

// firstOID names the object a decision was about, which is what makes a
// refusal an audit trail rather than a count.
func TestARefusalNamesTheObjectItWasAbout(t *testing.T) {
	in := parse(v2c("public", get(9, 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	if got := firstOID(in.PDU); got != "1.3.6.1.2.1.1.5.0" {
		t.Errorf("first oid %q", got)
	}
	if got := firstOID(nil); got != "" {
		t.Errorf("a nil pdu named %q", got)
	}
	empty := parse(v2c("public", pduOf(wire.TagGetRequest, 1, 0, 0)))
	if got := firstOID(empty.PDU); got != "" {
		t.Errorf("a request with no bindings named %q", got)
	}
}

// And the detail the shadow ledger records: enough for an engineer to look
// the entry up, which "snmp_rule" alone is not.
func TestTheLedgerSampleSaysWhatWasAsked(t *testing.T) {
	in := parse(v2c("public", set(10, "x", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	got := detailOf(in, Decision{Reason: "snmp_rule", Detail: "1.3.6.1.2.1.1.5.0"})
	if got != "v2c set 1.3.6.1.2.1.1.5.0" {
		t.Errorf("the sample is %q", got)
	}
	// And it never carries the community string, which is a credential.
	if bytes.Contains([]byte(got), []byte("public")) {
		t.Error("the ledger sample carries the community string")
	}
}

// The client check is a separate step because it happens before a message is
// parsed: an address that may not reach the equipment is refused without the
// relay having read anything it sent.
func TestTheClientCheckHappensBeforeAnythingIsParsed(t *testing.T) {
	p, err := compile(&config.SNMPListener{AllowClients: []string{"10.0.0.0/24"}}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Client(netip.MustParseAddr("10.0.0.7")) {
		t.Error("a listed client was refused")
	}
	if p.Client(netip.MustParseAddr("10.0.1.7")) {
		t.Error("an unlisted client was allowed")
	}
}

// A request that never left the relay does not hold a slot until it expires:
// the count an operator reads is the requests that are actually outstanding.
func TestARequestThatNeverLeftReleasesItsSlot(t *testing.T) {
	p := newPending(4, time.Second)
	now := time.Now()
	p.add(&exchange{requestID: 11}, now)
	if n, _ := p.status(); n != 1 {
		t.Fatalf("%d outstanding after one add", n)
	}
	p.drop(11)
	if n, _ := p.status(); n != 0 {
		t.Errorf("%d outstanding after the drop", n)
	}
	// Dropping something that is not there changes nothing, which matters
	// because a notification never had a slot to begin with.
	p.drop(11)
	p.drop(99)
	if n, dropped := p.status(); n != 0 || dropped != 0 {
		t.Errorf("status after dropping nothing: %d, %d", n, dropped)
	}
	// And the server-level helper only touches a request: a notification has
	// no answer coming and never took a slot.
	s := &server{m: &config.SNMPListener{}, pend: newPending(4, time.Second), upgrade: -1}
	s.pend.add(&exchange{requestID: 12}, now)
	s.forget(parse(v2c("public", trap(12, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3))))
	if n, _ := s.pend.status(); n != 1 {
		t.Errorf("a notification released a request's slot")
	}
	s.forget(parse(v2c("public", get(12, 1, 3, 6, 1, 2, 1))))
	if n, _ := s.pend.status(); n != 0 {
		t.Errorf("%d outstanding after forgetting the request", n)
	}
}

// An answer carrying the right request identifier from the wrong agent is not
// this exchange's answer.
//
// On a datagram protocol the identifier is the manager's own and the relay's
// upstream socket is unconnected, so without this check anything that could
// reach that socket -- including one agent in a multi-endpoint pool, which sees
// the port on every poll -- could answer another agent's question by matching a
// value it already knew. The manager would have received the forged varbinds
// re-enveloped in its own version and community, logged as a legitimate answer,
// with nothing counted as unsolicited because the pairing matched.
func TestAnAnswerFromAnotherAgentDoesNotMatchTheExchange(t *testing.T) {
	now := time.Now()
	asked := netip.MustParseAddr("192.0.2.10")
	stranger := netip.MustParseAddr("192.0.2.99")
	p := newPending(8, 5*time.Second)
	if !p.add(&exchange{requestID: 7, agent: asked}, now) {
		t.Fatal("the question was not recorded")
	}

	// The stranger's answer does not take the slot.
	if _, ok := p.take(7, stranger, now); ok {
		t.Error("an answer from an address nobody asked was paired")
	}
	// And the slot is still there, so the agent that was asked can still
	// answer: a stranger must not be able to spend somebody else's window.
	if n, _ := p.status(); n != 1 {
		t.Errorf("%d outstanding after a stranger's answer, want 1", n)
	}
	e, ok := p.take(7, asked, now)
	if !ok || e == nil || e.requestID != 7 {
		t.Fatalf("the agent that was asked could not answer: %v %v", e, ok)
	}

	// An exchange recorded without an agent -- a stream, where the connection
	// is the binding -- still pairs on the identifier alone.
	if !p.add(&exchange{requestID: 8}, now) {
		t.Fatal("the stream question was not recorded")
	}
	if _, ok := p.take(8, netip.Addr{}, now); !ok {
		t.Error("a stream answer did not pair")
	}
}
