package s7

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/s7"
)

// Learning mode, through the whole relay.
//
// The drawings say which blocks a controller has. They do not say which of them
// the integrator's HMI reads every second, and a policy written from the
// drawings refuses half of it on the first shift.

func learnRelay(t *testing.T, rules string, plc *fakePLC, enforce bool) (*proxy.Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "learned.yaml")
	s, addr := relayFor(t, fmt.Sprintf(`        upstream: cpu
        learn:
          enabled: true
          file: %s
          enforce: %t
%s`, path, enforce, rules), plc.addr())
	return s, addr, path
}

// learnedReport shuts the listener down, which is what writes the report, and
// reads it. The client is closed first: a shutdown waits for the sessions to
// drain, and an idle connection nobody closed makes every test here wait out
// the whole grace period.
func learnedReport(t *testing.T, s *proxy.Server, cl *client, path string) string {
	t.Helper()
	_ = cl.c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	return string(body)
}

// learnSession drives a connection as far as a usable session. connect
// negotiates the PDU length itself, so there is exactly one setup in the
// report and not two.
func learnSession(t *testing.T, addr string) *client {
	t.Helper()
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)
	return cl
}

// What a learning run produces: the blocks and bytes actually touched, and a
// rule set that permits exactly those.
func TestAnS7LearningRunWritesWhatItSaw(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	// Writes are outside the default operation set, because the default
	// refuses everything that changes the controller. A commissioning run on a
	// line whose HMI writes has to name them, or it would be learning from
	// traffic the listener was refusing.
	s, addr, path := learnRelay(t, "        default_action: allow\n"+
		"        operations: [setup, read, write]", plc, true)

	cl := learnSession(t, addr)
	// Two reads of adjacent bytes in DB1, so the report shows one range rather
	// than two, and a write to DB2 so the written bytes are kept apart.
	cl.allowed(readJob(3, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	cl.allowed(readJob(4, item(wire.TransportByte, 4, 1, wire.AreaDB, 4)))
	cl.allowed(writeJob(5, item(wire.TransportByte, 2, 2, wire.AreaDB, 10),
		wire.TransportByte, []byte{0x01, 0x02}))

	got := learnedReport(t, s, cl, path)

	for _, want := range []string{
		"S7comm traffic",
		`listener "plc"`,
		"operation: read",
		"operation: write",
		"area: db",
		"db: 1",
		"db: 2",
		"max_items_seen: 1",
		"transports: [byte]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report has no %q:\n%s", want, got)
		}
	}
	// The two adjacent reads are one range: a report with a line per request is
	// a report nobody reads.
	if !strings.Contains(got, `bytes: ["0-7"]`) {
		t.Errorf("the adjacent reads were not merged into one range:\n%s", got)
	}
	// What was written is kept apart from what was read, because that is the
	// rule an engineer reads most carefully.
	if !strings.Contains(got, `written: ["10-11"]`) {
		t.Errorf("the written bytes are not recorded separately:\n%s", got)
	}
	// And the proposal is in the vocabulary s7.rules actually uses.
	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report proposes no rules:\n%s", got)
	}
	_ = obs
	for _, want := range []string{"action: allow", "operations: [read]", "operations: [write]",
		"areas: [db]", `dbs: ["1"]`, "write_addresses:", "max_items: 1"} {
		if !strings.Contains(rules, want) {
			t.Errorf("the proposal has no %q:\n%s", want, rules)
		}
	}
}

// A learning run is observe-only by default, which is the point: a run that
// refused half the traffic would have changed the thing it was measuring.
func TestAnS7LearningRunDoesNotEnforceByDefault(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	s, addr, path := learnRelay(t, `        default_action: deny`, plc, false)

	cl := learnSession(t, addr)
	// No rule allows this, and the default is deny. The listener is learning,
	// so it goes through and the report says the policy disagreed.
	cl.allowed(readJob(3, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	if n := len(plc.saws()); n == 0 {
		t.Fatal("a learning run refused the request it was meant to be measuring")
	}
	got := learnedReport(t, s, cl, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the report does not say the policy disagreed:\n%s", got)
	}
}

// A request the controller itself refuses belongs out of the policy rather than
// in it. A password-protected CPU answers exactly this.
func TestARequestTheControllerRefusesIsNotProposed(t *testing.T) {
	plc := startPLC(t, &fakePLC{fault: true})
	s, addr, path := learnRelay(t, "        default_action: allow", plc, true)

	cl := learnSession(t, addr)
	cl.write(readJob(3, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	cl.next()
	got := learnedReport(t, s, cl, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	// The fault is attributed to the block the request named, which the answer
	// itself never carries.
	if !strings.Contains(obs, "access_faults:") {
		t.Errorf("the controller's refusal was not recorded:\n%s", obs)
	}
	if !strings.Contains(obs, "db: 1") {
		t.Errorf("the fault was not attributed to the block asked for:\n%s", obs)
	}
	// So no rule is proposed for it: permitting it would permit a thing that
	// cannot happen, and an engineer reading the rule would think it could.
	if strings.Contains(rules, "operations: [read]") {
		t.Errorf("the proposal writes a rule for a request the controller refuses:\n%s", rules)
	}
}

// What the section refuses to load.
func TestWhatAnS7LearningSectionRefusesToLoad(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "learning with no file",
			section: "        learn: {enabled: true}",
			wants:   "learn.file: required",
		},
		{
			name:    "a relative path",
			section: "        learn: {enabled: true, file: learned.yaml}",
			wants:   "must be an absolute path",
		},
		{
			name:    "an interval nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, interval: 1s}",
			wants:   "learn.interval: must be between 10s and 24h",
		},
		{
			name:    "a bound nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, max_subjects: 2}",
			wants:   "learn.max_subjects: must be between 16 and 1000000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(s7YAML, "        upstream: cpu\n"+tc.section, plc.addr())
			if _, err := config.Parse([]byte(yaml)); err == nil {
				t.Fatal("the section loaded")
			} else if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error is %v, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// A fault belongs to the request it answers and to nothing else.
//
// A controller that refuses writes and answers reads is the ordinary
// password-protected CPU. If its refusals landed on the read as well, the
// proposal would drop the read the HMI depends on -- and a commissioning run
// that produced a policy locking out the HMI is worse than no run at all.
func TestAFaultLandsOnTheOperationItAnswers(t *testing.T) {
	plc := startPLC(t, &fakePLC{faultOn: wire.FnWriteVar})
	s, addr, path := learnRelay(t, "        default_action: allow\n"+
		"        operations: [setup, read, write]", plc, true)

	cl := learnSession(t, addr)
	cl.allowed(readJob(3, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	cl.write(writeJob(4, item(wire.TransportByte, 2, 2, wire.AreaDB, 10),
		wire.TransportByte, []byte{0x01, 0x02}))
	cl.next()
	got := learnedReport(t, s, cl, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	read, write, ok := strings.Cut(obs, "    operation: write")
	if !ok {
		t.Fatalf("the write is not in the report:\n%s", obs)
	}
	if strings.Contains(read, "access_faults:") {
		t.Errorf("the write's refusal was charged to the read:\n%s", read)
	}
	if !strings.Contains(write, "access_faults: 1") {
		t.Errorf("the write's refusal was not recorded against it:\n%s", write)
	}
	// So the read is proposed and the write is not.
	if !strings.Contains(rules, "operations: [read]") {
		t.Errorf("the read the HMI depends on was not proposed:\n%s", rules)
	}
	if strings.Contains(rules, "operations: [write]") {
		t.Errorf("a write the controller refuses was proposed:\n%s", rules)
	}
}

// An answer may not invent a request nobody made.
//
// A controller that answered faults about operations no client had asked for
// could otherwise write subjects into the report -- and, through the "the
// equipment refuses this" exclusion, rules out of it.
func TestAnAnswerCannotInventASubject(t *testing.T) {
	plc := startPLC(t, &fakePLC{faultOn: wire.FnWriteVar, faultAs: wire.FnPLCStop})
	s, addr, path := learnRelay(t, "        default_action: allow\n"+
		"        operations: [setup, read, write]", plc, true)

	cl := learnSession(t, addr)
	cl.write(writeJob(4, item(wire.TransportByte, 2, 2, wire.AreaDB, 10),
		wire.TransportByte, []byte{0x01, 0x02}))
	cl.next()
	got := learnedReport(t, s, cl, path)

	if strings.Contains(got, "operation: stop") {
		t.Errorf("an answer about a stop nobody asked for became a subject:\n%s", got)
	}
	// And the write, which did happen, is still there -- the fault simply did
	// not attach to anything.
	if !strings.Contains(got, "operation: write") {
		t.Errorf("the write that did happen is not in the report:\n%s", got)
	}
	if strings.Contains(got, "access_faults:") {
		t.Errorf("a fault about another operation was charged to the write:\n%s", got)
	}
}

// An operation this package cannot name is recorded and never proposed.
//
// `operations` is a closed vocabulary. A report that proposed a rule naming
// something outside it would be a report the configuration refuses to load,
// which is the one failure a learning run cannot recover from -- the traffic it
// was measuring is gone.
func TestAnOperationWithNoNameIsRecordedAndNotProposed(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	s, addr, path := learnRelay(t, "        default_action: allow", plc, false)

	cl := learnSession(t, addr)
	// Function 0x5a is not one of the documented ones, so the policy refuses it
	// and the run records it without a name.
	cl.write(job(9, []byte{0x5a, 0x00}, nil))
	cl.next()
	got := learnedReport(t, s, cl, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	if !strings.Contains(obs, "operation: unknown") {
		t.Errorf("the unnamed operation is not in the report:\n%s", obs)
	}
	if !strings.Contains(obs, "functions: [0x5a]") {
		t.Errorf("the report does not say which function arrived:\n%s", obs)
	}
	if strings.Contains(rules, "operations: []") || strings.Contains(rules, "unknown") {
		t.Errorf("a rule was proposed for an operation with no name:\n%s", rules)
	}
	if strings.Contains(rules, "0x5a") {
		t.Errorf("the raw function code leaked into the proposal:\n%s", rules)
	}
}

// An item addressed in a syntax this package does not decode has no area and no
// block, and a report that filled those in with zeroes would be a report an
// engineer reads as fact. The operation is still recorded.
func TestAnItemWithNoAddressIsRecordedWithoutOne(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	s, addr, path := learnRelay(t, "        default_action: allow", plc, false)

	cl := learnSession(t, addr)
	// A read whose one item uses a syntax identifier outside S7ANY, which is
	// how symbolic addressing arrives.
	symbolic := join([]byte{0x12, 0x0a, 0xb0, 0x00}, be16b(1), be16b(0),
		[]byte{0x00, 0x00, 0x00, 0x00})
	cl.write(job(9, join([]byte{wire.FnReadVar, 1}, symbolic), nil))
	cl.next()
	got := learnedReport(t, s, cl, path)

	if !strings.Contains(got, "operation: read") {
		t.Errorf("a read nobody could decode the address of went unrecorded:\n%s", got)
	}
	if strings.Contains(got, "area:") || strings.Contains(got, "db:") {
		t.Errorf("the report invented an area or a block:\n%s", got)
	}
	if strings.Contains(got, "areas:") || strings.Contains(got, "dbs:") {
		t.Errorf("the proposal invented an area or a block:\n%s", got)
	}
	// Nor a byte range, nor a transport size: the item carried neither, and an
	// engineer reading `bytes: ["0"]` would think byte zero was what was asked
	// for.
	if strings.Contains(got, "bytes: [") || strings.Contains(got, "transports: [") {
		t.Errorf("the report invented a byte range or a transport size:\n%s", got)
	}
	if strings.Contains(got, "addresses: [") {
		t.Errorf("the proposal invented an address range:\n%s", got)
	}
}

// Learning with enforcement on is a listener that still refuses. The two are
// separate knobs on purpose: a run on a line that cannot be left unprotected
// keeps the policy in force and writes down what it refused.
func TestALearningRunWithEnforcementStillRefuses(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	// The negotiation is allowed and nothing else is, because a listener that
	// refused the negotiation would have no session to learn from.
	s, addr, path := learnRelay(t, `        default_action: deny
        rules:
          - {name: negotiate, action: allow, operations: [setup]}`, plc, true)

	cl := learnSession(t, addr)
	cl.refused(readJob(3, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	if plc.got("read") {
		t.Error("the read reached the controller")
	}
	got := learnedReport(t, s, cl, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the refusal is not in the report:\n%s", got)
	}
}
