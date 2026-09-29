package modbus

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
)

var (
	countPoll  = []byte{8, 0x00, 0x0B, 0x00, 0x00} // return bus message count
	listenOnly = []byte{8, 0x00, 0x04, 0x00, 0x00} // force listen only mode
	clearLog   = []byte{8, 0x00, 0x0A, 0x00, 0x00} // clear counters and diagnostic register
	umasRead   = []byte{0x5A, 0x21, 0x22}          // read variables
	umasStop   = []byte{0x5A, 0x21, 0x41}          // stop the PLC
	umasUpload = []byte{0x5A, 0x21, 0x31}          // upload a program block
	canopen    = []byte{43, 13, 0x00}              // the CANopen tunnel
)

// This is the finding, as a test. A rule allowing "diagnostic" was written
// by somebody thinking of counter polls; the same rule used to allow
// sub-function 4, which is one frame that takes a device off the bus.
func TestARuleThatOnlyNamedTheFunctionCodeDoesNotAllowTheFrameThatStopsADevice(t *testing.T) {
	p := policyFor(t, `        rules:
          - name: maintenance
            action: allow
            functions: [diagnostic]`)
	if d := p.Decide(req(t, "10.0.0.5", "", 1, countPoll)); !d.Allow {
		t.Errorf("a counter poll was refused: %+v", d)
	}
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"force listen only", listenOnly},
		{"clear counters", clearLog},
	} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, c.pdu))
		if d.Allow || d.Reason != "unsafe_sub_function" {
			t.Errorf("%s passed a rule that named the function code alone: %+v", c.what, d)
		}
		if d.Rule != "maintenance" {
			t.Errorf("%s was refused by rule %q, and the rule that permitted the code is the one to name", c.what, d.Rule)
		}
	}
}

// And this is what a plant actually wants to be able to say, which it
// could not say before: the counters yes, listen-only mode never.
func TestARuleCanAllowTheCountersAndRefuseListenOnlyMode(t *testing.T) {
	p := policyFor(t, `        rules:
          - name: no-listen-only
            action: deny
            diagnostics: [force_listen_only, restart_communications]
            comment: "one frame and the device is off the bus"
          - name: counters
            action: allow
            diagnostics: [11-18]
          - name: polls
            action: allow
            access: [read]`)
	for _, c := range []struct {
		what   string
		pdu    []byte
		allow  bool
		rule   string
		reason string
	}{
		{"a counter poll", countPoll, true, "counters", ""},
		{"force listen only", listenOnly, false, "no-listen-only", "rule_deny"},
		{"a restart", diagnose, false, "no-listen-only", "rule_deny"},
		{"a register read", readRegs, true, "polls", ""},
		// Not named by any rule, and the default is deny: a clear of the
		// counters is neither a poll a rule allowed nor a refusal a rule
		// spelled out.
		{"clearing the counters", clearLog, false, "", "no_rule"},
	} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, c.pdu))
		if d.Allow != c.allow || d.Rule != c.rule || (!c.allow && d.Reason != c.reason) {
			t.Errorf("%s: %+v, want allow %t by %q (%s)", c.what, d, c.allow, c.rule, c.reason)
		}
	}
	// The comment is what the change record is written from, so it has to
	// come back with the decision.
	if d := p.Decide(req(t, "10.0.0.5", "", 1, listenOnly)); !strings.Contains(d.Comment, "off the bus") {
		t.Errorf("the rule's comment did not reach the decision: %+v", d)
	}
}

// `diagnostics: [11-18]` above is a range, and a range of sub-function
// numbers is not something the compiler accepts -- the names and numbers
// are a list. This pins what the compiler does with each form, because a
// rule that silently compiled to nothing would be a control that is not
// one.
func TestTheWaysASubFunctionListCanBeWritten(t *testing.T) {
	for _, c := range []struct {
		in    []string
		in_   []int
		out   []int
		notIn []int
		bad   bool
	}{
		{in: []string{"force_listen_only"}, out: []int{4}, notIn: []int{3, 5}},
		{in: []string{"4"}, out: []int{4}},
		{in: []string{"0x04"}, out: []int{4}},
		{in: []string{"sub_37"}, out: []int{37}},
		{in: []string{"force_listen_only", "10"}, out: []int{4, 10}, notIn: []int{5}},
		// A range means here what it means in an address list, which is
		// what lets "the counters" be written as one entry.
		{in: []string{"11-18"}, out: []int{11, 14, 18}, notIn: []int{10, 19}},
		{in: []string{"stop_plc"}, bad: true},
		{in: []string{"65536"}, bad: true},
		{in: []string{""}, bad: true},
	} {
		r, err := compileRule(&config.ModbusRule{Name: "r", Diagnostics: c.in})
		if c.bad {
			if err == nil {
				t.Errorf("diagnostics: %q compiled", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("diagnostics: %q: %v", c.in, err)
			continue
		}
		for _, sub := range c.out {
			if !r.diags.Has(sub) {
				t.Errorf("diagnostics: %q does not cover sub-function %d", c.in, sub)
			}
		}
		for _, sub := range c.notIn {
			if r.diags.Has(sub) {
				t.Errorf("diagnostics: %q covers sub-function %d", c.in, sub)
			}
		}
	}
	// A UMAS command is a byte, so the same list written for function code
	// 90 has a tighter bound -- which is the compiler's business and not
	// only the validator's, because a learned or generated rule set does
	// not go through the validator's messages.
	for _, c := range []struct {
		in  []string
		bad bool
	}{
		{in: []string{"stop_plc"}},
		{in: []string{"0x41"}},
		{in: []string{"64-80"}},
		{in: []string{"300"}, bad: true},
		{in: []string{"200-300"}, bad: true},
		{in: []string{"force_listen_only"}, bad: true},
	} {
		_, err := compileRule(&config.ModbusRule{Name: "r", UMASCommands: c.in})
		if (err != nil) != c.bad {
			t.Errorf("umas_commands: %q: %v", c.in, err)
		}
	}
	// A rule naming a sub-function only ever matches the function code
	// that has it, whether or not the rule also named the code.
	p := policyFor(t, `        rules:
          - name: subs-only
            action: allow
            diagnostics: [force_listen_only]`)
	if d := p.Decide(req(t, "10.0.0.5", "", 1, listenOnly)); !d.Allow || d.Rule != "subs-only" {
		t.Errorf("the rule did not decide its own sub-function: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.5", "", 1, readRegs)); d.Allow {
		t.Errorf("a rule about a diagnostic sub-function matched a register read: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.5", "", 1, countPoll)); d.Allow {
		t.Errorf("a rule about sub-function 4 matched sub-function 11: %+v", d)
	}
}

// The vendor half. UMAS is a protocol inside function code 90, and a
// policy that could only say "vendor" could not tell a variable read from
// a PLC stop.
func TestAUMASRuleDecidesPerCommand(t *testing.T) {
	p := policyFor(t, `        rules:
          - name: engineering-reads
            action: allow
            clients: [10.0.0.9/32]
            functions: [umas]
            umas_commands: [init_comm, keep_alive, take_plc_reservation, release_plc_reservation, read_variables, read_id]
          - name: no-program-change
            action: deny
            umas_commands: [stop_plc, start_plc, upload_block, download_block]
            comment: "a program change goes through the change process, not the relay"`)
	for _, c := range []struct {
		what   string
		client string
		pdu    []byte
		allow  bool
		reason string
	}{
		{"a variable read from the engineering station", "10.0.0.9", umasRead, true, ""},
		{"a stop from the engineering station", "10.0.0.9", umasStop, false, "rule_deny"},
		{"a block upload from the engineering station", "10.0.0.9", umasUpload, false, "rule_deny"},
		{"a variable read from anywhere else", "10.0.0.5", umasRead, false, "no_rule"},
	} {
		d := p.Decide(req(t, c.client, "", 1, c.pdu))
		if d.Allow != c.allow || (!c.allow && d.Reason != c.reason) {
			t.Errorf("%s: %+v, want allow %t (%s)", c.what, d, c.allow, c.reason)
		}
	}
	// And a UMAS command nobody here can read is not allowed by a rule
	// written about the commands that are readable.
	d := p.Decide(req(t, "10.0.0.9", "", 1, []byte{0x5A, 0x21, 0x90}))
	if d.Allow {
		t.Errorf("an unreadable UMAS command was allowed: %+v", d)
	}
}

// A rule about an effect is the one that outlives the code that carried
// it: "nothing that stops a device or changes its program" is one rule
// across function code 8, function code 90 and the tunnel in 43.
func TestARuleAboutAnEffectCoversWhicheverFunctionCodeCarriedIt(t *testing.T) {
	p := policyFor(t, `        default_action: allow
        rules:
          - name: nothing-destructive
            action: deny
            effects: [control, program, clear, unknown]
            comment: "the plant's own change process decides these"`)
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"force listen only", listenOnly},
		{"clearing the counters", clearLog},
		{"a UMAS stop", umasStop},
		{"a UMAS block upload", umasUpload},
		{"the CANopen tunnel", canopen},
	} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, c.pdu))
		if d.Allow || d.Reason != "rule_deny" || d.Rule != "nothing-destructive" {
			t.Errorf("%s: %+v, want a deny by nothing-destructive", c.what, d)
		}
	}
	// And a frame with no sub-function at all is not matched by a rule
	// about effects: a register write is a thing to decide with a value
	// bound, not with this.
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"a register read", readRegs},
		{"a register write", writeReg},
		{"a counter poll", countPoll},
		{"a UMAS variable read", umasRead},
	} {
		if d := p.Decide(req(t, "10.0.0.5", "", 1, c.pdu)); !d.Allow {
			t.Errorf("%s was caught by a rule about destructive effects: %+v", c.what, d)
		}
	}
}

// default_action: allow is the least deliberate thing in a configuration,
// so it is the last place a frame that stops a PLC should get through.
func TestADefaultAllowDoesNotAllowAFrameThatStopsADevice(t *testing.T) {
	p := policyFor(t, `        default_action: allow`)
	if d := p.Decide(req(t, "10.0.0.5", "", 1, countPoll)); !d.Allow {
		t.Errorf("a counter poll was refused by a default-allow listener: %+v", d)
	}
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"force listen only", listenOnly},
		{"a UMAS stop", umasStop},
		{"the CANopen tunnel", canopen},
	} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, c.pdu))
		if d.Allow || d.Reason != "unsafe_sub_function" {
			t.Errorf("%s passed a default-allow listener: %+v", c.what, d)
		}
	}
}

// The guard is a default and not a law: a listener that has a reason to
// hand a whole function code back says so, visibly, and the validator
// warns about it.
func TestTurningTheGuardOffGivesTheWholeFunctionCodeBack(t *testing.T) {
	p := policyFor(t, `        refuse_unsafe_sub_functions: false
        rules:
          - name: maintenance
            action: allow
            functions: [diagnostic, umas]`)
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"a counter poll", countPoll},
		{"force listen only", listenOnly},
		{"a UMAS stop", umasStop},
	} {
		if d := p.Decide(req(t, "10.0.0.5", "", 1, c.pdu)); !d.Allow {
			t.Errorf("%s was refused with the guard off: %+v", c.what, d)
		}
	}
}

// A read-only listener answers the vendor half without needing any of
// this: UMAS is not a read, whichever command it carries.
func TestAReadOnlyListenerRefusesUMASWhateverTheCommand(t *testing.T) {
	p := policy(t, &config.ModbusListener{
		ReadOnly: true,
		Rules:    []config.ModbusRule{{Name: "everything", Action: "allow"}},
	}, time.Now())
	for _, pdu := range [][]byte{umasRead, umasStop, umasUpload} {
		d := p.Decide(req(t, "10.0.0.5", "", 1, pdu))
		if d.Allow || d.Reason != "read_only" {
			t.Errorf("UMAS %x passed a read-only listener: %+v", pdu[2], d)
		}
	}
}

// An observe rule records and decides nothing, and that has to stay true
// of the sub-function selectors: a rule tried out on live traffic must not
// start refusing frames because it happens to name a sub-function.
func TestAnObserveRuleNamingASubFunctionStillDecidesNothing(t *testing.T) {
	p := policyFor(t, `        default_action: allow
        rules:
          - name: watch-the-stops
            action: observe
            effects: [control]`)
	d := p.Decide(req(t, "10.0.0.5", "", 1, umasStop))
	if d.Allow || d.Reason != "unsafe_sub_function" {
		// The observe rule carried on, so the default decided -- and the
		// default does not allow a stop.
		t.Errorf("a UMAS stop under an observe rule: %+v", d)
	}
	names := p.Observed(req(t, "10.0.0.5", "", 1, umasStop))
	if len(names) != 1 || names[0] != "watch-the-stops" {
		t.Errorf("the observe rule did not record the stop: %v", names)
	}
	if names := p.Observed(req(t, "10.0.0.5", "", 1, readRegs)); len(names) != 0 {
		t.Errorf("the observe rule recorded a register read: %v", names)
	}
}

// The refusal has to reach a master as something its own diagnostics make
// sense of, and "illegal function" is what a sub-function refusal is.
func TestASubFunctionRefusalIsAnIllegalFunctionException(t *testing.T) {
	if got := exceptionFor(Decision{Reason: "unsafe_sub_function"}); got != wire.ExIllegalFunction {
		t.Errorf("exception 0x%02x, want illegal function 0x%02x", got, wire.ExIllegalFunction)
	}
}

// The trace is where an engineer reads what a master is actually doing, so
// "function: diagnostic" is not enough on its own: the line has to say
// whether a device was polled or taken off the bus.
func TestTheTraceNamesTheSubFunction(t *testing.T) {
	dir := t.TempDir()
	tr, err := NewTracer("plant", dir+"/trace.jsonl", 1<<20, false, true, true)
	if err != nil {
		t.Fatalf("tracer: %v", err)
	}
	defer tr.Close()
	for _, pdu := range [][]byte{listenOnly, umasStop} {
		p, err := wire.ParseRequest(pdu)
		if err != nil {
			t.Fatalf("pdu %x: %v", pdu, err)
		}
		tr.Request(TraceEntry{Client: "10.0.0.5", Unit: 1}, p, pdu)
	}
	body := traceBody(t, dir+"/trace.jsonl")
	for _, want := range []string{
		`"sub_function":"force_listen_only"`,
		`"effect":"control"`,
		`"sub_function":"stop_plc"`,
		`"umas_session":33`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the trace does not carry %s:\n%s", want, body)
		}
	}
	// A frame with no sub-function carries none of those fields rather
	// than carrying them empty.
	p, err := wire.ParseRequest(readRegs)
	if err != nil {
		t.Fatal(err)
	}
	tr.Request(TraceEntry{Client: "10.0.0.5", Unit: 1}, p, readRegs)
	for _, line := range strings.Split(strings.TrimSpace(traceBody(t, dir+"/trace.jsonl")), "\n") {
		if strings.Contains(line, "read_holding_registers") && strings.Contains(line, "sub_function") {
			t.Errorf("a register read traced a sub-function: %s", line)
		}
	}
}

// traceBody reads the trace file the test just wrote.
func traceBody(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the trace: %v", err)
	}
	return string(b)
}

// A learning run writes the rules a plant starts from, and a listener now
// refuses the dangerous sub-functions to a rule that did not name them. So
// the report has to name them: a learned rule that said `functions:
// [diagnostic]` and nothing else would be a rule that does not permit the
// traffic it was generated from, and the difference would surface on the
// shift after enforcement went on rather than here.
func TestTheLearnedRuleNamesTheSubFunctionItWasLearnedFrom(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	day := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	l.Observe(req(t, "10.0.0.7", "", 3, countPoll), true, day)
	l.Observe(req(t, "10.0.0.7", "", 3, listenOnly), false, day.Add(time.Second))
	l.Observe(req(t, "10.0.0.9", "engineer", 3, umasRead), true, day)
	l.Observe(req(t, "10.0.0.9", "engineer", 3, canopen), true, day)

	r := l.Report()
	for _, want := range []string{
		// The observation says which sub-function and what it does, so an
		// engineer reading the report can see the difference the function
		// code alone hides.
		"sub_function: return_bus_message_count",
		"effect: read",
		"sub_function: force_listen_only",
		"effect: control",
		"sub_function: read_variables",
		// And the rules name them in the field the policy reads.
		"diagnostics: [return_bus_message_count]",
		"diagnostics: [force_listen_only]",
		"umas_commands: [read_variables]",
		// The encapsulated interface has no selector of its own, so the
		// MEI type is named by what it does.
		"effects: [unknown]",
		"name: learned-10-0-0-7-u3-diagnostic_return_bus_message_count",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("the report does not carry %q:\n%s", want, r)
		}
	}
	// The two halves of function code 8 are two subjects, not one activity
	// reported as a range: a report that merged them would propose a rule
	// allowing `diagnostic`, which is a rule allowing an outage.
	if n := strings.Count(r, "function: diagnostic\n"); n != 2 {
		t.Errorf("function code 8 was reported as %d subjects, want 2:\n%s", n, r)
	}

	// And what the report proposes compiles, and permits what was seen.
	p := policyFor(t, `        rules:
          - name: learned-counters
            action: allow
            clients: [10.0.0.7/32]
            units: [3]
            functions: [diagnostic]
            diagnostics: [return_bus_message_count]`)
	if d := p.Decide(req(t, "10.0.0.7", "", 3, countPoll)); !d.Allow {
		t.Errorf("the learned rule refuses the traffic it was learned from: %+v", d)
	}
	if d := p.Decide(req(t, "10.0.0.7", "", 3, listenOnly)); d.Allow {
		t.Errorf("the learned rule allows the frame it was not learned from: %+v", d)
	}
}

// A rule whose only sub-function selector is an effect still names the
// sub-function, so it may allow one of the four the listener otherwise
// refuses. "The engineering station may start the PLC" is a policy, and it
// is written this way.
func TestAnAllowRuleNamingAnEffectMayAllowOneOfTheRefusedOnes(t *testing.T) {
	p := policyFor(t, `        rules:
          - name: engineering-may-start
            action: allow
            clients: [10.0.0.9/32]
            effects: [control]`)
	for _, c := range []struct {
		what   string
		client string
		pdu    []byte
		allow  bool
	}{
		{"a start from the engineering station", "10.0.0.9", []byte{0x5A, 0x21, 0x40}, true},
		{"a restart from the engineering station", "10.0.0.9", diagnose, true},
		{"a start from anywhere else", "10.0.0.5", []byte{0x5A, 0x21, 0x40}, false},
		// The rule is about control and nothing else, so a block download
		// from the same station is not covered by it.
		{"a block upload from the engineering station", "10.0.0.9", umasUpload, false},
	} {
		if d := p.Decide(req(t, c.client, "", 1, c.pdu)); d.Allow != c.allow {
			t.Errorf("%s: %+v, want allow %t", c.what, d, c.allow)
		}
	}
}

// The sub-function numbers are not one namespace, and this is the pair
// that proves a rule cannot cross them: sub-function 4 of a diagnostic
// forces listen-only mode, and UMAS command 4 reads the PLC's identity.
func TestASubFunctionRuleDoesNotReachAnotherFunctionCodesNumber(t *testing.T) {
	p := policyFor(t, `        rules:
          - name: no-sub-4
            action: deny
            diagnostics: ["4"]
          - name: umas-reads
            action: allow
            umas_commands: ["4"]
          - name: reads
            action: allow
            access: [read]`)
	if d := p.Decide(req(t, "10.0.0.5", "", 1, listenOnly)); d.Allow || d.Rule != "no-sub-4" {
		t.Errorf("diagnostic sub-function 4: %+v, want a deny by no-sub-4", d)
	}
	// UMAS command 4 is read_plc_info. The deny above names the number 4
	// in the diagnostic namespace, so it must not reach this frame.
	d := p.Decide(req(t, "10.0.0.5", "", 1, []byte{0x5A, 0x21, 0x04}))
	if !d.Allow || d.Rule != "umas-reads" {
		t.Errorf("UMAS command 4: %+v, want an allow by umas-reads", d)
	}
}

// A diagnostic sub-function this relay has no name for is refused to a
// rule that named the function code alone -- the same as the ones it does
// know, and for the stronger reason: nothing here can say what it does.
func TestADiagnosticSubFunctionNobodyKnowsIsRefusedToARuleThatNamedTheCode(t *testing.T) {
	p := policyFor(t, `        rules:
          - name: maintenance
            action: allow
            functions: [diagnostic]`)
	unknown := []byte{8, 0x00, 0x25, 0x00, 0x00} // sub-function 37
	d := p.Decide(req(t, "10.0.0.5", "", 1, unknown))
	if d.Allow || d.Reason != "unsafe_sub_function" {
		t.Errorf("an unrecognised diagnostic sub-function: %+v", d)
	}
	// And a rule that names it decides it, which is the only way it passes.
	p = policyFor(t, `        rules:
          - name: that-one-diagnostic
            action: allow
            diagnostics: [sub_37]`)
	if d := p.Decide(req(t, "10.0.0.5", "", 1, unknown)); !d.Allow {
		t.Errorf("a rule naming sub_37 did not allow it: %+v", d)
	}
}

// The security event and the access line are the audit trail, and "unit 3,
// diagnostic, refused" is not one: the function code is the same for a
// counter poll and for the frame that took the device off the bus.
func TestTheLogLineNamesTheSubFunction(t *testing.T) {
	for _, c := range []struct {
		what string
		pdu  []byte
		want []any
	}{
		{"force listen only", listenOnly, []any{"sub_function", "force_listen_only", "effect", "control"}},
		{"a counter poll", countPoll, []any{"sub_function", "return_bus_message_count", "effect", "read"}},
		{"a UMAS stop", umasStop, []any{"sub_function", "stop_plc", "effect", "control",
			"umas_session", byte(0x21)}},
		{"a register read", readRegs, nil},
	} {
		p, err := wire.ParseRequest(c.pdu)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		got := subAttrs(nil, p)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.what, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: attr %d is %v, want %v", c.what, i, got[i], c.want[i])
			}
		}
	}
}
