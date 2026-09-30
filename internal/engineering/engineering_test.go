package engineering

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
)

// What a block means, which is the part an operator gets wrong: an absent block
// reports and requires nothing, `enabled: false` is silence, and a class named
// without require_grant is a mistake rather than a default.

func TestAnAbsentBlockStillReports(t *testing.T) {
	g, err := FromConfig(nil, "s7", "cell", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !g.On() {
		t.Fatal("an absent block turned reporting off, so a program download would not be in the log")
	}
	if p := g.Policy(); p.RequireGrant || p.Deny || p.Ledger {
		t.Errorf("an absent block asks for something: %+v", p)
	}
	// And it decides nothing, because there is no ledger to ask.
	var reported int
	reason := g.Decide(Operation{Class: ClassProgramDownload}, "10.0.0.8", "plc", nil, true,
		Handler{Report: func(Operation, *access.Grant) { reported++ }})
	if reason != "" || reported != 1 {
		t.Errorf("reason %q reported %d", reason, reported)
	}
}

func TestEnabledFalseIsSilence(t *testing.T) {
	off := false
	g, err := FromConfig(&config.Engineering{Enabled: &off}, "s7", "cell", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g.On() {
		t.Error("enabled: false still reports")
	}
	if got := g.Decide(Operation{Class: ClassProgramDownload}, "x", "p", nil, true, Handler{}); got != "" {
		t.Errorf("a nil guard refused %q", got)
	}
}

func TestAClassNamedWithoutRequireGrantIsRefused(t *testing.T) {
	_, err := FromConfig(&config.Engineering{Classes: []string{"program_download"}}, "s7", "cell", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "without require_grant") {
		t.Errorf("error %v", err)
	}
	_, err = FromConfig(&config.Engineering{RequireGrant: true, Classes: []string{"nonsense"}}, "s7", "cell", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not one this project recognises") {
		t.Errorf("error %v", err)
	}
	_, err = FromConfig(&config.Engineering{Action: "tarpit"}, "s7", "cell", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "alert or deny") {
		t.Errorf("error %v", err)
	}
}

func TestCoversIsEveryClassUnlessSomeAreNamed(t *testing.T) {
	all := Policy{RequireGrant: true}
	for _, c := range Classes() {
		if !all.Covers(c) {
			t.Errorf("require_grant on its own does not cover %s", c)
		}
	}
	some := Policy{RequireGrant: true, Classes: map[Class]bool{ClassProgramDownload: true}}
	if !some.Covers(ClassProgramDownload) || some.Covers(ClassModeChange) {
		t.Error("a named class list covers the wrong classes")
	}
	if (Policy{}).Covers(ClassProgramDownload) {
		t.Error("a block that requires nothing covers something")
	}
}

// The whole point, end to end against a real ledger: a download with no work
// order is refused where the listener requires one, carried and alerted where it
// does not, and carried where a grant is open -- and every one of the three is
// written to the hash-chained trail.
func TestTheWorkOrderDecides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	led, err := access.Open(path, access.Policy{Approvals: 1, MaxDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = led.Close() }()

	deny, err := FromConfig(&config.Engineering{RequireGrant: true}, "s7", "cell", led, nil)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Class: ClassProgramDownload, Detail: "download block DB12"}
	var refused, ungranted, reported int
	h := Handler{
		Report:    func(Operation, *access.Grant) { reported++ },
		Ungranted: func(Operation, string) { ungranted++ },
		Refused:   func(Operation, string) { refused++ },
	}
	if got := deny.Decide(op, "eng-1", "plc", nil, true, h); got != ReasonNoGrant {
		t.Errorf("a download with no work order: %q", got)
	}
	if refused != 1 || reported != 1 || ungranted != 0 {
		t.Errorf("calls refused=%d reported=%d ungranted=%d", refused, reported, ungranted)
	}

	// The same operation on a listener that only wants to be told.
	tell, err := FromConfig(&config.Engineering{}, "s7", "cell", led, nil)
	if err != nil {
		t.Fatal(err)
	}
	refused, ungranted, reported = 0, 0, 0
	if got := tell.Decide(op, "eng-1", "plc", nil, true, h); got != "" {
		t.Errorf("a listener that requires nothing refused %q", got)
	}
	if ungranted != 1 || refused != 0 {
		t.Errorf("an operation outside every window was not alerted: %d", ungranted)
	}

	// And with a grant open, it goes through with the grant on the event.
	g, err := led.Request(access.Request{Subject: "eng-1", Listener: "cell", Target: "plc",
		Reason: "change 4711: recipe download", By: "eng-1",
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "approved at the morning meeting"); err != nil {
		t.Fatal(err)
	}
	var seen *access.Grant
	if got := deny.Decide(op, "eng-1", "plc", nil, true, Handler{
		Report: func(_ Operation, gr *access.Grant) { seen = gr },
	}); got != "" {
		t.Errorf("an approved download was refused: %q", got)
	}
	if seen == nil || seen.ID != g.ID {
		t.Fatalf("the event did not carry the work order: %+v", seen)
	}

	// The trail has all three, and says which had a grant and which did not.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(string(b), `"kind":"engineering"`)
	if lines != 3 {
		t.Errorf("the ledger holds %d engineering records of 3:\n%s", lines, b)
	}
	if n := strings.Count(string(b), `"refusal":"no_grant"`); n != 2 {
		t.Errorf("%d records name the refusal, wanted 2", n)
	}
	if got := led.Stats().Engineering; got != 3 {
		t.Errorf("the ledger counted %d engineering records", got)
	}
}

// Shadow mode records what enforcing would have cost and carries the operation,
// which is the same contract every other decision on these listeners has.
func TestShadowModeRecordsAndCarries(t *testing.T) {
	dir := t.TempDir()
	led, err := access.Open(filepath.Join(dir, "l.jsonl"), access.Policy{Approvals: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = led.Close() }()
	g, err := FromConfig(&config.Engineering{RequireGrant: true}, "mms", "bay", led, nil)
	if err != nil {
		t.Fatal(err)
	}
	var would int
	if got := g.Decide(Operation{Class: ClassConfiguration}, "who", "ied", nil, false,
		Handler{Would: func(Operation, string) { would++ }}); got != "" {
		t.Errorf("shadow mode refused %q", got)
	}
	if would != 1 {
		t.Errorf("the would-be refusal was not recorded: %d", would)
	}
}

func TestEveryClassHasAReasonAndEveryReasonIsNamed(t *testing.T) {
	for _, c := range Classes() {
		if !Known(string(c)) {
			t.Errorf("%s is not Known", c)
		}
		if got := Reason(c); got != "engineering_"+string(c) {
			t.Errorf("Reason(%s) = %q", c, got)
		}
	}
	if Known("program_downloads") {
		t.Error("a name that is not a class was accepted")
	}
	if got := len(Reasons()); got != len(Classes())+2 {
		t.Errorf("%d reasons for %d classes", got, len(Classes()))
	}
	if got := (Operation{Class: ClassProgramDownload, Detail: "d", Point: "DB12"}).String(); got != "program_download d DB12" {
		t.Errorf("String() = %q", got)
	}
}
