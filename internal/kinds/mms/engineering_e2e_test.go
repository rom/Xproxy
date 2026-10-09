package mms

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// "Downloads into an IED only during an approved window", through the whole
// listener: the classification is unit-tested next door, and what has to be
// true here is that the relay asked the ledger, reported the operation
// whatever the answer, refused it where this listener requires a grant, and
// carried the same request once a supervisor had approved one.

// engSection is a listener that carries the domain services, which is what
// makes a download reach the engineering decision at all: the service list is
// a separate knob from `allow_domain_services`, and a request the policy
// refused never gets as far as the ledger.
const engSection = `        upstream: ieds
        default_action: allow
        allow_domain_services: true
        write_constraints: [ST, MX, SP, CF, SG]
`

// engRelay starts a relay with its own top-level sections: the access ledger a
// grant is written in sits outside the listener.
func engRelay(t *testing.T, section, top, ied string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: substation
      address: "127.0.0.1:0"
      kind: mms
      mms:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: ieds, endpoints: [{address: %q}]}
`, top, section, ied))
	return s, proxytest.Addr(t, s, "substation")
}

// apTitle is the AP-title the session helper's association carries, which is
// the subject a grant for it is filed against.
const apTitle = "1.1.999.1"

// engLedger is the `access` section, with four eyes: the person who asks for a
// window is not the person who approves it.
func engLedger(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
}

// awaitEng waits for a snapshot to satisfy a condition, which is how these
// tests read a counter without racing the goroutine that writes it.
func awaitEng(t *testing.T, s *proxy.Server, what string, ok func(proxy.Snapshot) bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s never happened; refusals %v, would-refuse %v, engineering %v, outside %v",
		what, sn.Refusals["mms"], sn.WouldRefusals["mms"], sn.EngineeringOps,
		sn.EngineeringOutside)
}

// securityEvents collects the security log, which is where the engineering
// record and the alert beside it are written.
type securityEvents struct {
	mu     sync.Mutex
	events []engEvent
}

type engEvent struct {
	action, reason string
	attrs          map[string]any
}

func (c *securityEvents) SecurityEvent(action, reason string, attrs []any) {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	c.mu.Lock()
	c.events = append(c.events, engEvent{action: action, reason: reason, attrs: m})
	c.mu.Unlock()
}

// find waits for an event with this reason and returns it.
func (c *securityEvents) find(t *testing.T, reason string) engEvent {
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
	return engEvent{}
}

func (c *securityEvents) forget() {
	c.mu.Lock()
	c.events = nil
	c.mu.Unlock()
}

// seen says whether an event with this reason has arrived, for the assertions
// that are about silence.
func (c *securityEvents) seen(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.reason == reason {
			return true
		}
	}
	return false
}

// A download with nothing open is refused and the IED never hears about it;
// the same download goes through once a supervisor has approved a window.
//
// This is the operation this listener most exists to refuse. A domain download
// replaces the content of a protection relay, and it is one request: there is
// no partial state to roll back to if it is allowed by mistake.
func TestADownloadIntoAnIEDNeedsAnApprovedGrant(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := engRelay(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), ied.addr())
	cl := session(t, addr)

	answer := cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	if !isError(t, answer) {
		t.Error("the client was not told: the answer is not an MMS error")
	}
	awaitEng(t, s, "the refusal and the engineering event", func(sn proxy.Snapshot) bool {
		return sn.Refusals["mms"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["mms/program_download"] >= 1
	})
	if ied.sawService(wire.SvcInitiateDownloadSequence) {
		t.Errorf("the download reached the IED: %v", ied.seen())
	}

	// The operation is in the hash-chained trail whether or not it was
	// carried, which is the record an audit asks for a year later.
	led := s.Access()
	if led == nil {
		t.Fatal("the daemon has no access ledger")
	}
	if got := led.Stats().Engineering; got == 0 {
		t.Error("the refused operation was not written to the trail")
	}

	// A window, asked for by the engineer and approved by somebody else. The
	// subject is the association's own AP-title, not its address: on this
	// protocol the client says who it is.
	g, err := led.Request(access.Request{Subject: apTitle, Listener: "substation",
		Target: "ieds", Reason: "change 4711: new protection settings for feeder 1",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the outage meeting"); err != nil {
		t.Fatal(err)
	}

	cl2 := session(t, addr)
	cl2.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the approved download")
}

// An upload is the same decision in the other direction, and it is the one a
// substation is more likely to see: this is how a utility's protection
// settings leave the site.
func TestAnUploadIsEngineeringToo(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := engRelay(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), ied.addr())
	cl := session(t, addr)

	if !isError(t, cl.service(serviceBody(1, wire.SvcInitiateUploadSequence, "AA1J1Q01A1LD0"))) {
		t.Error("the client was not told")
	}
	awaitEng(t, s, "the upload refused as engineering", func(sn proxy.Snapshot) bool {
		return sn.Refusals["mms"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["mms/program_upload"] >= 1
	})
}

// A setting-group write is engineering although it is an ordinary Write to an
// ordinary object: on this protocol the object name is the whole difference
// between changing a relay's trip characteristic and reading a measurement.
func TestASettingWriteIsEngineeringOnAnAllowedConstraint(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := engRelay(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), ied.addr())
	cl := session(t, addr)

	answer := cl.service(writeBody(1,
		objectName("AA1J1Q01A1LD0", "PTOC1$SG$StrVal$setMag$f")))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	awaitEng(t, s, "the setting write refused as engineering", func(sn proxy.Snapshot) bool {
		return sn.Refusals["mms"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["mms/configuration"] >= 1
	})
	if ied.sawService(wire.SvcWrite) {
		t.Errorf("the setting write reached the IED: %v", ied.seen())
	}

	// And the event names the object, which is what makes the record worth
	// having: "a setting changed" is not a finding, "$SG$StrVal on PTOC1
	// changed" is.
	cap := &securityEvents{}
	s.Logs().Watch(cap)
	cl2 := session(t, addr)
	cl2.service(writeBody(1, objectName("AA1J1Q01A1LD0", "PTOC1$SG$StrVal$setMag$f")))
	ev := cap.find(t, "engineering_configuration")
	if got := ev.attrs["object"]; got != "AA1J1Q01A1LD0/PTOC1$SG$StrVal$setMag$f" {
		t.Errorf("the event names object %v", got)
	}
	if got := ev.attrs["identity"]; got != apTitle {
		t.Errorf("identity %v, want the association's AP-title %v", got, apTitle)
	}
}

// A work order changes the tone and permits nothing, which is the pair of
// claims worth testing together. If a work order stood in for an approval the
// person who wanted the access could file one for themselves, and four eyes
// would be decoration.
func TestAWorkOrderChangesTheToneOfAnMMSDownload(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	// action: alert is the step an estate takes first: be told when a download
	// happens outside a window, before refusing them.
	s, addr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), ied.addr())
	cap := &securityEvents{}
	s.Logs().Watch(cap)

	cl := session(t, addr)
	cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the download, which this listener only reports")
	ev := cap.find(t, "engineering_program_download")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}
	awaitEng(t, s, "the operation recorded as outside every window", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["mms/program_download"] >= 1
	})
	if n := s.Stats().Refusals["mms"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a listener that only alerts refused anyway: %d", n)
	}

	// Now file one against the pool this listener reaches.
	led := s.Access()
	if _, err := led.FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "ieds", Note: "protection settings for feeder 1", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap.forget()

	cl2 := session(t, addr)
	cl2.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ev = cap.find(t, "engineering_program_download")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	awaitEng(t, s, "the operation under a work order", func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["mms/program_download"] >= 1
	})

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline filters on.
	alert := cap.find(t, "mms_engineering_ungranted")
	if got := alert.attrs["severity"]; got != "notice" {
		t.Errorf("the ungranted alert stayed at %v although the work was filed", got)
	}
	if got := alert.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("the ungranted alert names work_order %v", got)
	}

	// And a listener that requires a grant refuses the same operation, work
	// order or not.
	strict, saddr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n", engLedger(t), ied.addr())
	if _, err := strict.Access().FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0482",
		Device: "ieds", Note: "the same work, filed", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	sc := session(t, saddr)
	if !isError(t, sc.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))) {
		t.Error("a work order lifted the refusal")
	}
	awaitEng(t, strict, "the refusal a work order must not lift", func(sn proxy.Snapshot) bool {
		return sn.Refusals["mms"]["engineering_no_grant"] >= 1
	})
}

// A shadow listener says what it would have refused and forwards it, which is
// how an estate finds out how many windows it would have to file before it
// turns the refusal on.
func TestAShadowListenerSaysWhatTheEngineeringGateWouldHaveRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := engRelay(t, engSection+
		"        monitor_only: true\n"+
		"        engineering:\n          require_grant: true\n",
		engLedger(t), ied.addr())
	cl := session(t, addr)

	cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the download a shadow listener forwards")
	awaitEng(t, s, "the shadow record", func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["mms"]["engineering_no_grant"] >= 1
	})
	if n := s.Stats().Refusals["mms"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a shadow listener refused: %d", n)
	}
}

// alert_on_deny off silences the alert and nothing else: the operation is
// still reported, still counted and still refused. The two halves are
// separately useful -- an estate that has turned the per-refusal alert off
// because the policy is noisy has not asked to stop hearing about downloads.
func TestEngineeringAlertsFollowAlertOnDeny(t *testing.T) {
	for _, tc := range []struct {
		name, section, alert string
	}{
		{"refused", "        engineering:\n          require_grant: true\n",
			"mms_engineering_no_grant"},
		{"carried outside every window",
			"        engineering:\n          require_grant: true\n          action: alert\n",
			"mms_engineering_ungranted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ied := startIED(t, &fakeIED{})
			s, addr := engRelay(t, engSection+"        alert_on_deny: false\n"+tc.section,
				engLedger(t), ied.addr())
			cap := &securityEvents{}
			s.Logs().Watch(cap)

			cl := session(t, addr)
			cl.serviceQuiet(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
			// The report is the event that is not an alert, so waiting for it
			// proves the decision ran before the silence is asserted.
			cap.find(t, "engineering_program_download")
			if cap.seen(tc.alert) {
				t.Errorf("%s was raised although alert_on_deny is off", tc.alert)
			}
		})
	}
}

// With the block turned off the listener decides nothing about engineering:
// no report, no counter, no refusal. It is the one way to carry a download
// through a listener that has a ledger without filing anything, and it is
// stated rather than inferred.
func TestEngineeringCanBeTurnedOff(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := engRelay(t, engSection+"        engineering:\n          enabled: false\n",
		engLedger(t), ied.addr())
	cl := session(t, addr)

	cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the download")
	sn := s.Stats()
	if n := sn.EngineeringOps["mms/program_download"]; n != 0 {
		t.Errorf("the operation was reported anyway: %d", n)
	}
	if n := sn.Refusals["mms"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
}

// The trail ties the operation to the window it happened in, which is the
// question an audit actually asks: not "was there a grant" but "which grant
// was this download under".
func TestTheTrailTiesTheDownloadToItsGrant(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	dir := t.TempDir()
	ledger := filepath.Join(dir, "access.jsonl")
	top := fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h", ledger)
	s, addr := engRelay(t, engSection+"        engineering:\n          require_grant: true\n",
		top, ied.addr())

	led := s.Access()
	g, err := led.Request(access.Request{Subject: apTitle, Listener: "substation",
		Target: "ieds", Reason: "change 4711", By: "engineer",
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed"); err != nil {
		t.Fatal(err)
	}

	cap := &securityEvents{}
	s.Logs().Watch(cap)
	cl := session(t, addr)
	cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the approved download")

	ev := cap.find(t, "engineering_program_download")
	if got := ev.attrs["grant"]; got != g.ID {
		t.Errorf("the event names grant %v, want %v", got, g.ID)
	}
	if got, ok := ev.attrs["grant_reason"]; !ok || !strings.Contains(fmt.Sprint(got), "4711") {
		t.Errorf("the event does not carry the reason the window was opened: %v", got)
	}
	b, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"class":"program_download"`) {
		t.Errorf("the trail does not carry the operation:\n%s", b)
	}
}

// An association that sent no AP-title is its address, and a grant filed for
// that address admits it.
//
// IEC 61850 does not require the AP-title, so this is a client an estate
// really has. The identity a log line shows for one is a placeholder saying
// which part is missing -- "<no ap-title>" -- and that is a label rather than
// a subject: keyed on it, one approved window would admit every unnamed client
// on the listener, and the address, the only thing an operator can see about
// such a client, could never be approved at all. So the subject falls back to
// the address, and this test is both halves of that: the window for the
// address works, and the placeholder is not what the ledger was asked about.
func TestAnAssociationWithNoIdentityIsItsAddress(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := engRelay(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), ied.addr())

	// No AP-title: the association carries the presentation context and the
	// qualifier and nothing that says who is calling.
	cl := dial(t, addr)
	cl.connect()
	cl.associate(nil, 12, "")
	cl.initiate()

	if !isError(t, cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))) {
		t.Error("the client was not told")
	}
	awaitEng(t, s, "the refusal", func(sn proxy.Snapshot) bool {
		return sn.Refusals["mms"]["engineering_no_grant"] >= 1
	})

	led := s.Access()
	// A window for the placeholder admits nothing, because that is not what
	// the ledger was asked about.
	ph, err := led.Request(access.Request{Subject: "<no ap-title>", Listener: "substation",
		Target: "ieds", Reason: "a window filed against the label", By: "engineer",
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(ph.ID, "supervisor", "agreed"); err != nil {
		t.Fatal(err)
	}
	cl2 := dial(t, addr)
	cl2.connect()
	cl2.associate(nil, 12, "")
	cl2.initiate()
	if !isError(t, cl2.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))) {
		t.Error("a window filed against the placeholder admitted the download")
	}

	// A window for the address does.
	g, err := led.Request(access.Request{Subject: "127.0.0.1", Listener: "substation",
		Target: "ieds", Reason: "change 4712: the engineering laptop has no AP-title",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the outage meeting"); err != nil {
		t.Fatal(err)
	}
	cl3 := dial(t, addr)
	cl3.connect()
	cl3.associate(nil, 12, "")
	cl3.initiate()
	cl3.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the download under a window filed for the address")
}
