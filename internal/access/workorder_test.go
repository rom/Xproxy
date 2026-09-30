package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openLedger(t *testing.T, pol Policy) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.jsonl")
	l, err := Open(path, pol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

// Filing, extending, closing: the three acts, and what each one leaves in the
// trail.
func TestAWorkOrderIsFiledExtendedAndClosed(t *testing.T) {
	l, path := openLedger(t, Policy{})
	now := time.Now()
	v, err := l.FileWorkOrder(WorkOrder{Reference: "WO-1", Device: "plc-line1",
		Note: "drive replacement", By: "maintenance", Expires: now.Add(8 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if v.State != OrderOpen {
		t.Errorf("state %q: a window that starts now is open", v.State)
	}
	if l.OpenWorkOrders() != 1 {
		t.Errorf("open %d", l.OpenWorkOrders())
	}

	// Filing the same reference again extends it rather than making a second.
	if _, err := l.FileWorkOrder(WorkOrder{Reference: "WO-1", Device: "plc-line1",
		Note: "drive replacement, overrunning", By: "maintenance",
		Expires: now.Add(16 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := l.WorkOrders(); len(got) != 1 {
		t.Fatalf("filing the same reference again made %d records", len(got))
	}
	if got := l.WorkOrders()[0].Note; !strings.Contains(got, "overrunning") {
		t.Errorf("the extension did not replace the record: %q", got)
	}

	// Closing ends it, and the record says who.
	if _, err := l.CloseWorkOrder("WO-1", "supervisor", "work finished early"); err != nil {
		t.Fatal(err)
	}
	got := l.WorkOrders()[0]
	if got.State != OrderClosed || got.Closed == nil || got.Closed.By != "supervisor" {
		t.Errorf("after closing: %+v", got)
	}
	if l.OpenWorkOrders() != 0 {
		t.Error("a closed work order is still open")
	}
	// Closing twice is refused rather than silently accepted: the second
	// caller believes they did something.
	if _, err := l.CloseWorkOrder("WO-1", "somebody", ""); err == nil {
		t.Error("closing a closed work order succeeded")
	}
	if _, err := l.CloseWorkOrder("WO-nothing", "somebody", ""); err == nil {
		t.Error("closing a work order nobody filed succeeded")
	}

	// And the trail has all three acts, hash-chained with the rest.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`"kind":"work_order"`, `"kind":"work_order_closed"`, "WO-1", "supervisor"} {
		if !strings.Contains(text, want) {
			t.Errorf("the trail does not contain %q:\n%s", want, text)
		}
	}
}

// A reopened ledger has the work orders it had, because the trail is the
// authority and a process restart must not turn filed work into unfiled work.
func TestWorkOrdersSurviveAReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	l, err := Open(path, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.FileWorkOrder(WorkOrder{Reference: "WO-2", Device: "rtu-7", By: "op",
		Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if again.OpenWorkOrders() != 1 {
		t.Fatalf("after reopening: %+v", again.WorkOrders())
	}
	if w := again.WorkOrderFor("plant", []string{"rtu-7"}); w == nil || w.Reference != "WO-2" {
		t.Errorf("the work order did not survive: %+v", w)
	}
}

// What a work order has to say, and the two bounds.
func TestAWorkOrderHasToSayWhatItIs(t *testing.T) {
	l, _ := openLedger(t, Policy{MaxWorkOrder: 24 * time.Hour, MaxLead: time.Hour})
	now := time.Now()
	for _, tc := range []struct {
		name string
		w    WorkOrder
		want string
	}{
		{"no reference", WorkOrder{Device: "d", By: "op", Expires: now.Add(time.Hour)}, "reference"},
		{"no device", WorkOrder{Reference: "r", By: "op", Expires: now.Add(time.Hour)}, "device"},
		{"nobody filing", WorkOrder{Reference: "r", Device: "d", Expires: now.Add(time.Hour)}, "by"},
		{"no end", WorkOrder{Reference: "r", Device: "d", By: "op"}, "expires"},
		{"end before start", WorkOrder{Reference: "r", Device: "d", By: "op",
			NotBefore: now.Add(time.Hour), Expires: now}, "expires"},
		{"longer than the bound", WorkOrder{Reference: "r", Device: "d", By: "op",
			Expires: now.Add(48 * time.Hour)}, "max_work_order"},
		{"further ahead than the lead", WorkOrder{Reference: "r", Device: "d", By: "op",
			NotBefore: now.Add(6 * time.Hour), Expires: now.Add(7 * time.Hour)}, "max_lead"},
		{"reference too long", WorkOrder{Reference: strings.Repeat("x", 129), Device: "d", By: "op",
			Expires: now.Add(time.Hour)}, "reference"},
	} {
		_, err := l.FileWorkOrder(tc.w)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not name %q", tc.name, err, tc.want)
		}
	}
}

// Matching is literal and per device, and where two cover one operation the
// one ending soonest is the one reported: it is the one about to stop being
// true.
func TestTheWorkOrderReportedIsTheOneEndingSoonest(t *testing.T) {
	l, _ := openLedger(t, Policy{})
	now := time.Now()
	for _, w := range []WorkOrder{
		{Reference: "WO-long", Device: "plc-line1", By: "op", Expires: now.Add(8 * time.Hour)},
		{Reference: "WO-short", Device: "plc-line1", By: "op", Expires: now.Add(2 * time.Hour)},
		{Reference: "WO-elsewhere", Device: "plc-line2", By: "op", Expires: now.Add(time.Hour)},
		{Reference: "WO-listener", Device: "rtu-7", Listener: "substation", By: "op",
			Expires: now.Add(time.Hour)},
		{Reference: "WO-later", Device: "plc-line3", By: "op",
			NotBefore: now.Add(time.Hour), Expires: now.Add(2 * time.Hour)},
	} {
		if _, err := l.FileWorkOrder(w); err != nil {
			t.Fatalf("%s: %v", w.Reference, err)
		}
	}
	if w := l.WorkOrderFor("plant", []string{"plc-line1"}); w == nil || w.Reference != "WO-short" {
		t.Errorf("got %+v, want WO-short", w)
	}
	// A pool name and an address are both targets, and either may match.
	if w := l.WorkOrderFor("plant", []string{"pool", "plc-line2"}); w == nil || w.Reference != "WO-elsewhere" {
		t.Errorf("got %+v, want WO-elsewhere", w)
	}
	// A work order naming a listener covers that listener and no other.
	if w := l.WorkOrderFor("substation", []string{"rtu-7"}); w == nil {
		t.Error("a listener-scoped work order did not cover its own listener")
	}
	if w := l.WorkOrderFor("other", []string{"rtu-7"}); w != nil {
		t.Errorf("a listener-scoped work order covered %q", "other")
	}
	// Scheduled is not open.
	if w := l.WorkOrderFor("plant", []string{"plc-line3"}); w != nil {
		t.Errorf("a work order whose window has not started covered an operation: %+v", w)
	}
	// And nothing matches a device nobody filed for, which is the case that
	// has to stay negative: the whole point is the difference.
	if w := l.WorkOrderFor("plant", []string{"plc-line9"}); w != nil {
		t.Errorf("got %+v for a device with no work order", w)
	}
	if w := l.WorkOrderFor("plant", nil); w != nil {
		t.Error("no targets matched a work order")
	}
}

// The bound is refused rather than dropping the oldest: a work order that
// vanished would be one whose engineering then read as unfiled.
func TestTheWorkOrderTableIsBoundedAndSaysSo(t *testing.T) {
	l, _ := openLedger(t, Policy{})
	now := time.Now()
	for i := 0; i < maxWorkOrders; i++ {
		if _, err := l.FileWorkOrder(WorkOrder{Reference: "WO-" + itoa(i), Device: "d", By: "op",
			Expires: now.Add(time.Hour)}); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	_, err := l.FileWorkOrder(WorkOrder{Reference: "one-too-many", Device: "d", By: "op",
		Expires: now.Add(time.Hour)})
	if err == nil {
		t.Fatal("past the bound, filing succeeded")
	}
	// An existing reference is still accepted at the bound: extending a work
	// order adds no row, and refusing it would strand the work.
	if _, err := l.FileWorkOrder(WorkOrder{Reference: "WO-0", Device: "d", By: "op",
		Expires: now.Add(2 * time.Hour)}); err != nil {
		t.Errorf("extending at the bound: %v", err)
	}
}

// itoa without a strconv import, matching the style of the package.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
