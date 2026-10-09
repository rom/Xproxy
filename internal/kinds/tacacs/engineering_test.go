package tacacs

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// Which administration commands are engineering, on its own.
//
// Device administration is engineering activity, and this is the only
// listener in the project that can see one: a `configure terminal` on a core
// router at three in the morning is the same kind of event as a PLC
// download. What is not engineering is a `show` -- every device in an estate
// is looked at constantly by monitoring, by scripts and by people, and a
// class that included those would be a class nobody reads.
//
// The table below is the vendor grammar, which is where this gets
// interesting: the first word usually decides, but `request` does not --
// `request system reboot` is a restart and `request system software add` is a
// firmware change, and only the arguments say which.
func TestWhichAdministrationCommandsAreEngineering(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  string
		want engineering.Class
	}{
		// The device going away and coming back, which is the one whose
		// effect is immediate and total.
		{name: "reload", cmd: "reload", want: engineering.ClassRestart},
		{name: "reboot", cmd: "reboot now", want: engineering.ClassRestart},
		{name: "restart", cmd: "restart shell", want: engineering.ClassRestart},

		// Configuration, in the two grammars an estate actually runs.
		{name: "configure terminal", cmd: "configure terminal",
			want: engineering.ClassConfiguration},
		{name: "the abbreviation an engineer types", cmd: "conf t",
			want: engineering.ClassConfiguration},
		{name: "write memory makes it survive a reboot", cmd: "write memory",
			want: engineering.ClassConfiguration},
		{name: "write erase removes it", cmd: "write erase",
			want: engineering.ClassConfiguration},
		{name: "a Junos set", cmd: "set interfaces ge-0/0/0 disable",
			want: engineering.ClassConfiguration},
		{name: "a Junos delete", cmd: "delete firewall filter protect",
			want: engineering.ClassConfiguration},
		{name: "a Junos commit", cmd: "commit confirmed 5",
			want: engineering.ClassConfiguration},
		{name: "and a rollback", cmd: "rollback 1",
			want: engineering.ClassConfiguration},

		// A file moving. Which direction it is depends on the arguments, and
		// `copy running-config tftp:` is a configuration leaving the estate
		// whichever way a reader counts it.
		{name: "a configuration leaving", cmd: "copy running-config tftp://10.0.0.5/r1.cfg",
			want: engineering.ClassFileTransfer},
		{name: "an image arriving in flash", cmd: "copy tftp: flash:",
			want: engineering.ClassFirmware},
		{name: "an image arriving in bootflash", cmd: "copy tftp: bootflash:img.bin",
			want: engineering.ClassFirmware},
		{name: "an archive to disk0", cmd: "archive tar /create disk0:cfg.tar",
			want: engineering.ClassFirmware},
		{name: "an upload", cmd: "upload running-config scp://host/r1",
			want: engineering.ClassFileTransfer},

		// The firmware verbs.
		{name: "upgrade", cmd: "upgrade hw-module", want: engineering.ClassFirmware},
		{name: "install", cmd: "install add file bootflash:img",
			want: engineering.ClassFirmware},
		{name: "boot", cmd: "boot system flash:img.bin",
			want: engineering.ClassFirmware},

		// `request`, where the first word cannot tell them apart.
		{name: "request system reboot is a restart", cmd: "request system reboot",
			want: engineering.ClassRestart},
		{name: "request a halt is too", cmd: "request system halt",
			want: engineering.ClassRestart},
		{name: "request a power-off as well", cmd: "request system power-off",
			want: engineering.ClassRestart},
		{name: "request software add is a firmware change",
			cmd:  "request system software add /var/tmp/junos.tgz",
			want: engineering.ClassFirmware},
		// A `request` that is neither falls back to configuration, which is
		// the safer of the two: it is reported rather than missed. Note what
		// that means for a line card -- `request chassis fpc slot 1 restart`
		// restarts hardware and is reported as a configuration change,
		// because the restart words are reboot, halt and power-off. The class
		// is coarser than the command; the command itself is in the detail.
		{name: "any other request is configuration",
			cmd:  "request chassis fpc slot 1 restart",
			want: engineering.ClassConfiguration},

		// And what is not engineering, which is the half that keeps this
		// readable.
		{name: "a show is how an estate is monitored", cmd: "show version"},
		{name: "a running-config show is still a show", cmd: "show running-config"},
		{name: "a ping is not a change", cmd: "ping 10.0.0.1"},
		{name: "a traceroute is not either", cmd: "traceroute 10.0.0.1"},
		// A vendor's own spelling of a change this table does not know is
		// missed, and that is the right failure: a gap in a record beats a
		// report on every `show interfaces`, which is a record nobody opens.
		{name: "a spelling this table does not know", cmd: "frobnicate the-widget"},
		{name: "no command at all", cmd: ""},
		{name: "a command of nothing but spaces", cmd: "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Command: tc.cmd, User: "alice", Port: "vty0",
				Client: netip.MustParseAddr("10.0.0.9")}
			op, ok := engineeringOf(req)
			if tc.want == "" {
				if ok {
					t.Fatalf("reported as engineering: %+v", op)
				}
				return
			}
			if !ok {
				t.Fatal("not reported as engineering")
			}
			if op.Class != tc.want {
				t.Errorf("class %q, want %q", op.Class, tc.want)
			}
			// The whole line is the detail and the port is the point: a
			// record saying "configuration on r1" without the command is not
			// a record anybody can act on.
			if op.Detail != tc.cmd {
				t.Errorf("detail %q, want the command line", op.Detail)
			}
			if op.Point != "vty0" {
				t.Errorf("point %q, want the port", op.Point)
			}
			if op.Subject != "alice" {
				t.Errorf("subject %q, want the user", op.Subject)
			}
		})
	}

	// With no port the point is the device's address, because a record has to
	// say which device even when the session does not name a line.
	req := Request{Command: "configure terminal", User: "alice",
		Client: netip.MustParseAddr("10.0.0.9")}
	op, ok := engineeringOf(req)
	if !ok {
		t.Fatal("not reported as engineering")
	}
	if op.Point != "10.0.0.9" {
		t.Errorf("point %q, want the client address", op.Point)
	}
}

// "A router is configured only during an approved window", through the whole
// relay.

const engSection = "        allow_clients: [127.0.0.1/32]\n" +
	"        default_action: allow\n"

// engLedger is the `access` section, with four eyes.
func engLedger(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
}

// engEvents collects the security log.
type engEvents struct {
	mu     sync.Mutex
	events []engEvent
}

type engEvent struct {
	action, reason string
	attrs          map[string]any
}

func (c *engEvents) SecurityEvent(action, reason string, attrs []any) {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	c.mu.Lock()
	c.events = append(c.events, engEvent{action: action, reason: reason, attrs: m})
	c.mu.Unlock()
}

func (c *engEvents) find(t *testing.T, reason string) engEvent {
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

func (c *engEvents) seen(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.reason == reason {
			return true
		}
	}
	return false
}

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
		what, sn.Refusals["tacacs"], sn.WouldRefusals["tacacs"], sn.EngineeringOps,
		sn.EngineeringOutside)
}

// engRelay starts a relay with its own top-level sections, which is where
// the access ledger lives: the shared harness has a slot at listener level
// only.
func engRelay(t *testing.T, section, top, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: admin
      address: "127.0.0.1:0"
      kind: tacacs
      tacacs:
        upstream: servers
        secret_file: %q
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, top, keyFile(t, theKey), section, serverAddr))
	return s, proxytest.Addr(t, s, "admin")
}

// A `configure terminal` with nothing open is refused and the device's own
// TACACS+ server never sees it; the same command goes through once a
// supervisor has approved a window.
//
// This is the case worth having on this kind. A router configured outside
// every change window is the ordinary shape of both an incident and a
// Tuesday afternoon, and the ledger is what tells them apart.
func TestAConfigureNeedsAnApprovedGrant(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n",
		engLedger(t), srv.addr())

	d := connect(t, addr)
	r, ok := d.authorize(1, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal")
	if ok && r.Status.Pass() {
		t.Fatal("the configure was allowed with nothing open")
	}
	awaitEng(t, s, "the refusal and the engineering event", func(sn proxy.Snapshot) bool {
		return sn.Refusals["tacacs"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["tacacs/configuration"] >= 1
	})
	if got := srv.seen(&srv.commands); len(got) != 0 {
		t.Errorf("the refused command reached the server: %q", got)
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

	// A window for the *person*: this protocol's whole job is to say who is
	// typing, so a grant on a TACACS+ listener names a user.
	g, err := led.Request(access.Request{Subject: "alice", Listener: "admin",
		Target: "servers", Reason: "change 4711: the new uplink filter",
		By: "alice", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the change board"); err != nil {
		t.Fatal(err)
	}

	d2 := connect(t, addr)
	r, ok = d2.authorize(2, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal")
	if !ok || !r.Status.Pass() {
		t.Fatalf("the approved configure was refused: %+v ok=%v", r, ok)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) &&
		len(srv.seen(&srv.commands)) == 0; {
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.seen(&srv.commands); len(got) != 1 || got[0] != "configure terminal" {
		t.Errorf("the server saw %q", got)
	}
}

// And the window is that person's. Another engineer's configure is refused by
// the same grant, which is the point of having a name to put on it.
func TestAnotherEngineersConfigureIsNotCoveredByTheGrant(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n",
		engLedger(t), srv.addr())
	led := s.Access()
	g, err := led.Request(access.Request{Subject: "alice", Listener: "admin",
		Target: "servers", Reason: "change 4711", By: "alice",
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed"); err != nil {
		t.Fatal(err)
	}

	d := connect(t, addr)
	if r, ok := d.authorize(1, "bob", 15, "service=shell", "cmd=configure", "cmd-arg=terminal"); ok && r.Status.Pass() {
		t.Fatal("another engineer's configure was allowed by alice's window")
	}
	awaitEng(t, s, "the refusal of the other engineer's command", func(sn proxy.Snapshot) bool {
		return sn.Refusals["tacacs"]["engineering_no_grant"] >= 1
	})
	if got := srv.seen(&srv.commands); len(got) != 0 {
		t.Errorf("the refused command reached the server: %q", got)
	}
}

// A `show` through the same listener is untouched by the gate, which is what
// makes this deployable: an estate's monitoring reads every device all day
// and none of it should need a work order.
func TestAShowIsNotHeldByTheEngineeringGate(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n",
		engLedger(t), srv.addr())

	d := connect(t, addr)
	r, ok := d.authorize(1, "monitoring", 1, "service=shell", "cmd=show", "cmd-arg=version")
	if !ok || !r.Status.Pass() {
		t.Fatalf("a show was refused: %+v ok=%v", r, ok)
	}
	sn := s.Stats()
	if n := sn.Refusals["tacacs"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a show was refused as engineering: %d", n)
	}
	if len(sn.EngineeringOps) != 0 {
		t.Errorf("a show was reported as engineering: %v", sn.EngineeringOps)
	}
}

// A work order changes the tone and permits nothing, and the event names the
// command: "a configuration change on r1" is not a finding, "write erase on
// r1" is.
func TestAWorkOrderChangesTheToneOfAConfigure(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	// action: alert is the step an estate takes first: be told when a router
	// is configured outside a window, before refusing it.
	s, addr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), srv.addr())
	cap := &engEvents{}
	s.Logs().Watch(cap)

	d := connect(t, addr)
	if r, ok := d.authorize(1, "alice", 15, "service=shell", "cmd=write", "cmd-arg=erase"); !ok || !r.Status.Pass() {
		t.Fatalf("a listener that only alerts refused: %+v ok=%v", r, ok)
	}
	ev := cap.find(t, "engineering_configuration")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}
	awaitEng(t, s, "the operation recorded as outside every window", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["tacacs/configuration"] >= 1
	})
	if n := s.Stats().Refusals["tacacs"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a listener that only alerts refused anyway: %d", n)
	}

	// Now a relay with one on file against the pool it reaches.
	srv2 := startServer(t, &fakeServer{})
	s2, addr2 := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), srv2.addr())
	if _, err := s2.Access().FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "servers", Note: "the new uplink filter", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap2 := &engEvents{}
	s2.Logs().Watch(cap2)

	d2 := connect(t, addr2)
	if r, ok := d2.authorize(1, "alice", 15, "service=shell", "cmd=write", "cmd-arg=erase"); !ok || !r.Status.Pass() {
		t.Fatalf("the filed command was refused: %+v ok=%v", r, ok)
	}
	ev = cap2.find(t, "engineering_configuration")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	awaitEng(t, s2, "the operation under a work order", func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["tacacs/configuration"] >= 1
	})

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline filters on.
	alert := cap2.find(t, "tacacs_engineering_ungranted")
	if got := alert.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("the ungranted alert names work_order %v", got)
	}
}

// A shadow listener says what it would have refused and carries the command,
// which is how an estate finds out how many windows it would have to file
// before it turns the refusal on.
func TestAShadowListenerSaysWhatTheEngineeringGateWouldHaveRefused(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := engRelay(t, engSection+
		"        engineering:\n          require_grant: true\n",
		engLedger(t)+"\npolicy: {mode: shadow}", srv.addr())

	d := connect(t, addr)
	if r, ok := d.authorize(1, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal"); !ok || !r.Status.Pass() {
		t.Fatalf("a shadow listener refused: %+v ok=%v", r, ok)
	}
	awaitEng(t, s, "the shadow record", func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["tacacs"]["engineering_no_grant"] >= 1
	})
	if n := s.Stats().Refusals["tacacs"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a shadow listener refused: %d", n)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) &&
		len(srv.seen(&srv.commands)) == 0; {
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.seen(&srv.commands); len(got) != 1 {
		t.Errorf("a shadow listener held the command it only meant to record: %q", got)
	}
}

// alert_on_deny off silences the alert and nothing else: the operation is
// still reported and still counted.
func TestEngineeringAlertsFollowAlertOnDeny(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := engRelay(t, engSection+"        alert_on_deny: false\n"+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), srv.addr())
	cap := &engEvents{}
	s.Logs().Watch(cap)

	d := connect(t, addr)
	d.authorize(1, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal")
	// The report is the event that is not an alert, so waiting for it proves
	// the decision ran before the silence is asserted.
	cap.find(t, "engineering_configuration")
	awaitEng(t, s, "the operation recorded", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["tacacs/configuration"] >= 1
	})
	if cap.seen("tacacs_engineering_ungranted") {
		t.Error("the ungranted alert was raised although alert_on_deny is off")
	}
}

// With the block turned off the listener decides nothing about engineering:
// no report, no counter, no refusal.
func TestEngineeringCanBeTurnedOff(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := engRelay(t, engSection+"        engineering:\n          enabled: false\n",
		engLedger(t), srv.addr())

	d := connect(t, addr)
	if r, ok := d.authorize(1, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal"); !ok || !r.Status.Pass() {
		t.Fatalf("the configure was refused: %+v ok=%v", r, ok)
	}
	sn := s.Stats()
	if n := sn.EngineeringOps["tacacs/configuration"]; n != 0 {
		t.Errorf("the operation was reported anyway: %d", n)
	}
	if n := sn.Refusals["tacacs"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
}
