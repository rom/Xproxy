package tftp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/tftp"
)

func mustCompile(t *testing.T, m *config.TFTPListener) *Policy {
	t.Helper()
	p, err := compile(m, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ask(op wire.Op, name string) request {
	return request{client: netip.MustParseAddr("10.0.0.5"), op: op,
		path: wire.Classify(name), mode: wire.ModeOctet, at: time.Now()}
}

// TestTheDefaultsAreReadOnlyAndDenyEverythingElse pins the two defaults this
// kind is mostly here for.
func TestTheDefaultsAreReadOnlyAndDenyEverythingElse(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers"})
	if d := p.Decide(ask(wire.OpRead, "boot.bin")); d.Allow {
		t.Fatal("default_action deny allowed a read")
	}
	p = mustCompile(t, &config.TFTPListener{Upstream: "servers", DefaultAction: "allow"})
	if d := p.Decide(ask(wire.OpRead, "boot.bin")); !d.Allow {
		t.Fatalf("a read was refused: %s", d.Reason)
	}
	d := p.Decide(ask(wire.OpWrite, "boot.bin"))
	if d.Allow {
		t.Fatal("a write was allowed with no operations list")
	}
	if d.Reason != "operation_not_allowed" {
		t.Fatalf("a write was refused as %q", d.Reason)
	}
	if d.Hard {
		t.Fatal("the direction is policy, so it is shadowable")
	}
}

// TestAPathClassIsRefusedByShapeAndOnlyTheSoftOnesCanBeAllowed is the line
// between what a configuration may permit and what it may not.
func TestAPathClassIsRefusedByShapeAndOnlyTheSoftOnesCanBeAllowed(t *testing.T) {
	base := &config.TFTPListener{Upstream: "servers", DefaultAction: "allow"}
	p := mustCompile(t, base)
	// A slice rather than a map: two of these keys differ from an ordinary
	// name only by a trailing space or a control character, and a map literal
	// is the one place that difference is invisible to a reader.
	for _, c := range []struct {
		name, want string
		hard       bool
	}{
		{name: "../../etc/shadow", want: "path_traversal"},
		{name: "/etc/shadow", want: "path_absolute"},
		{name: `fw\boot.bin`, want: "path_backslash"},
		{name: `c:\boot.bin`, want: "path_drive"},
		{name: "boot.bin ", want: "path_trailing"},
		{name: "bøt.bin", want: "path_non_ascii"},
		{name: "boot\r.bin", want: "path_control", hard: true},
	} {
		d := p.Decide(ask(wire.OpRead, c.name))
		if d.Allow || d.Reason != c.want {
			t.Errorf("%q: allow=%v reason=%q, want %q", c.name, d.Allow, d.Reason, c.want)
		}
		if d.Hard != c.hard {
			t.Errorf("%q: hard=%v, want %v", c.name, d.Hard, c.hard)
		}
	}
	// An estate that really does serve absolute paths says so, and then it
	// works -- while the classes nothing may allow stay refused.
	wide := *base
	wide.AllowPathClasses = []string{"absolute", "non_ascii"}
	p = mustCompile(t, &wide)
	if d := p.Decide(ask(wire.OpRead, "/tftpboot/boot.bin")); !d.Allow {
		t.Errorf("an allowed class was still refused: %s", d.Reason)
	}
	if d := p.Decide(ask(wire.OpRead, "boot\x1b[2J.bin")); d.Allow {
		t.Error("a control character was allowed")
	}
	// And naming one of those three is refused at compile time, not ignored.
	for _, name := range []string{"nul", "control", "empty", "nonsense"} {
		bad := *base
		bad.AllowPathClasses = []string{name}
		if _, err := compile(&bad, time.Now); err == nil {
			t.Errorf("allow_path_classes accepted %q", name)
		}
	}
}

// TestADirectoryIsABoundaryAndADenyListIsNotOverridable is the shape of the
// path policy: element-wise, and a deny no rule can widen.
func TestADirectoryIsABoundaryAndADenyListIsNotOverridable(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers", DefaultAction: "allow",
		Directories:     []string{"firmware", "boot/images"},
		DenyDirectories: []string{"firmware/staging"},
		DenyFilenames:   []string{"*.cfg"},
		Rules: []config.TFTPRule{
			{Name: "everything", Action: "allow"},
		},
	})
	for _, c := range []struct {
		name   string
		allow  bool
		reason string
	}{
		{name: "firmware/boot.bin", allow: true},
		{name: "boot/images/pxe", allow: true},
		{name: "firmware-staging/boot.bin", reason: "directory_not_allowed"},
		{name: "elsewhere/boot.bin", reason: "directory_not_allowed"},
		{name: "firmware/staging/boot.bin", reason: "directory_denied"},
		{name: "firmware/router.cfg", reason: "filename_denied"},
	} {
		d := p.Decide(ask(wire.OpRead, c.name))
		if d.Allow != c.allow || d.Reason != c.reason {
			t.Errorf("%q: allow=%v reason=%q, want allow=%v reason=%q",
				c.name, d.Allow, d.Reason, c.allow, c.reason)
		}
	}
}

// TestAFilenamePatternMatchesTheWholePathAndTheLeafBoth is what an operator
// means by either spelling.
func TestAFilenamePatternMatchesTheWholePathAndTheLeafBoth(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers", DefaultAction: "allow",
		Filenames: []string{"firmware/*.bin", "*.img"}})
	for name, want := range map[string]bool{
		"firmware/boot.bin":  true,
		"anywhere/disk.img":  true,
		"firmware/boot.conf": false,
		"boot.bin":           false,
	} {
		if d := p.Decide(ask(wire.OpRead, name)); d.Allow != want {
			t.Errorf("%q: allow=%v, want %v (%s)", name, d.Allow, want, d.Reason)
		}
	}
}

// TestTheBoundsAreNeverShadowedAndARuleCanNarrowThem: a bound is not policy,
// and a rule may make one tighter for its own traffic.
func TestTheBoundsAreNeverShadowedAndARuleCanNarrowThem(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers", DefaultAction: "allow",
		MaxFilenameBytes: 16, MaxDepth: 2, MaxTransferBytes: 1 << 20,
		MaxBlockSize: 1468, MaxWindowSize: 4,
		Rules: []config.TFTPRule{
			{Name: "narrow", Action: "allow", Directories: []string{"firmware"},
				MaxTransferBytes: 4096, MaxBlockSize: 512, MaxWindowSize: 1},
			{Name: "rest", Action: "allow"},
		},
	})
	d := p.Decide(ask(wire.OpRead, "this-name-is-far-too-long.bin"))
	if d.Allow || d.Reason != "filename_too_long" || !d.Hard {
		t.Fatalf("got allow=%v reason=%q hard=%v", d.Allow, d.Reason, d.Hard)
	}
	d = p.Decide(ask(wire.OpRead, "a/b/c/d.bin"))
	if d.Allow || d.Reason != "path_too_deep" || !d.Hard {
		t.Fatalf("got allow=%v reason=%q hard=%v", d.Allow, d.Reason, d.Hard)
	}
	d = p.Decide(ask(wire.OpRead, "firmware/b.bin"))
	if !d.Allow || d.Rule != "narrow" {
		t.Fatalf("got allow=%v rule=%q reason=%q", d.Allow, d.Rule, d.Reason)
	}
	if d.MaxBytes != 4096 || d.MaxBlock != 512 || d.MaxWindow != 1 {
		t.Fatalf("the rule's bounds were not applied: %+v", d)
	}
	d = p.Decide(ask(wire.OpRead, "other.bin"))
	if !d.Allow || d.Rule != "rest" {
		t.Fatalf("got allow=%v rule=%q", d.Allow, d.Rule)
	}
	if d.MaxBytes != 1<<20 || d.MaxBlock != 1468 || d.MaxWindow != 4 {
		t.Fatalf("the listener's bounds were not carried: %+v", d)
	}
}

// TestAnObservingRuleDecidesNothing is how a rule is tried on live traffic.
func TestAnObservingRuleDecidesNothing(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers",
		Rules: []config.TFTPRule{
			{Name: "watch", Action: "observe", Directories: []string{"firmware"}},
			{Name: "allow-firmware", Action: "allow", Directories: []string{"firmware"}},
		},
	})
	d := p.Decide(ask(wire.OpRead, "firmware/boot.bin"))
	if !d.Allow || d.Rule != "allow-firmware" {
		t.Fatalf("an observing rule decided: allow=%v rule=%q", d.Allow, d.Rule)
	}
	// And with nothing after it, the default still decides.
	p = mustCompile(t, &config.TFTPListener{Upstream: "servers",
		Rules: []config.TFTPRule{{Name: "watch", Action: "observe"}}})
	if d := p.Decide(ask(wire.OpRead, "boot.bin")); d.Allow || d.Reason != "default_deny" {
		t.Fatalf("got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

// TestARuleWidensAClassForItsOwnTrafficOnly is the one legacy server written
// down without opening the class for everything.
func TestARuleWidensAClassForItsOwnTrafficOnly(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers",
		Rules: []config.TFTPRule{
			{Name: "legacy", Action: "allow", Clients: []string{"10.0.0.0/8"},
				AllowPathClasses: []string{"absolute"}, Directories: []string{"/tftpboot"}},
		},
	})
	if d := p.Decide(ask(wire.OpRead, "/tftpboot/boot.bin")); !d.Allow {
		t.Fatalf("the rule's own traffic was refused: %s", d.Reason)
	}
	// From another network the rule does not match, so the class is refused
	// by the listener's list as before.
	other := ask(wire.OpRead, "/tftpboot/boot.bin")
	other.client = netip.MustParseAddr("192.0.2.9")
	if d := p.Decide(other); d.Allow {
		t.Fatal("a rule widened a class for traffic it does not cover")
	}
	// A class nothing may allow is refused before any rule is read.
	if d := p.Decide(ask(wire.OpRead, "/tftpboot/boot\x00.bin")); d.Allow || !d.Hard {
		t.Fatalf("got allow=%v hard=%v", d.Allow, d.Hard)
	}
}

// TestTheScheduleDecidesWhenAWriteIsAllowed is what a firmware window is.
func TestTheScheduleDecidesWhenAWriteIsAllowed(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers",
		Operations: []string{"read", "write"},
		Rules: []config.TFTPRule{
			{Name: "window", Action: "allow", Operations: []string{"write"},
				Schedule: &config.ModbusSchedule{From: "01:00", To: "02:00", Timezone: "UTC"}},
		},
	})
	inside := ask(wire.OpWrite, "cfg.txt")
	inside.at = time.Date(2026, 3, 4, 1, 30, 0, 0, time.UTC)
	if d := p.Decide(inside); !d.Allow {
		t.Fatalf("a write inside the window was refused: %s", d.Reason)
	}
	outside := inside
	outside.at = time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	if d := p.Decide(outside); d.Allow {
		t.Fatal("a write outside the window was allowed")
	}
}

// TestTheClientListIsTheOnlyIdentityThereIs, and deny is read first.
func TestTheClientListIsTheOnlyIdentityThereIs(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers",
		AllowClients: []string{"10.0.0.0/8"}, DenyClients: []string{"10.9.0.0/16"}})
	for addr, want := range map[string]bool{
		"10.0.0.5":  true,
		"10.9.0.5":  false,
		"192.0.2.1": false,
	} {
		if got := p.Client(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	if p.Client(netip.Addr{}) {
		t.Fatal("an address that is not one was admitted")
	}
	// An empty allow list admits everything, which is what validation warns
	// about rather than refuses.
	open := mustCompile(t, &config.TFTPListener{Upstream: "servers"})
	if !open.Client(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("an empty allow list refused an address")
	}
}

// TestAModeIsAnAllowListAndMailIsNotInItByDefault: RFC 1350 removed mail, and
// a server that still implements it delivers the file as mail.
func TestAModeIsAnAllowListAndMailIsNotInItByDefault(t *testing.T) {
	p := mustCompile(t, &config.TFTPListener{Upstream: "servers", DefaultAction: "allow"})
	for mode, want := range map[string]bool{
		wire.ModeOctet:    true,
		wire.ModeNetASCII: true,
		wire.ModeMail:     false,
		"nonsense":        false,
	} {
		req := ask(wire.OpRead, "boot.bin")
		req.mode = mode
		d := p.Decide(req)
		if d.Allow != want {
			t.Errorf("%q: allow=%v, want %v (%s)", mode, d.Allow, want, d.Reason)
		}
	}
}

// TestCompileRefusesWhatItCannotUnderstand, rather than ignoring it: a policy
// that silently dropped a line would be a policy nobody wrote.
func TestCompileRefusesWhatItCannotUnderstand(t *testing.T) {
	for what, m := range map[string]*config.TFTPListener{
		"allow_clients":  {AllowClients: []string{"not-a-cidr"}},
		"deny_clients":   {DenyClients: []string{"10/8"}},
		"operations":     {Operations: []string{"delete"}},
		"rule clients":   {Rules: []config.TFTPRule{{Name: "r", Clients: []string{"x"}}}},
		"rule ops":       {Rules: []config.TFTPRule{{Name: "r", Operations: []string{"oack"}}}},
		"rule classes":   {Rules: []config.TFTPRule{{Name: "r", AllowPathClasses: []string{"nul"}}}},
		"rule schedule":  {Rules: []config.TFTPRule{{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}}},
		"listener class": {AllowPathClasses: []string{"plain "}},
	} {
		if _, err := compile(m, time.Now); err == nil {
			t.Errorf("%s: compiled", what)
		}
	}
}
