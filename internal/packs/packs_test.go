package packs

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A pack is data, and the tests are about the two properties that makes it
// worth having: a file nobody trusted does not load, and a pack cannot claim a
// detection this build cannot make.

const minimal = `pack: 1
id: test-walk-then-write
revision: 1
name: A walk then a write
summary: An address that enumerated the register space and then wrote to it.
technique: T0861
kinds: [modbus]
severity: high
enforcement: alert
detect:
  window: 10m
  ordered: true
  signals:
    - name: the-walk
      reasons: [modbus_anomaly_write_burst]
      count: 2
    - name: the-write
      reasons: [modbus_read_only]
`

func key(t *testing.T) (Key, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey("plant", base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	return k, priv
}

// write a pack, and its signature where a private key is given.
func write(t *testing.T, dir, name, body string, priv ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		return
	}
	if err := os.WriteFile(path+SigExt, []byte(Sign("plant", priv, []byte(body))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestASignedPackLoadsAndAnUnsignedOneDoesNot(t *testing.T) {
	k, priv := key(t)

	// Signed by a key the estate trusts.
	dir := t.TempDir()
	write(t, dir, "walk.yaml", minimal, priv)
	rep, err := Load(dir, Trust{Keys: []Key{k}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Packs) != 1 {
		t.Fatalf("%d packs", len(rep.Packs))
	}
	if got := rep.Packs[0].Signer; got != "plant" {
		t.Errorf("signer %q", got)
	}
	if len(rep.Unsigned) != 0 {
		t.Errorf("a signed pack reported as unsigned: %v", rep.Unsigned)
	}

	// The same file with no signature beside it.
	bare := t.TempDir()
	write(t, bare, "walk.yaml", minimal, nil)
	if _, err := Load(bare, Trust{Keys: []Key{k}}); err == nil {
		t.Fatal("an unsigned pack loaded: a directory read at start is a way into this process")
	} else if !strings.Contains(err.Error(), "allow_unsigned") {
		t.Errorf("the refusal does not say how an operator would allow it: %v", err)
	}
	rep, err = Load(bare, Trust{Keys: []Key{k}, AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unsigned) != 1 {
		t.Errorf("allow_unsigned loaded it without saying so: %+v", rep)
	}

	// Signed by a key nobody trusts, and a file changed after signing.
	other := t.TempDir()
	_, rogue := key(t)
	write(t, other, "walk.yaml", minimal, rogue)
	if _, err := Load(other, Trust{Keys: []Key{k}}); err == nil {
		t.Error("a pack signed by another key loaded")
	}
	edited := t.TempDir()
	write(t, edited, "walk.yaml", minimal, priv)
	if err := os.WriteFile(filepath.Join(edited, "walk.yaml"),
		[]byte(strings.Replace(minimal, "severity: high", "severity: info", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(edited, Trust{Keys: []Key{k}}); err == nil {
		t.Error("a pack edited after it was signed loaded")
	} else if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the refusal does not say the file changed: %v", err)
	}
}

// The check that keeps the catalogue honest: a pack cannot name a reason this
// build does not emit, nor a technique it cannot observe, nor a kind it does
// not serve. Each would be a claim in a coverage report.
func TestAPackCannotClaimWhatTheBuildCannotDo(t *testing.T) {
	bad := map[string]string{
		"a reason nothing emits": strings.Replace(minimal,
			"reasons: [modbus_read_only]", "reasons: [modbus_invented_reason]", 1),
		"a technique nothing observes": strings.Replace(minimal,
			"technique: T0861", "technique: T9999", 1),
		"a kind nothing serves": strings.Replace(minimal,
			"kinds: [modbus]", "kinds: [profinet]", 1),
		"a later format": strings.Replace(minimal, "pack: 1", "pack: 2", 1),
		"a signal narrowed to a kind the pack does not name": strings.Replace(minimal,
			"      reasons: [modbus_read_only]", "      reasons: [modbus_read_only]\n      kinds: [s7]", 1),
		"a field this build does not know": minimal + "surprise: true\n",
		"no signal at all":                 strings.Split(minimal, "  signals:")[0] + "  signals: []\n",
		"an unknown severity":              strings.Replace(minimal, "severity: high", "severity: urgent", 1),
		"an unknown enforcement": strings.Replace(minimal,
			"enforcement: alert", "enforcement: quarantine", 1),
	}
	k, priv := key(t)
	for name, body := range bad {
		dir := t.TempDir()
		write(t, dir, "p.yaml", body, priv)
		if _, err := Load(dir, Trust{Keys: []Key{k}}); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// Two files, one identifier: the higher revision wins and the fact is
// reported, which is how an update is dropped in beside what is there.
func TestTheHigherRevisionWins(t *testing.T) {
	k, priv := key(t)
	dir := t.TempDir()
	write(t, dir, "a-walk.yaml", minimal, priv)
	write(t, dir, "b-walk.yaml", strings.Replace(
		strings.Replace(minimal, "revision: 1", "revision: 4", 1),
		"name: A walk then a write", "name: A walk then a write, corrected", 1), priv)
	rep, err := Load(dir, Trust{Keys: []Key{k}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Packs) != 1 || rep.Packs[0].Revision != 4 {
		t.Fatalf("%d packs, first revision %d", len(rep.Packs), rep.Packs[0].Revision)
	}
	if len(rep.Superseded) != 1 || rep.Superseded[0] != "a-walk.yaml" {
		t.Errorf("superseded %v", rep.Superseded)
	}
	// The same revision twice is a mistake, not a choice to make silently.
	same := t.TempDir()
	write(t, same, "a.yaml", minimal, priv)
	write(t, same, "b.yaml", minimal, priv)
	if _, err := Load(same, Trust{Keys: []Key{k}}); err == nil {
		t.Error("two files with one identifier and one revision loaded")
	}
}

// A directory may hold a README and the signatures without either being read
// as a detection.
func TestADirectoryMayHoldOtherFiles(t *testing.T) {
	k, priv := key(t)
	dir := t.TempDir()
	write(t, dir, "walk.yaml", minimal, priv)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# packs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Load(dir, Trust{Keys: []Key{k}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Packs) != 1 {
		t.Fatalf("%d packs", len(rep.Packs))
	}
	if !contains(rep.Skipped, "README.md") || !contains(rep.Skipped, "walk.yaml"+SigExt) {
		t.Errorf("skipped %v", rep.Skipped)
	}
}

func load(t *testing.T, body string) *Pack {
	t.Helper()
	k, priv := key(t)
	dir := t.TempDir()
	write(t, dir, "p.yaml", body, priv)
	rep, err := Load(dir, Trust{Keys: []Key{k}})
	if err != nil {
		t.Fatal(err)
	}
	return rep.Packs[0]
}

// The evaluator: the order matters where the pack says so, the window closes,
// and one campaign is one alert.
func TestTheSequenceIsTheDetection(t *testing.T) {
	p := load(t, minimal)
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	e := New([]*Pack{p}, Options{})
	e.SetClock(func() time.Time { return at })
	actor := netip.MustParseAddr("10.40.9.9")

	burst := func(n int) Event {
		return Event{Action: "alert", Reason: "modbus_anomaly_write_burst", Kind: "modbus",
			Actor: actor, At: at.Add(time.Duration(n) * time.Minute)}
	}
	write := func(n int) Event {
		return Event{Action: "deny", Reason: "modbus_read_only", Kind: "modbus",
			Actor: actor, At: at.Add(time.Duration(n) * time.Minute)}
	}

	// The write alone is not the pack, and one burst is not two.
	if fs := e.Observe(write(0)); len(fs) != 0 {
		t.Fatalf("the second signal alone matched: %+v", fs)
	}
	if fs := e.Observe(burst(1)); len(fs) != 0 {
		t.Fatalf("one of two matched: %+v", fs)
	}
	// Two bursts and then the write, inside the window.
	if fs := e.Observe(burst(2)); len(fs) != 0 {
		t.Fatalf("the walk alone matched: %+v", fs)
	}
	fs := e.Observe(write(3))
	if len(fs) != 1 {
		t.Fatalf("the sequence did not match: %+v", fs)
	}
	f := fs[0]
	if f.Pack != "test-walk-then-write" || f.Technique != "T0861" || f.Severity != SeverityHigh {
		t.Errorf("finding %+v", f)
	}
	if f.Denied {
		t.Error("an alert-only pack quarantined an actor")
	}
	if want := "the-walk then the-write on modbus"; f.Detail() != want {
		t.Errorf("detail %q, want %q", f.Detail(), want)
	}

	// One campaign is one alert: refire defaults to the window.
	if fs := e.Observe(write(4)); len(fs) != 0 {
		t.Errorf("a second alert inside the refire interval: %+v", fs)
	}
	// Past the window and the refire, it is a new attempt and reports again.
	for _, n := range []int{40, 41} {
		e.Observe(burst(n))
	}
	if fs := e.Observe(write(42)); len(fs) != 1 {
		t.Errorf("a fresh sequence an hour later did not report: %+v", fs)
	}
}

// Out of order, on a pack that asked for an order: not a match. The same
// events on a pack that did not: a match. This is the difference between "read
// the program, then write one" and "did both today".
func TestOrderIsAStatement(t *testing.T) {
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	actor := netip.MustParseAddr("10.40.9.9")
	feed := func(p *Pack) int {
		e := New([]*Pack{p}, Options{})
		e.SetClock(func() time.Time { return at })
		n := 0
		// the write first, then the two bursts
		for i, ev := range []Event{
			{Reason: "modbus_read_only", Kind: "modbus", Actor: actor},
			{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: actor},
			{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: actor},
		} {
			ev.At = at.Add(time.Duration(i) * time.Minute)
			n += len(e.Observe(ev))
		}
		return n
	}
	if n := feed(load(t, minimal)); n != 0 {
		t.Errorf("an ordered pack matched out of order %d times", n)
	}
	if n := feed(load(t, strings.Replace(minimal, "ordered: true", "ordered: false", 1))); n != 1 {
		t.Errorf("an unordered pack matched %d times, want 1", n)
	}
}

// A pack that spans kinds, which is the statement no single listener can make.
func TestAcrossKindsNeedsMoreThanOneProtocol(t *testing.T) {
	p := load(t, `pack: 1
id: test-three-protocols
revision: 1
name: One host on three control protocols
summary: A host refused on three different control protocols inside ten minutes.
technique: T0846
kinds: [modbus, s7, iec104]
severity: high
detect:
  window: 10m
  across_kinds: 3
  signals:
    - name: refused
      reasons: [modbus_read_only, s7_operation_denied, iec104_rule]
      count: 3
`)
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	actor := netip.MustParseAddr("10.40.9.9")
	e := New([]*Pack{p}, Options{})
	e.SetClock(func() time.Time { return at })

	// Three refusals on one kind is not three kinds, whatever the count says.
	for i := 0; i < 3; i++ {
		if fs := e.Observe(Event{Reason: "modbus_read_only", Kind: "modbus", Actor: actor,
			At: at.Add(time.Duration(i) * time.Second)}); len(fs) != 0 {
			t.Fatalf("one protocol matched a three-protocol pack: %+v", fs)
		}
	}
	e.Observe(Event{Reason: "s7_operation_denied", Kind: "s7", Actor: actor, At: at.Add(time.Minute)})
	fs := e.Observe(Event{Reason: "iec104_rule", Kind: "iec104", Actor: actor, At: at.Add(2 * time.Minute)})
	if len(fs) != 1 {
		t.Fatalf("three protocols did not match: %+v", fs)
	}
	if got := fs[0].Kinds; len(got) != 3 {
		t.Errorf("the finding names %v, want all three", got)
	}
}

// Quarantine: only where the pack declared deny AND the operator turned
// enforcement on, bounded, and expiring by itself. It is never the ban ladder.
func TestQuarantineNeedsBothThePackAndTheOperator(t *testing.T) {
	denying := strings.Replace(minimal, "enforcement: alert", "enforcement: deny", 1)
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	actor := netip.MustParseAddr("10.40.9.9")
	run := func(p *Pack, enforce bool) (*Engine, bool) {
		e := New([]*Pack{p}, Options{Enforce: enforce})
		e.SetClock(func() time.Time { return at })
		var denied bool
		for i, ev := range []Event{
			{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: actor},
			{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: actor},
			{Reason: "modbus_read_only", Kind: "modbus", Actor: actor},
		} {
			ev.At = at.Add(time.Duration(i) * time.Second)
			for _, f := range e.Observe(ev) {
				denied = denied || f.Denied
			}
		}
		return e, denied
	}

	// The pack says alert: no configuration can make it refuse.
	e, denied := run(load(t, minimal), true)
	if denied {
		t.Error("an alert-only pack refused with enforcement on")
	}
	if _, held := e.Quarantined(actor); held {
		t.Error("an alert-only pack quarantined an actor")
	}

	// The pack says deny and the operator has not turned it on.
	e, denied = run(load(t, denying), false)
	if denied {
		t.Error("a deny pack refused without enforcement")
	}
	if _, held := e.Quarantined(actor); held {
		t.Error("quarantined with enforcement off")
	}

	// Both.
	e, denied = run(load(t, denying), true)
	if !denied {
		t.Fatal("a deny pack with enforcement on did not refuse")
	}
	pack, held := e.Quarantined(actor)
	if !held || pack != "test-walk-then-write" {
		t.Fatalf("quarantined %q %v", pack, held)
	}
	// It expires by itself with the pack's window, and nothing outlives it.
	e.SetClock(func() time.Time { return at.Add(11 * time.Minute) })
	if _, held := e.Quarantined(actor); held {
		t.Error("the quarantine outlived the pack's window")
	}
	// And an operator can lift one.
	e.SetClock(func() time.Time { return at })
	run2, _ := run(load(t, denying), true)
	if !run2.Release(actor) {
		t.Error("nothing to release")
	}
	if _, held := run2.Quarantined(actor); held {
		t.Error("released and still held")
	}
}

// A pack an operator disabled is not in force at all, and the status says what
// is.
func TestDisabledAndStatus(t *testing.T) {
	p := load(t, minimal)
	e := New([]*Pack{p}, Options{Disabled: []string{p.ID}})
	if e.On() {
		t.Error("a disabled pack is still in force")
	}
	e = New([]*Pack{p}, Options{})
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	e.SetClock(func() time.Time { return at })
	actor := netip.MustParseAddr("10.40.9.9")
	for i, ev := range []Event{
		{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: actor},
		{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: actor},
		{Reason: "modbus_read_only", Kind: "modbus", Actor: actor},
	} {
		ev.At = at.Add(time.Duration(i) * time.Second)
		e.Observe(ev)
	}
	st := e.Status()
	if st.Packs != 1 || st.Actors != 1 || st.Matches[p.ID] != 1 {
		t.Errorf("status %+v", st)
	}
	if st.Enforcing {
		t.Error("status claims enforcement with none configured")
	}
}

// Traffic no pack cares about leaves no state behind. A plant is a few masters
// making the same requests for years, and a table that grew on the ordinary
// case would be a memory leak with a clock on it.
func TestOrdinaryTrafficLeavesNoState(t *testing.T) {
	e := New([]*Pack{load(t, minimal)}, Options{})
	for i := 0; i < 1000; i++ {
		addr := netip.AddrFrom4([4]byte{10, 40, byte(i / 256), byte(i % 256)})
		e.Observe(Event{Reason: "modbus_tls_handshake", Kind: "modbus", Actor: addr})
		e.Observe(Event{Reason: "s7_operation_denied", Kind: "s7", Actor: addr})
	}
	if st := e.Status(); st.Actors != 0 {
		t.Errorf("%d actors held for traffic no pack matches", st.Actors)
	}
}

// The actor table is bounded, and an eviction is counted rather than silent.
func TestTheActorTableIsBounded(t *testing.T) {
	e := New([]*Pack{load(t, minimal)}, Options{Bounds: Bounds{MaxActors: 8}})
	for i := 0; i < 64; i++ {
		addr := netip.AddrFrom4([4]byte{10, 40, 0, byte(i)})
		e.Observe(Event{Reason: "modbus_anomaly_write_burst", Kind: "modbus", Actor: addr,
			At: time.Now().Add(time.Duration(i) * time.Second)})
	}
	st := e.Status()
	if st.Actors > 8 {
		t.Errorf("%d actors past a bound of 8", st.Actors)
	}
	if st.Evicted == 0 {
		t.Error("the table dropped rows without counting them")
	}
}

func TestAKeyFileIsReadable(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plant.pub")
	if err := os.WriteFile(path, []byte("# the plant's pack signing key\n"+
		base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeyFile("plant", path)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Public.Equal(pub) {
		t.Error("the key read back differently")
	}
	if _, err := ParseKey("plant", "AAAA"); err == nil {
		t.Error("a key of the wrong length was accepted")
	}
	if _, err := ParseKey("", base64.StdEncoding.EncodeToString(pub)); err == nil {
		t.Error("a key with no name was accepted")
	}
}
