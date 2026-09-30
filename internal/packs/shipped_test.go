package packs

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped pack directory, and the replay beside each pack.
//
// A pack is data, so the thing that can rot is the data: a reason renamed in a
// kind, a technique dropped from the catalogue, a count edited to a number the
// pack's own window cannot reach. None of that breaks a build and none of it is
// visible in production -- the detection simply stops happening.
//
// So each pack has a trace in packs/testdata: the sequence of security events it
// is about, which must report, and the same sequence one signal short, which
// must not. A pack edit that changes what the pack needs shows up here.

const shippedDir = "../../packs"

func shipped(t *testing.T) []*Pack {
	t.Helper()
	// Signed the way the loader verifies, over a copy, so the test exercises the
	// signature path rather than the allow_unsigned one: what ships in this tree
	// is the pack source, and an estate's own release signs it.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey("test", base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	entries, err := os.ReadDir(shippedDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(shippedDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()+SigExt),
			[]byte(Sign("test", priv, b)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Load(dir, Trust{Keys: []Key{k}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unsigned) != 0 {
		t.Fatalf("a signed copy loaded unsigned: %v", rep.Unsigned)
	}
	return rep.Packs
}

func TestTheShippedPacksLoad(t *testing.T) {
	ps := shipped(t)
	if len(ps) < 25 {
		t.Fatalf("%d packs, and the set is meant to be the ten techniques, "+
			"the named malware and the tooling", len(ps))
	}
	byTech := map[string]int{}
	for _, p := range ps {
		byTech[p.Technique]++
		if len(p.References) == 0 {
			t.Errorf("%s: no references, and a detection nobody can trace back to "+
				"an analysis is one nobody can argue with", p.ID)
		}
		if p.Severity == SeverityCritical && p.Enforcement == EnforceAlert {
			// Not an error: most critical packs are alert-only on purpose,
			// because the evidence is a shape and not a fact. Just make sure
			// the two fields were both thought about.
			t.Logf("%s is critical and alert-only", p.ID)
		}
	}
	// The ten technique packs are named after their technique, which is what
	// makes the set readable as coverage rather than as a pile of files.
	tech := 0
	for _, p := range ps {
		if strings.HasPrefix(p.ID, "t0") {
			tech++
			if !strings.HasPrefix(p.ID, strings.ToLower(p.Technique)+"-") {
				t.Errorf("%s is named for a technique other than %s", p.ID, p.Technique)
			}
		}
	}
	if tech != 10 {
		t.Errorf("%d technique packs, want 10", tech)
	}
}

// Every pack may deny only where its own declaration says so, and the set as a
// whole keeps the rule this project has had since the first OT detection: a
// finding derived from novelty alerts, because the first legitimate thing a
// plant does after a quiet year looks exactly like the first illegitimate one.
func TestOnlyFactsMayDeny(t *testing.T) {
	for _, p := range shipped(t) {
		if !p.MayDeny() {
			continue
		}
		// A pack that may deny has to rest on something named on the wire --
		// an engineering operation, or a refusal the policy itself made -- and
		// not on a novelty model alone.
		grounded := false
		for _, s := range p.Detect.Signals {
			for _, r := range s.Reasons {
				if !strings.HasPrefix(bareReason("", r), "anomaly_") {
					grounded = true
				}
			}
		}
		if !grounded {
			t.Errorf("%s may deny on behavioural findings alone: a detection built "+
				"only on 'I have not seen this before' must not refuse a plant's traffic", p.ID)
		}
	}
}

// replay is one trace file: the events that must report, and the events that
// must not.
type replay struct {
	fire, hold []Event
}

func readReplay(t *testing.T, path string) replay {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // the test's own testdata
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var r replay
	into := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "fire" || line == "hold" {
			into = line
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("%s: %q is not `<kind> <action> <reason>`", path, line)
		}
		e := Event{Kind: fields[0], Action: fields[1], Reason: fields[2]}
		if into == "fire" {
			r.fire = append(r.fire, e)
		} else {
			r.hold = append(r.hold, e)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(r.fire) == 0 {
		t.Fatalf("%s: no fire section", path)
	}
	return r
}

func TestEveryPackHasAReplayAndItFires(t *testing.T) {
	at := time.Date(2026, 4, 7, 11, 0, 0, 0, time.UTC)
	actor := netip.MustParseAddr("10.40.9.33")
	for _, p := range shipped(t) {
		t.Run(p.ID, func(t *testing.T) {
			path := filepath.Join(shippedDir, "testdata", p.ID+".replay")
			r := readReplay(t, path)

			// The whole sequence reports, once.
			feed := func(evs []Event) []Finding {
				e := New([]*Pack{p}, Options{})
				e.SetClock(func() time.Time { return at })
				var out []Finding
				for i, ev := range evs {
					// Spread across the pack's window, so a trace that only
					// fires because every event landed on one instant is a
					// trace that fails.
					ev.Actor = actor
					ev.At = at.Add(time.Duration(i+1) * p.Detect.Window / time.Duration(len(evs)+2))
					out = append(out, e.Observe(ev)...)
				}
				return out
			}
			got := feed(r.fire)
			if len(got) != 1 {
				t.Fatalf("the trace reported %d times, want 1: %+v", len(got), got)
			}
			if got[0].Pack != p.ID {
				t.Errorf("reported %s", got[0].Pack)
			}
			if got[0].Technique != p.Technique {
				t.Errorf("technique %s, want %s", got[0].Technique, p.Technique)
			}
			if got[0].Denied {
				t.Error("a finding quarantined with enforcement off")
			}

			// One signal short reports nothing. This is the half that fails
			// when somebody weakens a pack.
			if len(r.hold) > 0 {
				if got := feed(r.hold); len(got) != 0 {
					t.Errorf("the trace one signal short reported anyway: %+v", got)
				}
			}
		})
	}
}

// A pack that declares deny, with an operator who turned enforcement on, holds
// the actor out -- and the hold is over when the pack's own window is.
func TestTheDenyingPacksQuarantineAndItExpires(t *testing.T) {
	at := time.Date(2026, 4, 7, 11, 0, 0, 0, time.UTC)
	actor := netip.MustParseAddr("10.40.9.33")
	n := 0
	for _, p := range shipped(t) {
		if !p.MayDeny() {
			continue
		}
		n++
		r := readReplay(t, filepath.Join(shippedDir, "testdata", p.ID+".replay"))
		e := New([]*Pack{p}, Options{Enforce: true})
		e.SetClock(func() time.Time { return at })
		denied := false
		for i, ev := range r.fire {
			ev.Actor = actor
			ev.At = at.Add(time.Duration(i+1) * p.Detect.Window / time.Duration(len(r.fire)+2))
			for _, f := range e.Observe(ev) {
				denied = denied || f.Denied
			}
		}
		if !denied {
			t.Errorf("%s declares deny and did not hold the actor out", p.ID)
			continue
		}
		if _, held := e.Quarantined(actor); !held {
			t.Errorf("%s: reported a quarantine and is not holding one", p.ID)
		}
		e.SetClock(func() time.Time { return at.Add(p.Detect.Window + time.Hour) })
		if _, held := e.Quarantined(actor); held {
			t.Errorf("%s: the quarantine outlived its window", p.ID)
		}
	}
	if n == 0 {
		t.Error("no shipped pack declares deny, so the enforcement path ships untested")
	}
}
