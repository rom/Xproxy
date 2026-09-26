package access

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// onDisk is a ledger in a file, with a clock a test drives.
func onDisk(t *testing.T, path string, pol Policy, now *time.Time) *Ledger {
	t.Helper()
	l, err := Open(path, pol)
	if err != nil {
		t.Fatal(err)
	}
	l.SetClockForTest(func() time.Time { return *now })
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// What survives a restart is the whole point: a one-shot grant that refills
// itself when the daemon is restarted is not one-shot, and a revocation that
// does not survive is worse than one that was never made.
func TestTheLedgerSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "access.log")
	now := t0
	l := onDisk(t, path, fourEyes(), &now)
	g, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "db-1:22", Reason: "incident 4711",
		By: "carol", Expires: t0.Add(time.Hour), MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(g.ID, "bob", "spoke to alice"); err != nil {
		t.Fatal(err)
	}
	if err := l.Use(g.ID, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	again := onDisk(t, path, fourEyes(), &now)
	v, ok := again.Get(g.ID)
	if !ok {
		t.Fatal("the grant did not come back")
	}
	if v.State != Active || v.Uses != 1 || len(v.Approvals) != 1 || v.Approvals[0].Note != "spoke to alice" {
		t.Fatalf("after the restart: %+v", v)
	}
	// The remaining use is the remaining use, not a fresh pair.
	if err := again.Use(g.ID, "sess-2"); err != nil {
		t.Fatal(err)
	}
	if _, reason := again.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonSpent {
		t.Errorf("after both uses: %q, want %q", reason, ReasonSpent)
	}
	if s := again.Stats(); s.Requests != 1 || s.Approvals != 1 || s.Uses != 2 {
		t.Errorf("the counters did not come back: %+v", s)
	}
}

// The chain is what makes the trail worth reading after an incident. An edited
// line is found at load, and the daemon refuses to serve a trail it cannot
// stand behind rather than presenting it as intact.
func TestAnEditedTrailIsRefused(t *testing.T) {
	dir := t.TempDir()
	for name, edit := range map[string]func(lines []string) []string{
		"a changed field": func(lines []string) []string {
			lines[0] = strings.Replace(lines[0], `"incident 4711"`, `"routine work"`, 1)
			return lines
		},
		"a removed record": func(lines []string) []string { return lines[1:] },
		"a record dropped from the middle": func(lines []string) []string {
			return append(lines[:1:1], lines[2:]...)
		},
		"two records swapped": func(lines []string) []string {
			lines[0], lines[1] = lines[1], lines[0]
			return lines
		},
		"an appended record of somebody's own": func(lines []string) []string {
			var r record
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
				panic(err)
			}
			r.Seq++
			r.Kind, r.Actor, r.Prev = kindApprove, "eve", r.Hash
			// Forged without recomputing the hash, which is the whole
			// point: the forger does not have to be careless for this
			// to be caught, but a careless one certainly is.
			b, _ := json.Marshal(r)
			return append(lines, string(b))
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".log")
			now := t0
			l := onDisk(t, path, fourEyes(), &now)
			g, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "db-1:22",
				Reason: "incident 4711", By: "carol", Expires: t0.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Approve(g.ID, "bob", ""); err != nil {
				t.Fatal(err)
			}
			if err := l.Use(g.ID, "sess-1"); err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
			if err := os.WriteFile(path, []byte(strings.Join(edit(lines), "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			again, err := Open(path, fourEyes())
			if err == nil {
				_ = again.Close()
				t.Fatal("an edited trail loaded without complaint")
			}
			if !strings.Contains(err.Error(), "edited") {
				t.Errorf("the error does not say the trail was edited: %v", err)
			}
		})
	}
}

// One process owns one trail. Two daemons appending to the same file would
// interleave their chains, and a chain that does not verify is worth nothing at
// the only moment it is read -- so the second one is refused at start rather
// than leaving it to be found later.
func TestASecondHolderIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	now := t0
	first := onDisk(t, path, fourEyes(), &now)
	second, err := Open(path, fourEyes())
	if err == nil {
		_ = second.Close()
		t.Fatal("two ledgers held the same file")
	}
	if !strings.Contains(err.Error(), "another process") {
		t.Errorf("the error does not say why: %v", err)
	}
	// And the file is usable again once the first one lets go.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := Open(path, fourEyes())
	if err != nil {
		t.Fatalf("after the first closed: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

// A ledger with no path is a ledger with no trail. It is allowed, because a
// test and an estate that keeps its record elsewhere both need it, but nothing
// about it is written -- and that is the configuration's warning to give, not
// this package's.
func TestAMemoryLedgerKeepsNoTrail(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "carol")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if v, ok := l.Get(g.ID); !ok || v.State != Active {
		t.Errorf("a memory ledger did not keep the grant: %+v", v)
	}
	if err := l.Close(); err != nil {
		t.Errorf("closing a memory ledger: %v", err)
	}
}

// A file that is not a ledger fails the load, rather than being read as an
// empty one: an operator who pointed the daemon at the wrong path has to be
// told.
func TestAFileThatIsNotALedgerFailsTheLoad(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"not json":               "hello\n",
		"json but not a record":  "[1,2,3]\n",
		"a record with no grant": `{"seq":1,"kind":"request","id":"x","prev":"","hash":"x"}` + "\n",
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".log")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := Open(path, fourEyes())
		if err == nil {
			_ = l.Close()
			t.Errorf("%s: loaded", name)
		}
	}
}

// Blank lines are not records. A trail an operator has scrolled through, or one
// a rotation left a newline in, still verifies.
func TestBlankLinesAreNotRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	now := t0
	l := onDisk(t, path, fourEyes(), &now)
	g := ask(t, l, "alice", "carol")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("\n\n"), append(raw, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	again := onDisk(t, path, fourEyes(), &now)
	if _, ok := again.Get(g.ID); !ok {
		t.Error("the grant did not survive a blank line")
	}
}

// The file holds credentials in the sense that matters -- who may reach what,
// and who agreed -- so it is not readable by the rest of the machine.
func TestTheTrailIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "access.log")
	now := t0
	l := onDisk(t, path, fourEyes(), &now)
	ask(t, l, "alice", "carol")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, want 0700", di.Mode().Perm())
	}
}

// A ledger with no room left cannot pretend a grant was recorded. The write
// happens before the grant is in force, so a disk that will not take writes
// produces an error and no grant -- rather than a grant this process honours
// and the next one has never heard of.
func TestAWriteThatFailsIsNotAGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	now := t0
	l := onDisk(t, path, fourEyes(), &now)
	good := ask(t, l, "alice", "carol")
	if _, err := l.Approve(good.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	// Closing the file underneath the ledger is the cheapest stand-in for a
	// full or unwritable filesystem.
	if err := l.f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Request(Request{Subject: "dave", Listener: "bastion", Target: "db-1:22", Reason: "x",
		By: "carol", Expires: t0.Add(time.Hour)}); err == nil {
		t.Fatal("a request was accepted although nothing could be written")
	}
	if n := len(l.Grants()); n != 1 {
		t.Errorf("%d grants after the failed write, want only the one written before it", n)
	}
	if _, reason := l.Admit("dave", "bastion", []string{"db-1:22"}); reason != ReasonNoGrant {
		t.Errorf("the unwritten grant admitted a session: %q", reason)
	}
	// A failed approval is the same: it is not in force, so the grant it was
	// meant to approve stays pending.
	pending := &Grant{}
	l.mu.Lock()
	for _, id := range l.order {
		if l.byID[id].ID == good.ID {
			pending = l.byID[id]
		}
	}
	l.mu.Unlock()
	if _, err := l.Approve(pending.ID, "erin", ""); err == nil {
		t.Error("an approval was accepted although nothing could be written")
	}
	if len(pending.Approvals) != 1 {
		t.Errorf("the unwritten approval was counted: %d approvals", len(pending.Approvals))
	}
	l.f, l.w = nil, nil
}

// A trail longer than the replay bound fails the load with what to do about it,
// rather than reading an unbounded file into memory. The bound is lowered here
// rather than writing a million records, and the records are real ones from the
// ledger's own writer, so nothing about the chain is faked.
func TestAnEnormousTrailSaysToArchiveIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	now := t0
	l := onDisk(t, path, fourEyes(), &now)
	g := ask(t, l, "alice", "carol")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if err := l.Use(g.ID, "sess"); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Three real, chained records against a bound of two.
	small := &Ledger{path: path, byID: map[string]*Grant{}, now: time.Now, maxRecords: 2}
	f, err := os.Open(path) //nolint:gosec // the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	err = small.replay(f)
	if err == nil {
		t.Fatal("a trail past the bound loaded")
	}
	if !strings.Contains(err.Error(), "archive") {
		t.Errorf("the error does not say what to do: %v", err)
	}
	// And the same file within the bound loads, so the bound is what refused
	// it rather than the file being broken.
	again, err := Open(path, fourEyes())
	if err != nil {
		t.Fatalf("the same trail with the ordinary bound: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

// Closing twice is not an error, because a daemon shutting down after a failed
// start will do it.
func TestClosingTwiceIsFine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	l, err := Open(path, fourEyes())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
	// A path that cannot exist -- under a file rather than a directory --
	// fails the load rather than starting an empty trail.
	if bad, err := Open(filepath.Join(path, "under-a-file"), fourEyes()); err == nil {
		_ = bad.Close()
		t.Error("a path under a file loaded")
	}
}
