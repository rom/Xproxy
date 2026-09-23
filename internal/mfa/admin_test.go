package mfa

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// write puts an enrolment file in place and returns its path.
func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An enrolment made through the store is one the store can verify
// with, and the secret and codes come back once.
func TestEnrolMakesAWorkingFactor(t *testing.T) {
	path := writeFile(t, "seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, recovery, err := s.Enrol("alice", Params{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery) != RecoveryCodes {
		t.Fatalf("%d recovery codes, want %d", len(recovery), RecoveryCodes)
	}
	raw, err := ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	// The factor works immediately, with no reload of anything.
	g := NewGuard(s, 0, Lockout{})
	code, err := Code(raw, Counter(time.Now(), 30*time.Second), Params{})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Verify("alice", code, time.Now()); err != nil {
		t.Fatalf("the new enrolment did not verify: %v", err)
	}
	// And so does a recovery code, once.
	if err := g.Verify("alice", recovery[0], time.Now()); err != nil {
		t.Fatalf("a recovery code did not verify: %v", err)
	}
	if err := g.Verify("alice", recovery[0], time.Now()); err == nil {
		t.Error("a recovery code worked twice")
	}

	// The file holds the secret and the hashes, not the codes.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "alice:") {
		t.Errorf("the file has no line for alice:\n%s", body)
	}
	for _, c := range recovery {
		if strings.Contains(string(body), c) {
			t.Error("a recovery code is in the file in clear")
		}
	}
	// The user who was there before is still there.
	if _, ok := s.Get("seed"); !ok {
		t.Error("enrolling one user removed another")
	}
}

// Removing an enrolment takes effect at once, because an enrolment
// that needs a restart to go away has not gone away.
func TestRemoveTakesEffectAtOnce(t *testing.T) {
	path := writeFile(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEH\nbob:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(s, 0, Lockout{})
	if !g.Enrolled("alice") {
		t.Fatal("alice is not enrolled to begin with")
	}
	if err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if g.Enrolled("alice") {
		t.Error("a removed user is still enrolled")
	}
	if !g.Enrolled("bob") {
		t.Error("removing one user removed another")
	}
	if err := s.Remove("alice"); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("removing a user twice: %v", err)
	}
	// Removing the last one leaves an empty file that still loads.
	if err := s.Remove("bob"); err != nil {
		t.Fatal(err)
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("after removing everyone: %+v", got)
	}
}

// An edit made outside the proxy is picked up without a restart.
func TestAnEditOutsideIsPickedUp(t *testing.T) {
	path := writeFile(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("bob"); ok {
		t.Fatal("bob is enrolled to begin with")
	}
	// The stamp is the size, the modification time and the identity,
	// so a file written a moment later is a different file.
	if err := os.WriteFile(path, []byte("alice:JBSWY3DPEHPK3PXPJBSWY3DPEH\nbob:JBSWY3DPEHPK3PXPJBSWY3DPEH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.checked = time.Time{} // the next lookup restats rather than waiting a second
	if _, ok := s.Get("bob"); !ok {
		t.Error("an enrolment added outside was not seen")
	}
}

// A file that does not parse leaves what is in memory in force, and
// says so, rather than enrolling or un-enrolling anybody.
func TestABrokenFileChangesNothing(t *testing.T) {
	path := writeFile(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var warned error
	s.Warn = func(err error) { warned = err }
	if err := os.WriteFile(path, []byte("this is not an enrolment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.checked = time.Time{}
	if _, ok := s.Get("alice"); !ok {
		t.Error("a broken file un-enrolled a user")
	}
	if warned == nil {
		t.Error("a broken file was not reported")
	}
	// And the next check tries again rather than giving up, so putting
	// the file back is enough.
	if err := os.WriteFile(path, []byte("bob:JBSWY3DPEHPK3PXPJBSWY3DPEH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.checked = time.Time{}
	if _, ok := s.Get("bob"); !ok {
		t.Error("the file was not re-read after it parsed again")
	}
}

// A name that cannot go in the file is refused before anything is
// written, since the separators are what the format is made of.
func TestNamesAreChecked(t *testing.T) {
	path := writeFile(t, "seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "a:b", "a,b", "a b", "a\tb", "a\nb", "#alice", strings.Repeat("a", MaxUserName+1)} {
		if _, _, err := s.Enrol(name, Params{}); !errors.Is(err, ErrBadUserName) {
			t.Errorf("%q was accepted (%v)", name, err)
		}
	}
	// A name with the characters a real directory uses is fine. The
	// check is called directly rather than through an enrolment,
	// because hashing ten recovery codes for each of them is seconds
	// of work to prove something about a string.
	for _, name := range []string{"alice", "LAB\\alice", "alice@example.com", "alice.smith-1"} {
		if err := ValidName(name); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}
	// And one of them all the way through, so the check is wired in.
	if _, _, err := s.Enrol("alice", Params{}); err != nil {
		t.Errorf("enrolling a valid name: %v", err)
	}
}

// Replacing the recovery codes invalidates the old ones.
func TestRecoveryCodesAreReplaced(t *testing.T) {
	path := writeFile(t, "seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enrol("alice", Params{}); err != nil {
		t.Fatal(err)
	}
	old, err := s.Recovery("alice")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Recovery("alice")
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(s, 0, Lockout{})
	if err := g.Verify("alice", old[0], time.Now()); err == nil {
		t.Error("a replaced recovery code still works")
	}
	if err := g.Verify("alice", fresh[0], time.Now()); err != nil {
		t.Errorf("a new recovery code does not work: %v", err)
	}
	if _, err := s.Recovery("nobody"); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("recovery codes for a user who is not there: %v", err)
	}
}

// The parameters an enrolment was made with survive a round trip
// through the file, which is what an authenticator needs to agree.
func TestParametersSurviveTheFile(t *testing.T) {
	path := writeFile(t, "seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Params{Digits: 8, Period: 60 * time.Second, Algo: "SHA256"}
	secret, _, err := s.Enrol("alice", want)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := again.Get("alice")
	if !ok {
		t.Fatal("alice is not in the file")
	}
	if e.Params != want {
		t.Errorf("parameters %+v, want %+v", e.Params, want)
	}
	// And a code made with them verifies.
	raw, err := ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	code, err := Code(raw, Counter(time.Now(), 60*time.Second), want)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewGuard(again, 0, Lockout{}).Verify("alice", code, time.Now()); err != nil {
		t.Errorf("a code made with the stored parameters did not verify: %v", err)
	}
}

// The file the writer leaves behind is not readable by anyone else.
func TestTheFileStaysPrivate(t *testing.T) {
	path := writeFile(t, "seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enrol("alice", Params{}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the file is mode %04o after a write", fi.Mode().Perm())
	}
}

// A status view sees who is enrolled and what this process remembers,
// and never the secret.
func TestTheStatusViewShowsNoSecret(t *testing.T) {
	path := writeFile(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEH:digits=8,period=60\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(s, 0, Lockout{MaxFailures: 2, Window: time.Minute, Duration: time.Hour})
	now := time.Now()
	list := g.List(now)
	if len(list) != 1 || list[0].User != "alice" {
		t.Fatalf("status %+v", list)
	}
	if list[0].Digits != 8 || list[0].Period != 60 {
		t.Errorf("parameters %+v", list[0])
	}
	if list[0].Locked || list[0].Failures != 0 {
		t.Errorf("a fresh user is %+v", list[0])
	}

	// Wrong codes lock the user out, and an operator can let them back.
	_ = g.Verify("alice", "000000", now)
	_ = g.Verify("alice", "000000", now)
	if !g.Locked("alice", now) {
		t.Fatal("the user was not locked out")
	}
	if list := g.List(now); !list[0].Locked || list[0].LockedUntil.IsZero() {
		t.Errorf("the status does not show the lockout: %+v", list[0])
	}
	if !g.Unlock("alice") {
		t.Error("unlocking reported nothing to do")
	}
	if g.Locked("alice", now) {
		t.Error("the user is still locked out")
	}
	if g.Unlock("nobody") {
		t.Error("unlocking a user with no state reported something to do")
	}
}

// Recovery codes are made of characters somebody can read back.
func TestRecoveryCodesAreLegible(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := recoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Fatalf("two codes came out the same: %q", c)
		}
		seen[c] = true
		groups := strings.Split(c, "-")
		if len(groups) != recoveryCodeGroups {
			t.Fatalf("%q has %d groups", c, len(groups))
		}
		for _, g := range groups {
			if len(g) != recoveryGroupLen {
				t.Fatalf("%q has a group of %d", c, len(g))
			}
		}
		if strings.ContainsAny(c, "01lOI") {
			t.Errorf("%q has a character that is read back wrongly", c)
		}
	}
}

// Forgetting a user drops what this process remembers, so the next
// person enrolled under the name does not inherit a lockout.
func TestForgettingAUserClearsTheState(t *testing.T) {
	path := writeFile(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEH\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(s, 0, Lockout{MaxFailures: 1, Window: time.Minute, Duration: time.Hour})
	now := time.Now()
	_ = g.Verify("alice", "000000", now)
	if !g.Locked("alice", now) {
		t.Fatal("the user was not locked out")
	}
	g.Forget("alice")
	if g.Locked("alice", now) {
		t.Error("the lockout survived being forgotten")
	}
}

// TestARecoveryCodeFitsWhereACodeGoes is the third finding of the
// sixth round. A recovery code is seventeen characters with its
// separators, and the two protocols that carry a code inside the
// password field -- FTP and RDP, neither of which has anywhere to ask a
// question -- would only split off sixteen. So a recovery code was
// never seen as a code on either of them: it went to the desktop as
// part of the password, the factor check saw nothing, and the refusal
// was byte for byte the one a wrong code gets.
//
// That is the worst shape a bug can have here. The recovery path exists
// for the person who has lost their authenticator, so it is used when
// somebody is already locked out and in a hurry, and it failed in a way
// that looks exactly like them mistyping.
func TestARecoveryCodeFitsWhereACodeGoes(t *testing.T) {
	if RecoveryCodeLength != 17 {
		t.Fatalf("a recovery code is %d characters; the callers' bound has to be at least that", RecoveryCodeLength)
	}
	if MaxCode < RecoveryCodeLength {
		t.Fatalf("MaxCode is %d and a recovery code is %d", MaxCode, RecoveryCodeLength)
	}
	if MaxCode < MaxDigits {
		t.Fatalf("MaxCode is %d and a time based code can be %d digits", MaxCode, MaxDigits)
	}
	// And the codes the generator makes are that length, so the
	// constant cannot drift away from the thing it describes.
	codes, _, err := newRecovery(RecoveryCodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		if len(c) != RecoveryCodeLength {
			t.Fatalf("the generator made a %d character code: %q", len(c), c)
		}
	}
}

// TestAWrongCodeCostsTheSameWhoeverItIsFor is the fourth finding of
// the sixth round, and the one with the widest consequences.
//
// A wrong code was verified against every recovery code the enrolment
// held, each a PBKDF2 hash at a password's iteration count. So a wrong
// six digit code against an enrolled name cost about a second of
// processor time, and against a name with no enrolment cost twenty
// microseconds: four and a half orders of magnitude, which is not a
// side channel so much as an announcement. Anybody who could reach the
// prompt could enumerate who was enrolled, and the documentation's
// claim that a wrong code and an unenrolled name look alike was true
// of the reply and false of the clock.
//
// The same arithmetic was a denial of service: one packet bought a
// second of a core, repeatable as fast as a client could send.
//
// Three changes, and this test is what holds them. Recovery codes are
// hashed at a low iteration count, because a code of seventy four
// random bits does not need stretching and stretching it cost this.
// They are only compared when what arrived is shaped like one, so a
// wrong digit code touches none of them. And a name with no enrolment
// spends what a name with one spends.
func TestAWrongCodeCostsTheSameWhoeverItIsFor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa")
	if err := os.WriteFile(path, []byte("seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_, codes, err := store.Enrol("alice", Params{})
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(store, 1, Lockout{MaxFailures: 1 << 20, Window: time.Hour, Duration: time.Hour, MaxUsers: 100})

	// The codes the generator makes still work, which is the thing all
	// of this must not have broken.
	if err := g.Verify("alice", codes[0], time.Now()); err != nil {
		t.Fatalf("a recovery code from the generator: %v", err)
	}

	// A wrong code must not cost a password's worth of hashing. Before
	// the fix this was a second; the bound is generous enough to
	// survive a loaded machine and still fail if the cost comes back.
	if d := best(func() { _ = g.Verify("alice", "000000", time.Now()) }); d > 100*time.Millisecond {
		t.Fatalf("a wrong code against an enrolled name took %v", d)
	}

	// And a wrong code costs about the same whether the name is
	// enrolled or not, whatever shape it has. The bound is a factor of
	// eight either way: the difference it is there to catch was forty
	// five thousand.
	for _, code := range []string{"000000", "abcde-fghjk-mnpqr", "something-else-entirely"} {
		known := best(func() { _ = g.Verify("alice", code, time.Now()) })
		unknown := best(func() { _ = g.Verify("nobody-at-all", code, time.Now()) })
		ratio := float64(known) / float64(unknown)
		if ratio > 8 || ratio < 0.125 {
			t.Errorf("code %q: enrolled %v, unknown %v (%.1fx apart)", code, known, unknown, ratio)
		}
	}
}

// best runs f a few times and returns the fastest, which is the
// measurement least disturbed by whatever else the machine is doing.
func best(f func()) time.Duration {
	out := time.Duration(1 << 62)
	for i := 0; i < 5; i++ {
		start := time.Now()
		f()
		if d := time.Since(start); d < out {
			out = d
		}
	}
	return out
}
