package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/mfa"
)

// The MFA commands run locally, and the only thing that really has to be true
// of them is a round trip: the line `enrol` prints, pasted into the enrolment
// file, has to be a line `verify` accepts a current code for. Everything else
// about a second factor is an operator following instructions, and if the
// instructions and the verifier disagree the symptom is nobody being able to
// log in -- after the secret has already been sent to the user.

func mfaRun(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	fs := flag.NewFlagSet("xproxyctl", flag.ContinueOnError)
	fs.SetOutput(&errOut)
	_ = fs.Parse(append([]string{"mfa"}, args...))
	return mfaCommand(fs, &out, &errOut), out.String(), errOut.String()
}

// enrolmentLine pulls the file line out of what enrol printed. It is the
// first line of the output that looks like one, which is also how an operator
// finds it.
func enrolmentLine(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "alice:") {
			return l
		}
	}
	t.Fatalf("no enrolment line in:\n%s", out)
	return ""
}

// TestAnEnrolmentLineIsOneTheVerifierAccepts walks the whole exchange: enrol,
// paste, verify with a code computed the way an authenticator application
// would, and then the two refusals that matter -- a code from the wrong secret
// and a user who was never enrolled.
func TestAnEnrolmentLineIsOneTheVerifierAccepts(t *testing.T) {
	code, out, errOut := mfaRun("enrol", "-user", "alice", "-issuer", "acme", "-recovery", "2")
	if code != 0 {
		t.Fatalf("enrol: %d %q %q", code, out, errOut)
	}
	line := enrolmentLine(t, out)
	// The URI is what a QR code carries, and the issuer has to be in it or the
	// user's application labels the entry with somebody else's name.
	if !strings.Contains(out, "otpauth://totp/") || !strings.Contains(out, "acme") {
		t.Errorf("no provisioning URI for the issuer:\n%s", out)
	}
	// Two recovery codes were asked for and two are shown, each only now.
	if n := strings.Count(out, "-"); n < 4 {
		t.Errorf("the recovery codes are not in the output:\n%s", out)
	}

	file := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The secret is the second field. Computing the code here rather than
	// asking the package to verify its own output is the point: this is what
	// the user's telephone will do.
	secret := strings.Split(line, ":")[1]
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatalf("the printed secret does not parse: %v", err)
	}
	now := time.Now()
	want, err := mfa.Code(raw, mfa.Counter(now, mfa.DefaultPeriod), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := mfaRun("verify", "-file", file, "-user", "alice", "-code", want); code != 0 {
		t.Fatalf("verify: %d %q %q", code, out, errOut)
	} else if !strings.Contains(out, "accepted") {
		t.Errorf("verify said %q", out)
	}

	// A code from another enrolment is not accepted for this one.
	other, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, err := mfa.ParseSecret(other)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := mfa.Code(otherRaw, mfa.Counter(now, mfa.DefaultPeriod), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if code, out, _ := mfaRun("verify", "-file", file, "-user", "alice", "-code", wrong); code != 1 || !strings.Contains(out, "not accepted") {
		t.Errorf("a code for another secret: %d %q", code, out)
	}
	// A user who is not in the file is refused in the same words, because
	// which of the two it was is not the caller's business.
	if code, out, _ := mfaRun("verify", "-file", file, "-user", "mallory", "-code", want); code != 1 || !strings.Contains(out, "not accepted") {
		t.Errorf("an unenrolled user: %d %q", code, out)
	}

	// list reports the parameters the line carries, and how many recovery
	// codes are left -- which is the number an operator needs before telling
	// somebody to use one.
	code, out, errOut = mfaRun("list", "-file", file)
	if code != 0 {
		t.Fatalf("list: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"alice", "6 digits", "SHA1", "2 recovery codes"} {
		if !strings.Contains(out, want) {
			t.Errorf("list has no %q:\n%s", want, out)
		}
	}
	if errOut != "" {
		t.Errorf("a 0600 file warned about: %q", errOut)
	}
}

// TestTheEnrolmentParametersReachTheVerifier: a listener configured for eight
// digits on a sixty second step has to verify codes computed that way, so the
// parameters have to cross from the printed line into the file and back out.
// They are the part of this an operator cannot check by eye.
func TestTheEnrolmentParametersReachTheVerifier(t *testing.T) {
	code, out, errOut := mfaRun("enrol", "-user", "alice", "-digits", "8", "-period", "60", "-algo", "sha256")
	if code != 0 {
		t.Fatalf("enrol: %d %q %q", code, out, errOut)
	}
	line := enrolmentLine(t, out)
	if !strings.Contains(line, "digits=8,period=60,algo=SHA256") {
		t.Fatalf("the parameters are not in the line: %q", line)
	}
	file := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := mfa.Params{Digits: 8, Period: 60 * time.Second, Algo: "SHA256"}
	raw, err := mfa.ParseSecret(strings.Split(line, ":")[1])
	if err != nil {
		t.Fatal(err)
	}
	want, err := mfa.Code(raw, mfa.Counter(time.Now(), p.Period), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 8 {
		t.Fatalf("an eight digit code is %d long", len(want))
	}
	if code, out, errOut := mfaRun("verify", "-file", file, "-user", "alice", "-code", want); code != 0 {
		t.Fatalf("verify: %d %q %q", code, out, errOut)
	}
	// A six digit code for the same secret is not an eight digit one.
	short, err := mfa.Code(raw, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := mfaRun("verify", "-file", file, "-user", "alice", "-code", short); code != 1 {
		t.Error("a code computed with the default parameters was accepted")
	}
	if code, out, _ := mfaRun("list", "-file", file); code != 0 || !strings.Contains(out, "8 digits") || !strings.Contains(out, "SHA256") {
		t.Errorf("list: %d %q", code, out)
	}
}

// TestTheFileModeIsCheckedInTwoPlaces: the file holds every second factor in
// the estate, and there are two different answers about its mode. A
// world-readable file is refused outright by the store, which is the one the
// listener depends on too -- so it is a failure and not a warning. A file
// readable by a group is loaded and warned about, because a deployment where
// an operators group reads it is a choice somebody may have made on purpose.
// Asserting both is what keeps the refusal from quietly becoming the warning.
func TestTheFileModeIsCheckedInTwoPlaces(t *testing.T) {
	code, out, _ := mfaRun("enrol", "-user", "alice")
	if code != 0 {
		t.Fatal(out)
	}
	line := enrolmentLine(t, out)
	dir := t.TempDir()

	world := filepath.Join(dir, "world")
	if err := os.WriteFile(world, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := mfaRun("list", "-file", world)
	if code != 1 {
		t.Errorf("a world readable file was listed: %d %q", code, out)
	}
	if !strings.Contains(errOut, "world readable") {
		t.Errorf("the refusal does not say why: %q", errOut)
	}
	// And verify refuses it for the same reason, rather than reading it and
	// deciding about a code.
	if code, _, errOut := mfaRun("verify", "-file", world, "-user", "alice", "-code", "000000"); code != 1 || !strings.Contains(errOut, "world readable") {
		t.Errorf("verify against a world readable file: %d %q", code, errOut)
	}

	group := filepath.Join(dir, "group")
	if err := os.WriteFile(group, []byte(line+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = mfaRun("list", "-file", group)
	if code != 0 || !strings.Contains(out, "alice") {
		t.Fatalf("a group readable file: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(errOut, "should be 0600") {
		t.Errorf("no warning about the mode: %q", errOut)
	}
}

// TestMfaRefusesWhatWouldProduceAnUnusableEnrolment: each of these is a line
// that would be written into the file and then fail at somebody's first login.
func TestMfaRefusesWhatWouldProduceAnUnusableEnrolment(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no user", []string{"enrol"}, 2, "-user is required"},
		// A colon is the field separator of the file, so a name carrying one
		// would be read back as a different user with a different secret.
		{"a colon in the name", []string{"enrol", "-user", "a:b"}, 2, "must not contain a colon"},
		{"a newline in the name", []string{"enrol", "-user", "a\nb"}, 2, "must not contain a colon"},
		{"too few digits", []string{"enrol", "-user", "a", "-digits", "5"}, 2, "6..10"},
		{"too many digits", []string{"enrol", "-user", "a", "-digits", "11"}, 2, "6..10"},
		{"a step too short", []string{"enrol", "-user", "a", "-period", "5"}, 2, "10..300"},
		{"a step too long", []string{"enrol", "-user", "a", "-period", "301"}, 2, "10..300"},
		{"too many recovery codes", []string{"enrol", "-user", "a", "-recovery", "21"}, 2, "0..20"},
		{"a negative count", []string{"enrol", "-user", "a", "-recovery", "-1"}, 2, "0..20"},
		// An algorithm nothing implements is refused here rather than at the
		// first login, by being used once.
		{"an unknown algorithm", []string{"enrol", "-user", "a", "-algo", "md5"}, 2, "mfa enrol:"},
		{"verify with no file", []string{"verify", "-user", "a", "-code", "1"}, 2, "are required"},
		{"verify with no user", []string{"verify", "-file", "f", "-code", "1"}, 2, "are required"},
		{"verify with no code", []string{"verify", "-file", "f", "-user", "a"}, 2, "are required"},
		{"verify a missing file", []string{"verify", "-file", filepath.Join(dir, "absent"), "-user", "a", "-code", "1"}, 1, "mfa verify:"},
		{"list with no file", []string{"list"}, 2, "-file is required"},
		{"list a missing file", []string{"list", "-file", filepath.Join(dir, "absent")}, 1, "mfa list:"},
		{"no subcommand", []string{}, 2, "usage: xproxyctl mfa"},
		{"an unknown subcommand", []string{"bogus"}, 2, "usage: xproxyctl mfa"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := mfaRun(c.args...)
			if code != c.code {
				t.Fatalf("code %d, want %d (%q %q)", code, c.code, out, errOut)
			}
			if !strings.Contains(errOut, c.want) {
				t.Errorf("stderr %q does not mention %q", errOut, c.want)
			}
		})
	}
	// Both spellings of the subcommand work, because both are what somebody
	// types.
	for _, spelling := range []string{"enrol", "enroll"} {
		if code, _, errOut := mfaRun(spelling, "-user", "alice"); code != 0 {
			t.Errorf("%s: %d %q", spelling, code, errOut)
		}
	}
}
