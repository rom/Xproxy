package fipsmode

import (
	"crypto/fips140"
	"crypto/tls"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Require is the one check an estate under audit depends on, and its message has
// to carry the remedy: the mode comes from the toolchain and the GODEBUG, so
// there is nothing in the configuration file to change.
func TestRequireRefusesWhenTheRuntimeIsNotInTheMode(t *testing.T) {
	if err := Require(false); err != nil {
		t.Errorf("not required: %v", err)
	}
	err := Require(true)
	if fips140.Enabled() {
		if err != nil {
			t.Errorf("required and enabled: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("required and not enabled: no error")
	}
	for _, want := range []string{"GODEBUG=fips140=on", "toolchain", "required: false"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lacks %q: %v", want, err)
		}
	}
}

// The probe answers "will this configuration work here" by doing it. Outside
// FIPS mode every group and suite the proxy offers has to pass, which is also
// the test that the probe itself is not simply refusing everything.
func TestTheProbeAcceptsWhatThisRuntimeCanDo(t *testing.T) {
	groups := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	suites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	refused, err := Probe(groups, suites)
	if err != nil {
		t.Fatal(err)
	}
	if fips140.Enabled() {
		t.Logf("in FIPS mode this runtime refuses: %v", refused)
		return
	}
	if len(refused) != 0 {
		t.Errorf("outside FIPS mode the probe refused %v, which means it is testing itself rather than the runtime", refused)
	}
}

// A group this runtime does not implement at all is reported, which is the
// mechanism the FIPS answer rests on: the probe reports what fails rather than
// what a table says should fail.
func TestTheProbeReportsAGroupThatCannotWork(t *testing.T) {
	refused, err := Probe([]tls.CurveID{tls.CurveID(0xFEFE)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) != 1 || !strings.Contains(refused[0], "group-65278") {
		t.Errorf("refused %v, want the unknown group named", refused)
	}
}

// The names in the report are the names the configuration uses, because an
// operator has to find the line to change.
func TestTheNamesAreTheConfigurationsOwn(t *testing.T) {
	for id, want := range map[tls.CurveID]string{
		tls.X25519MLKEM768: "X25519MLKEM768",
		tls.X25519:         "X25519",
		tls.CurveP256:      "P-256",
		tls.CurveP384:      "P-384",
		tls.CurveP521:      "P-521",
	} {
		if got := groupName(id); got != want {
			t.Errorf("%v named %q, want %q", id, got, want)
		}
	}
}

// The claim that matters most is one a test in this process cannot make, because
// the mode is fixed before main runs: so the test re-runs itself in a child
// process with the GODEBUG set, and asserts what that child reports.
func TestInFIPSModeTheRuntimeSaysSo(t *testing.T) {
	if os.Getenv("XPROXY_FIPS_CHILD") == "1" {
		// The child: report the mode and what the probe refuses, for the
		// parent to read.
		refused, err := Probe([]tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
			[]uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CHILD enabled=%v required_error=%v refused=%v", Enabled(), Require(true) != nil, refused)
		if !Enabled() {
			t.Fatal("CHILD: the GODEBUG did not switch the module on")
		}
		if Require(true) != nil {
			t.Fatal("CHILD: required and enabled still refused")
		}
		return
	}
	if fips140.Enabled() {
		t.Skip("this runtime is already in FIPS mode, so there is nothing to compare")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestInFIPSModeTheRuntimeSaysSo", "-test.v")
	cmd.Env = append(os.Environ(), "XPROXY_FIPS_CHILD=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child failed: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "CHILD enabled=true") {
		t.Errorf("the child did not report the mode:\n%s", text)
	}
	// And what it refuses is worth recording: it is the answer an operator
	// gets from the probe on this toolchain.
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "CHILD enabled=") {
			t.Log(strings.TrimSpace(line))
		}
	}
}

// Status is the shape the management view and the exposition read.
func TestStatusIsTheShapeTheViewsRead(t *testing.T) {
	s := Status{Enabled: Enabled(), Required: true, Probed: true, Refused: []string{"key_exchange X25519"}}
	if !slices.Contains(s.Refused, "key_exchange X25519") {
		t.Error("the refused list did not survive")
	}
	if s.Enabled != fips140.Enabled() {
		t.Error("Enabled disagrees with the runtime")
	}
}
