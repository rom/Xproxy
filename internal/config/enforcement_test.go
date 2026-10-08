package config

import (
	"strings"
	"testing"
)

// The fold, every combination. Three settings can switch enforcement off and
// they belong to different layers, so what matters is that the precedence is one
// precedence -- and that the mode names the reason rather than collapsing all
// three into "not enforcing", because an operator fixing a listener needs to know
// which switch to look at.
func TestEnforcementFoldsEveryReasonAndNamesIt(t *testing.T) {
	for _, tc := range []struct {
		name      string
		e         Enforcement
		enforcing bool
		mode      string
	}{
		{"nothing set is enforcing, which is the only safe default",
			Enforcement{}, true, "enforce"},
		{"shadow", Enforcement{Shadow: true}, false, "shadow"},
		{"monitor_only", Enforcement{MonitorOnly: true}, false, "monitor"},
		{"a learning run is observe-only unless it says otherwise",
			Enforcement{Learning: true}, false, "learn"},
		{"a learning run that says it enforces does",
			Enforcement{Learning: true, LearnEnforce: true}, true, "enforce"},
		// Either explicit switch wins over a learning run: an operator who
		// wrote shadow meant the listener, not the part of it that is not
		// learning.
		{"shadow beats a learning run that enforces",
			Enforcement{Shadow: true, Learning: true, LearnEnforce: true}, false, "shadow"},
		{"monitor_only beats a learning run that enforces",
			Enforcement{MonitorOnly: true, Learning: true, LearnEnforce: true}, false, "monitor"},
		// And between the two explicit ones, shadow is reported: it is the
		// estate's switch rather than the kind's, so it is the one an operator
		// who set it is looking for.
		{"shadow is named before monitor_only",
			Enforcement{Shadow: true, MonitorOnly: true}, false, "shadow"},
		{"learn_enforce alone means nothing without a run",
			Enforcement{LearnEnforce: true}, true, "enforce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.Enforcing(); got != tc.enforcing {
				t.Errorf("Enforcing() = %v, want %v", got, tc.enforcing)
			}
			if got := tc.e.Mode(); got != tc.mode {
				t.Errorf("Mode() = %q, want %q", got, tc.mode)
			}
			// The two must never disagree: a mode of enforce with
			// Enforcing false, or the other way round, is a status view
			// that lies about the one field it must not get wrong.
			if (tc.e.Mode() == "enforce") != tc.e.Enforcing() {
				t.Errorf("Mode()=%q disagrees with Enforcing()=%v", tc.e.Mode(), tc.e.Enforcing())
			}
		})
	}
}

// A listener that says the same thing twice loads and behaves, and should be
// told so: an operator who turns one switch off and finds the listener still
// refusing nothing is an operator whose shadow run becomes permanent.
func TestTwoReasonsNotToEnforceAreAdvisedOn(t *testing.T) {
	warn := func(ln Listener) string {
		v := &validator{}
		v.enforcementSources("listeners[0]", &ln)
		if len(v.advice) == 0 {
			return ""
		}
		return v.advice[0]
	}
	shadow := &ListenerPolicy{Mode: "shadow"}

	// One reason on its own: nothing to say here, the policy.mode check
	// already warns about shadow.
	for _, ln := range []Listener{
		{Name: "a", Kind: "postgres", Policy: shadow, Postgres: &PostgresListener{}},
		{Name: "b", Kind: "postgres", Postgres: &PostgresListener{MonitorOnly: true}},
		{Name: "c", Kind: "modbus", Modbus: &ModbusListener{Learn: &ModbusLearn{Enabled: true}}},
	} {
		if got := warn(ln); got != "" {
			t.Errorf("%s: one reason was advised on: %s", ln.Name, got)
		}
	}

	// Two, and the advice names both and the mode that wins.
	got := warn(Listener{Name: "d", Kind: "postgres", Policy: shadow,
		Postgres: &PostgresListener{MonitorOnly: true}})
	for _, want := range []string{"policy.mode: shadow", "monitor_only", `"shadow"`} {
		if !strings.Contains(got, want) {
			t.Errorf("the advice does not mention %s: %q", want, got)
		}
	}
	// Three.
	got = warn(Listener{Name: "e", Kind: "opcua", Policy: shadow,
		OPCUA: &OPCUAListener{MonitorOnly: true, Learn: &OPCUALearn{Enabled: true}}})
	for _, want := range []string{"policy.mode: shadow", "monitor_only", "learn without enforce"} {
		if !strings.Contains(got, want) {
			t.Errorf("the advice does not mention %s: %q", want, got)
		}
	}
	// A learning run that enforces is not a reason not to enforce.
	if got := warn(Listener{Name: "f", Kind: "opcua",
		OPCUA: &OPCUAListener{MonitorOnly: true, Learn: &OPCUALearn{Enabled: true, Enforce: true}}}); got != "" {
		t.Errorf("a learning run that enforces was counted: %s", got)
	}
	// And iec104's monitor_only is the protocol's monitor direction, which
	// refuses every command rather than permitting them, so pairing it with
	// shadow is not saying the same thing twice.
	if got := warn(Listener{Name: "g", Kind: "iec104", Policy: shadow,
		IEC104: &IEC104Listener{MonitorOnly: true}}); got != "" {
		t.Errorf("iec104 monitor_only was read as not-enforcing: %s", got)
	}
}
