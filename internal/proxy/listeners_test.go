package proxy

import (
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/listener"
)

// feat finds one guard row by name.
func feat(t *testing.T, v ListenerView, name string) FeatureView {
	t.Helper()
	for _, f := range v.Features {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("listener %s (kind %s) has no %s row, only %+v", v.Name, v.Kind, name, v.Features)
	return FeatureView{}
}

// hasFeat reports whether a guard row exists at all.
func hasFeat(v ListenerView, name string) bool {
	for _, f := range v.Features {
		if f.Name == name {
			return true
		}
	}
	return false
}

// An http listener: the kind has no section of its own, so there is
// nothing to report but the socket, and the default is to enforce.
func TestTheHTTPListenerViewIsTheSocketAndNothingElse(t *testing.T) {
	v := listenerView(config.Listener{Name: "main", Address: "0.0.0.0:443", TLS: &config.TLS{},
		Protocols: []config.Protocol{config.ProtocolH1, config.ProtocolH2}})
	if v.Kind != "http" {
		t.Errorf("kind %q: an empty kind is http", v.Kind)
	}
	if v.Role != "edge" || v.Daemon != "xproxy" {
		t.Errorf("role %q daemon %q", v.Role, v.Daemon)
	}
	if v.Mode != "enforce" {
		t.Errorf("mode %q: the default is to enforce", v.Mode)
	}
	if !v.TLS || len(v.Protocols) != 2 {
		t.Errorf("tls %v protocols %v", v.TLS, v.Protocols)
	}
	if v.Configured {
		t.Error("http has no section of its own to be configured by")
	}
	if len(v.Features) != 0 {
		t.Errorf("features %+v: http's policy is its routes", v.Features)
	}
	if !v.Authorises {
		t.Error("http consults the authorization section")
	}
}

// The mode is the field a status view must not get wrong, so each of the
// three ways of not enforcing is checked separately.
func TestTheModeSaysWhetherTheListenerRefusesAnything(t *testing.T) {
	shadow := listenerView(config.Listener{Name: "plant", Kind: "modbus",
		Policy: &config.ListenerPolicy{Mode: "shadow"}, Modbus: &config.ModbusListener{}})
	if shadow.Mode != "shadow" {
		t.Errorf("mode %q: policy.mode shadow", shadow.Mode)
	}
	monitor := listenerView(config.Listener{Name: "db", Kind: "postgres",
		Postgres: &config.PostgresListener{MonitorOnly: true}})
	if monitor.Mode != "monitor" {
		t.Errorf("mode %q: monitor_only", monitor.Mode)
	}
	// Shadow wins over monitor_only: both mean nothing is refused, and
	// the estate-wide switch is the one an operator will look for.
	both := listenerView(config.Listener{Name: "db2", Kind: "postgres",
		Policy:   &config.ListenerPolicy{Mode: "shadow"},
		Postgres: &config.PostgresListener{MonitorOnly: true}})
	if both.Mode != "shadow" {
		t.Errorf("mode %q", both.Mode)
	}
	enforce := listenerView(config.Listener{Name: "plant2", Kind: "modbus", Modbus: &config.ModbusListener{}})
	if enforce.Mode != "enforce" {
		t.Errorf("mode %q", enforce.Mode)
	}
	// The third reason, and the one this view used to miss. A learning run is
	// observe-only unless it says otherwise, so the listener decides nothing --
	// and the mode read "enforce", which is the one field a status view must not
	// get wrong. The guard row said "observe" all along, so the two disagreed.
	learning := listenerView(config.Listener{Name: "plant3", Kind: "modbus",
		Modbus: &config.ModbusListener{Learn: &config.ModbusLearn{Enabled: true}}})
	if learning.Mode != "learn" {
		t.Errorf("mode %q: a learning run that does not enforce", learning.Mode)
	}
	// And a run that says it enforces is enforcing, so the mode must not
	// frighten anybody into thinking otherwise.
	learnEnforce := listenerView(config.Listener{Name: "plant4", Kind: "modbus",
		Modbus: &config.ModbusListener{Learn: &config.ModbusLearn{Enabled: true, Enforce: true}}})
	if learnEnforce.Mode != "enforce" {
		t.Errorf("mode %q: a learning run that enforces", learnEnforce.Mode)
	}
	// An explicit switch still wins, because it is about the whole listener.
	learnShadow := listenerView(config.Listener{Name: "plant5", Kind: "modbus",
		Policy: &config.ListenerPolicy{Mode: "shadow"},
		Modbus: &config.ModbusListener{Learn: &config.ModbusLearn{Enabled: true, Enforce: true}}})
	if learnShadow.Mode != "shadow" {
		t.Errorf("mode %q: shadow over a learning run", learnShadow.Mode)
	}
	// The guard row and the mode are two readings of the same thing and must
	// agree: the row saying "observe" while the mode says "enforce" is exactly
	// the state that shipped.
	if f := feat(t, learning, "learn"); f.Mode == "observe" && learning.Mode == "enforce" {
		t.Error("the learn row and the listener mode disagree")
	}
}

// A kind reports the guards it has and only those: there is no mfa row on
// a Modbus listener, because Modbus has nobody to ask.
func TestAKindReportsItsOwnGuardsAndNoOthers(t *testing.T) {
	v := listenerView(config.Listener{Name: "plant", Kind: "modbus", Modbus: &config.ModbusListener{}})
	for _, want := range []string{"learn", "anomaly", "engineering", "deception"} {
		if !hasFeat(v, want) {
			t.Errorf("modbus has no %s row", want)
		}
	}
	for _, unwanted := range []string{"mfa", "recording", "yara", "icap"} {
		if hasFeat(v, unwanted) {
			t.Errorf("modbus reported %s, which it does not have", unwanted)
		}
	}
	ssh := listenerView(config.Listener{Name: "bastion", Kind: "ssh", SSH: &config.SSHListener{}})
	for _, want := range []string{"recording", "mfa", "deception"} {
		if !hasFeat(ssh, want) {
			t.Errorf("ssh has no %s row", want)
		}
	}
	if hasFeat(ssh, "engineering") {
		t.Error("ssh reported engineering: an engineering class is the plant's, not the bastion's")
	}
}

// Engineering is the guard whose default is on, and a report that showed
// it off would be wrong about the most consequential event class there is.
func TestEngineeringIsOnWithoutAnybodyWritingItDown(t *testing.T) {
	bare := listenerView(config.Listener{Name: "plant", Kind: "s7", S7: &config.S7Listener{}})
	if f := feat(t, bare, "engineering"); !f.Enabled {
		t.Error("engineering is reported on an OT listener whether or not it is configured")
	}
	off := false
	quiet := listenerView(config.Listener{Name: "plant", Kind: "s7",
		S7: &config.S7Listener{Engineering: &config.Engineering{Enabled: &off}}})
	if f := feat(t, quiet, "engineering"); f.Enabled {
		t.Error("enabled: false is how an operator says otherwise")
	}
	// And the mode is the decision, not the block's presence: a grant
	// required means a download outside a window is refused.
	grant := listenerView(config.Listener{Name: "plant", Kind: "s7",
		S7: &config.S7Listener{Engineering: &config.Engineering{RequireGrant: true}}})
	if f := feat(t, grant, "engineering"); f.Mode != "deny" {
		t.Errorf("mode %q: require_grant with no action denies", f.Mode)
	}
	alert := listenerView(config.Listener{Name: "plant", Kind: "s7",
		S7: &config.S7Listener{Engineering: &config.Engineering{RequireGrant: true, Action: "alert"}}})
	if f := feat(t, alert, "engineering"); f.Mode != "alert" {
		t.Errorf("mode %q: action alert", f.Mode)
	}
	report := listenerView(config.Listener{Name: "plant", Kind: "s7",
		S7: &config.S7Listener{Engineering: &config.Engineering{}}})
	if f := feat(t, report, "engineering"); f.Mode != "alert" {
		t.Errorf("mode %q: nothing required means report and allow", f.Mode)
	}
}

// A learning run says whether what it learned is applied, which is the
// difference between a listener that is building an allow list and one
// that is enforcing the list it built.
func TestALearningRunSaysWhetherItEnforces(t *testing.T) {
	observing := listenerView(config.Listener{Name: "plant", Kind: "modbus",
		Modbus: &config.ModbusListener{Learn: &config.ModbusLearn{Enabled: true}}})
	if f := feat(t, observing, "learn"); !f.Enabled || f.Mode != "observe" {
		t.Errorf("learn %+v: enabled and observing", f)
	}
	enforcing := listenerView(config.Listener{Name: "plant", Kind: "modbus",
		Modbus: &config.ModbusListener{Learn: &config.ModbusLearn{Enabled: true, Enforce: true}}})
	if f := feat(t, enforcing, "learn"); f.Mode != "enforce" {
		t.Errorf("learn %+v", f)
	}
	absent := listenerView(config.Listener{Name: "plant", Kind: "modbus", Modbus: &config.ModbusListener{}})
	if f := feat(t, absent, "learn"); f.Enabled {
		t.Errorf("learn %+v: no learn section is not a learning run", f)
	}
}

// An anomaly section that is written down but not switched on is off, and
// has to read as off: this is the one detector an operator adds and then
// forgets to enable.
func TestAnomalyIsOffUntilItIsEnabled(t *testing.T) {
	written := listenerView(config.Listener{Name: "plant", Kind: "modbus",
		Modbus: &config.ModbusListener{Anomaly: &config.Anomaly{}}})
	if f := feat(t, written, "anomaly"); f.Enabled {
		t.Errorf("anomaly %+v: the section has its own enabled flag", f)
	}
	on := listenerView(config.Listener{Name: "plant", Kind: "modbus",
		Modbus: &config.ModbusListener{Anomaly: &config.Anomaly{Enabled: true, Action: "deny"}}})
	if f := feat(t, on, "anomaly"); !f.Enabled || f.Mode != "deny" {
		t.Errorf("anomaly %+v", f)
	}
}

// The seven kinds two daemons serve report the one that owns this
// listener, because "my syslog is not answering" is answered by knowing
// which program was supposed to bind it.
func TestASharedKindNamesTheDaemonThatOwnsTheListener(t *testing.T) {
	relay := listenerView(config.Listener{Name: "logs", Kind: "syslog", Syslog: &config.SyslogListener{}})
	if relay.Daemon != "xrelay" || relay.Role != "relay" {
		t.Errorf("daemon %q role %q: xrelay keeps the default", relay.Daemon, relay.Role)
	}
	plant := listenerView(config.Listener{Name: "logs", Kind: "syslog", Daemon: "xot",
		Syslog: &config.SyslogListener{}})
	if plant.Daemon != "xot" || plant.Role != "ot" {
		t.Errorf("daemon %q role %q: the listener named xot", plant.Daemon, plant.Role)
	}
}

// Every kind in the roster has a view: the inventory is worthless if it
// silently omits a protocol, and reflection over the configuration is how
// a kind added tomorrow appears without this file being edited.
func TestEveryKindInTheRosterHasAView(t *testing.T) {
	for _, kind := range listener.Kinds() {
		v := listenerView(config.Listener{Name: "l", Kind: kind, Address: "127.0.0.1:1"})
		if v.Kind != kind {
			t.Errorf("kind %q became %q", kind, v.Kind)
		}
		if v.Role == "" || v.Daemon == "" {
			t.Errorf("kind %s: role %q daemon %q", kind, v.Role, v.Daemon)
		}
		if v.Mode != "enforce" {
			t.Errorf("kind %s: mode %q", kind, v.Mode)
		}
	}
}

// The refusal breakdown is heaviest first, and stable where two are equal.
func TestTheRefusalBreakdownIsHeaviestFirst(t *testing.T) {
	got := reasonCounts(map[string]uint64{"a": 1, "b": 9, "c": 9, "d": 4})
	want := []ReasonCount{{"b", 9}, {"c", 9}, {"d", 4}, {"a", 1}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
	if reasonCounts(nil) != nil {
		t.Error("an empty table is no rows, not a row saying zero")
	}
}
