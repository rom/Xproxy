package config

import (
	"strings"
	"testing"
)

// modbusConfig wraps a modbus section in the smallest document that
// carries it: one relay listener and one device pool.
func modbusConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:502"
      kind: modbus
      modbus:
` + section + `
upstreams:
  - {name: plc, endpoints: [{address: "10.10.0.5:502"}]}
  - {name: cell_b, endpoints: [{address: "10.10.0.6:502"}]}
`
}

const modbusGood = `        upstream: plc
        framing: tcp
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        units: ["1-16"]
        rules:
          - {name: historian, action: allow, clients: ["10.20.0.9/32"], access: [read],
             addresses: ["0-999"], max_quantity: 125}
          - {name: setpoints, action: allow, clients: ["10.20.0.10/32"],
             functions: [write_single_register, write_multiple_registers],
             addresses: ["400-499"],
             values: [{registers: "400-499", min: 0, max: 100}],
             schedule: {days: [mon, tue, wed, thu, fri], from: "06:00", to: "18:00", timezone: Europe/Stockholm}}
`

// The section a plant actually writes loads, and the defaults are the
// ones the documentation promises.
func TestModbusSectionLoads(t *testing.T) {
	cfg, err := ParseWith([]byte(modbusConfig(modbusGood)), false)
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Server.Listeners[0].Modbus
	if m == nil || m.Upstream != "plc" || len(m.Rules) != 2 {
		t.Fatalf("section: %+v", m)
	}
	if m.Pending() != 16 {
		t.Errorf("MBAP allows sixteen requests in flight, got %d", m.Pending())
	}
	if !m.Alerts() {
		t.Error("a refusal is alerted on unless the listener says otherwise")
	}
	if got := m.Rules[1].Schedule.Timezone; got != "Europe/Stockholm" {
		t.Errorf("timezone %q", got)
	}
}

// What does not load. Each of these is a policy that would read as
// something it is not.
func TestModbusRefusals(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"no upstream and no route", `        framing: tcp
`, "upstream: required"},
		{"a forward listener with nowhere to send", `        mode: forward
        upstream: ""
`, "upstream: required"},
		{"a mode that is not one", `        upstream: plc
        mode: sideways
`, "mode: must be reverse or forward"},
		{"a framing that is not one", `        upstream: plc
        framing: serial
`, "framing: must be tcp, rtu or ascii"},
		{"an upstream framing that is not one", `        upstream: plc
        upstream_framing: serial
`, "upstream_framing: must be tcp"},
		{"a route with no units", `        upstream: plc
        routes: [{name: line, upstream: cell_b}]
`, "units: required"},
		{"a route with no upstream", `        upstream: plc
        routes: [{name: line, units: ["1"]}]
`, "routes[0].upstream: required"},
		{"a route naming a pool that is not there", `        upstream: plc
        routes: [{name: line, units: ["1"], upstream: nowhere}]
`, "unknown upstream"},
		{"two routes with one name", `        upstream: plc
        routes:
          - {name: line, units: ["1"], upstream: plc}
          - {name: line, units: ["2"], upstream: cell_b}
`, "duplicate"},
		{"a unit identifier past 255", `        upstream: plc
        units: ["1-300"]
`, "units"},
		{"a range the wrong way round", `        upstream: plc
        units: ["16-1"]
`, "units"},
		{"an upstream that is not there", `        upstream: missing
`, "unknown upstream"},
		{"implicit tls with no certificate", `        upstream: plc
        tls_mode: implicit
`, "tls_mode: implicit needs the listener's tls section"},
		{"a role required with no tls at all", `        upstream: plc
        security: {mode: require}
`, "require needs the listener's tls section"},
		{"a security mode that is not one", `        upstream: plc
        security: {mode: maybe}
`, "security.mode: must be off, allow or require"},
		{"a role source that is not one", `        upstream: plc
        security: {role_source: serial_number}
`, "role_source: must be extension, cn or ou"},
		{"a role name with a space in it", `        upstream: plc
        security: {roles: ["plant engineer"]}
`, "is not a role name"},
		{"an action that is not one", `        upstream: plc
        rules: [{name: r, action: maybe}]
`, "action: must be allow, deny or observe"},
		{"a default action that is not one", `        upstream: plc
        default_action: maybe
`, "default_action: must be deny or allow"},
		{"a deny response that is not one", `        upstream: plc
        deny_response: reset
`, "deny_response: must be exception, drop or close"},
		{"a function code that is not one", `        upstream: plc
        rules: [{name: r, action: allow, functions: [write_everything]}]
`, "is not a function code name"},
		{"a function code past the public range", `        upstream: plc
        rules: [{name: r, action: allow, functions: ["200"]}]
`, "is not a function code name"},
		{"an access class that is not one", `        upstream: plc
        rules: [{name: r, action: allow, access: [execute]}]
`, "access[0]: must be read, write, diagnostic, identify or vendor"},
		{"a quantity past the protocol's own bound", `        upstream: plc
        rules: [{name: r, action: allow, max_quantity: 3000}]
`, "max_quantity: must be between 0 and 2000"},
		{"a value bound with no bounds", `        upstream: plc
        rules: [{name: r, action: allow, values: [{registers: "1-2"}]}]
`, "min and max are both required"},
		{"a value bound the wrong way round", `        upstream: plc
        rules: [{name: r, action: allow, values: [{min: 100, max: 0}]}]
`, "is above max"},
		{"a value bound outside a register", `        upstream: plc
        rules: [{name: r, action: allow, values: [{min: 0, max: 70000}]}]
`, "outside 0 to 65535"},
		{"a signed bound outside a register", `        upstream: plc
        rules: [{name: r, action: allow, values: [{min: -40000, max: 0, signed: true}]}]
`, "outside -32768 to 32767"},
		{"a day that is not one", `        upstream: plc
        rules: [{name: r, action: allow, schedule: {days: [funday], from: "06:00", to: "18:00"}}]
`, "is not a day"},
		{"a clock that is not one", `        upstream: plc
        rules: [{name: r, action: allow, schedule: {from: "6am", to: "18:00"}}]
`, "schedule.from"},
		{"a time zone that is not one", `        upstream: plc
        rules: [{name: r, action: allow, schedule: {from: "06:00", to: "18:00", timezone: Mars/Olympus}}]
`, "schedule.timezone"},
		{"a schedule that schedules nothing", `        upstream: plc
        rules: [{name: r, action: allow, schedule: {}}]
`, "schedule: sets nothing"},
		{"learning with no file", `        upstream: plc
        learn: {enabled: true}
`, "learn.file: required"},
		{"a learning file that is not absolute", `        upstream: plc
        learn: {enabled: true, file: learned.yaml}
`, "must be an absolute path"},
		{"a learning interval nobody meant", `        upstream: plc
        learn: {enabled: true, file: /var/lib/x.yaml, interval: 1s}
`, "learn.interval: must be between 10s and 24h"},
		{"a subject bound nobody meant", `        upstream: plc
        learn: {enabled: true, file: /var/lib/x.yaml, max_subjects: 4}
`, "max_subjects: must be between 16 and 1000000"},
		{"a trace with no file", `        upstream: plc
        trace: {}
`, "trace.file: required"},
		{"a trace bound nobody meant", `        upstream: plc
        trace: {file: /var/log/t.jsonl, max_bytes: 4096}
`, "trace.max_bytes: must be between 1MiB and 64GiB"},
		{"a frame bound past the longest ADU", `        upstream: plc
        max_frame_bytes: 4096
`, "max_frame_bytes: must be between 8 and 260"},
		{"more requests in flight than a device has", `        upstream: plc
        max_pending: 4096
`, "max_pending: must be between 0 and 256"},
		{"a session bound nobody meant", `        upstream: plc
        max_connections: -1
`, "max_connections: must be between 0 and 65536"},
		{"a timeout nobody meant", `        upstream: plc
        request_timeout: 30m
`, "request_timeout: must be between 0 and 10m"},
		{"a rule with no name", `        upstream: plc
        rules: [{action: allow}]
`, "is not a valid name"},
		{"two rules with one name", `        upstream: plc
        rules:
          - {name: r, action: allow}
          - {name: r, action: deny}
`, "duplicate"},
		{"a client network that is not one", `        upstream: plc
        allow_clients: ["10.20.0.1"]
`, "allow_clients"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(modbusConfig(tc.section)), false)
			if err == nil {
				t.Fatalf("the document loaded; wanted %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// The modbus section only belongs on a modbus listener, because a section
// that is read nowhere is a policy an operator believes is in force.
func TestModbusSectionOnlyOnAModbusListener(t *testing.T) {
	_, err := ParseWith([]byte(`
version: 1
server:
  listeners:
    - name: main
      address: ":8080"
      modbus: {upstream: plc}
upstreams:
  - {name: plc, endpoints: [{address: "10.10.0.5:502"}]}
routes:
  - {name: app, upstream: plc}
`), false)
	if err == nil || !strings.Contains(err.Error(), "modbus") {
		t.Fatalf("error %v, want a refusal naming the modbus section", err)
	}
}

// The advice: each of these loads, and each is a relay in front of
// equipment with one fewer lock on it than it should have.
func TestModbusAdvice(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"no client list", `        upstream: plc
        log_frames: true
        rules: [{name: r, action: allow, access: [read]}]
`, "allow_clients is empty"},
		{"a relay that only watches", `        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        default_action: allow
`, "no rules and default_action allow"},
		{"a read-only listener with a writing rule", `        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        read_only: true
        rules: [{name: r, action: allow, access: [write]}]
`, "read_only listener"},
		{"no per-frame audit trail", `        upstream: plc
        allow_clients: ["10.20.0.0/24"]
        rules: [{name: r, action: allow, access: [read]}]
`, "log_frames is off"},
		{"learning left on", `        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        learn: {enabled: true, file: /var/lib/xproxy/learned.yaml}
`, "learn is enabled without enforce"},
		{"a role read out of the subject", `        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        security: {mode: allow, role_source: cn}
        rules: [{name: r, action: allow, roles: [engineer]}]
`, "role_source is cn"},
		{"process data in the trace", `        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        rules: [{name: r, action: allow, access: [read]}]
        trace: {file: /var/log/xproxy/modbus.jsonl, include_data: true}
`, "include_data"},
		{"value bounds on an observe rule", `        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        rules: [{name: r, action: observe, values: [{min: 0, max: 100}]}]
`, "decides nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(modbusConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("the document did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.want) {
				t.Fatalf("no advice about %q: %v", tc.want, cfg.Advice())
			}
		})
	}
	// And the configuration a plant should be running is quiet.
	cfg, err := ParseWith([]byte(modbusConfig(modbusGood)), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cfg.Advice() {
		if strings.Contains(a, "modbus") {
			t.Errorf("a sound configuration warned: %q", a)
		}
	}
}

// deceptionConfig is a modbus listener with whatever deception section
// the test is about.
func deceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
` + section + `
upstreams:
  - name: plc
    endpoints: [{address: "10.0.0.9:502"}]
`
}

// The client list is the rule worth being strict about. On a web gateway a
// deceptive answer goes to a scanner; on a plant floor the same answer can
// put a fabricated tank level in front of an operator, so a section that
// would lie to anybody on a listener that reaches real devices does not
// load.
func TestModbusDeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		section string
		wants   string
	}{
		{
			name: "answer mode with a client list",
			section: `        upstream: plc
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: plc
        deception:
          mode: answer`,
			wants: "clients: required in mode answer",
		},
		{
			name: "the default mode is answer, so the same rule holds",
			section: `        upstream: plc
        deception:
          profile: generic-plc`,
			wants: "clients: required in mode answer",
		},
		{
			name: "a decoy listener needs no upstream and no clients",
			section: `        deception:
          mode: decoy`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: plc
        deception:
          mode: decoy`,
			wants: "decoy is the whole listener",
		},
		{
			name: "a mode that does not exist",
			section: `        upstream: plc
        deception:
          mode: pretend
          clients: ["10.9.0.0/24"]`,
			wants: "must be answer or decoy",
		},
		{
			name: "turned off, and then nothing else has to make sense",
			section: `        upstream: plc
        deception:
          enabled: false`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(deceptionConfig(tc.section)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// The rest of the section is held to the same bounds every other one is.
func TestModbusDeceptionFieldsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "a profile that does not exist",
			section: `        deception:
          mode: decoy
          profile: siemens-s7`,
			wants: "is not a profile",
		},
		{
			name: "a unit outside the protocol",
			section: `        deception:
          mode: decoy
          units: ["300"]`,
			wants: "units",
		},
		{
			name: "a tripwire outside the address space",
			section: `        deception:
          mode: decoy
          tripwire: ["70000"]`,
			wants: "tripwire",
		},
		{
			name: "a function code that does not exist",
			section: `        deception:
          mode: decoy
          functions: [read_the_future]`,
			wants: "is not a function code",
		},
		{
			name: "a band with no addresses",
			section: `        deception:
          mode: decoy
          bands: [{shape: analogue}]`,
			wants: "addresses: required",
		},
		{
			name: "a shape that does not exist",
			section: `        deception:
          mode: decoy
          bands: [{addresses: "0-99", shape: sawtooth}]`,
			wants: "must be analogue, discrete or counter",
		},
		{
			name: "an analogue band whose range is the wrong way round",
			section: `        deception:
          mode: decoy
          bands: [{addresses: "0-99", shape: analogue, min: 900, max: 100}]`,
			wants: "max must be above min",
		},
		{
			name: "a period nobody meant",
			section: `        deception:
          mode: decoy
          period: 24h`,
			wants: "period: must be between 1s and 1h",
		},
		{
			name: "a sensible section",
			section: `        deception:
          mode: decoy
          profile: generic-meter
          units: ["1-8"]
          tripwire: ["9000-9099"]
          functions: [read_holding_registers, 4]
          period: 45s
          max_clients: 256
          bands:
            - {addresses: "0-99", shape: analogue, min: 21000, max: 24500}
            - {addresses: "100-299", shape: counter, rate: 7}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(deceptionConfig(tc.section)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// Two things are worth saying at load rather than at three in the morning.
func TestModbusDeceptionWarnings(t *testing.T) {
	cfg, err := ParseWith([]byte(deceptionConfig(`        deception:
          mode: decoy`)), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "every client that connects is answered by the fabricated device") {
		t.Errorf("no warning about a decoy with no client list: %v", cfg.Advice())
	}
	// deny_response is what a refused client is told, and a deceived one
	// is told something else: an engineer should not have to discover that
	// from a connection that stayed open.
	cfg, err = ParseWith([]byte(deceptionConfig(`        upstream: plc
        deny_response: close
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]`)), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "deny_response close does not apply") {
		t.Errorf("no warning about deny_response: %v", cfg.Advice())
	}
}

// The sub-function selectors. Each of these is a policy that would read as
// something it is not: a rule naming a sub-function of a function code it
// excludes, or a name from the wrong namespace.
func TestModbusSubFunctionSelectors(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"a diagnostic name that is not one", `        upstream: plc
        rules: [{name: r, action: deny, diagnostics: [force_listen_onlyy]}]
`, "is not a diagnostic sub-function name"},
		{"a UMAS command from the diagnostic namespace", `        upstream: plc
        rules: [{name: r, action: deny, diagnostics: [stop_plc]}]
`, "is not a diagnostic sub-function name"},
		{"a diagnostic sub-function past the field", `        upstream: plc
        rules: [{name: r, action: deny, diagnostics: ["70000"]}]
`, "is not a diagnostic sub-function name"},
		{"a UMAS command past a byte", `        upstream: plc
        rules: [{name: r, action: deny, umas_commands: ["300"]}]
`, "is not a umas sub-function name"},
		{"an effect that is not one", `        upstream: plc
        rules: [{name: r, action: deny, effects: [destructive]}]
`, "must be read, write, control, program, clear, session or unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(modbusConfig(tc.section)), false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one about %q", err, tc.want)
			}
		})
	}
	// A rule that names a diagnostic sub-function and a function list
	// without function code 8 in it can never match, which is a rule that
	// looks like a control and is not one.
	cfg, err := ParseWith([]byte(modbusConfig(`        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        rules:
          - {name: r, action: deny, functions: [write_single_register], diagnostics: [force_listen_only]}
`)), false)
	if err != nil {
		t.Fatalf("the document did not load: %v", err)
	}
	if !hasAdvice(cfg, "can never match") {
		t.Fatalf("no advice about a rule that cannot match: %v", cfg.Advice())
	}
	// Naming the function code by number counts as naming it, so the same
	// rule written the other way is quiet.
	cfg, err = ParseWith([]byte(modbusConfig(`        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        rules:
          - {name: r, action: deny, functions: ["8"], diagnostics: [force_listen_only]}
          - {name: u, action: deny, functions: [umas], umas_commands: [stop_plc]}
          - {name: e, action: allow, access: [read]}
`)), false)
	if err != nil {
		t.Fatalf("the document did not load: %v", err)
	}
	for _, a := range cfg.Advice() {
		if strings.Contains(a, "can never match") {
			t.Errorf("a sound rule warned: %q", a)
		}
	}
}

// Turning the guard off is allowed and it is not quiet: the listener has
// just handed a whole function code back, and sub-function 4 is in it.
func TestModbusUnsafeSubFunctionGuardWarnsWhenItIsOff(t *testing.T) {
	cfg, err := ParseWith([]byte(modbusConfig(`        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        refuse_unsafe_sub_functions: false
        rules: [{name: r, action: allow, functions: [diagnostic]}]
`)), false)
	if err != nil {
		t.Fatalf("the document did not load: %v", err)
	}
	if !hasAdvice(cfg, "Force Listen Only Mode") {
		t.Fatalf("no advice about the guard being off: %v", cfg.Advice())
	}
	// And leaving it on -- or saying so -- is quiet, because a validator
	// warning that fires on a correct configuration is a warning an
	// operator learns to scroll past.
	cfg, err = ParseWith([]byte(modbusConfig(`        upstream: plc
        log_frames: true
        allow_clients: ["10.20.0.0/24"]
        refuse_unsafe_sub_functions: true
        rules: [{name: r, action: allow, functions: [diagnostic], diagnostics: ["11-18"]}]
`)), false)
	if err != nil {
		t.Fatalf("the document did not load: %v", err)
	}
	for _, a := range cfg.Advice() {
		if strings.Contains(a, "sub_function") || strings.Contains(a, "sub-function") {
			t.Errorf("a sound configuration warned: %q", a)
		}
	}
}
