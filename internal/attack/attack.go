// Package attack names what a refusal or a detection means in MITRE
// ATT&CK for ICS terms, and is the one place in this repository where
// that mapping lives.
//
// # Why a technique identifier is worth carrying
//
// An operations centre does not read `modbus_read_only` or
// `mms_write_constraint_not_allowed`. It reads a case in a SIEM whose
// detections are catalogued by technique, reports coverage by technique,
// and is asked at an audit which techniques the estate can see. A relay
// that says "a write was refused on a read-only listener" is saying
// T0855, Unauthorized Command Message, and saying it in a vocabulary
// nobody has to translate. So the technique travels with the event, in
// the security log and in a counter, rather than being reconstructed
// later from a spreadsheet that maps reason strings to techniques and
// goes stale the first time a kind gains one.
//
// # What is deliberately not here
//
// **Not every reason maps, and the unmapped ones stay unmapped.** A
// malformed frame, a TLS handshake that failed, a datagram over the size
// bound: those are protocol hygiene and a bound an operator set. Naming
// a technique for them would put a technique label on the noise floor,
// which is worse than leaving the field off, because a coverage report
// built from it would claim detections this proxy does not have. The
// table below is the subset where the reason itself implies the
// adversary behaviour.
//
// **The mapping is not a claim about intent.** A refusal tagged T0843 is
// a program download this policy did not allow; whether it was an
// attacker or an engineer working outside a window is what the rest of
// the event says. The identifier says which *behaviour* was observed,
// which is what ATT&CK is a catalogue of.
//
// **One reason may carry more than one technique**, because the
// behaviours overlap by construction: an unsafe Modbus diagnostic
// sub-function is a restart (T0816) and a way to stop a device answering
// (T0804), and pretending otherwise would lose half the signal.
//
// The identifiers and technique names are MITRE's. The catalogue here is
// the subset this proxy can actually observe; a technique this project
// has no way to see is not listed, so `attack.All()` is an honest answer
// to "what can this relay detect".
package attack

import (
	"sort"
	"strings"
)

// Tactic is an ATT&CK for ICS tactic, the column a technique sits under.
type Tactic string

// The tactics the techniques below belong to.
const (
	TacticInitialAccess     Tactic = "initial-access"
	TacticExecution         Tactic = "execution"
	TacticPersistence       Tactic = "persistence"
	TacticEvasion           Tactic = "evasion"
	TacticDiscovery         Tactic = "discovery"
	TacticLateralMovement   Tactic = "lateral-movement"
	TacticCollection        Tactic = "collection"
	TacticCommandAndControl Tactic = "command-and-control"
	TacticInhibitResponse   Tactic = "inhibit-response-function"
	TacticImpairProcess     Tactic = "impair-process-control"
	TacticImpact            Tactic = "impact"
)

// Technique is one entry of the catalogue.
type Technique struct {
	// ID is the MITRE identifier, "T0855".
	ID string
	// Name is MITRE's name for it, "Unauthorized Command Message".
	Name string
	// Tactics are the tactics it sits under. Several techniques sit
	// under more than one, and the first is the one this project's
	// events are usually about.
	Tactics []Tactic
	// Why says, in this project's terms, what makes a refusal or a
	// detection an instance of this technique. It is here rather than in
	// the documentation because the documentation is generated from it,
	// and because a mapping whose justification lives somewhere else is
	// one nobody checks.
	Why string
}

// Tactic is the first tactic, which is the one a single-valued field
// wants.
func (t Technique) Tactic() Tactic {
	if len(t.Tactics) == 0 {
		return ""
	}
	return t.Tactics[0]
}

// catalogue is every technique this proxy can observe.
var catalogue = map[string]Technique{
	"T0802": {"T0802", "Automated Collection", []Tactic{TacticCollection},
		"A bulk pull: an SNMP walk, an MMS or FTP fetch of configuration and fault records, a large history read. One request is a question; a sweep is collection."},
	"T0804": {"T0804", "Block Reporting Message", []Tactic{TacticInhibitResponse},
		"Stopping the telemetry a control room watches: IEC 104 STOPDT, a report control block disabled, a device put into listen-only."},
	"T0806": {"T0806", "Brute Force I/O", []Tactic{TacticImpairProcess},
		"Commands to one point faster than the equipment can follow -- a breaker or valve cycled at a rate no operator produces."},
	"T0812": {"T0812", "Default Credentials", []Tactic{TacticLateralMovement},
		"A credential the equipment shipped with: a community string of `public` or `private`, a vendor default user, a password this estate never set."},
	"T0814": {"T0814", "Denial of Service", []Tactic{TacticInhibitResponse},
		"A device or this relay made unable to answer: a flood, an amplification, a connection table filled, a frame crafted to cost more than it looks."},
	"T0816": {"T0816", "Device Restart/Shutdown", []Tactic{TacticInhibitResponse},
		"A restart or a shutdown asked for over the control protocol: an S7 CPU stop, a Modbus diagnostic restart, a BACnet ReinitializeDevice."},
	"T0831": {"T0831", "Manipulation of Control", []Tactic{TacticImpact},
		"The process driven somewhere it should not go, through the control protocol's own legitimate messages."},
	"T0835": {"T0835", "Manipulate I/O Image", []Tactic{TacticImpairProcess},
		"A write that changes the controller's image of its inputs or outputs rather than a setting: coils and registers that are the I/O image itself."},
	"T0836": {"T0836", "Modify Parameter", []Tactic{TacticImpairProcess},
		"A setting changed rather than a command sent: a setpoint, a protection threshold, an alarm limit, a device configuration attribute."},
	"T0839": {"T0839", "Module Firmware", []Tactic{TacticPersistence},
		"Firmware pushed to a module or a device -- the change that survives every restart and every program download after it."},
	"T0843": {"T0843", "Program Download", []Tactic{TacticLateralMovement},
		"Control logic written to a controller: an S7 block download, a UMAS program write, an MMS domain download."},
	"T0845": {"T0845", "Program Upload", []Tactic{TacticCollection},
		"Control logic read *out* of a controller, which is how a plant's process knowledge leaves the site."},
	"T0846": {"T0846", "Remote System Discovery", []Tactic{TacticDiscovery},
		"Finding what is on the segment: unit identifier sweeps, who-is with no range, a client touching addresses nothing has ever answered on."},
	"T0855": {"T0855", "Unauthorized Command Message", []Tactic{TacticImpairProcess},
		"A command the policy does not grant this client: the plainest thing an OT relay refuses, and the one an operations centre asks about first."},
	"T0856": {"T0856", "Spoof Reporting Message", []Tactic{TacticImpairProcess},
		"Telemetry that did not come from the device it claims to: an answer from an address that is not the device, a reply that arrived without a question."},
	"T0857": {"T0857", "System Firmware", []Tactic{TacticPersistence},
		"The device's own firmware image replaced, usually over the provisioning protocol the estate already runs."},
	"T0858": {"T0858", "Change Operating Mode", []Tactic{TacticEvasion, TacticExecution},
		"A controller moved between run, program and stop, or into a mode where it accepts what it would otherwise refuse."},
	"T0859": {"T0859", "Valid Accounts", []Tactic{TacticLateralMovement, TacticPersistence},
		"A real credential used where the policy does not grant it: an identity, user or key that authenticates and is still not allowed here."},
	"T0861": {"T0861", "Point & Tag Identification", []Tactic{TacticCollection},
		"Learning the control loop rather than the network: object and tag enumeration, reading the names and types a device exposes."},
	"T0867": {"T0867", "Lateral Tool Transfer", []Tactic{TacticLateralMovement},
		"A file moved onto or off a device over the estate's own transfer protocol."},
	"T0871": {"T0871", "Execution through API", []Tactic{TacticExecution},
		"A method or service call the protocol provides for the purpose: an OPC UA Call, an MMS operate, anything that runs code on the far end by design."},
	"T0883": {"T0883", "Internet Accessible Device", []Tactic{TacticInitialAccess},
		"Something reaching an OT listener from where nothing should: an address outside every network the policy names."},
	"T0884": {"T0884", "Connection Proxy", []Tactic{TacticCommandAndControl},
		"The device asked to fetch or forward on somebody else's behalf, which turns it into the attacker's proxy and amplifier."},
	"T0886": {"T0886", "Remote Services", []Tactic{TacticInitialAccess, TacticLateralMovement},
		"The estate's own remote access used as the way in: a session that is valid, from an identity or a place the OT policy does not grant."},
	"T0888": {"T0888", "Remote System Information Discovery", []Tactic{TacticDiscovery},
		"Asking devices what they are: identification requests, SZL walks, object dictionary reads, an SNMP walk of the system tree."},
}

// mapping is one (kind, reason) pair and the techniques it carries.
//
// The reason is the canonical form: the same string the refusal counter
// labels and the security log's `reason` carries, with the kind's own
// prefix removed where a kind spells one.
type mapping struct {
	kind   string
	reason string
	ids    []string
	// note, where the reason alone would not explain the choice.
	note string
}

// mappings is the table. It is grouped by kind, and within a kind by
// what the reasons are about, because it is read by somebody asking
// "what does this relay tag" rather than looked up by machine.
var mappings = []mapping{
	// Modbus. The protocol with no identity at all, where the policy is
	// the access control and every refusal is therefore a behaviour.
	{kind: "modbus", reason: "read_only", ids: []string{"T0855", "T0835"},
		note: "a write on a listener that grants none: the command was not authorised, and what it would have changed is the I/O image"},
	{kind: "modbus", reason: "read_only_unknown_function", ids: []string{"T0855"}},
	{kind: "modbus", reason: "rule_deny", ids: []string{"T0855"}},
	{kind: "modbus", reason: "no_rule", ids: []string{"T0855"}},
	{kind: "modbus", reason: "unit_not_allowed", ids: []string{"T0846"},
		note: "a unit identifier the policy does not name is a sweep or a misroute, and a sweep of 1 to 247 is how a segment is mapped"},
	{kind: "modbus", reason: "unsafe_sub_function", ids: []string{"T0816", "T0804"},
		note: "function 8 sub-function 1 restarts the device and sub-function 4 puts it in listen-only, which stops it answering anybody"},
	{kind: "modbus", reason: "client_not_allowed", ids: []string{"T0883"}},
	{kind: "modbus", reason: "value_out_of_range", ids: []string{"T0836", "T0831"},
		note: "a setpoint outside the values the process can hold: the write is a parameter change and the process is where it goes"},
	{kind: "modbus", reason: "value_delta", ids: []string{"T0836", "T0831"}},
	{kind: "modbus", reason: "value_transition", ids: []string{"T0831"}},
	{kind: "modbus", reason: "value_no_select", ids: []string{"T0855"}},
	{kind: "modbus", reason: "value_masked_write", ids: []string{"T0835"}},
	{kind: "modbus", reason: "coil_set_not_allowed", ids: []string{"T0831", "T0835"}},
	{kind: "modbus", reason: "coil_clear_not_allowed", ids: []string{"T0831", "T0835"}},
	{kind: "modbus", reason: "value_rate", ids: []string{"T0806"},
		note: "a point written faster than the bound is the rate no operator produces and the mechanism cannot follow"},
	{kind: "modbus", reason: "anomaly_new_function", ids: []string{"T0855"}},
	{kind: "modbus", reason: "anomaly_new_write_address", ids: []string{"T0836", "T0835"}},
	{kind: "modbus", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"},
		note: "writes across many addresses in a burst is the shape of walking the address space, not of a control action"},

	// IEC 60870-5-104. A control centre's protocol, where the type
	// identification says what was asked for.
	{kind: "iec104", reason: "control", ids: []string{"T0855"}},
	{kind: "iec104", reason: "default_deny", ids: []string{"T0855"}},
	{kind: "iec104", reason: "rule", ids: []string{"T0855"}},
	{kind: "iec104", reason: "monitor_only", ids: []string{"T0855"}},
	{kind: "iec104", reason: "station_command", ids: []string{"T0816", "T0858"},
		note: "the station-level commands are reset process and the clock, which restart and re-time a substation gateway"},
	{kind: "iec104", reason: "common_address", ids: []string{"T0846"}},
	{kind: "iec104", reason: "setpoint_range", ids: []string{"T0836", "T0831"}},
	{kind: "iec104", reason: "setpoint_delta", ids: []string{"T0836", "T0831"}},
	{kind: "iec104", reason: "setpoint_unknown", ids: []string{"T0836"}},
	{kind: "iec104", reason: "select_unavailable", ids: []string{"T0855"},
		note: "an operate with no select before it is a command that skipped the protocol's own confirmation"},
	{kind: "iec104", reason: "command_rate_limited", ids: []string{"T0806"}},
	{kind: "iec104", reason: "client_not_allowed", ids: []string{"T0883"}},

	// S7comm. The protocol with the least security here, and the one
	// whose operations are the engineering workflow itself.
	{kind: "s7", reason: "operation_denied", ids: []string{"T0855"}},
	{kind: "s7", reason: "operation_not_allowed", ids: []string{"T0855"}},
	{kind: "s7", reason: "rule_denied", ids: []string{"T0855"}},
	{kind: "s7", reason: "no_rule_matched", ids: []string{"T0855"}},
	{kind: "s7", reason: "block_type_not_allowed", ids: []string{"T0843", "T0845"},
		note: "a block operation is control logic moving in one direction or the other, and which one the operation says"},
	{kind: "s7", reason: "area_denied", ids: []string{"T0836", "T0835"}},
	{kind: "s7", reason: "area_not_allowed", ids: []string{"T0836", "T0835"}},
	{kind: "s7", reason: "address_not_allowed", ids: []string{"T0836"}},
	{kind: "s7", reason: "db_not_allowed", ids: []string{"T0836"}},
	{kind: "s7", reason: "rack_not_allowed", ids: []string{"T0846"}},
	{kind: "s7", reason: "slot_not_allowed", ids: []string{"T0846"}},
	{kind: "s7", reason: "s7comm_plus_denied", ids: []string{"T0855"}},
	{kind: "s7", reason: "s7comm_plus_not_allowed", ids: []string{"T0855"}},

	// IEC 61850 MMS, where the object names carry the semantics.
	{kind: "mms", reason: "operate_not_allowed", ids: []string{"T0855", "T0871"}},
	{kind: "mms", reason: "not_selected", ids: []string{"T0855"}},
	{kind: "mms", reason: "selection_expired", ids: []string{"T0855"}},
	{kind: "mms", reason: "constraint_denied", ids: []string{"T0836"},
		note: "the functional constraint says what a write is: $CF$ is configuration and $SG$ and $SE$ are a protection relay's trip characteristic"},
	{kind: "mms", reason: "constraint_not_allowed", ids: []string{"T0836"}},
	{kind: "mms", reason: "write_constraint_not_allowed", ids: []string{"T0836"}},
	{kind: "mms", reason: "write_object_not_allowed", ids: []string{"T0836"}},
	{kind: "mms", reason: "object_denied", ids: []string{"T0855"}},
	{kind: "mms", reason: "object_not_allowed", ids: []string{"T0855"}},
	{kind: "mms", reason: "domain_denied", ids: []string{"T0843"}},
	{kind: "mms", reason: "domain_not_allowed", ids: []string{"T0843"}},
	{kind: "mms", reason: "file_denied", ids: []string{"T0802", "T0867"},
		note: "the file services are how COMTRADE records and SCL descriptions leave an IED, which is the plant's own description of itself"},
	{kind: "mms", reason: "file_not_allowed", ids: []string{"T0802", "T0867"}},
	{kind: "mms", reason: "service_not_allowed", ids: []string{"T0855"}},
	{kind: "mms", reason: "service_class_not_allowed", ids: []string{"T0855"}},

	// BACnet/IP: a building's protocol, with no user and no session.
	{kind: "bacnet", reason: "rule_denied", ids: []string{"T0855"}},
	{kind: "bacnet", reason: "client_not_allowed", ids: []string{"T0883"}},
	{kind: "bacnet", reason: "too_many_broadcasts", ids: []string{"T0846"},
		note: "who-is with no range, repeated, is how a building's device list is collected"},
	{kind: "bacnet", reason: "unsolicited_broadcast", ids: []string{"T0846"}},
	{kind: "bacnet", reason: "unsolicited_reply", ids: []string{"T0856"}},
	{kind: "bacnet", reason: "forwarded_origin_mismatch", ids: []string{"T0856"}},

	// OPC UA: the one industrial protocol that brought its own security.
	{kind: "opcua", reason: "service_denied", ids: []string{"T0855"}},
	{kind: "opcua", reason: "service_not_allowed", ids: []string{"T0855"}},
	{kind: "opcua", reason: "method_denied", ids: []string{"T0871"}},
	{kind: "opcua", reason: "method_not_allowed", ids: []string{"T0871"}},
	{kind: "opcua", reason: "node_denied", ids: []string{"T0836"}},
	{kind: "opcua", reason: "node_not_allowed", ids: []string{"T0836"}},
	{kind: "opcua", reason: "attribute_not_allowed", ids: []string{"T0836"},
		note: "a write to `value` moves an actuator and a write to `access_level` changes who may, which is why the attribute is a policy field"},
	{kind: "opcua", reason: "namespace_not_allowed", ids: []string{"T0861"}},
	{kind: "opcua", reason: "user_not_allowed", ids: []string{"T0859"}},
	{kind: "opcua", reason: "empty_user", ids: []string{"T0859"}},
	{kind: "opcua", reason: "plaintext_password", ids: []string{"T0859"}},
	{kind: "opcua", reason: "token_kind_not_allowed", ids: []string{"T0859"}},
	{kind: "opcua", reason: "certificate_uri_mismatch", ids: []string{"T0859"}},
	{kind: "opcua", reason: "application_not_allowed", ids: []string{"T0886"}},
	{kind: "opcua", reason: "endpoint_not_allowed", ids: []string{"T0886"}},
	{kind: "opcua", reason: "publishing_interval", ids: []string{"T0814"},
		note: "a subscription asking for a publishing interval below the bound is amplification the server pays for"},
	{kind: "opcua", reason: "sampling_interval", ids: []string{"T0814"}},

	// CoAP, where the path is the object model.
	{kind: "coap", reason: "method_not_allowed", ids: []string{"T0855"}},
	{kind: "coap", reason: "path_not_allowed", ids: []string{"T0855"}},
	{kind: "coap", reason: "default_deny", ids: []string{"T0855"}},
	{kind: "coap", reason: "rule", ids: []string{"T0855"}},
	{kind: "coap", reason: "discovery_not_allowed", ids: []string{"T0846", "T0861"},
		note: "/.well-known/core exists to list everything the device has, which is the object model rather than the network"},
	{kind: "coap", reason: "proxying_not_allowed", ids: []string{"T0884"},
		note: "Proxy-Uri tells the device to fetch a URI of the client's choosing: an open forward proxy with an amplifier attached"},
	{kind: "coap", reason: "unknown_psk_identity", ids: []string{"T0859"},
		note: "a pre-shared key identity nobody enrolled, which on a shared segment is either a misprovisioned device or somebody trying names"},
	{kind: "coap", reason: "no_security_name", ids: []string{"T0859"}},
	{kind: "coap", reason: "client_not_allowed", ids: []string{"T0883"}},
	{kind: "coap", reason: "device_not_allowed", ids: []string{"T0856"}},
	{kind: "coap", reason: "unsolicited", ids: []string{"T0856"}},
	{kind: "coap", reason: "amplified", ids: []string{"T0814"}},

	// SNMP: the estate's own equipment, where the credential is a
	// cleartext password in every datagram.
	{kind: "snmp", reason: "community", ids: []string{"T0812", "T0859"},
		note: "a community string this listener does not hold is the vendor default being tried more often than not"},
	{kind: "snmp", reason: "user", ids: []string{"T0859"}},
	{kind: "snmp", reason: "security_level", ids: []string{"T0859"}},
	{kind: "snmp", reason: "tsm_no_name", ids: []string{"T0859"}},
	{kind: "snmp", reason: "tsm_level", ids: []string{"T0859"}},
	{kind: "snmp", reason: "read_only", ids: []string{"T0836"},
		note: "an SNMP SET on network or field equipment is a configuration change, which is what this protocol's writes are"},
	{kind: "snmp", reason: "rule", ids: []string{"T0855"}},
	{kind: "snmp", reason: "default_deny", ids: []string{"T0855"}},
	{kind: "snmp", reason: "var_binds", ids: []string{"T0888"}},
	{kind: "snmp", reason: "max_repetitions", ids: []string{"T0888", "T0814"},
		note: "a GETBULK repetition count above the bound is a walk of the whole tree and an amplifier at the same time"},
	{kind: "snmp", reason: "response_ratio", ids: []string{"T0814"}},
	{kind: "snmp", reason: "response_too_large", ids: []string{"T0814"}},
	{kind: "snmp", reason: "unsolicited_response", ids: []string{"T0856"}},
	{kind: "snmp", reason: "client_not_allowed", ids: []string{"T0883"}},

	// TFTP: how field equipment is provisioned, and how firmware moves.
	{kind: "tftp", reason: "filename_denied", ids: []string{"T0857", "T0839"},
		note: "on this protocol a filename is a firmware or configuration image, in one direction or the other"},
	{kind: "tftp", reason: "filename_not_allowed", ids: []string{"T0857", "T0839"}},
	{kind: "tftp", reason: "directory_denied", ids: []string{"T0867"}},
	{kind: "tftp", reason: "directory_not_allowed", ids: []string{"T0867"}},
	{kind: "tftp", reason: "operation_not_allowed", ids: []string{"T0867"}},
	{kind: "tftp", reason: "client_not_allowed", ids: []string{"T0883"}},
	{kind: "tftp", reason: "transfer_too_large", ids: []string{"T0814"}},

	// DHCP and DHCPv6: provisioning, where an answer decides what a
	// device believes about the network it is on.
	{kind: "dhcp", reason: "rogue_server", ids: []string{"T0856", "T0886"},
		note: "an answer from an address that is not a server this estate runs is the provisioning path being taken over"},
	{kind: "dhcp", reason: "boot_file_not_allowed", ids: []string{"T0857", "T0867"}},
	{kind: "dhcp", reason: "boot_server_not_allowed", ids: []string{"T0857", "T0867"}},
	{kind: "dhcp", reason: "option_denied", ids: []string{"T0836"}},
	{kind: "dhcp6", reason: "server_not_allowed", ids: []string{"T0856", "T0886"}},
	{kind: "dhcp6", reason: "denied_option", ids: []string{"T0836"}},
	{kind: "dhcp6", reason: "reconfigure_not_allowed", ids: []string{"T0836", "T0858"}},

	// The gate kinds, for the one thing they say about an OT estate: the
	// remote access that is the way in.
	{kind: "ssh", reason: "no_grant", ids: []string{"T0886"}},
	{kind: "rdp", reason: "no_grant", ids: []string{"T0886"}},
	{kind: "vnc", reason: "no_grant", ids: []string{"T0886"}},
	{kind: "telnet", reason: "no_grant", ids: []string{"T0886"}},
}

// byKindReason and byEvent are the two indexes: one for a counter that
// has the kind in hand, one for a log line that has the event name.
var (
	byKindReason = map[string]map[string][]Technique{}
	byEvent      = map[string][]Technique{}
)

func init() {
	for _, m := range mappings {
		ts := make([]Technique, 0, len(m.ids))
		for _, id := range m.ids {
			t, ok := catalogue[id]
			if !ok {
				// A mapping naming a technique the catalogue does not
				// have is a mistake in this file, and the package test
				// fails on it. Nothing is registered for it, so a
				// running process tags nothing rather than tagging a
				// technique with an empty name.
				continue
			}
			ts = append(ts, t)
		}
		if len(ts) == 0 {
			continue
		}
		if byKindReason[m.kind] == nil {
			byKindReason[m.kind] = map[string][]Technique{}
		}
		byKindReason[m.kind][m.reason] = ts
		byEvent[m.kind+"_"+m.reason] = ts
	}
}

// Of are the techniques a kind's refusal or detection reason carries.
// The reason is the canonical form, without the kind's own prefix; a
// reason spelled with it is accepted too, because the kinds spell it
// both ways and this package is not the place to care.
func Of(kind, reason string) []Technique {
	byReason := byKindReason[kind]
	if byReason == nil {
		return nil
	}
	if ts := byReason[reason]; len(ts) > 0 {
		return ts
	}
	if p := kind + "_"; strings.HasPrefix(reason, p) {
		return byReason[reason[len(p):]]
	}
	return nil
}

// OfEvent are the techniques a security event's name carries, for the
// log, where the name is the kind and the reason already joined.
func OfEvent(event string) []Technique { return byEvent[event] }

// IDs are the identifiers of a technique set, in the order the mapping
// wrote them, joined for a log attribute. A set with one technique --
// which is most of them -- reads as "T0855" rather than as a list.
func IDs(ts []Technique) string {
	if len(ts) == 1 {
		return ts[0].ID
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return strings.Join(out, ",")
}

// Names are the technique names of a set, joined the same way.
func Names(ts []Technique) string {
	if len(ts) == 1 {
		return ts[0].Name
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return strings.Join(out, ",")
}

// Tactics are the distinct first tactics of a set, joined the same way.
// The first tactic rather than all of them, because a log field that
// carried every tactic of every technique would be a field nobody
// filters on.
func Tactics(ts []Technique) string {
	seen := make(map[Tactic]bool, len(ts))
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		k := t.Tactic()
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, string(k))
	}
	return strings.Join(out, ",")
}

// Get is one technique by identifier, for the pack data that names one.
func Get(id string) (Technique, bool) {
	t, ok := catalogue[strings.ToUpper(strings.TrimSpace(id))]
	return t, ok
}

// Known reports whether an identifier is one this project can observe.
// It is what validation uses to refuse a pack naming a technique nothing
// here could ever detect, which would otherwise read in a coverage
// report as a detection this estate has.
func Known(id string) bool {
	_, ok := Get(id)
	return ok
}

// All is the catalogue, sorted by identifier: an honest answer to "what
// can this relay detect".
func All() []Technique {
	out := make([]Technique, 0, len(catalogue))
	for _, t := range catalogue {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Mapping is one row of the table, for the documentation and for a
// status view that has to show what is tagged.
type Mapping struct {
	Kind   string
	Reason string
	IDs    []string
	Note   string
}

// Mappings is the table, sorted by kind and then by reason.
func Mappings() []Mapping {
	out := make([]Mapping, 0, len(mappings))
	for _, m := range mappings {
		ids := make([]string, len(m.ids))
		copy(ids, m.ids)
		out = append(out, Mapping{Kind: m.kind, Reason: m.reason, IDs: ids, Note: m.note})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// Kinds are the listener kinds that have at least one mapping, sorted.
func Kinds() []string {
	out := make([]string, 0, len(byKindReason))
	for k := range byKindReason {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
