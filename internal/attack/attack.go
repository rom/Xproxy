// Package attack names what a refusal or a detection means in MITRE
// ATT&CK terms -- in ATT&CK for ICS for the plant, and in Enterprise
// ATT&CK for everything else -- and is the one place in this repository
// where that mapping lives.
//
// # Why a technique identifier is worth carrying
//
// An operations centre does not read `modbus_read_only`,
// `mms_write_constraint_not_allowed` or `ldap_leading_wildcard`. It reads
// a case in a SIEM whose detections are catalogued by technique, reports
// coverage by technique, and is asked at an audit which techniques the
// estate can see. A relay that says "a write was refused on a read-only
// listener" is saying T0855, Unauthorized Command Message, and a gate
// that says "a directory query asked for everything under the base"
// is saying T1087, Account Discovery -- both in a vocabulary nobody has
// to translate. So the technique travels with the event, in the security
// log and in a counter, rather than being reconstructed later from a
// spreadsheet that maps reason strings to techniques and goes stale the
// first time a kind gains one.
//
// # Two matrices, because this proxy stands in two worlds
//
// ATT&CK for ICS is the catalogue for a plant: program downloads,
// operating-mode changes, reporting messages. Enterprise ATT&CK is the
// catalogue for the rest of an estate: brute force, protocol tunnelling,
// proxying, data from a repository. A proxy that carries SSH, HTTP and
// PostgreSQL beside Modbus and S7 has events in both, so every technique
// here says which matrix it is from (`Matrix`, and the `matrix` field on
// the event), and a reason may carry techniques from both at once. The
// identifier spaces do not collide -- ICS is T0xxx, Enterprise is T1xxx
// with sub-techniques like T1021.004 -- so one field can hold both and
// a query can still tell them apart.
//
// The pairing is often the point. An SSH session admitted with no access
// grant is T0886, Remote Services, to the plant's assessor and T1133,
// External Remote Services, to the enterprise's; the same refusal, read
// by two teams whose dashboards do not share a vocabulary. Carrying both
// is what stops each of them maintaining their own translation table.
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
// The identifiers and technique names are MITRE's. The catalogues here
// are the subset this proxy can actually observe; a technique this
// project has no way to see is not listed, so `attack.All()` is an
// honest answer to "what can this relay detect".
package attack

import (
	"sort"
	"strings"
)

// Matrix is which ATT&CK matrix a technique comes from. The two have
// separate identifier spaces and separate tactic vocabularies, and an
// operations centre usually reports on them separately, so the event
// says which one rather than leaving it to be inferred from the digit
// after the T.
type Matrix string

// The matrices this project tags in.
const (
	MatrixICS        Matrix = "ics"
	MatrixEnterprise Matrix = "enterprise"
)

// Tactic is an ATT&CK tactic, the column a technique sits under. The two
// matrices share most of the names and differ in a few: ICS has
// `evasion` and `inhibit-response-function`, Enterprise has
// `defense-evasion` and `credential-access`.
type Tactic string

// The tactics the techniques below belong to.
const (
	TacticInitialAccess     Tactic = "initial-access"
	TacticExecution         Tactic = "execution"
	TacticPersistence       Tactic = "persistence"
	TacticPrivilegeEsc      Tactic = "privilege-escalation"
	TacticEvasion           Tactic = "evasion"
	TacticDefenseEvasion    Tactic = "defense-evasion"
	TacticCredentialAccess  Tactic = "credential-access" //nolint:gosec // an ATT&CK tactic name, not a credential
	TacticDiscovery         Tactic = "discovery"
	TacticLateralMovement   Tactic = "lateral-movement"
	TacticCollection        Tactic = "collection"
	TacticCommandAndControl Tactic = "command-and-control"
	TacticExfiltration      Tactic = "exfiltration"
	TacticInhibitResponse   Tactic = "inhibit-response-function"
	TacticImpairProcess     Tactic = "impair-process-control"
	TacticImpact            Tactic = "impact"
)

// Technique is one entry of a catalogue.
type Technique struct {
	// Matrix is which ATT&CK matrix it is from.
	Matrix Matrix
	// ID is the MITRE identifier: "T0855", or "T1021.004" for an
	// Enterprise sub-technique.
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

// URL is MITRE's page for the technique. A sub-technique's identifier is
// written with a dot and its URL with a slash, which is the one place
// that difference has to be handled.
func (t Technique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(t.ID, ".", "/") + "/"
}

// entry is one catalogue row. The matrix is not in the row because the
// catalogue it sits in says which one it is, and a field repeated on
// every row is a field that can disagree with its own table.
type entry struct {
	id      string
	name    string
	tactics []Tactic
	why     string
}

// icsCatalogue is every ATT&CK for ICS technique this proxy can observe.
var icsCatalogue = []entry{
	{"T0801", "Monitor Process State", []Tactic{TacticCollection},
		"Watching the process rather than touching it: a poller whose rhythm changed is reading the plant at a rate nobody configured, which is what reconnaissance on a control network looks like."},
	{"T0802", "Automated Collection", []Tactic{TacticCollection},
		"A bulk pull: an SNMP walk, an MMS or FTP fetch of configuration and fault records, a large history read. One request is a question; a sweep is collection."},
	{"T0804", "Block Reporting Message", []Tactic{TacticInhibitResponse},
		"Stopping the telemetry a control room watches: IEC 104 STOPDT, a report control block disabled, a device put into listen-only."},
	{"T0806", "Brute Force I/O", []Tactic{TacticImpairProcess},
		"Commands to one point faster than the equipment can follow -- a breaker or valve cycled at a rate no operator produces."},
	{"T0812", "Default Credentials", []Tactic{TacticLateralMovement},
		"A credential the equipment shipped with: a community string of `public` or `private`, a vendor default user, a password this estate never set."},
	{"T0814", "Denial of Service", []Tactic{TacticInhibitResponse},
		"A device or this relay made unable to answer: a flood, an amplification, a connection table filled, a frame crafted to cost more than it looks."},
	{"T0816", "Device Restart/Shutdown", []Tactic{TacticInhibitResponse},
		"A restart or a shutdown asked for over the control protocol: an S7 CPU stop, a Modbus diagnostic restart, a BACnet ReinitializeDevice."},
	{"T0831", "Manipulation of Control", []Tactic{TacticImpact},
		"The process driven somewhere it should not go, through the control protocol's own legitimate messages."},
	{"T0832", "Manipulation of View", []Tactic{TacticImpairProcess},
		"What the control room sees made wrong: a point that stopped moving, a run of readings that repeats, two values that cannot both be true of one process."},
	{"T0835", "Manipulate I/O Image", []Tactic{TacticImpairProcess},
		"A write that changes the controller's image of its inputs or outputs rather than a setting: coils and registers that are the I/O image itself."},
	{"T0836", "Modify Parameter", []Tactic{TacticImpairProcess},
		"A setting changed rather than a command sent: a setpoint, a protection threshold, an alarm limit, a device configuration attribute."},
	{"T0839", "Module Firmware", []Tactic{TacticPersistence},
		"Firmware pushed to a module or a device -- the change that survives every restart and every program download after it."},
	{"T0843", "Program Download", []Tactic{TacticLateralMovement},
		"Control logic written to a controller: an S7 block download, a UMAS program write, an MMS domain download."},
	{"T0845", "Program Upload", []Tactic{TacticCollection},
		"Control logic read *out* of a controller, which is how a plant's process knowledge leaves the site."},
	{"T0846", "Remote System Discovery", []Tactic{TacticDiscovery},
		"Finding what is on the segment: unit identifier sweeps, who-is with no range, a client touching addresses nothing has ever answered on."},
	{"T0855", "Unauthorized Command Message", []Tactic{TacticImpairProcess},
		"A command the policy does not grant this client: the plainest thing an OT relay refuses, and the one an operations centre asks about first."},
	{"T0856", "Spoof Reporting Message", []Tactic{TacticImpairProcess},
		"Telemetry that did not come from the device it claims to: an answer from an address that is not the device, a reply that arrived without a question."},
	{"T0857", "System Firmware", []Tactic{TacticPersistence},
		"The device's own firmware image replaced, usually over the provisioning protocol the estate already runs."},
	{"T0858", "Change Operating Mode", []Tactic{TacticEvasion, TacticExecution},
		"A controller moved between run, program and stop, or into a mode where it accepts what it would otherwise refuse."},
	{"T0859", "Valid Accounts", []Tactic{TacticLateralMovement, TacticPersistence},
		"A real credential used where the policy does not grant it: an identity, user or key that authenticates and is still not allowed here."},
	{"T0861", "Point & Tag Identification", []Tactic{TacticCollection},
		"Learning the control loop rather than the network: object and tag enumeration, reading the names and types a device exposes."},
	{"T0867", "Lateral Tool Transfer", []Tactic{TacticLateralMovement},
		"A file moved onto or off a device over the estate's own transfer protocol."},
	{"T0871", "Execution through API", []Tactic{TacticExecution},
		"A method or service call the protocol provides for the purpose: an OPC UA Call, an MMS operate, anything that runs code on the far end by design."},
	{"T0883", "Internet Accessible Device", []Tactic{TacticInitialAccess},
		"Something reaching an OT listener from where nothing should: an address outside every network the policy names."},
	{"T0884", "Connection Proxy", []Tactic{TacticCommandAndControl},
		"The device asked to fetch or forward on somebody else's behalf, which turns it into the attacker's proxy and amplifier."},
	{"T0886", "Remote Services", []Tactic{TacticInitialAccess, TacticLateralMovement},
		"The estate's own remote access used as the way in: a session that is valid, from an identity or a place the OT policy does not grant."},
	{"T0888", "Remote System Information Discovery", []Tactic{TacticDiscovery},
		"Asking devices what they are: identification requests, SZL walks, object dictionary reads, an SNMP walk of the system tree."},
}

// enterpriseCatalogue is every Enterprise ATT&CK technique this proxy can
// observe. It is the vocabulary for the levels above the plant -- the
// bastion, the edge, the directory, the databases and the brokers --
// where ATT&CK for ICS has nothing to say.
var enterpriseCatalogue = []entry{
	{"T1005", "Data from Local System", []Tactic{TacticCollection},
		"A file read off the far end's own filesystem over a protocol that was not meant to be a file service: an IED's fault records, a database made to read a file from the client's disk."},
	{"T1021", "Remote Services", []Tactic{TacticLateralMovement},
		"An interactive session to a machine inside the estate, over the remote-access protocol the estate already runs, from an identity or a place the policy does not grant."},
	{"T1021.001", "Remote Services: Remote Desktop Protocol", []Tactic{TacticLateralMovement},
		"The same, over RDP: the protocol a Windows estate is administered with, and the one an operator's workstation answers on."},
	{"T1021.004", "Remote Services: SSH", []Tactic{TacticLateralMovement},
		"The same, over SSH: a shell, a forwarded port or an SFTP session on a machine the policy does not open to this client."},
	{"T1021.005", "Remote Services: VNC", []Tactic{TacticLateralMovement},
		"The same, over VNC or RFB: the framebuffer protocol an HMI is reached with, where a session is a hand on the plant's own screen."},
	{"T1040", "Network Sniffing", []Tactic{TacticCredentialAccess, TacticDiscovery},
		"A credential or a session put on the wire where anything on the segment can read it: a bind in the clear, a cleartext password, an authentication method downgraded, TLS not used where it was available."},
	{"T1046", "Network Service Discovery", []Tactic{TacticDiscovery},
		"Finding what answers: a client choosing destination after destination through a relay, a request for a name or a host this edge does not serve."},
	{"T1041", "Exfiltration Over C2 Channel", []Tactic{TacticExfiltration},
		"Data leaving through the same connection that is carrying the instructions, so there is no second destination to notice: a long-lived response on a port that is already open and already allowed out."},
	{"T1048", "Exfiltration Over Alternative Protocol", []Tactic{TacticExfiltration},
		"Data leaving over a protocol that exists for something else: a name query carrying payload in its labels, a tunnel inside a service the policy allows out."},
	{"T1059", "Command and Scripting Interpreter", []Tactic{TacticExecution},
		"A command interpreter reached through a protocol that is not meant to be one: COPY ... PROGRAM, a LOAD from a program, xp_cmdshell, a Redis MODULE or SCRIPT, a shell command on a bastion the policy does not grant."},
	{"T1071", "Application Layer Protocol", []Tactic{TacticCommandAndControl},
		"An ordinary protocol carrying something else: a request through a forward proxy to a destination no egress rule covers, which is where a channel is built out of traffic that looks like browsing."},
	{"T1071.001", "Application Layer Protocol: Web Protocols", []Tactic{TacticCommandAndControl},
		"HTTP used as a channel rather than as a request and an answer: a response held open for hours carrying whatever the application chose to put in it, which is what an event stream is by design."},
	{"T1071.004", "Application Layer Protocol: DNS", []Tactic{TacticCommandAndControl},
		"Name resolution used as a channel rather than as a lookup: a name on a block list or a policy zone, a query whose shape is a tunnel."},
	{"T1078", "Valid Accounts", []Tactic{TacticDefenseEvasion, TacticInitialAccess, TacticPersistence, TacticPrivilegeEsc},
		"A real credential used where the policy does not grant it: an account, an application identity or a certificate that authenticates and is still not allowed here, now, or for this target."},
	{"T1078.001", "Valid Accounts: Default Accounts", []Tactic{TacticDefenseEvasion, TacticInitialAccess, TacticPersistence, TacticPrivilegeEsc},
		"A credential the equipment or the product shipped with: an SNMP community of `public`, a vendor account, a password this estate never set."},
	{"T1087", "Account Discovery", []Tactic{TacticDiscovery},
		"The directory read as a list rather than as a lookup: an anonymous bind, a leading-wildcard filter, a result set past the bound, a query for everything under the base."},
	{"T1090", "Proxy", []Tactic{TacticCommandAndControl},
		"This proxy, or something behind it, asked to carry traffic on somebody else's behalf: a destination the policy does not name, a tunnel whose inner target disagrees with its outer name, a data connection from a third party."},
	{"T1098", "Account Manipulation", []Tactic{TacticPersistence, TacticPrivilegeEsc},
		"A change to who may do what, rather than a use of what one may: a directory write, a broker's user and permission administration, a password-modify operation."},
	{"T1105", "Ingress Tool Transfer", []Tactic{TacticCommandAndControl},
		"A file moved into or out of a session that is meant to be interactive: an SFTP or FTP transfer the policy refuses, a transfer the content scanner stopped."},
	{"T1110", "Brute Force", []Tactic{TacticCredentialAccess},
		"Credentials tried rather than known: a failed authentication, a bind the directory refused, an identity nobody enrolled, the same source failing faster than a person types."},
	{"T1114", "Email Collection", []Tactic{TacticCollection},
		"A mailbox read for what is in it rather than to read mail: a request that names most of a folder, a search across every mailbox an account can open, messages copied somewhere easier to fetch from."},
	{"T1114.002", "Email Collection: Remote Email Collection", []Tactic{TacticCollection},
		"The mail server itself queried with a credential rather than a client's own mailbox being read on its own machine, which is what an IMAP or POP3 relay sees all of: the volume is the signal, because the access is legitimate."},
	{"T1071.003", "Application Layer Protocol: Mail Protocols", []Tactic{TacticCommandAndControl},
		"A mail protocol used as a channel rather than for mail: a mailbox written to and read from as a drop box, which looks like a client that appends and fetches and never sends."},
	{"T1133", "External Remote Services", []Tactic{TacticInitialAccess, TacticPersistence},
		"The estate's own remote access reached from where the policy does not allow it, or without the just-in-time grant that makes a session legitimate."},
	{"T1190", "Exploit Public-Facing Application", []Tactic{TacticInitialAccess},
		"A request shaped to make the service in front do something its author did not mean: a WAF rule or virtual patch matching, a smuggled message, a statement before authentication, a command inlined into another protocol."},
	{"T1213", "Data from Information Repositories", []Tactic{TacticCollection},
		"The estate's own stores read past what the policy grants: a database, a directory or a broker queried for data this client has no business holding."},
	{"T1498", "Network Denial of Service", []Tactic{TacticImpact},
		"This proxy or a service behind it made into an amplifier, or flooded from outside: a reflected query, an ANY over UDP, a mode-6 control request, an answer far larger than the question."},
	{"T1499", "Endpoint Denial of Service", []Tactic{TacticImpact},
		"A bound reached rather than a packet crafted: connections, sessions, channels, in-flight requests or bodies past what the listener holds for everybody else."},
	{"T1529", "System Shutdown/Reboot", []Tactic{TacticImpact},
		"A device told to restart over the protocol it is administered with: a `reload` authorised through TACACS+, an IED reinitialised, a controller reset."},
	{"T1548", "Abuse Elevation Control Mechanism", []Tactic{TacticDefenseEvasion, TacticPrivilegeEsc},
		"The far end's own privilege ladder climbed: `enable` on a network device, a RADIUS or TACACS+ answer granting priv-lvl 15, Service-Type = Administrative-User -- a session that authenticated as somebody and ends up with more than that somebody has."},
	{"T1550", "Use Alternate Authentication Material", []Tactic{TacticDefenseEvasion, TacticLateralMovement},
		"A ticket or a token used in place of a credential: a Kerberos delegation request, a forwarded or proxiable ticket presented from somewhere it was not issued to."},
	{"T1556", "Modify Authentication Process", []Tactic{TacticCredentialAccess, TacticDefenseEvasion, TacticPersistence},
		"The authentication decision itself interfered with rather than answered: a forged RADIUS reply, an authorization request that names no authenticated user, attributes added to a decision in flight."},
	{"T1558", "Steal or Forge Kerberos Tickets", []Tactic{TacticCredentialAccess},
		"A Kerberos ticket obtained for what can be done with it offline or elsewhere: a request for an encryption type whose ticket is crackable, a delegation that mints a ticket as somebody else, a lifetime nobody asked a KDC for by accident."},
	{"T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", []Tactic{TacticCredentialAccess},
		"A service ticket asked for so that its encrypted part can be cracked against the service account's password: an RC4-only TGS request, or a client collecting service tickets by the dozen."},
	{"T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting", []Tactic{TacticCredentialAccess},
		"An AS exchange completed without pre-authentication, which means the account is exempt and the reply's encrypted part is an offline password-cracking target."},
	{"T1557", "Adversary-in-the-Middle", []Tactic{TacticCredentialAccess, TacticCollection},
		"Something answering in place of the service: a provisioning answer from an address the estate does not run, authentication stripped from a time exchange, a resolver answer that points a client somewhere else."},
	{"T1565.001", "Data Manipulation: Stored Data Manipulation", []Tactic{TacticImpact},
		"A write to a store the policy grants only reads of: the database, key space or directory changed rather than read."},
	{"T1565.002", "Data Manipulation: Transmitted Data Manipulation", []Tactic{TacticImpact},
		"Data altered in flight rather than at rest: telemetry that repeats or has stopped moving as it crosses this relay, which is what an operator's screen is drawn from."},
	{"T1562", "Impair Defenses", []Tactic{TacticDefenseEvasion},
		"A change to what the estate's own equipment enforces or records: an access list edited, logging turned off, a configuration command on a device whose job is to filter."},
	{"T1567", "Exfiltration Over Web Service", []Tactic{TacticExfiltration},
		"Data leaving through a service that exists to receive it: an upload to file sharing, a paste site, a webhook -- which is why an egress policy about a method and a destination category is worth more than one about addresses."},
	{"T1572", "Protocol Tunneling", []Tactic{TacticCommandAndControl},
		"A channel inside a channel: a forwarded port, an upgrade to a stream protocol, a datagram tunnel through a proxy that was asked for a request."},
	{"T1601", "Modify System Image", []Tactic{TacticDefenseEvasion},
		"An image written to a device that runs it: a firmware copy to flash, an upgrade command, a file put where the next boot will read it."},
	{"T1602", "Data from Configuration Repository", []Tactic{TacticCollection},
		"A device's own configuration read out of it: `copy running-config tftp:`, an SNMP walk of the configuration tree, a file service reading the description the estate wrote of itself."},
	{"T1621", "Multi-Factor Authentication Request Generation", []Tactic{TacticCredentialAccess},
		"A second factor asked for and not given: a push the person refused or was asked for too often, which is what it looks like when somebody else already has the password."},
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

// otMappings is the plant's table: the kinds xot serves, where the
// vocabulary is ATT&CK for ICS and the Enterprise identifier is the
// second reading rather than the first.
//
// It is grouped by kind, and within a kind by what the reasons are about,
// because it is read by somebody asking "what does this relay tag" rather
// than looked up by machine.
var otMappings = []mapping{
	// Modbus. The protocol with no identity at all, where the policy is
	// the access control and every refusal is therefore a behaviour.
	{kind: "modbus", reason: "read_only", ids: []string{"T0855", "T0835"},
		note: "a write on a listener that grants none: the command was not authorised, and what it would have changed is the I/O image"},
	{kind: "modbus", reason: "read_only_unknown_function", ids: []string{"T0855"}},
	{kind: "modbus", reason: "rule_deny", ids: []string{"T0855"}},
	{kind: "modbus", reason: "no_rule", ids: []string{"T0855"}},
	{kind: "modbus", reason: "unit_not_allowed", ids: []string{"T0846", "T1046"},
		note: "a unit identifier the policy does not name is a sweep or a misroute, and a sweep of 1 to 247 is how a segment is mapped"},
	{kind: "modbus", reason: "unsafe_sub_function", ids: []string{"T0816", "T0804"},
		note: "function 8 sub-function 1 restarts the device and sub-function 4 puts it in listen-only, which stops it answering anybody"},
	{kind: "modbus", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
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
	// The behavioural models (internal/anomaly). The reasons are the same
	// on every kind that runs them, which is why an operations centre can
	// filter on `anomaly_cycle_changed` without knowing the protocol.
	{kind: "modbus", reason: "anomaly_new_symbol", ids: []string{"T0855"},
		note: "a function code this master has never used: not a command the policy refused, a command this master's own history says it does not send"},
	{kind: "modbus", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "modbus", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"},
		note: "writes across many addresses in a burst is the shape of walking the address space, not of a control action"},
	{kind: "modbus", reason: "anomaly_new_talker", ids: []string{"T0886"},
		note: "an address this listener has never served, on a segment whose device list does not change from one year to the next"},
	{kind: "modbus", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"},
		note: "a known master on a unit it has never addressed, which is one host working along the segment"},
	{kind: "modbus", reason: "anomaly_cycle_changed", ids: []string{"T0801"},
		note: "a scan cycle that changed: the same requests at a rate this poller has never used"},
	{kind: "modbus", reason: "anomaly_sequence_unseen", ids: []string{"T0855"},
		note: "a legitimate-looking request in an illegitimate place: an operation that has never followed the one before it"},
	{kind: "modbus", reason: "anomaly_telemetry_frozen", ids: []string{"T0832", "T0856", "T1565.002"},
		note: "a register that had been moving and stopped, which is the crude way to show a control room something other than the process"},
	{kind: "modbus", reason: "anomaly_telemetry_replayed", ids: []string{"T0832", "T0856", "T1565.002"},
		note: "a run of readings repeated exactly, which is the careful way: the screen stays alive while the process does something else"},
	{kind: "modbus", reason: "anomaly_correlation_broken", ids: []string{"T0831", "T0832"},
		note: "two points the process ties together that stopped agreeing: a pump commanded to full speed next to no flow at all"},

	// IEC 60870-5-104. A control centre's protocol, where the type
	// identification says what was asked for.
	{kind: "iec104", reason: "control", ids: []string{"T0855"}},
	{kind: "iec104", reason: "default_deny", ids: []string{"T0855"}},
	{kind: "iec104", reason: "rule", ids: []string{"T0855"}},
	{kind: "iec104", reason: "monitor_only", ids: []string{"T0855"}},
	{kind: "iec104", reason: "station_command", ids: []string{"T0816", "T0858"},
		note: "the station-level commands are reset process and the clock, which restart and re-time a substation gateway"},
	{kind: "iec104", reason: "common_address", ids: []string{"T0846", "T1046"}},
	{kind: "iec104", reason: "setpoint_range", ids: []string{"T0836", "T0831"}},
	{kind: "iec104", reason: "setpoint_delta", ids: []string{"T0836", "T0831"}},
	{kind: "iec104", reason: "setpoint_unknown", ids: []string{"T0836"}},
	{kind: "iec104", reason: "select_unavailable", ids: []string{"T0855"},
		note: "an operate with no select before it is a command that skipped the protocol's own confirmation"},
	{kind: "iec104", reason: "command_rate_limited", ids: []string{"T0806"}},
	{kind: "iec104", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
	{kind: "iec104", reason: "anomaly_new_symbol", ids: []string{"T0855"},
		note: "a type identification this controlling station has never sent: a control centre's repertoire does not change between projects"},
	{kind: "iec104", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "iec104", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "iec104", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "iec104", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"},
		note: "a controlling station addressing a common address it has never addressed, which is one control centre working through a substation list"},
	{kind: "iec104", reason: "anomaly_cycle_changed", ids: []string{"T0801"},
		note: "a general interrogation cycle that changed: this protocol's rhythm is a control centre's configuration, not a choice made per request"},
	{kind: "iec104", reason: "anomaly_sequence_unseen", ids: []string{"T0855"}},
	{kind: "iec104", reason: "anomaly_telemetry_frozen", ids: []string{"T0832", "T0856", "T1565.002"},
		note: "a measured value a substation has stopped moving, which is what a control room is shown while the process does something else"},
	{kind: "iec104", reason: "anomaly_telemetry_replayed", ids: []string{"T0832", "T0856", "T1565.002"}},
	{kind: "iec104", reason: "anomaly_correlation_broken", ids: []string{"T0831", "T0832"}},

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
	{kind: "s7", reason: "rack_not_allowed", ids: []string{"T0846", "T1046"}},
	{kind: "s7", reason: "slot_not_allowed", ids: []string{"T0846", "T1046"}},
	{kind: "s7", reason: "s7comm_plus_denied", ids: []string{"T0855"}},
	{kind: "s7", reason: "s7comm_plus_not_allowed", ids: []string{"T0855"}},
	{kind: "s7", reason: "anomaly_new_symbol", ids: []string{"T0855"},
		note: "an operation this station has never used, which on this protocol is the engineering workflow: a client that has only ever read, downloading"},
	{kind: "s7", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "s7", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "s7", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "s7", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"},
		note: "a client on a rack and slot it has never addressed, which is how a station works along a cell"},
	{kind: "s7", reason: "anomaly_cycle_changed", ids: []string{"T0801"}},
	{kind: "s7", reason: "anomaly_sequence_unseen", ids: []string{"T0855"},
		note: "read, write, read back is what a tool does every time; a write with no read before it is a tool that is not this one"},

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
	{kind: "mms", reason: "file_denied", ids: []string{"T0802", "T0867", "T1005"},
		note: "the file services are how COMTRADE records and SCL descriptions leave an IED, which is the plant's own description of itself"},
	{kind: "mms", reason: "file_not_allowed", ids: []string{"T0802", "T0867", "T1005"}},
	{kind: "mms", reason: "service_not_allowed", ids: []string{"T0855"}},
	{kind: "mms", reason: "service_class_not_allowed", ids: []string{"T0855"}},
	// The behavioural models. On this protocol the symbol carries the
	// functional constraint with the service, so "a client that has always
	// written $SP$ setpoints and now writes $CF$" is a new symbol rather than
	// another write.
	{kind: "mms", reason: "anomaly_new_symbol", ids: []string{"T0855"}},
	{kind: "mms", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "mms", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "mms", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "mms", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"}},
	{kind: "mms", reason: "anomaly_cycle_changed", ids: []string{"T0801"}},
	{kind: "mms", reason: "anomaly_sequence_unseen", ids: []string{"T0855"}},

	// BACnet/IP: a building's protocol, with no user and no session.
	{kind: "bacnet", reason: "rule_denied", ids: []string{"T0855"}},
	{kind: "bacnet", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
	{kind: "bacnet", reason: "too_many_broadcasts", ids: []string{"T0846", "T1046"},
		note: "who-is with no range, repeated, is how a building's device list is collected"},
	{kind: "bacnet", reason: "unsolicited_broadcast", ids: []string{"T0846", "T1046"}},
	{kind: "bacnet", reason: "unsolicited_reply", ids: []string{"T0856", "T1557"}},
	{kind: "bacnet", reason: "forwarded_origin_mismatch", ids: []string{"T0856", "T1557"}},
	// The behavioural models. The talkers model is worth more here than on
	// most kinds: a building's device list is written at commissioning and
	// does not change for a decade.
	{kind: "bacnet", reason: "anomaly_new_symbol", ids: []string{"T0855"}},
	{kind: "bacnet", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "bacnet", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "bacnet", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "bacnet", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"}},
	{kind: "bacnet", reason: "anomaly_cycle_changed", ids: []string{"T0801"}},
	{kind: "bacnet", reason: "anomaly_sequence_unseen", ids: []string{"T0855"}},

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
	{kind: "opcua", reason: "user_not_allowed", ids: []string{"T0859", "T1078"}},
	{kind: "opcua", reason: "empty_user", ids: []string{"T0859"}},
	{kind: "opcua", reason: "plaintext_password", ids: []string{"T0859", "T1040"}},
	{kind: "opcua", reason: "token_kind_not_allowed", ids: []string{"T0859"}},
	{kind: "opcua", reason: "certificate_uri_mismatch", ids: []string{"T0859", "T1078"}},
	{kind: "opcua", reason: "application_not_allowed", ids: []string{"T0886", "T1078"}},
	{kind: "opcua", reason: "endpoint_not_allowed", ids: []string{"T0886", "T1133"}},
	{kind: "opcua", reason: "publishing_interval", ids: []string{"T0814", "T1499"},
		note: "a subscription asking for a publishing interval below the bound is amplification the server pays for"},
	{kind: "opcua", reason: "sampling_interval", ids: []string{"T0814", "T1499"}},
	// The behavioural models. A Call's symbol carries the method with it,
	// because "Call" on its own says almost nothing.
	{kind: "opcua", reason: "anomaly_new_symbol", ids: []string{"T0855"}},
	{kind: "opcua", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "opcua", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "opcua", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "opcua", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"}},
	{kind: "opcua", reason: "anomaly_cycle_changed", ids: []string{"T0801"}},
	{kind: "opcua", reason: "anomaly_sequence_unseen", ids: []string{"T0855"}},

	// CoAP, where the path is the object model.
	{kind: "coap", reason: "method_not_allowed", ids: []string{"T0855"}},
	{kind: "coap", reason: "path_not_allowed", ids: []string{"T0855"}},
	{kind: "coap", reason: "default_deny", ids: []string{"T0855"}},
	{kind: "coap", reason: "rule", ids: []string{"T0855"}},
	{kind: "coap", reason: "discovery_not_allowed", ids: []string{"T0846", "T0861", "T1046"},
		note: "/.well-known/core exists to list everything the device has, which is the object model rather than the network"},
	{kind: "coap", reason: "proxying_not_allowed", ids: []string{"T0884", "T1090"},
		note: "Proxy-Uri tells the device to fetch a URI of the client's choosing: an open forward proxy with an amplifier attached"},
	{kind: "coap", reason: "unknown_psk_identity", ids: []string{"T0859", "T1110"},
		note: "a pre-shared key identity nobody enrolled, which on a shared segment is either a misprovisioned device or somebody trying names"},
	{kind: "coap", reason: "no_security_name", ids: []string{"T0859"}},
	{kind: "coap", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
	{kind: "coap", reason: "device_not_allowed", ids: []string{"T0856", "T1557"}},
	{kind: "coap", reason: "unsolicited", ids: []string{"T0856", "T1557"}},
	{kind: "coap", reason: "amplified", ids: []string{"T0814", "T1498"}},
	// The behavioural models, keyed on the method and the path -- which on an
	// LwM2M device is the object model.
	{kind: "coap", reason: "anomaly_new_symbol", ids: []string{"T0855"}},
	{kind: "coap", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "coap", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "coap", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "coap", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"}},
	{kind: "coap", reason: "anomaly_cycle_changed", ids: []string{"T0801"}},
	{kind: "coap", reason: "anomaly_sequence_unseen", ids: []string{"T0855"}},

	// SNMP: the estate's own equipment, where the credential is a
	// cleartext password in every datagram.
	{kind: "snmp", reason: "community", ids: []string{"T0812", "T0859", "T1078.001"},
		note: "a community string this listener does not hold is the vendor default being tried more often than not"},
	{kind: "snmp", reason: "user", ids: []string{"T0859", "T1078"}},
	{kind: "snmp", reason: "security_level", ids: []string{"T0859", "T1040"}},
	{kind: "snmp", reason: "tsm_no_name", ids: []string{"T0859"}},
	{kind: "snmp", reason: "tsm_level", ids: []string{"T0859", "T1040"}},
	{kind: "snmp", reason: "read_only", ids: []string{"T0836"},
		note: "an SNMP SET on network or field equipment is a configuration change, which is what this protocol's writes are"},
	{kind: "snmp", reason: "rule", ids: []string{"T0855"}},
	{kind: "snmp", reason: "default_deny", ids: []string{"T0855"}},
	{kind: "snmp", reason: "var_binds", ids: []string{"T0888", "T1046"}},
	{kind: "snmp", reason: "max_repetitions", ids: []string{"T0888", "T0814", "T1498"},
		note: "a GETBULK repetition count above the bound is a walk of the whole tree and an amplifier at the same time"},
	{kind: "snmp", reason: "response_ratio", ids: []string{"T0814", "T1498"}},
	{kind: "snmp", reason: "response_too_large", ids: []string{"T0814", "T1498"}},
	{kind: "snmp", reason: "unsolicited_response", ids: []string{"T0856", "T1557"}},
	{kind: "snmp", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
	// The behavioural models. The device here is the credential rather than
	// the address: on this protocol the community string or the USM user is
	// what a poller is.
	{kind: "snmp", reason: "anomaly_new_symbol", ids: []string{"T0855"}},
	{kind: "snmp", reason: "anomaly_new_write_point", ids: []string{"T0836", "T0835"}},
	{kind: "snmp", reason: "anomaly_write_burst", ids: []string{"T0806", "T0836"}},
	{kind: "snmp", reason: "anomaly_new_talker", ids: []string{"T0886"}},
	{kind: "snmp", reason: "anomaly_new_pair", ids: []string{"T0846", "T1046"}},
	{kind: "snmp", reason: "anomaly_cycle_changed", ids: []string{"T0801"}},
	{kind: "snmp", reason: "anomaly_sequence_unseen", ids: []string{"T0855"}},

	// TFTP: how field equipment is provisioned, and how firmware moves.
	{kind: "tftp", reason: "filename_denied", ids: []string{"T0857", "T0839", "T1105"},
		note: "on this protocol a filename is a firmware or configuration image, in one direction or the other"},
	{kind: "tftp", reason: "filename_not_allowed", ids: []string{"T0857", "T0839", "T1105"}},
	{kind: "tftp", reason: "directory_denied", ids: []string{"T0867", "T1105"}},
	{kind: "tftp", reason: "directory_not_allowed", ids: []string{"T0867", "T1105"}},
	{kind: "tftp", reason: "operation_not_allowed", ids: []string{"T0867", "T1105"}},
	{kind: "tftp", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
	{kind: "tftp", reason: "transfer_too_large", ids: []string{"T0814", "T1499"}},

	// DHCP and DHCPv6: provisioning, where an answer decides what a
	// device believes about the network it is on.
	{kind: "dhcp", reason: "rogue_server", ids: []string{"T0856", "T0886", "T1557"},
		note: "an answer from an address that is not a server this estate runs is the provisioning path being taken over"},
	{kind: "dhcp", reason: "boot_file_not_allowed", ids: []string{"T0857", "T0867", "T1105"}},
	{kind: "dhcp", reason: "boot_server_not_allowed", ids: []string{"T0857", "T0867", "T1557"}},
	{kind: "dhcp", reason: "option_denied", ids: []string{"T0836"}},
	{kind: "dhcp6", reason: "server_not_allowed", ids: []string{"T0856", "T0886", "T1557"}},
	{kind: "dhcp6", reason: "denied_option", ids: []string{"T0836"}},
	{kind: "dhcp6", reason: "reconfigure_not_allowed", ids: []string{"T0836", "T0858"}},

	// MQTT, which is a plant protocol and an estate protocol at once:
	// xot serves it for the line, xrelay for everything else.
	{kind: "mqtt", reason: "publish_topic_refused", ids: []string{"T0855"},
		note: "on a line a publish is a command, whatever the broker thinks it is carrying"},
	{kind: "mqtt", reason: "will_topic_refused", ids: []string{"T0855"},
		note: "a will is a command the broker sends when the client disappears, which is a command nobody watches happen"},
	{kind: "mqtt", reason: "retain_refused", ids: []string{"T0855"}},
	{kind: "mqtt", reason: "subscribe_refused", ids: []string{"T0802", "T1213"},
		note: "a wildcard subscription is every topic on the broker, which is collection rather than a subscription"},
	{kind: "mqtt", reason: "no_username", ids: []string{"T0859"}},
	{kind: "mqtt", reason: "client_not_allowed", ids: []string{"T0883", "T1133"}},
	{kind: "mqtt", reason: "max_connections", ids: []string{"T1499"}},
}

// itMappings is the table for everything above the plant: the bastion,
// the edge, the directory, the databases, the brokers and the estate's
// own infrastructure protocols. The vocabulary here is Enterprise
// ATT&CK, and an ICS identifier appears only where the refusal really is
// about the plant -- an OT listener reached from outside, a file that is
// a firmware image.
var itMappings = []mapping{
	// SSH: the bastion. Authentication, what a session may carry, and
	// what it may forward.
	{kind: "ssh", reason: "auth_failed", ids: []string{"T1110"}},
	{kind: "ssh", reason: "mfa_failed", ids: []string{"T1110"}},
	{kind: "ssh", reason: "mfa_push_refused", ids: []string{"T1621"},
		note: "a push the person declined: somebody who is not them is holding the password and asking them to approve it"},
	{kind: "ssh", reason: "mfa_push_throttled", ids: []string{"T1621"}},
	{kind: "ssh", reason: "client_not_allowed", ids: []string{"T1133", "T1021.004"}},
	{kind: "ssh", reason: "command_refused", ids: []string{"T1059"}},
	{kind: "ssh", reason: "shell_syntax", ids: []string{"T1059"},
		note: "a shell operator in a command the policy reads as a single program is how one allowed command becomes two"},
	{kind: "ssh", reason: "forward_refused", ids: []string{"T1572", "T1090"},
		note: "a forwarded port is a tunnel to a third machine, which is why a bastion that forwards anything is not a boundary"},
	{kind: "ssh", reason: "remote_forward_refused", ids: []string{"T1572", "T1090"}},
	{kind: "ssh", reason: "max_forwards", ids: []string{"T1572"}},
	{kind: "ssh", reason: "cert_no_port_forwarding", ids: []string{"T1572"}},
	{kind: "ssh", reason: "sftp_refused", ids: []string{"T1105"}},
	{kind: "ssh", reason: "file_transfer_refused", ids: []string{"T1105"}},
	{kind: "ssh", reason: "sftp_icap", ids: []string{"T1105"},
		note: "the content scanner stopped the file; which way it was going the transfer says, and both readings are a tool crossing a boundary"},
	{kind: "ssh", reason: "sftp_identity_refused", ids: []string{"T1078"}},
	{kind: "ssh", reason: "max_sessions", ids: []string{"T1499"}},
	{kind: "ssh", reason: "max_sessions_per_principal", ids: []string{"T1499"}},

	// Telnet, VNC and RDP: the rest of the gate, where the protocol
	// itself is the sub-technique.
	{kind: "telnet", reason: "client_refused", ids: []string{"T1133", "T1021"}},
	{kind: "telnet", reason: "mfa_failed", ids: []string{"T1110"}},
	{kind: "vnc", reason: "client_refused", ids: []string{"T1133", "T1021.005"}},
	{kind: "vnc", reason: "auth_failed", ids: []string{"T1110"}},
	{kind: "vnc", reason: "mfa_failed", ids: []string{"T1110"}},
	{kind: "rdp", reason: "client_refused", ids: []string{"T1133", "T1021.001"}},
	{kind: "rdp", reason: "mfa_failed", ids: []string{"T1110"}},

	// FTP: a gate protocol whose data connection is a second party.
	{kind: "ftp", reason: "auth_failed", ids: []string{"T1110"}},
	{kind: "ftp", reason: "mfa_failed", ids: []string{"T1110"}},
	{kind: "ftp", reason: "client_refused", ids: []string{"T1133"}},
	{kind: "ftp", reason: "identity_refused", ids: []string{"T1078"}},
	{kind: "ftp", reason: "data_stranger", ids: []string{"T1090"},
		note: "a data connection from an address that is not the control connection's is the bounce: the server is made somebody else's client"},
	{kind: "ftp", reason: "upstream_address", ids: []string{"T1090"}},
	{kind: "ftp", reason: "icap_blocked", ids: []string{"T1105"}},

	// SMTP: the one kind where the refusal is usually about the shape of
	// the message rather than about who sent it.
	{kind: "smtp", reason: "smuggling", ids: []string{"T1190"},
		note: "an end-of-data sequence the two ends read differently puts a second message inside the first, past every filter that read the first"},
	{kind: "smtp", reason: "bare_newline", ids: []string{"T1190"}},
	{kind: "smtp", reason: "starttls_injection", ids: []string{"T1557"},
		note: "a command written before the TLS handshake and replayed inside it is the classic way to speak in somebody else's session"},
	{kind: "smtp", reason: "max_connections", ids: []string{"T1499"}},

	// LDAP: the directory, which is an account list, a permission model
	// and a credential store at once.
	{kind: "ldap", reason: "bind_failed", ids: []string{"T1110"}},
	{kind: "ldap", reason: "bind_rate_limited", ids: []string{"T1110"}},
	{kind: "ldap", reason: "unauthenticated_bind", ids: []string{"T1110"},
		note: "a bind with a name and no password is accepted as anonymous by some directories, which is an authentication bypass being tried"},
	{kind: "ldap", reason: "anonymous_bind", ids: []string{"T1087"}},
	{kind: "ldap", reason: "bind_in_clear", ids: []string{"T1040"}},
	{kind: "ldap", reason: "sasl_mechanism", ids: []string{"T1040"}},
	{kind: "ldap", reason: "leading_wildcard", ids: []string{"T1087"},
		note: "`(cn=*)` and its relatives ask the directory for everything, one page at a time, which is enumeration wearing a filter"},
	{kind: "ldap", reason: "filter_terms", ids: []string{"T1087"}},
	{kind: "ldap", reason: "filter_depth", ids: []string{"T1087"}},
	{kind: "ldap", reason: "filter_attribute", ids: []string{"T1087"}},
	{kind: "ldap", reason: "attribute", ids: []string{"T1087"}},
	{kind: "ldap", reason: "attribute_not_allowed", ids: []string{"T1087"}},
	{kind: "ldap", reason: "base_dn", ids: []string{"T1087"}},
	{kind: "ldap", reason: "max_entries", ids: []string{"T1087", "T1499"}},
	{kind: "ldap", reason: "read_only", ids: []string{"T1098"},
		note: "a directory write is a change to who may do what, which outlives the session that made it"},
	{kind: "ldap", reason: "extended", ids: []string{"T1098"},
		note: "the extended operations include password modify, which is an account change rather than a query"},
	{kind: "ldap", reason: "rule", ids: []string{"T1213"}},
	{kind: "ldap", reason: "default_deny", ids: []string{"T1213"}},
	{kind: "ldap", reason: "max_connections", ids: []string{"T1499"}},
	{kind: "ldap", reason: "rate_limited", ids: []string{"T1499"}},
	{kind: "ldap", reason: "too_many_outstanding", ids: []string{"T1499"}},

	// RADIUS: the protocol that authenticates the network equipment, where
	// the whole of the cryptography is one shared secret and MD5.
	{kind: "radius", reason: "client_not_allowed", ids: []string{"T1078", "T1133"}},
	{kind: "radius", reason: "code_not_allowed", ids: []string{"T1078"}},
	{kind: "radius", reason: "dynamic_authorization_not_allowed", ids: []string{"T1556", "T1499"},
		note: "RFC 5176's Disconnect-Request ends a live user's session and CoA-Request re-authorises it, from one datagram, running from the server towards the equipment"},
	{kind: "radius", reason: "missing_message_authenticator", ids: []string{"T1557", "T1556"},
		note: "without RFC 3579's keyed digest a reply's only integrity check is MD5 with the secret appended, which a chosen-prefix collision forges (CVE-2024-3596)"},
	{kind: "radius", reason: "bad_message_authenticator", ids: []string{"T1557", "T1556"}},
	{kind: "radius", reason: "bad_response_authenticator", ids: []string{"T1557", "T1556"}},
	{kind: "radius", reason: "bad_request_authenticator", ids: []string{"T1557", "T1556"},
		note: "an Accounting-Request and the dynamic authorization codes carry a computed authenticator rather than a nonce, which is the only integrity check they have when they carry no digest attribute"},
	{kind: "radius", reason: "unsolicited_reply", ids: []string{"T1557"}},
	{kind: "radius", reason: "wrong_direction", ids: []string{"T1557"}},
	{kind: "radius", reason: "plaintext_password", ids: []string{"T1040"},
		note: "User-Password is XORed with MD5(secret || authenticator), so anybody holding the secret reads it -- which is everybody who can read the switch's configuration"},
	{kind: "radius", reason: "auth_type_not_allowed", ids: []string{"T1040"}},
	{kind: "radius", reason: "weak_eap_type", ids: []string{"T1040", "T1556"},
		note: "a client that Naks its way down to EAP-MD5 has downgraded the estate's authentication to a hash somebody can crack on a laptop"},
	{kind: "radius", reason: "eap_type_not_allowed", ids: []string{"T1040"}},
	{kind: "radius", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "radius", reason: "realm_not_allowed", ids: []string{"T1090", "T1078"},
		note: "a realm is routing: a server proxies by it, so a name carrying one asks this estate to forward the credential somewhere else"},
	{kind: "radius", reason: "realm_required", ids: []string{"T1078"}},
	{kind: "radius", reason: "nas_not_allowed", ids: []string{"T1078"}},
	{kind: "radius", reason: "privilege_too_high", ids: []string{"T1548", "T1078"},
		note: "the grant is in the reply: a Cisco av-pair saying shell:priv-lvl=15 is enable on every router that receives it"},
	{kind: "radius", reason: "administrative_reply_not_allowed", ids: []string{"T1548"}},
	{kind: "radius", reason: "attribute_not_allowed", ids: []string{"T1556"}},
	{kind: "radius", reason: "reply_attribute_not_allowed", ids: []string{"T1556"},
		note: "Tunnel-Private-Group-Id is the VLAN a RADIUS answer puts a port in, which is authorisation rather than authentication"},
	{kind: "radius", reason: "proxy_state_not_allowed", ids: []string{"T1090"}},
	{kind: "radius", reason: "malformed", ids: []string{"T1190"}},
	{kind: "radius", reason: "malformed_reply", ids: []string{"T1190"}},
	{kind: "radius", reason: "rule_denied", ids: []string{"T1078"}},
	{kind: "radius", reason: "no_rule_matched", ids: []string{"T1078"}},
	{kind: "radius", reason: "outside_schedule", ids: []string{"T1078"}},
	{kind: "radius", reason: "rate_limited", ids: []string{"T1110", "T1499"},
		note: "on this protocol the rate limit is also what stands between a credential-stuffing run and a server doing a key derivation per attempt"},
	{kind: "radius", reason: "too_many_pending", ids: []string{"T1499"}},
	{kind: "radius", reason: "identifier_in_use", ids: []string{"T1499"}},
	{kind: "radius", reason: "too_many_attributes", ids: []string{"T1499"}},
	{kind: "radius", reason: "message_too_large", ids: []string{"T1499"}},
	{kind: "radius", reason: "reply_too_large", ids: []string{"T1499"}},
	// The behavioural models. The symbol here is the code and the method
	// together, so a NAS that has only ever done 802.1X with PEAP and starts
	// sending PAP is a new symbol rather than another request.
	{kind: "radius", reason: "anomaly_new_symbol", ids: []string{"T1040", "T1556"}},
	{kind: "radius", reason: "anomaly_new_talker", ids: []string{"T1133"},
		note: "an estate's RADIUS clients are a list changed by a change request, so a new address authenticating against the directory is worth a line whatever the address lists say"},
	{kind: "radius", reason: "anomaly_new_pair", ids: []string{"T1046"}},
	{kind: "radius", reason: "anomaly_write_burst", ids: []string{"T1110"}},
	{kind: "radius", reason: "anomaly_sequence_unseen", ids: []string{"T1078"}},

	// TACACS+: device administration, where the command is in the packet.
	{kind: "tacacs", reason: "client_not_allowed", ids: []string{"T1078", "T1133"}},
	{kind: "tacacs", reason: "exchange_not_allowed", ids: []string{"T1078"}},
	{kind: "tacacs", reason: "unencrypted_body", ids: []string{"T1040"},
		note: "RFC 8907 allows the flag only on a secured transport; on bare TCP an administrative login's user name and password are on the wire"},
	{kind: "tacacs", reason: "plaintext_password", ids: []string{"T1040"}},
	{kind: "tacacs", reason: "authen_type_not_allowed", ids: []string{"T1040"}},
	{kind: "tacacs", reason: "follow_not_allowed", ids: []string{"T1557", "T1090"},
		note: "a FOLLOW reply carries another server's address, port and key, and a client that follows one sends its next credential there"},
	{kind: "tacacs", reason: "change_password_not_allowed", ids: []string{"T1098"}},
	{kind: "tacacs", reason: "sendauth_not_allowed", ids: []string{"T1213", "T1040"},
		note: "a SENDAUTH session asks the server for a credential to send onwards, which in a modern estate is either dead configuration or credential extraction"},
	{kind: "tacacs", reason: "unauthenticated_authorization", ids: []string{"T1556", "T1078"},
		note: "a device asking whether an unnamed user may run a command, and being told yes, has authorised it for whoever is on the port"},
	{kind: "tacacs", reason: "command_not_allowed", ids: []string{"T1059", "T1078"}},
	{kind: "tacacs", reason: "privilege_too_high", ids: []string{"T1548"}},
	{kind: "tacacs", reason: "privilege_grant_too_high", ids: []string{"T1548"},
		note: "priv-lvl in an authorization response is a mandatory argument, and a device that receives a mandatory argument must apply it"},
	{kind: "tacacs", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "tacacs", reason: "service_not_allowed", ids: []string{"T1078"}},
	{kind: "tacacs", reason: "authen_service_not_allowed", ids: []string{"T1548", "T1078"}},
	{kind: "tacacs", reason: "no_such_session", ids: []string{"T1557"}},
	{kind: "tacacs", reason: "session_in_use", ids: []string{"T1557"}},
	{kind: "tacacs", reason: "sequence_out_of_order", ids: []string{"T1557"}},
	{kind: "tacacs", reason: "wrong_direction", ids: []string{"T1557"}},
	{kind: "tacacs", reason: "tls_required", ids: []string{"T1040"}},
	{kind: "tacacs", reason: "malformed", ids: []string{"T1190"}},
	{kind: "tacacs", reason: "malformed_reply", ids: []string{"T1190"}},
	{kind: "tacacs", reason: "rule_denied", ids: []string{"T1078"}},
	{kind: "tacacs", reason: "no_rule_matched", ids: []string{"T1078"}},
	{kind: "tacacs", reason: "outside_schedule", ids: []string{"T1078"},
		note: "a configuration command outside the change window: the schedule is what a change window is written as"},
	{kind: "tacacs", reason: "rate_limited", ids: []string{"T1110", "T1499"}},
	{kind: "tacacs", reason: "too_many_sessions", ids: []string{"T1499"}},
	{kind: "tacacs", reason: "too_many_arguments", ids: []string{"T1499"}},
	{kind: "tacacs", reason: "body_too_large", ids: []string{"T1499"}},
	{kind: "tacacs", reason: "idle_timeout", ids: []string{"T1499"}},
	// The behavioural models, which have more to work with here than on any
	// other kind: a named user, a named device and a command.
	{kind: "tacacs", reason: "anomaly_new_symbol", ids: []string{"T1059", "T1078"},
		note: "the symbol is the command, so a user who has only ever run show commands and runs `configure terminal` is a new symbol"},
	{kind: "tacacs", reason: "anomaly_new_write_point", ids: []string{"T1562"}},
	{kind: "tacacs", reason: "anomaly_write_burst", ids: []string{"T1562"}},
	{kind: "tacacs", reason: "anomaly_new_talker", ids: []string{"T1133"}},
	{kind: "tacacs", reason: "anomaly_new_pair", ids: []string{"T1046"}},
	{kind: "tacacs", reason: "anomaly_sequence_unseen", ids: []string{"T1059"},
		note: "device administration has a shape -- log in, enable, look, change, save -- and a session that skips the looking is worth a line"},

	// The Kerberos KDC proxy: the one place an estate's Kerberos traffic is
	// inspectable, and the one where the interesting attacks are in the
	// plaintext fields.
	{kind: "kkdcp", reason: "realm_not_allowed", ids: []string{"T1090"},
		note: "a KDC proxy with no realm policy relays Kerberos for any realm a client names, from this estate's address"},
	{kind: "kkdcp", reason: "realm_mismatch", ids: []string{"T1090", "T1557"},
		note: "the envelope's realm is what the proxy routes by and the inner one is what the KDC decides on; a client that sends two different ones is asking the two to disagree"},
	{kind: "kkdcp", reason: "target_domain_required", ids: []string{"T1090"}},
	{kind: "kkdcp", reason: "message_type_not_allowed", ids: []string{"T1078"}},
	{kind: "kkdcp", reason: "etype_not_allowed", ids: []string{"T1558", "T1040"}},
	{kind: "kkdcp", reason: "weak_etype_only", ids: []string{"T1558.003"},
		note: "a TGS request offering nothing but RC4 has asked for a ticket it can crack offline against the service account's password"},
	{kind: "kkdcp", reason: "weak_ticket_etype", ids: []string{"T1558.003"}},
	{kind: "kkdcp", reason: "service_ticket_enumeration", ids: []string{"T1558.003", "T1046"},
		note: "forty different service principals in a minute is the realm's service accounts being collected, whatever encryption was asked for"},
	{kind: "kkdcp", reason: "preauth_not_required", ids: []string{"T1558.004"},
		note: "a KDC that answers a request with no pre-authentication with a ticket has said the account is exempt, and the reply is an offline cracking target"},
	{kind: "kkdcp", reason: "preauth_failure_burst", ids: []string{"T1110"},
		note: "per client rather than per account, because a sprayer tries one password against a thousand accounts and the account lockout is what it wanted"},
	{kind: "kkdcp", reason: "s4u2self_not_allowed", ids: []string{"T1558", "T1550"},
		note: "PA-FOR-USER names the impersonated user in the clear: a service account asking the KDC for a ticket to itself as anybody in the realm"},
	{kind: "kkdcp", reason: "s4u2proxy_not_allowed", ids: []string{"T1558", "T1550"}},
	{kind: "kkdcp", reason: "forwarded_ticket_not_allowed", ids: []string{"T1550"}},
	{kind: "kkdcp", reason: "anonymous_not_allowed", ids: []string{"T1078"}},
	{kind: "kkdcp", reason: "password_change_not_allowed", ids: []string{"T1098"}},
	{kind: "kkdcp", reason: "principal_not_allowed", ids: []string{"T1078"}},
	{kind: "kkdcp", reason: "service_not_allowed", ids: []string{"T1078"}},
	{kind: "kkdcp", reason: "option_not_allowed", ids: []string{"T1558"}},
	{kind: "kkdcp", reason: "lifetime_too_long", ids: []string{"T1558"}},
	{kind: "kkdcp", reason: "malformed_envelope", ids: []string{"T1190"}},
	{kind: "kkdcp", reason: "malformed_message", ids: []string{"T1190"}},
	{kind: "kkdcp", reason: "malformed_reply", ids: []string{"T1190"}},
	{kind: "kkdcp", reason: "body_too_large", ids: []string{"T1499"}},
	{kind: "kkdcp", reason: "rate_limited", ids: []string{"T1110", "T1499"}},
	{kind: "kkdcp", reason: "rule_denied", ids: []string{"T1078"}},
	{kind: "kkdcp", reason: "no_rule_matched", ids: []string{"T1078"}},
	{kind: "kkdcp", reason: "outside_schedule", ids: []string{"T1078"}},
	// The behavioural models. The rate model earns its keep beside the
	// distinct-service bound: that one counts different names, this one
	// counts requests.
	{kind: "kkdcp", reason: "anomaly_new_symbol", ids: []string{"T1558"}},
	{kind: "kkdcp", reason: "anomaly_new_write_point", ids: []string{"T1558.003"}},
	{kind: "kkdcp", reason: "anomaly_write_burst", ids: []string{"T1558.003"}},
	{kind: "kkdcp", reason: "anomaly_new_talker", ids: []string{"T1133"}},
	{kind: "kkdcp", reason: "anomaly_new_pair", ids: []string{"T1046"}},
	{kind: "kkdcp", reason: "anomaly_sequence_unseen", ids: []string{"T1558"}},

	// PostgreSQL, MySQL and TDS: the stores, where a statement is either
	// a read of a repository or a way out of it.
	// The two mailbox protocols. The bound refusals are the ones that carry
	// T1114: they are about how much of a mailbox a request named, which is
	// the only thing that separates a client synchronising from an account
	// being emptied -- the access itself is legitimate in both cases.
	{kind: "imap", reason: "fetch_too_large", ids: []string{"T1114", "T1114.002"},
		note: "a request named more of a mailbox than the policy allows"},
	{kind: "imap", reason: "open_sequence_set", ids: []string{"T1114", "T1114.002"},
		note: "a request named every message in the mailbox, so its size is the mailbox's"},
	{kind: "imap", reason: "mailbox_denied", ids: []string{"T1114"}},
	{kind: "imap", reason: "mailbox_not_allowed", ids: []string{"T1114"}},
	{kind: "imap", reason: "rule_denied", ids: []string{"T1114", "T1213"}},
	{kind: "imap", reason: "default_deny", ids: []string{"T1114", "T1213"}},
	{kind: "imap", reason: "command_denied", ids: []string{"T1114"}},
	{kind: "imap", reason: "command_not_allowed", ids: []string{"T1114"}},
	{kind: "imap", reason: "unknown_command", ids: []string{"T1071.003"},
		note: "a command this relay cannot name, which it refuses rather than tunnel"},
	{kind: "imap", reason: "wrong_state", ids: []string{"T1071.003"}},
	{kind: "imap", reason: "read_only", ids: []string{"T1565.001"}},
	{kind: "imap", reason: "append_too_large", ids: []string{"T1071.003", "T1565.001"},
		note: "a message written into a mailbox, which is how a mailbox becomes a drop box"},
	{kind: "imap", reason: "literal_too_large", ids: []string{"T1499"}},
	{kind: "imap", reason: "tls_required", ids: []string{"T1040"},
		note: "a mailbox password on an unencrypted connection"},
	{kind: "imap", reason: "mechanism_not_allowed", ids: []string{"T1040"}},
	{kind: "imap", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "imap", reason: "auth_failed", ids: []string{"T1110"},
		note: "a credential the mail server refused"},
	{kind: "imap", reason: "preauth_greeting", ids: []string{"T1556"},
		note: "the server said the transport had authenticated somebody this relay never saw"},
	{kind: "imap", reason: "compression_not_allowed", ids: []string{"T1562"},
		note: "a deflated connection cannot be inspected"},
	{kind: "imap", reason: "starttls_injection", ids: []string{"T1557"},
		note: "a command pipelined behind the upgrade, plaintext to one end and ciphertext to the other"},
	{kind: "imap", reason: "starttls_not_offered", ids: []string{"T1040"}},
	{kind: "imap", reason: "malformed_command", ids: []string{"T1190"}},
	{kind: "imap", reason: "malformed_mailbox", ids: []string{"T1190"}},
	{kind: "imap", reason: "malformed_sequence_set", ids: []string{"T1190"}},
	{kind: "imap", reason: "malformed_response", ids: []string{"T1190"}},
	{kind: "imap", reason: "malformed_greeting", ids: []string{"T1190"}},
	{kind: "imap", reason: "line_too_long", ids: []string{"T1499"}},
	{kind: "imap", reason: "response_too_long", ids: []string{"T1499"}},
	{kind: "imap", reason: "too_many_literals", ids: []string{"T1499"}},
	{kind: "imap", reason: "too_many_commands", ids: []string{"T1499"}},
	{kind: "imap", reason: "too_many_pending", ids: []string{"T1499"}},
	{kind: "imap", reason: "idle_too_long", ids: []string{"T1499"}},
	{kind: "imap", reason: "idle_not_allowed", ids: []string{"T1499"}},
	{kind: "imap", reason: "not_done", ids: []string{"T1071.003"}},
	{kind: "imap", reason: "max_connections", ids: []string{"T1499"}},
	{kind: "imap", reason: "rate_limited", ids: []string{"T1499"}},
	{kind: "imap", reason: "session_timeout", ids: []string{"T1499"}},
	{kind: "imap", reason: "client_not_allowed", ids: []string{"T1133"}},
	{kind: "imap", reason: "anomaly_new_symbol", ids: []string{"T1114.002"}},
	{kind: "imap", reason: "anomaly_new_device", ids: []string{"T1114"},
		note: "a mailbox this account has not opened before"},
	{kind: "imap", reason: "anomaly_new_point", ids: []string{"T1078"}},
	{kind: "imap", reason: "anomaly_new_talker", ids: []string{"T1133"}},
	{kind: "imap", reason: "anomaly_new_pair", ids: []string{"T1114"}},
	{kind: "imap", reason: "anomaly_off_hours", ids: []string{"T1114.002"}},
	{kind: "imap", reason: "anomaly_rate", ids: []string{"T1114.002"},
		note: "a fetch volume this account has not reached before"},
	{kind: "imap", reason: "anomaly_write_rate", ids: []string{"T1071.003"}},
	{kind: "imap", reason: "anomaly_value_range", ids: []string{"T1114.002"}},
	{kind: "imap", reason: "anomaly_value_jump", ids: []string{"T1114.002"}},
	{kind: "imap", reason: "anomaly_sequence_unseen", ids: []string{"T1114"}},
	{kind: "imap", reason: "anomaly_quiet", ids: []string{"T1114"}},

	{kind: "pop3", reason: "retrieval_too_large", ids: []string{"T1114", "T1114.002"},
		note: "the octets one connection retrieved, which on this protocol is the only copying bound there is"},
	{kind: "pop3", reason: "too_many_messages", ids: []string{"T1114", "T1114.002"}},
	{kind: "pop3", reason: "rule_denied", ids: []string{"T1114", "T1213"}},
	{kind: "pop3", reason: "default_deny", ids: []string{"T1114", "T1213"}},
	{kind: "pop3", reason: "command_denied", ids: []string{"T1114"}},
	{kind: "pop3", reason: "command_not_allowed", ids: []string{"T1114"}},
	{kind: "pop3", reason: "unknown_command", ids: []string{"T1071.003"}},
	{kind: "pop3", reason: "wrong_state", ids: []string{"T1071.003"}},
	{kind: "pop3", reason: "read_only", ids: []string{"T1565.001"},
		note: "DELE and RSET, which decide what the mailbox holds after the update state"},
	{kind: "pop3", reason: "tls_required", ids: []string{"T1040"},
		note: "USER and PASS put the password on the wire one line apart"},
	{kind: "pop3", reason: "mechanism_not_allowed", ids: []string{"T1040"}},
	{kind: "pop3", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "pop3", reason: "auth_failed", ids: []string{"T1110"}},
	{kind: "pop3", reason: "stls_injection", ids: []string{"T1557"}},
	{kind: "pop3", reason: "stls_not_offered", ids: []string{"T1040"}},
	{kind: "pop3", reason: "malformed_command", ids: []string{"T1190"}},
	{kind: "pop3", reason: "malformed_reply", ids: []string{"T1190"}},
	{kind: "pop3", reason: "malformed_greeting", ids: []string{"T1190"}},
	{kind: "pop3", reason: "malformed_message_number", ids: []string{"T1190"}},
	{kind: "pop3", reason: "malformed_line_count", ids: []string{"T1190"}},
	{kind: "pop3", reason: "line_too_long", ids: []string{"T1499"}},
	{kind: "pop3", reason: "max_connections", ids: []string{"T1499"}},
	{kind: "pop3", reason: "rate_limited", ids: []string{"T1499"}},
	{kind: "pop3", reason: "session_timeout", ids: []string{"T1499"}},
	{kind: "pop3", reason: "client_not_allowed", ids: []string{"T1133"}},
	{kind: "pop3", reason: "anomaly_new_symbol", ids: []string{"T1114.002"}},
	{kind: "pop3", reason: "anomaly_new_point", ids: []string{"T1078"}},
	{kind: "pop3", reason: "anomaly_new_talker", ids: []string{"T1133"}},
	{kind: "pop3", reason: "anomaly_new_pair", ids: []string{"T1114"}},
	{kind: "pop3", reason: "anomaly_off_hours", ids: []string{"T1114.002"}},
	{kind: "pop3", reason: "anomaly_rate", ids: []string{"T1114.002"}},
	{kind: "pop3", reason: "anomaly_write_rate", ids: []string{"T1565.001"}},
	{kind: "pop3", reason: "anomaly_value_range", ids: []string{"T1114.002"}},
	{kind: "pop3", reason: "anomaly_value_jump", ids: []string{"T1114.002"},
		note: "a retrieval far larger than this account's own history"},
	{kind: "pop3", reason: "anomaly_sequence_unseen", ids: []string{"T1114"}},
	{kind: "pop3", reason: "anomaly_quiet", ids: []string{"T1114"}},
	{kind: "pop3", reason: "anomaly_new_device", ids: []string{"T1114"}},

	{kind: "postgres", reason: "statement_denied", ids: []string{"T1213"}},
	{kind: "postgres", reason: "statement_not_allowed", ids: []string{"T1213"}},
	{kind: "postgres", reason: "rule_denied", ids: []string{"T1213"}},
	{kind: "postgres", reason: "database_not_allowed", ids: []string{"T1213"}},
	{kind: "postgres", reason: "read_only", ids: []string{"T1565.001"}},
	{kind: "postgres", reason: "copy_not_allowed", ids: []string{"T1059"},
		note: "COPY ... FROM PROGRAM is a shell on the database server, which is why it is a policy field of its own"},
	{kind: "postgres", reason: "copy_program", ids: []string{"T1059"}},
	{kind: "postgres", reason: "function_call", ids: []string{"T1059"}},
	{kind: "postgres", reason: "replication_not_allowed", ids: []string{"T1213"},
		note: "a replication connection is a copy of the whole database, continuously, which no query has to be written for"},
	{kind: "postgres", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "postgres", reason: "no_user", ids: []string{"T1078"}},
	{kind: "postgres", reason: "auth_not_allowed", ids: []string{"T1110"}},
	{kind: "postgres", reason: "weak_auth", ids: []string{"T1040"},
		note: "an authentication method that puts the password on the wire, offered where a stronger one was available"},
	{kind: "postgres", reason: "tls_required", ids: []string{"T1040"}},
	{kind: "postgres", reason: "outside_schedule", ids: []string{"T1078"}},
	{kind: "postgres", reason: "statement_before_auth", ids: []string{"T1190"}},
	{kind: "postgres", reason: "application_not_allowed", ids: []string{"T1078"}},
	{kind: "mysql", reason: "statement_denied", ids: []string{"T1213"}},
	{kind: "mysql", reason: "statement_not_allowed", ids: []string{"T1213"}},
	{kind: "mysql", reason: "rule_denied", ids: []string{"T1213"}},
	{kind: "mysql", reason: "command_denied", ids: []string{"T1213"}},
	{kind: "mysql", reason: "command_not_allowed", ids: []string{"T1213"}},
	{kind: "mysql", reason: "database_not_allowed", ids: []string{"T1213"}},
	{kind: "mysql", reason: "read_only", ids: []string{"T1565.001"}},
	{kind: "mysql", reason: "program_not_allowed", ids: []string{"T1059"}},
	{kind: "mysql", reason: "load_not_allowed", ids: []string{"T1005"},
		note: "LOAD DATA LOCAL INFILE reads a file off the client's own disk, which is how a malicious server collects from whoever connects to it"},
	{kind: "mysql", reason: "load_local", ids: []string{"T1005"}},
	{kind: "mysql", reason: "local_infile", ids: []string{"T1005"}},
	{kind: "mysql", reason: "multi_statements_denied", ids: []string{"T1190"},
		note: "several statements in one command is what turns an injection into an arbitrary one"},
	{kind: "mysql", reason: "replication_command", ids: []string{"T1213"}},
	{kind: "mysql", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "mysql", reason: "no_user", ids: []string{"T1078"}},
	{kind: "mysql", reason: "auth_not_allowed", ids: []string{"T1110"}},
	{kind: "mysql", reason: "weak_auth", ids: []string{"T1040"}},
	{kind: "mysql", reason: "cleartext_password_unencrypted", ids: []string{"T1040"}},
	{kind: "mysql", reason: "tls_required", ids: []string{"T1040"}},
	{kind: "mysql", reason: "upstream_no_tls", ids: []string{"T1040"}},
	{kind: "mysql", reason: "outside_schedule", ids: []string{"T1078"}},
	{kind: "tds", reason: "statement_denied", ids: []string{"T1213"}},
	{kind: "tds", reason: "statement_not_allowed", ids: []string{"T1213"}},
	{kind: "tds", reason: "rule_denied", ids: []string{"T1213"}},
	{kind: "tds", reason: "database_not_allowed", ids: []string{"T1213"}},
	{kind: "tds", reason: "type_denied", ids: []string{"T1213"}},
	{kind: "tds", reason: "type_not_allowed", ids: []string{"T1213"}},
	{kind: "tds", reason: "read_only", ids: []string{"T1565.001"}},
	{kind: "tds", reason: "procedure_denied", ids: []string{"T1059"},
		note: "the stored procedures include xp_cmdshell, which is a shell on the database host under the service account"},
	{kind: "tds", reason: "procedure_not_allowed", ids: []string{"T1059"}},
	{kind: "tds", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "tds", reason: "no_user", ids: []string{"T1078"}},
	{kind: "tds", reason: "app_not_allowed", ids: []string{"T1078"}},
	{kind: "tds", reason: "integrated_not_allowed", ids: []string{"T1078"}},
	{kind: "tds", reason: "cleartext_password", ids: []string{"T1040"}},
	{kind: "tds", reason: "tls_required", ids: []string{"T1040"}},
	{kind: "tds", reason: "upstream_no_tls", ids: []string{"T1040"}},
	{kind: "tds", reason: "outside_schedule", ids: []string{"T1078"}},

	// Redis: a cache whose command set includes several ways out of it.
	{kind: "redis", reason: "command_denied", ids: []string{"T1059"},
		note: "CONFIG SET, MODULE LOAD, SCRIPT, SLAVEOF and DEBUG are the commands that turn a key-value store into execution or into somebody else's replica"},
	{kind: "redis", reason: "command_not_allowed", ids: []string{"T1059"}},
	{kind: "redis", reason: "subcommand_denied", ids: []string{"T1059"}},
	{kind: "redis", reason: "subcommand_not_allowed", ids: []string{"T1059"}},
	{kind: "redis", reason: "key_denied", ids: []string{"T1213"}},
	{kind: "redis", reason: "key_not_allowed", ids: []string{"T1213"}},
	{kind: "redis", reason: "database_not_allowed", ids: []string{"T1213"}},
	{kind: "redis", reason: "rule_denied", ids: []string{"T1213"}},
	{kind: "redis", reason: "read_only", ids: []string{"T1565.001"}},
	{kind: "redis", reason: "inline_not_allowed", ids: []string{"T1190"},
		note: "an inline command is how an HTTP request smuggles Redis commands into a port it was never speaking to"},
	{kind: "redis", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "redis", reason: "outside_schedule", ids: []string{"T1078"}},
	{kind: "redis", reason: "tls_required", ids: []string{"T1040"}},
	{kind: "redis", reason: "too_many_commands", ids: []string{"T1499"}},

	// AMQP: a broker, where the identity on a message and the topology a
	// client may create are the two things worth policing.
	{kind: "amqp", reason: "user_not_allowed", ids: []string{"T1078"}},
	{kind: "amqp", reason: "vhost_not_allowed", ids: []string{"T1078"}},
	{kind: "amqp", reason: "user_id_mismatch", ids: []string{"T1078"},
		note: "a published message claiming another user's identity: the broker's own field for who sent it, set to somebody else"},
	{kind: "amqp", reason: "user_id_missing", ids: []string{"T1078"}},
	{kind: "amqp", reason: "outside_schedule", ids: []string{"T1078"}},
	{kind: "amqp", reason: "administrative_not_allowed", ids: []string{"T1098"},
		note: "a client that can administer the broker can grant itself the access it was refused, and keep it"},
	{kind: "amqp", reason: "management_node_denied", ids: []string{"T1098"}},
	{kind: "amqp", reason: "consume_not_allowed", ids: []string{"T1213"}},
	{kind: "amqp", reason: "rate_limited", ids: []string{"T1499"}},
	{kind: "amqp", reason: "too_many_channels", ids: []string{"T1499"}},
	{kind: "amqp", reason: "too_many_links", ids: []string{"T1499"}},
	{kind: "amqp", reason: "too_many_methods", ids: []string{"T1499"}},
	{kind: "amqp", reason: "tls_required", ids: []string{"T1040"}},

	// The forward proxy: the kind whose whole job is to be asked to reach
	// somewhere, and whose refusals are therefore about where.
	{kind: "forward", reason: "sni_mismatch", ids: []string{"T1572", "T1090"},
		note: "the name in the handshake and the name in the CONNECT disagreeing is a tunnel to one host hidden behind permission for another"},
	{kind: "forward", reason: "host_mismatch", ids: []string{"T1572", "T1090"},
		note: "the same disagreement one layer in: a request inside an intercepted tunnel naming a host the tunnel was not opened to is one name's permission being spent on another"},
	{kind: "forward", reason: "bad_request", ids: []string{"T1190"},
		note: "a head inside a tunnel that the two ends would frame differently -- a length and a chunked encoding both -- is the smuggling shape, and an intercepting proxy is the only place it can be seen at all"},
	{kind: "forward", reason: "masque_spoofed", ids: []string{"T1090"}},
	{kind: "forward", reason: "masque_unsolicited", ids: []string{"T1090"}},
	{kind: "forward", reason: "masque_context", ids: []string{"T1090"}},
	{kind: "forward", reason: "udp_unsolicited", ids: []string{"T1090"}},
	{kind: "forward", reason: "udp_wrong_source", ids: []string{"T1090"}},
	{kind: "forward", reason: "udp_disabled", ids: []string{"T1572"}},
	{kind: "forward", reason: "tunnel_limit", ids: []string{"T1499"}},
	{kind: "forward", reason: "udp_peer_table_full", ids: []string{"T1499"}},
	{kind: "forward", reason: "rule_deny", ids: []string{"T1048", "T1567", "T1071"},
		note: "an egress rule refusing names what was being sent and where: a body to a destination " +
			"nobody approved is exfiltration over an alternative protocol or over a web service, and " +
			"the proxy is the application layer it went through"},
	{kind: "forward", reason: "no_rule", ids: []string{"T1071", "T1090"},
		note: "a destination no egress rule covers is the one an estate has not decided about, " +
			"which is where a tool that brought its own destination list goes first"},

	// The layer 4 kinds, where the destination is the only thing said.
	{kind: "tcp", reason: "destination_not_allowed", ids: []string{"T1090", "T1046"},
		note: "a client choosing its own destination through a relay is the relay being used as a proxy, and destination after destination is a sweep"},
	{kind: "tcp", reason: "max_connections", ids: []string{"T1499"}},
	{kind: "tcp", reason: "quic_max_flows", ids: []string{"T1499"}},
	{kind: "udp", reason: "max_sessions", ids: []string{"T1499"}},
	{kind: "udp", reason: "max_sessions_per_ip", ids: []string{"T1499"}},

	// DNS: a lookup service that is also the estate's favourite covert
	// channel and its most-used amplifier.
	{kind: "dns", reason: "tunnel", ids: []string{"T1071.004", "T1048"},
		note: "labels carrying payload rather than a name: the query is the request and the answer is the reply, over the one protocol every network lets out"},
	{kind: "dns", reason: "blocked", ids: []string{"T1071.004"}},
	{kind: "dns", reason: "rpz", ids: []string{"T1071.004"}},
	{kind: "dns", reason: "threat_intel", ids: []string{"T1071.004"}},
	{kind: "dns", reason: "any_over_udp", ids: []string{"T1498"},
		note: "ANY over UDP is the amplification query: a small question with the largest answer the zone can give"},
	{kind: "dns", reason: "client_not_allowed", ids: []string{"T1498"}},
	{kind: "dns", reason: "cookie_required", ids: []string{"T1498"}},
	{kind: "dns", reason: "cookie_missing", ids: []string{"T1498"}},
	{kind: "dns", reason: "cookie_malformed", ids: []string{"T1498"}},
	{kind: "dns", reason: "answer_denied", ids: []string{"T1557"},
		note: "an answer pointing at an address the policy does not allow is how a name is made to resolve to somebody else's machine"},
	{kind: "dns", reason: "answer_stripped", ids: []string{"T1557"}},

	// HTTP: the edge. Its security events log a bare reason rather than
	// one prefixed with the kind, which the index below accounts for.
	{kind: "http", reason: "waf", ids: []string{"T1190"}},
	{kind: "http", reason: "virtual_patch", ids: []string{"T1190"},
		note: "a virtual patch matches the shape of a known vulnerability in the application behind, which is the exploit attempt itself"},
	{kind: "http", reason: "normalization", ids: []string{"T1190"},
		note: "double encoding, overlong UTF-8 and traversal are ways to make two readers of one request disagree about what it asks for"},
	{kind: "http", reason: "honeytoken", ids: []string{"T1078"},
		note: "a credential that exists only to be stolen: whoever used it did not get it from the person it was issued to"},
	{kind: "http", reason: "no_route", ids: []string{"T1046"}},
	// Server-Sent Events. The direction is outward, so the bound refusals are
	// exfiltration rather than intrusion: an event stream is arbitrary text,
	// chunked, flushed per event, held open for hours, under a Content-Type a
	// dashboard uses -- which is both what a price feed is and what you would
	// build to move data out quietly.
	{kind: "http", reason: "sse_event_too_large", ids: []string{"T1041", "T1048", "T1567"},
		note: "one event carrying more than this stream's events are shaped to carry"},
	{kind: "http", reason: "sse_too_many_events", ids: []string{"T1041", "T1048", "T1567"},
		note: "a stream past the number of events a route carries, which is the bound that makes it finite"},
	{kind: "http", reason: "sse_stream_too_large", ids: []string{"T1041", "T1048", "T1567"},
		note: "a stream past the octets a route carries"},
	{kind: "http", reason: "sse_pattern", ids: []string{"T1041", "T1048", "T1567"},
		note: "an event whose payload matched a pattern the route refuses to let leave"},
	{kind: "http", reason: "sse_too_many_fields", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_stream_too_long", ids: []string{"T1071.001"},
		note: "a response held open past max_duration, which is the shape of a channel rather than a feed"},
	{kind: "http", reason: "sse_stream_idle", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_event_denied", ids: []string{"T1071.001", "T1213"}},
	{kind: "http", reason: "sse_event_not_allowed", ids: []string{"T1071.001", "T1213"},
		note: "an event name this route does not carry, which is the stream being used for something other than its purpose"},
	{kind: "http", reason: "sse_event_rate", ids: []string{"T1499"}},
	{kind: "http", reason: "sse_schema", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_json", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_not_inspectable", ids: []string{"T1071.001"},
		note: "an event too large to have been read, so the checks that depend on reading it cannot run"},
	{kind: "http", reason: "sse_id_too_long", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_name_too_long", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_line_too_long", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_control_character", ids: []string{"T1071.001"},
		note: "a control character in an event name, which is either a mistake or an attempt to confuse something downstream that logs it"},
	{kind: "http", reason: "sse_not_utf8", ids: []string{"T1071.001"}},
	{kind: "http", reason: "sse_malformed_stream", ids: []string{"T1071.001"}},
	// The cursor. Last-Event-ID is the one piece of client input here and the
	// application resumes from it, so an identifier of a shape the estate does
	// not issue is a request for history the client was not shown.
	{kind: "http", reason: "sse_last_event_id_shape", ids: []string{"T1213", "T1190"},
		note: "a resumption cursor of a shape this estate does not issue"},
	{kind: "http", reason: "sse_last_event_id_not_allowed", ids: []string{"T1213"}},
	{kind: "http", reason: "sse_encoding_not_allowed", ids: []string{"T1562"},
		note: "a compressed event stream cannot be read, so offering one is an offer to stop inspecting"},
	{kind: "http", reason: "sse_encoding_not_readable", ids: []string{"T1562"}},
	{kind: "http", reason: "bad_host", ids: []string{"T1046"}},
	{kind: "http", reason: "websocket", ids: []string{"T1572"}},
	{kind: "http", reason: "webtransport", ids: []string{"T1572"}},
	{kind: "http", reason: "rate_limit", ids: []string{"T1499"}},
	{kind: "http", reason: "concurrency", ids: []string{"T1499"}},
	{kind: "http", reason: "body_size", ids: []string{"T1499"}},
	{kind: "http", reason: "body_budget", ids: []string{"T1499"}},
	{kind: "http", reason: "max_connections", ids: []string{"T1499"}},
	{kind: "http", reason: "max_connections_per_ip", ids: []string{"T1499"}},

	// Syslog: the estate's log path, where a flood is the thing that
	// makes the other records unreadable.
	{kind: "syslog", reason: "rate_limit", ids: []string{"T1499"}},
	{kind: "syslog", reason: "queue_full", ids: []string{"T1499"}},
	{kind: "syslog", reason: "max_connections", ids: []string{"T1499"}},

	// NTP and NTS: time, which every certificate, every grant window and
	// every time-tagged command depends on.
	{kind: "ntp", reason: "auth_stripped", ids: []string{"T1557"},
		note: "authentication removed from a time exchange leaves the clock taking anybody's word, which is the step before a time-tagged command"},
	{kind: "ntp", reason: "nts_stripped", ids: []string{"T1557"}},
	{kind: "ntp", reason: "auth_failed", ids: []string{"T1110"}},
	{kind: "ntp", reason: "ambiguous_mac", ids: []string{"T1557"}},
	{kind: "ntp", reason: "offset", ids: []string{"T1557"},
		note: "an offset no drift explains is a clock being set by somebody: grants, certificates and time-tagged commands all read it"},
	{kind: "ntp", reason: "source_changed", ids: []string{"T1557"}},
	{kind: "ntp", reason: "bogus_timestamps", ids: []string{"T1557"}},
	{kind: "ntp", reason: "bogus_refid", ids: []string{"T1557"}},
	{kind: "ntp", reason: "control_mode", ids: []string{"T1498"},
		note: "mode 6 and mode 7 are the query interfaces behind the largest NTP reflections ever measured"},
	{kind: "ntp", reason: "private_mode", ids: []string{"T1498"}},
	{kind: "ntp", reason: "client_not_allowed", ids: []string{"T1498"}},
	{kind: "ntp", reason: "rate_limit", ids: []string{"T1499"}},
	{kind: "ntp", reason: "unsolicited", ids: []string{"T1557"}},
	{kind: "ntske", reason: "handshake_limit", ids: []string{"T1499"}},
	{kind: "ntske", reason: "max_connections", ids: []string{"T1499"}},
}

// engineeringMappings are the plant's own tooling: the operations internal/
// engineering recognises, per kind, and the two reasons the access ledger gives
// about them.
//
// An engineering operation is reported whether or not the policy allowed it, so
// these rows are the one place in this table where the event is not a refusal.
// The technique is the same either way -- a program download is T0843 whoever
// asked for it -- and what the rest of the event says is whether there was an
// approved work order open at the time.
var engineeringMappings = []mapping{
	{kind: "modbus", reason: "engineering_program_download", ids: []string{"T0843"}},
	{kind: "modbus", reason: "engineering_mode_change", ids: []string{"T0858"}},
	{kind: "modbus", reason: "engineering_configuration", ids: []string{"T0836"}},
	{kind: "iec104", reason: "engineering_restart", ids: []string{"T0816"}},
	{kind: "iec104", reason: "engineering_configuration", ids: []string{"T0836"}},
	{kind: "iec104", reason: "engineering_file_transfer", ids: []string{"T0867", "T1105"}},
	{kind: "s7", reason: "engineering_program_download", ids: []string{"T0843"}},
	{kind: "s7", reason: "engineering_program_upload", ids: []string{"T0845"}},
	{kind: "s7", reason: "engineering_mode_change", ids: []string{"T0858"}},
	{kind: "s7", reason: "engineering_restart", ids: []string{"T0816"}},
	{kind: "s7", reason: "engineering_configuration", ids: []string{"T0836"}},
	{kind: "mms", reason: "engineering_program_download", ids: []string{"T0843"}},
	{kind: "mms", reason: "engineering_program_upload", ids: []string{"T0845"}},
	{kind: "mms", reason: "engineering_configuration", ids: []string{"T0836"}},
	{kind: "mms", reason: "engineering_file_transfer", ids: []string{"T0867", "T1105"}},
	{kind: "bacnet", reason: "engineering_restart", ids: []string{"T0816"}},
	{kind: "bacnet", reason: "engineering_mode_change", ids: []string{"T0858"}},
	{kind: "bacnet", reason: "engineering_configuration", ids: []string{"T0836"}},
	{kind: "bacnet", reason: "engineering_file_transfer", ids: []string{"T0867", "T1105"}},
	{kind: "opcua", reason: "engineering_method_call", ids: []string{"T0871"},
		note: "a method is whatever the server's author decided -- LoadRecipe, Reset, StartBatch -- so the operation's meaning is the vendor's and the work order is what says it was expected"},
	{kind: "opcua", reason: "engineering_configuration", ids: []string{"T0836"}},
	{kind: "snmp", reason: "engineering_configuration", ids: []string{"T0836"},
		note: "an SNMP SET is a configuration change: a port disabled, a VLAN moved, a trap destination pointed somewhere else"},
	{kind: "tftp", reason: "engineering_firmware", ids: []string{"T0857", "T0839", "T1105"},
		note: "a write on this protocol puts an image where every device that boots from it will run it"},
	// TACACS+ is the one engineering kind that is not a plant protocol, so
	// its classes map to the Enterprise matrix: a `configure terminal` on a
	// router is a change to what the estate's own equipment enforces.
	{kind: "tacacs", reason: "engineering_configuration", ids: []string{"T1562"},
		note: "the device whose job is to filter, reconfigured: an access list edited, logging turned off, a route changed"},
	{kind: "tacacs", reason: "engineering_restart", ids: []string{"T1529"}},
	{kind: "tacacs", reason: "engineering_firmware", ids: []string{"T1601", "T1105"}},
	{kind: "tacacs", reason: "engineering_file_transfer", ids: []string{"T1602", "T1105"},
		note: "`copy running-config tftp:` is the estate's own description of its network leaving it"},
}

// engineeringKinds are the kinds that recognise engineering operations, for the
// two reasons the access ledger gives about any of them.
var engineeringKinds = []string{"modbus", "iec104", "s7", "mms", "bacnet", "opcua", "snmp", "tftp", "tacacs"}

// grantlessMappings are the access ledger's answers about an engineering
// operation: none at all, and the alert on a listener that only wants to be
// told. Both are a real identity acting outside every approved window, which is
// what T0859 and T1078 are.
var grantlessMappings = []mapping{
	{reason: "engineering_no_grant", ids: []string{"T0859", "T1078"},
		note: "an engineering operation with no approved work order open for it, on a listener that requires one"},
	{reason: "engineering_ungranted", ids: []string{"T0859", "T1078"},
		note: "the same operation on a listener that only asks to be told: it happened, and it happened outside every window"},
}

// grantKinds are the kinds a just-in-time access grant covers today: the
// gate, and FTP, which is a gate protocol with a data connection.
var grantKinds = []string{"ssh", "telnet", "vnc", "rdp", "ftp"}

// grantMappings are the access ledger's own refusals. They are expanded
// across every kind that asks the ledger rather than written out per
// kind, because the reason means exactly the same thing on each: an
// identity the estate knows, reaching remote access it has no approved
// work order for.
//
// T0886 is here beside T1133 because these are the bastions an OT estate
// is entered through, and an assessor reading the plant's coverage looks
// for the ICS identifier.
var grantMappings = []mapping{
	{reason: "no_grant", ids: []string{"T0886", "T1133", "T1078"},
		note: "no grant at all: a session the policy would otherwise allow, outside every approved window"},
	{reason: "grant_pending", ids: []string{"T0886", "T1133", "T1078"}},
	{reason: "grant_not_yet", ids: []string{"T0886", "T1133", "T1078"}},
	{reason: "grant_expired", ids: []string{"T0886", "T1133", "T1078"}},
	{reason: "grant_denied", ids: []string{"T0886", "T1133", "T1078"}},
	{reason: "grant_revoked", ids: []string{"T0886", "T1133", "T1078"}},
	{reason: "grant_spent", ids: []string{"T0886", "T1133", "T1078"}},
	{reason: "grant_wrong_target", ids: []string{"T0886", "T1133", "T1078"},
		note: "a grant that exists and names another machine: the session is approved, the target is not"},
}

// across expands rows over several kinds, for a reason that means the
// same thing on each of them.
func across(kinds []string, rows ...mapping) []mapping {
	out := make([]mapping, 0, len(kinds)*len(rows))
	for _, k := range kinds {
		for _, r := range rows {
			r.kind = k
			out = append(out, r)
		}
	}
	return out
}

// mappings is the whole table.
var mappings = func() []mapping {
	out := make([]mapping, 0, len(otMappings)+len(itMappings)+len(grantKinds)*len(grantMappings)+
		len(engineeringMappings)+len(engineeringKinds)*len(grantlessMappings))
	out = append(out, otMappings...)
	out = append(out, itMappings...)
	out = append(out, across(grantKinds, grantMappings...)...)
	out = append(out, engineeringMappings...)
	out = append(out, across(engineeringKinds, grantlessMappings...)...)
	return out
}()

// bareReasonKinds are the kinds whose security log carries a reason
// without the kind's own prefix, so the event index needs the bare form
// too. HTTP is the one: its refusals are named counters rather than rows
// of the refusals table, and its events have always logged `waf` rather
// than `http_waf`. An alias here is how those events get tagged without
// changing a field a SIEM already parses.
var bareReasonKinds = map[string]bool{"http": true}

// techniques is both catalogues in one table, which is what a lookup by
// identifier wants. The matrices have separate identifier spaces, so one
// table cannot collide: ICS is T0xxx and Enterprise is T1xxx.
var techniques = map[string]Technique{}

// byKindReason and byEvent are the two indexes: one for a counter that
// has the kind in hand, one for a log line that has the event name.
var (
	byKindReason = map[string]map[string][]Technique{}
	byEvent      = map[string][]Technique{}
)

func init() {
	for _, c := range []struct {
		matrix  Matrix
		entries []entry
	}{{MatrixICS, icsCatalogue}, {MatrixEnterprise, enterpriseCatalogue}} {
		for _, e := range c.entries {
			// A duplicate identifier would be one row silently winning
			// over another; the package test fails on it, and here the
			// first is kept so the behaviour is at least stable.
			if _, dup := techniques[e.id]; dup {
				continue
			}
			techniques[e.id] = Technique{Matrix: c.matrix, ID: e.id,
				Name: e.name, Tactics: e.tactics, Why: e.why}
		}
	}
	for _, m := range mappings {
		ts := make([]Technique, 0, len(m.ids))
		for _, id := range m.ids {
			t, ok := techniques[id]
			if !ok {
				// A mapping naming a technique no catalogue has is a
				// mistake in this file, and the package test fails on
				// it. Nothing is registered for it, so a running
				// process tags nothing rather than tagging a technique
				// with an empty name.
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
		if bareReasonKinds[m.kind] {
			byEvent[m.reason] = ts
		}
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
//
// A reason that carries its own detail after a colon -- the HTTP side
// logs `waf:942100` and `rate_limit:<name>` -- resolves on the part
// before it, because the detail is which rule fired and the technique is
// a property of the reason.
func OfEvent(event string) []Technique {
	if ts := byEvent[event]; len(ts) > 0 {
		return ts
	}
	if head, _, ok := strings.Cut(event, ":"); ok {
		return byEvent[head]
	}
	return nil
}

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

// Matrices are the distinct matrices of a set, in a fixed order rather
// than the mapping's, so a query for `matrix="ics,enterprise"` matches
// every event that is both. A refusal that means something in both
// catalogues is the common case on a gate, and the field says so rather
// than leaving it to be inferred from the identifiers.
func Matrices(ts []Technique) string {
	var ics, ent bool
	for _, t := range ts {
		switch t.Matrix {
		case MatrixICS:
			ics = true
		case MatrixEnterprise:
			ent = true
		}
	}
	switch {
	case ics && ent:
		return string(MatrixICS) + "," + string(MatrixEnterprise)
	case ics:
		return string(MatrixICS)
	case ent:
		return string(MatrixEnterprise)
	}
	return ""
}

// Get is one technique by identifier, for the pack data that names one.
func Get(id string) (Technique, bool) {
	t, ok := techniques[strings.ToUpper(strings.TrimSpace(id))]
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

// All is both catalogues, sorted by identifier: an honest answer to
// "what can this relay detect". ICS comes first because its identifiers
// do.
func All() []Technique {
	out := make([]Technique, 0, len(techniques))
	for _, t := range techniques {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// InMatrix is one catalogue, sorted by identifier.
func InMatrix(m Matrix) []Technique {
	out := make([]Technique, 0, len(techniques))
	for _, t := range techniques {
		if t.Matrix == m {
			out = append(out, t)
		}
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
