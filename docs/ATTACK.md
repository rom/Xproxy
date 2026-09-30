# MITRE ATT&CK

Every refusal and every detection this proxy reports carries what it
means in MITRE ATT&CK terms, where it means anything: a `technique`, a
`technique_name`, a `tactic` and a `matrix` on the security log line, a
counter per technique, and a metric an operations centre can graph and
alert on.

Two catalogues, because this proxy stands in two worlds. **ATT&CK for
ICS** is the vocabulary for the plant: program downloads, operating-mode
changes, reporting messages. **Enterprise ATT&CK** is the vocabulary for
everything above it: brute force, protocol tunnelling, proxying, data
from a repository, accounts. A relay that carries SSH, HTTP, LDAP and
PostgreSQL beside Modbus and S7 has events in both.

## Why the identifier travels with the event

An operations centre does not read `modbus_read_only`,
`mms_write_constraint_not_allowed` or `ldap_leading_wildcard`. It reads a
case in a SIEM whose detections are catalogued by technique, reports
coverage by technique, and is asked at an audit which techniques the
estate can see. A relay saying "a write was refused on a read-only
listener" is saying T0855, Unauthorized Command Message; one saying "a
directory query asked for everything under the base" is saying T1087,
Account Discovery -- both in a vocabulary nobody has to translate.

The alternative is the spreadsheet: a mapping from this proxy's reason
strings to techniques, kept by somebody else, going stale the first time a
listener kind gains a reason. So the mapping lives in the code
(`internal/attack`), the tagging happens at the two points every event
passes through -- the security log and the refusal counter -- and this
page is generated from the same table, which is why it cannot disagree
with what a log line says.

## One refusal, two readings

The pairing is often the point. An SSH session admitted with no access
grant is T0886, Remote Services, to the plant's assessor, and T1133,
External Remote Services, to the enterprise's: the same refusal, read by
two teams whose dashboards do not share a vocabulary. The `matrix` field
then says `ics,enterprise`, and each technique is counted under its own
identifier, so neither report has to be built from the other's.

The split is not cosmetic. The two matrices have separate identifier
spaces (T0xxx against T1xxx, with Enterprise sub-techniques written
`T1021.004`) and separate tactic vocabularies: ATT&CK for ICS has
`inhibit-response-function` and `evasion` where Enterprise has
`credential-access` and `defense-evasion`. A query that filtered on
tactic without knowing which matrix it was reading would silently miss
half of what it asked for.

## What is deliberately not tagged

**A reason that is protocol hygiene stays untagged.** A malformed frame, a
TLS handshake that failed, a datagram over the size bound: those are the
noise floor and a bound an operator set. A technique label on them would
show up in a coverage report as a detection this proxy does not have,
which is worse than an empty cell. The tables below are the subset where
the reason itself implies the adversary behaviour.

**A refusal with no counterpart in either catalogue stays untagged.** Some
of this proxy's policy is finer than ATT&CK is: an AMQP performative the
policy does not grant, an RDP channel refused, an LDAP control this
listener does not accept. Those are real refusals with real counters, and
inventing a technique for them would be worse than the gap.

**A technique nothing here can observe is not in the catalogue.** The
catalogue is the answer to "what can this relay detect", so a technique
with no detection behind it is not listed -- and the package's own test
fails if one is added without a mapping. It follows that the catalogue
grows as the detections do, rather than being a copy of MITRE's matrix
with most of it unreachable.

**A technique is not a claim about intent.** A refusal tagged T0843 is a
program download this policy did not allow; whether that was an attacker
or an engineer working outside a window is what the rest of the event
says -- the identifier names the *behaviour*, which is what ATT&CK is a
catalogue of.

**One reason may carry several techniques**, because the behaviours
overlap by construction: an unsafe Modbus diagnostic sub-function is a
restart (T0816) and a way to stop a device answering (T0804). The log
field then holds both, comma separated, and each is counted -- so the
technique counters do not sum to the refusal count, and are not meant to.
The question they answer is "how much of this technique did we see".

## Where it appears

| Surface | Field or name |
|---------|---------------|
| Security log | `technique`, `technique_name`, `tactic`, `matrix` beside `action` and `reason` |
| SIEM export | the same fields, because the export is the same record |
| Snapshot (`xproxyctl status -json`, `/v1/status`) | `techniques`, technique identifier to count |
| Metrics | `xproxy_attack_technique_total{technique,name,tactic,matrix}` |
| Command line | `xproxyctl techniques [-catalogue] [-matrix ics\|enterprise]` |

The refusal itself is still counted where it was
(`xproxy_refusals_total{kind,reason}`): the technique is an additional
reading of the same event, not a replacement for the one an engineer
debugging a listener needs.

**The HTTP side is the one exception to the counter.** Its refusals are
named counters of their own (`xproxy_denied_total`) rather than rows of
the refusals table, so an HTTP technique appears in the security log and
not in `xproxy_attack_technique_total`. Its events also log a bare reason
(`waf`, `rate_limit`) rather than one prefixed with the kind, and a WAF
refusal carries the rule that fired after a colon (`waf:942100`); the
lookup accounts for both.

**A few kinds log one refusal event for every reason.** vnc, telnet, ntp,
ntske, udp and dns write `<kind>_denied` and put the specific reason in an
attribute, so their mappings reach the technique counter and the metric
but not the log line's `technique` field. That is a property of those
kinds' logging rather than of this table, and it is the reason the counter
exists as well as the log field.

**Shadow mode is not tagged.** A listener in shadow mode did not detect a
technique, it decided not to act on one, and the two readings are kept
apart the way the two refusal tables are. What it would have refused is
in the shadow ledger (`xproxyctl policy report`).

**A technique label decides nothing.** It is a reading of an event, not an
input to one: the ban ladder sees what it always saw -- the kind's own
reason -- and the OT kinds still never feed it, because banning a plant's
master over a technique label would take the process away from the control
room, which is a worse outcome than the one being guarded against.

## The ATT&CK for ICS techniques this proxy can observe

| Technique | Name | Tactics | What makes an event an instance of it |
|-----------|------|---------|----------------------------------------|
| [T0802](https://attack.mitre.org/techniques/T0802/) | Automated Collection | collection | A bulk pull: an SNMP walk, an MMS or FTP fetch of configuration and fault records, a large history read. One request is a question; a sweep is collection. |
| [T0804](https://attack.mitre.org/techniques/T0804/) | Block Reporting Message | inhibit-response-function | Stopping the telemetry a control room watches: IEC 104 STOPDT, a report control block disabled, a device put into listen-only. |
| [T0806](https://attack.mitre.org/techniques/T0806/) | Brute Force I/O | impair-process-control | Commands to one point faster than the equipment can follow -- a breaker or valve cycled at a rate no operator produces. |
| [T0812](https://attack.mitre.org/techniques/T0812/) | Default Credentials | lateral-movement | A credential the equipment shipped with: a community string of `public` or `private`, a vendor default user, a password this estate never set. |
| [T0814](https://attack.mitre.org/techniques/T0814/) | Denial of Service | inhibit-response-function | A device or this relay made unable to answer: a flood, an amplification, a connection table filled, a frame crafted to cost more than it looks. |
| [T0816](https://attack.mitre.org/techniques/T0816/) | Device Restart/Shutdown | inhibit-response-function | A restart or a shutdown asked for over the control protocol: an S7 CPU stop, a Modbus diagnostic restart, a BACnet ReinitializeDevice. |
| [T0831](https://attack.mitre.org/techniques/T0831/) | Manipulation of Control | impact | The process driven somewhere it should not go, through the control protocol's own legitimate messages. |
| [T0835](https://attack.mitre.org/techniques/T0835/) | Manipulate I/O Image | impair-process-control | A write that changes the controller's image of its inputs or outputs rather than a setting: coils and registers that are the I/O image itself. |
| [T0836](https://attack.mitre.org/techniques/T0836/) | Modify Parameter | impair-process-control | A setting changed rather than a command sent: a setpoint, a protection threshold, an alarm limit, a device configuration attribute. |
| [T0839](https://attack.mitre.org/techniques/T0839/) | Module Firmware | persistence | Firmware pushed to a module or a device -- the change that survives every restart and every program download after it. |
| [T0843](https://attack.mitre.org/techniques/T0843/) | Program Download | lateral-movement | Control logic written to a controller: an S7 block download, a UMAS program write, an MMS domain download. |
| [T0845](https://attack.mitre.org/techniques/T0845/) | Program Upload | collection | Control logic read *out* of a controller, which is how a plant's process knowledge leaves the site. |
| [T0846](https://attack.mitre.org/techniques/T0846/) | Remote System Discovery | discovery | Finding what is on the segment: unit identifier sweeps, who-is with no range, a client touching addresses nothing has ever answered on. |
| [T0855](https://attack.mitre.org/techniques/T0855/) | Unauthorized Command Message | impair-process-control | A command the policy does not grant this client: the plainest thing an OT relay refuses, and the one an operations centre asks about first. |
| [T0856](https://attack.mitre.org/techniques/T0856/) | Spoof Reporting Message | impair-process-control | Telemetry that did not come from the device it claims to: an answer from an address that is not the device, a reply that arrived without a question. |
| [T0857](https://attack.mitre.org/techniques/T0857/) | System Firmware | persistence | The device's own firmware image replaced, usually over the provisioning protocol the estate already runs. |
| [T0858](https://attack.mitre.org/techniques/T0858/) | Change Operating Mode | evasion, execution | A controller moved between run, program and stop, or into a mode where it accepts what it would otherwise refuse. |
| [T0859](https://attack.mitre.org/techniques/T0859/) | Valid Accounts | lateral-movement, persistence | A real credential used where the policy does not grant it: an identity, user or key that authenticates and is still not allowed here. |
| [T0861](https://attack.mitre.org/techniques/T0861/) | Point & Tag Identification | collection | Learning the control loop rather than the network: object and tag enumeration, reading the names and types a device exposes. |
| [T0867](https://attack.mitre.org/techniques/T0867/) | Lateral Tool Transfer | lateral-movement | A file moved onto or off a device over the estate's own transfer protocol. |
| [T0871](https://attack.mitre.org/techniques/T0871/) | Execution through API | execution | A method or service call the protocol provides for the purpose: an OPC UA Call, an MMS operate, anything that runs code on the far end by design. |
| [T0883](https://attack.mitre.org/techniques/T0883/) | Internet Accessible Device | initial-access | Something reaching an OT listener from where nothing should: an address outside every network the policy names. |
| [T0884](https://attack.mitre.org/techniques/T0884/) | Connection Proxy | command-and-control | The device asked to fetch or forward on somebody else's behalf, which turns it into the attacker's proxy and amplifier. |
| [T0886](https://attack.mitre.org/techniques/T0886/) | Remote Services | initial-access, lateral-movement | The estate's own remote access used as the way in: a session that is valid, from an identity or a place the OT policy does not grant. |
| [T0888](https://attack.mitre.org/techniques/T0888/) | Remote System Information Discovery | discovery | Asking devices what they are: identification requests, SZL walks, object dictionary reads, an SNMP walk of the system tree. |

## The Enterprise ATT&CK techniques this proxy can observe

| Technique | Name | Tactics | What makes an event an instance of it |
|-----------|------|---------|----------------------------------------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | collection | A file read off the far end's own filesystem over a protocol that was not meant to be a file service: an IED's fault records, a database made to read a file from the client's disk. |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | lateral-movement | An interactive session to a machine inside the estate, over the remote-access protocol the estate already runs, from an identity or a place the policy does not grant. |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Services: Remote Desktop Protocol | lateral-movement | The same, over RDP: the protocol a Windows estate is administered with, and the one an operator's workstation answers on. |
| [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Remote Services: SSH | lateral-movement | The same, over SSH: a shell, a forwarded port or an SFTP session on a machine the policy does not open to this client. |
| [T1021.005](https://attack.mitre.org/techniques/T1021/005/) | Remote Services: VNC | lateral-movement | The same, over VNC or RFB: the framebuffer protocol an HMI is reached with, where a session is a hand on the plant's own screen. |
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | credential-access, discovery | A credential or a session put on the wire where anything on the segment can read it: a bind in the clear, a cleartext password, an authentication method downgraded, TLS not used where it was available. |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | discovery | Finding what answers: a client choosing destination after destination through a relay, a request for a name or a host this edge does not serve. |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | exfiltration | Data leaving over a protocol that exists for something else: a name query carrying payload in its labels, a tunnel inside a service the policy allows out. |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | execution | A command interpreter reached through a protocol that is not meant to be one: COPY ... PROGRAM, a LOAD from a program, xp_cmdshell, a Redis MODULE or SCRIPT, a shell command on a bastion the policy does not grant. |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | command-and-control | Name resolution used as a channel rather than as a lookup: a name on a block list or a policy zone, a query whose shape is a tunnel. |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | defense-evasion, initial-access, persistence, privilege-escalation | A real credential used where the policy does not grant it: an account, an application identity or a certificate that authenticates and is still not allowed here, now, or for this target. |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Valid Accounts: Default Accounts | defense-evasion, initial-access, persistence, privilege-escalation | A credential the equipment or the product shipped with: an SNMP community of `public`, a vendor account, a password this estate never set. |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | discovery | The directory read as a list rather than as a lookup: an anonymous bind, a leading-wildcard filter, a result set past the bound, a query for everything under the base. |
| [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | command-and-control | This proxy, or something behind it, asked to carry traffic on somebody else's behalf: a destination the policy does not name, a tunnel whose inner target disagrees with its outer name, a data connection from a third party. |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | persistence, privilege-escalation | A change to who may do what, rather than a use of what one may: a directory write, a broker's user and permission administration, a password-modify operation. |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | command-and-control | A file moved into or out of a session that is meant to be interactive: an SFTP or FTP transfer the policy refuses, a transfer the content scanner stopped. |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | credential-access | Credentials tried rather than known: a failed authentication, a bind the directory refused, an identity nobody enrolled, the same source failing faster than a person types. |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | initial-access, persistence | The estate's own remote access reached from where the policy does not allow it, or without the just-in-time grant that makes a session legitimate. |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | initial-access | A request shaped to make the service in front do something its author did not mean: a WAF rule or virtual patch matching, a smuggled message, a statement before authentication, a command inlined into another protocol. |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | collection | The estate's own stores read past what the policy grants: a database, a directory or a broker queried for data this client has no business holding. |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | impact | This proxy or a service behind it made into an amplifier, or flooded from outside: a reflected query, an ANY over UDP, a mode-6 control request, an answer far larger than the question. |
| [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | impact | A bound reached rather than a packet crafted: connections, sessions, channels, in-flight requests or bodies past what the listener holds for everybody else. |
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | credential-access, collection | Something answering in place of the service: a provisioning answer from an address the estate does not run, authentication stripped from a time exchange, a resolver answer that points a client somewhere else. |
| [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | Data Manipulation: Stored Data Manipulation | impact | A write to a store the policy grants only reads of: the database, key space or directory changed rather than read. |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | command-and-control | A channel inside a channel: a forwarded port, an upgrade to a stream protocol, a datagram tunnel through a proxy that was asked for a request. |
| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation | credential-access | A second factor asked for and not given: a push the person refused or was asked for too often, which is what it looks like when somebody else already has the password. |

## What maps to what

The reason is the canonical form: the same string the refusal counter
labels and the security log's `reason` carries, with the kind's own prefix
removed where a kind spells one. A reason not listed here carries no
technique.

The access ledger's refusals -- `no_grant` and the `grant_*` family --
are the same on every kind that asks it, so they appear under each of
them: a session the policy would otherwise allow, outside every approved
work order.

### The plant: the kinds xot serves

#### bacnet

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883, T1133 |  |
| `forwarded_origin_mismatch` | T0856, T1557 |  |
| `rule_denied` | T0855 |  |
| `too_many_broadcasts` | T0846, T1046 | who-is with no range, repeated, is how a building's device list is collected |
| `unsolicited_broadcast` | T0846, T1046 |  |
| `unsolicited_reply` | T0856, T1557 |  |

#### coap

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `amplified` | T0814, T1498 |  |
| `client_not_allowed` | T0883, T1133 |  |
| `default_deny` | T0855 |  |
| `device_not_allowed` | T0856, T1557 |  |
| `discovery_not_allowed` | T0846, T0861, T1046 | /.well-known/core exists to list everything the device has, which is the object model rather than the network |
| `method_not_allowed` | T0855 |  |
| `no_security_name` | T0859 |  |
| `path_not_allowed` | T0855 |  |
| `proxying_not_allowed` | T0884, T1090 | Proxy-Uri tells the device to fetch a URI of the client's choosing: an open forward proxy with an amplifier attached |
| `rule` | T0855 |  |
| `unknown_psk_identity` | T0859, T1110 | a pre-shared key identity nobody enrolled, which on a shared segment is either a misprovisioned device or somebody trying names |
| `unsolicited` | T0856, T1557 |  |

#### iec104

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883, T1133 |  |
| `command_rate_limited` | T0806 |  |
| `common_address` | T0846, T1046 |  |
| `control` | T0855 |  |
| `default_deny` | T0855 |  |
| `monitor_only` | T0855 |  |
| `rule` | T0855 |  |
| `select_unavailable` | T0855 | an operate with no select before it is a command that skipped the protocol's own confirmation |
| `setpoint_delta` | T0836, T0831 |  |
| `setpoint_range` | T0836, T0831 |  |
| `setpoint_unknown` | T0836 |  |
| `station_command` | T0816, T0858 | the station-level commands are reset process and the clock, which restart and re-time a substation gateway |

#### mms

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `constraint_denied` | T0836 | the functional constraint says what a write is: $CF$ is configuration and $SG$ and $SE$ are a protection relay's trip characteristic |
| `constraint_not_allowed` | T0836 |  |
| `domain_denied` | T0843 |  |
| `domain_not_allowed` | T0843 |  |
| `file_denied` | T0802, T0867, T1005 | the file services are how COMTRADE records and SCL descriptions leave an IED, which is the plant's own description of itself |
| `file_not_allowed` | T0802, T0867, T1005 |  |
| `not_selected` | T0855 |  |
| `object_denied` | T0855 |  |
| `object_not_allowed` | T0855 |  |
| `operate_not_allowed` | T0855, T0871 |  |
| `selection_expired` | T0855 |  |
| `service_class_not_allowed` | T0855 |  |
| `service_not_allowed` | T0855 |  |
| `write_constraint_not_allowed` | T0836 |  |
| `write_object_not_allowed` | T0836 |  |

#### modbus

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `anomaly_new_function` | T0855 |  |
| `anomaly_new_write_address` | T0836, T0835 |  |
| `anomaly_write_burst` | T0806, T0836 | writes across many addresses in a burst is the shape of walking the address space, not of a control action |
| `client_not_allowed` | T0883, T1133 |  |
| `coil_clear_not_allowed` | T0831, T0835 |  |
| `coil_set_not_allowed` | T0831, T0835 |  |
| `no_rule` | T0855 |  |
| `read_only` | T0855, T0835 | a write on a listener that grants none: the command was not authorised, and what it would have changed is the I/O image |
| `read_only_unknown_function` | T0855 |  |
| `rule_deny` | T0855 |  |
| `unit_not_allowed` | T0846, T1046 | a unit identifier the policy does not name is a sweep or a misroute, and a sweep of 1 to 247 is how a segment is mapped |
| `unsafe_sub_function` | T0816, T0804 | function 8 sub-function 1 restarts the device and sub-function 4 puts it in listen-only, which stops it answering anybody |
| `value_delta` | T0836, T0831 |  |
| `value_masked_write` | T0835 |  |
| `value_no_select` | T0855 |  |
| `value_out_of_range` | T0836, T0831 | a setpoint outside the values the process can hold: the write is a parameter change and the process is where it goes |
| `value_rate` | T0806 | a point written faster than the bound is the rate no operator produces and the mechanism cannot follow |
| `value_transition` | T0831 |  |

#### opcua

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `application_not_allowed` | T0886, T1078 |  |
| `attribute_not_allowed` | T0836 | a write to `value` moves an actuator and a write to `access_level` changes who may, which is why the attribute is a policy field |
| `certificate_uri_mismatch` | T0859, T1078 |  |
| `empty_user` | T0859 |  |
| `endpoint_not_allowed` | T0886, T1133 |  |
| `method_denied` | T0871 |  |
| `method_not_allowed` | T0871 |  |
| `namespace_not_allowed` | T0861 |  |
| `node_denied` | T0836 |  |
| `node_not_allowed` | T0836 |  |
| `plaintext_password` | T0859, T1040 |  |
| `publishing_interval` | T0814, T1499 | a subscription asking for a publishing interval below the bound is amplification the server pays for |
| `sampling_interval` | T0814, T1499 |  |
| `service_denied` | T0855 |  |
| `service_not_allowed` | T0855 |  |
| `token_kind_not_allowed` | T0859 |  |
| `user_not_allowed` | T0859, T1078 |  |

#### s7

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `address_not_allowed` | T0836 |  |
| `area_denied` | T0836, T0835 |  |
| `area_not_allowed` | T0836, T0835 |  |
| `block_type_not_allowed` | T0843, T0845 | a block operation is control logic moving in one direction or the other, and which one the operation says |
| `db_not_allowed` | T0836 |  |
| `no_rule_matched` | T0855 |  |
| `operation_denied` | T0855 |  |
| `operation_not_allowed` | T0855 |  |
| `rack_not_allowed` | T0846, T1046 |  |
| `rule_denied` | T0855 |  |
| `s7comm_plus_denied` | T0855 |  |
| `s7comm_plus_not_allowed` | T0855 |  |
| `slot_not_allowed` | T0846, T1046 |  |

### The gate: the kinds xgate serves

#### rdp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_refused` | T1133, T1021.001 |  |
| `grant_denied` | T0886, T1133, T1078 |  |
| `grant_expired` | T0886, T1133, T1078 |  |
| `grant_not_yet` | T0886, T1133, T1078 |  |
| `grant_pending` | T0886, T1133, T1078 |  |
| `grant_revoked` | T0886, T1133, T1078 |  |
| `grant_spent` | T0886, T1133, T1078 |  |
| `grant_wrong_target` | T0886, T1133, T1078 | a grant that exists and names another machine: the session is approved, the target is not |
| `mfa_failed` | T1110 |  |
| `no_grant` | T0886, T1133, T1078 | no grant at all: a session the policy would otherwise allow, outside every approved window |

#### ssh

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `auth_failed` | T1110 |  |
| `cert_no_port_forwarding` | T1572 |  |
| `client_not_allowed` | T1133, T1021.004 |  |
| `command_refused` | T1059 |  |
| `file_transfer_refused` | T1105 |  |
| `forward_refused` | T1572, T1090 | a forwarded port is a tunnel to a third machine, which is why a bastion that forwards anything is not a boundary |
| `grant_denied` | T0886, T1133, T1078 |  |
| `grant_expired` | T0886, T1133, T1078 |  |
| `grant_not_yet` | T0886, T1133, T1078 |  |
| `grant_pending` | T0886, T1133, T1078 |  |
| `grant_revoked` | T0886, T1133, T1078 |  |
| `grant_spent` | T0886, T1133, T1078 |  |
| `grant_wrong_target` | T0886, T1133, T1078 | a grant that exists and names another machine: the session is approved, the target is not |
| `max_forwards` | T1572 |  |
| `max_sessions` | T1499 |  |
| `max_sessions_per_principal` | T1499 |  |
| `mfa_failed` | T1110 |  |
| `mfa_push_refused` | T1621 | a push the person declined: somebody who is not them is holding the password and asking them to approve it |
| `mfa_push_throttled` | T1621 |  |
| `no_grant` | T0886, T1133, T1078 | no grant at all: a session the policy would otherwise allow, outside every approved window |
| `remote_forward_refused` | T1572, T1090 |  |
| `sftp_icap` | T1105 | the content scanner stopped the file; which way it was going the transfer says, and both readings are a tool crossing a boundary |
| `sftp_identity_refused` | T1078 |  |
| `sftp_refused` | T1105 |  |
| `shell_syntax` | T1059 | a shell operator in a command the policy reads as a single program is how one allowed command becomes two |

#### telnet

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_refused` | T1133, T1021 |  |
| `grant_denied` | T0886, T1133, T1078 |  |
| `grant_expired` | T0886, T1133, T1078 |  |
| `grant_not_yet` | T0886, T1133, T1078 |  |
| `grant_pending` | T0886, T1133, T1078 |  |
| `grant_revoked` | T0886, T1133, T1078 |  |
| `grant_spent` | T0886, T1133, T1078 |  |
| `grant_wrong_target` | T0886, T1133, T1078 | a grant that exists and names another machine: the session is approved, the target is not |
| `mfa_failed` | T1110 |  |
| `no_grant` | T0886, T1133, T1078 | no grant at all: a session the policy would otherwise allow, outside every approved window |

#### vnc

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `auth_failed` | T1110 |  |
| `client_refused` | T1133, T1021.005 |  |
| `grant_denied` | T0886, T1133, T1078 |  |
| `grant_expired` | T0886, T1133, T1078 |  |
| `grant_not_yet` | T0886, T1133, T1078 |  |
| `grant_pending` | T0886, T1133, T1078 |  |
| `grant_revoked` | T0886, T1133, T1078 |  |
| `grant_spent` | T0886, T1133, T1078 |  |
| `grant_wrong_target` | T0886, T1133, T1078 | a grant that exists and names another machine: the session is approved, the target is not |
| `mfa_failed` | T1110 |  |
| `no_grant` | T0886, T1133, T1078 | no grant at all: a session the policy would otherwise allow, outside every approved window |

### The estate: the kinds xrelay serves

#### amqp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `administrative_not_allowed` | T1098 | a client that can administer the broker can grant itself the access it was refused, and keep it |
| `consume_not_allowed` | T1213 |  |
| `management_node_denied` | T1098 |  |
| `outside_schedule` | T1078 |  |
| `rate_limited` | T1499 |  |
| `tls_required` | T1040 |  |
| `too_many_channels` | T1499 |  |
| `too_many_links` | T1499 |  |
| `too_many_methods` | T1499 |  |
| `user_id_mismatch` | T1078 | a published message claiming another user's identity: the broker's own field for who sent it, set to somebody else |
| `user_id_missing` | T1078 |  |
| `user_not_allowed` | T1078 |  |
| `vhost_not_allowed` | T1078 |  |

#### dhcp (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `boot_file_not_allowed` | T0857, T0867, T1105 |  |
| `boot_server_not_allowed` | T0857, T0867, T1557 |  |
| `option_denied` | T0836 |  |
| `rogue_server` | T0856, T0886, T1557 | an answer from an address that is not a server this estate runs is the provisioning path being taken over |

#### dhcp6 (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `denied_option` | T0836 |  |
| `reconfigure_not_allowed` | T0836, T0858 |  |
| `server_not_allowed` | T0856, T0886, T1557 |  |

#### ftp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `auth_failed` | T1110 |  |
| `client_refused` | T1133 |  |
| `data_stranger` | T1090 | a data connection from an address that is not the control connection's is the bounce: the server is made somebody else's client |
| `grant_denied` | T0886, T1133, T1078 |  |
| `grant_expired` | T0886, T1133, T1078 |  |
| `grant_not_yet` | T0886, T1133, T1078 |  |
| `grant_pending` | T0886, T1133, T1078 |  |
| `grant_revoked` | T0886, T1133, T1078 |  |
| `grant_spent` | T0886, T1133, T1078 |  |
| `grant_wrong_target` | T0886, T1133, T1078 | a grant that exists and names another machine: the session is approved, the target is not |
| `icap_blocked` | T1105 |  |
| `identity_refused` | T1078 |  |
| `mfa_failed` | T1110 |  |
| `no_grant` | T0886, T1133, T1078 | no grant at all: a session the policy would otherwise allow, outside every approved window |
| `upstream_address` | T1090 |  |

#### ldap

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `anonymous_bind` | T1087 |  |
| `attribute` | T1087 |  |
| `attribute_not_allowed` | T1087 |  |
| `base_dn` | T1087 |  |
| `bind_failed` | T1110 |  |
| `bind_in_clear` | T1040 |  |
| `bind_rate_limited` | T1110 |  |
| `default_deny` | T1213 |  |
| `extended` | T1098 | the extended operations include password modify, which is an account change rather than a query |
| `filter_attribute` | T1087 |  |
| `filter_depth` | T1087 |  |
| `filter_terms` | T1087 |  |
| `leading_wildcard` | T1087 | `(cn=*)` and its relatives ask the directory for everything, one page at a time, which is enumeration wearing a filter |
| `max_connections` | T1499 |  |
| `max_entries` | T1087, T1499 |  |
| `rate_limited` | T1499 |  |
| `read_only` | T1098 | a directory write is a change to who may do what, which outlives the session that made it |
| `rule` | T1213 |  |
| `sasl_mechanism` | T1040 |  |
| `too_many_outstanding` | T1499 |  |
| `unauthenticated_bind` | T1110 | a bind with a name and no password is accepted as anonymous by some directories, which is an authentication bypass being tried |

#### mqtt (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883, T1133 |  |
| `max_connections` | T1499 |  |
| `no_username` | T0859 |  |
| `publish_topic_refused` | T0855 | on a line a publish is a command, whatever the broker thinks it is carrying |
| `retain_refused` | T0855 |  |
| `subscribe_refused` | T0802, T1213 | a wildcard subscription is every topic on the broker, which is collection rather than a subscription |
| `will_topic_refused` | T0855 | a will is a command the broker sends when the client disappears, which is a command nobody watches happen |

#### mysql

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `auth_not_allowed` | T1110 |  |
| `cleartext_password_unencrypted` | T1040 |  |
| `command_denied` | T1213 |  |
| `command_not_allowed` | T1213 |  |
| `database_not_allowed` | T1213 |  |
| `load_local` | T1005 |  |
| `load_not_allowed` | T1005 | LOAD DATA LOCAL INFILE reads a file off the client's own disk, which is how a malicious server collects from whoever connects to it |
| `local_infile` | T1005 |  |
| `multi_statements_denied` | T1190 | several statements in one command is what turns an injection into an arbitrary one |
| `no_user` | T1078 |  |
| `outside_schedule` | T1078 |  |
| `program_not_allowed` | T1059 |  |
| `read_only` | T1565.001 |  |
| `replication_command` | T1213 |  |
| `rule_denied` | T1213 |  |
| `statement_denied` | T1213 |  |
| `statement_not_allowed` | T1213 |  |
| `tls_required` | T1040 |  |
| `upstream_no_tls` | T1040 |  |
| `user_not_allowed` | T1078 |  |
| `weak_auth` | T1040 |  |

#### ntp (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `ambiguous_mac` | T1557 |  |
| `auth_failed` | T1110 |  |
| `auth_stripped` | T1557 | authentication removed from a time exchange leaves the clock taking anybody's word, which is the step before a time-tagged command |
| `bogus_refid` | T1557 |  |
| `bogus_timestamps` | T1557 |  |
| `client_not_allowed` | T1498 |  |
| `control_mode` | T1498 | mode 6 and mode 7 are the query interfaces behind the largest NTP reflections ever measured |
| `nts_stripped` | T1557 |  |
| `offset` | T1557 | an offset no drift explains is a clock being set by somebody: grants, certificates and time-tagged commands all read it |
| `private_mode` | T1498 |  |
| `rate_limit` | T1499 |  |
| `source_changed` | T1557 |  |
| `unsolicited` | T1557 |  |

#### ntske (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `handshake_limit` | T1499 |  |
| `max_connections` | T1499 |  |

#### postgres

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `application_not_allowed` | T1078 |  |
| `auth_not_allowed` | T1110 |  |
| `copy_not_allowed` | T1059 | COPY ... FROM PROGRAM is a shell on the database server, which is why it is a policy field of its own |
| `copy_program` | T1059 |  |
| `database_not_allowed` | T1213 |  |
| `function_call` | T1059 |  |
| `no_user` | T1078 |  |
| `outside_schedule` | T1078 |  |
| `read_only` | T1565.001 |  |
| `replication_not_allowed` | T1213 | a replication connection is a copy of the whole database, continuously, which no query has to be written for |
| `rule_denied` | T1213 |  |
| `statement_before_auth` | T1190 |  |
| `statement_denied` | T1213 |  |
| `statement_not_allowed` | T1213 |  |
| `tls_required` | T1040 |  |
| `user_not_allowed` | T1078 |  |
| `weak_auth` | T1040 | an authentication method that puts the password on the wire, offered where a stronger one was available |

#### redis

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `command_denied` | T1059 | CONFIG SET, MODULE LOAD, SCRIPT, SLAVEOF and DEBUG are the commands that turn a key-value store into execution or into somebody else's replica |
| `command_not_allowed` | T1059 |  |
| `database_not_allowed` | T1213 |  |
| `inline_not_allowed` | T1190 | an inline command is how an HTTP request smuggles Redis commands into a port it was never speaking to |
| `key_denied` | T1213 |  |
| `key_not_allowed` | T1213 |  |
| `outside_schedule` | T1078 |  |
| `read_only` | T1565.001 |  |
| `rule_denied` | T1213 |  |
| `subcommand_denied` | T1059 |  |
| `subcommand_not_allowed` | T1059 |  |
| `tls_required` | T1040 |  |
| `too_many_commands` | T1499 |  |
| `user_not_allowed` | T1078 |  |

#### smtp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `bare_newline` | T1190 |  |
| `max_connections` | T1499 |  |
| `smuggling` | T1190 | an end-of-data sequence the two ends read differently puts a second message inside the first, past every filter that read the first |
| `starttls_injection` | T1557 | a command written before the TLS handshake and replayed inside it is the classic way to speak in somebody else's session |

#### snmp (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883, T1133 |  |
| `community` | T0812, T0859, T1078.001 | a community string this listener does not hold is the vendor default being tried more often than not |
| `default_deny` | T0855 |  |
| `max_repetitions` | T0888, T0814, T1498 | a GETBULK repetition count above the bound is a walk of the whole tree and an amplifier at the same time |
| `read_only` | T0836 | an SNMP SET on network or field equipment is a configuration change, which is what this protocol's writes are |
| `response_ratio` | T0814, T1498 |  |
| `response_too_large` | T0814, T1498 |  |
| `rule` | T0855 |  |
| `security_level` | T0859, T1040 |  |
| `tsm_level` | T0859, T1040 |  |
| `tsm_no_name` | T0859 |  |
| `unsolicited_response` | T0856, T1557 |  |
| `user` | T0859, T1078 |  |
| `var_binds` | T0888, T1046 |  |

#### syslog (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `max_connections` | T1499 |  |
| `queue_full` | T1499 |  |
| `rate_limit` | T1499 |  |

#### tds

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `app_not_allowed` | T1078 |  |
| `cleartext_password` | T1040 |  |
| `database_not_allowed` | T1213 |  |
| `integrated_not_allowed` | T1078 |  |
| `no_user` | T1078 |  |
| `outside_schedule` | T1078 |  |
| `procedure_denied` | T1059 | the stored procedures include xp_cmdshell, which is a shell on the database host under the service account |
| `procedure_not_allowed` | T1059 |  |
| `read_only` | T1565.001 |  |
| `rule_denied` | T1213 |  |
| `statement_denied` | T1213 |  |
| `statement_not_allowed` | T1213 |  |
| `tls_required` | T1040 |  |
| `type_denied` | T1213 |  |
| `type_not_allowed` | T1213 |  |
| `upstream_no_tls` | T1040 |  |
| `user_not_allowed` | T1078 |  |

#### tftp (shared: xrelay and xot)

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883, T1133 |  |
| `directory_denied` | T0867, T1105 |  |
| `directory_not_allowed` | T0867, T1105 |  |
| `filename_denied` | T0857, T0839, T1105 | on this protocol a filename is a firmware or configuration image, in one direction or the other |
| `filename_not_allowed` | T0857, T0839, T1105 |  |
| `operation_not_allowed` | T0867, T1105 |  |
| `transfer_too_large` | T0814, T1499 |  |

### The edge: the kinds xproxy serves

#### dns

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `answer_denied` | T1557 | an answer pointing at an address the policy does not allow is how a name is made to resolve to somebody else's machine |
| `answer_stripped` | T1557 |  |
| `any_over_udp` | T1498 | ANY over UDP is the amplification query: a small question with the largest answer the zone can give |
| `blocked` | T1071.004 |  |
| `client_not_allowed` | T1498 |  |
| `cookie_malformed` | T1498 |  |
| `cookie_missing` | T1498 |  |
| `cookie_required` | T1498 |  |
| `rpz` | T1071.004 |  |
| `threat_intel` | T1071.004 |  |
| `tunnel` | T1071.004, T1048 | labels carrying payload rather than a name: the query is the request and the answer is the reply, over the one protocol every network lets out |

#### forward

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `masque_context` | T1090 |  |
| `masque_spoofed` | T1090 |  |
| `masque_unsolicited` | T1090 |  |
| `sni_mismatch` | T1572, T1090 | the name in the handshake and the name in the CONNECT disagreeing is a tunnel to one host hidden behind permission for another |
| `tunnel_limit` | T1499 |  |
| `udp_disabled` | T1572 |  |
| `udp_peer_table_full` | T1499 |  |
| `udp_unsolicited` | T1090 |  |
| `udp_wrong_source` | T1090 |  |

#### http

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `bad_host` | T1046 |  |
| `body_budget` | T1499 |  |
| `body_size` | T1499 |  |
| `concurrency` | T1499 |  |
| `honeytoken` | T1078 | a credential that exists only to be stolen: whoever used it did not get it from the person it was issued to |
| `max_connections` | T1499 |  |
| `max_connections_per_ip` | T1499 |  |
| `no_route` | T1046 |  |
| `normalization` | T1190 | double encoding, overlong UTF-8 and traversal are ways to make two readers of one request disagree about what it asks for |
| `rate_limit` | T1499 |  |
| `virtual_patch` | T1190 | a virtual patch matches the shape of a known vulnerability in the application behind, which is the exploit attempt itself |
| `waf` | T1190 |  |
| `websocket` | T1572 |  |
| `webtransport` | T1572 |  |

#### tcp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `destination_not_allowed` | T1090, T1046 | a client choosing its own destination through a relay is the relay being used as a proxy, and destination after destination is a sweep |
| `max_connections` | T1499 |  |
| `quic_max_flows` | T1499 |  |

#### udp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `max_sessions` | T1499 |  |
| `max_sessions_per_ip` | T1499 |  |

## Adding a mapping

One row in `internal/attack`, and the log line, the counter, the metric,
the `techniques` view and this page all carry it, because all five read
the same table. What the row has to satisfy:

- The technique has to be in a catalogue, and every technique in a
  catalogue has to be mapped by something. A technique with no detection
  behind it fails `TestEveryTechniqueIsReachable`, because `attack.All()`
  is read as what this relay can detect.
- The kind has to be one a daemon of this project serves, and every kind
  it serves has to tag something: `TestEveryKindThisProjectServesTagsSomething`
  is what stops a new listener kind's refusals reaching a SIEM as strings
  nobody can catalogue.
- The reason has to be the string the kind actually reports. It is worth
  reading the kind's own refusal path rather than guessing the name: a
  mapping for a reason nothing emits is a row that does nothing and no
  test can see.
- Both matrices where both apply. A refusal that means something to a
  plant's assessor and to an enterprise's should say so, rather than
  making one of them keep a translation table.

