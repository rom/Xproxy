# ATT&CK for ICS

Every refusal and every detection this proxy reports carries what it
means in MITRE ATT&CK for ICS terms, where it means anything: a
`technique`, a `technique_name` and a `tactic` on the security log line,
a counter per technique, and a metric an operations centre can graph and
alert on.

## Why the identifier travels with the event

An operations centre does not read `modbus_read_only` or
`mms_write_constraint_not_allowed`. It reads a case in a SIEM whose
detections are catalogued by technique, reports coverage by technique, and
is asked at an audit which techniques the estate can see. A relay saying
"a write was refused on a read-only listener" is saying T0855,
Unauthorized Command Message -- and saying it in a vocabulary nobody has
to translate.

The alternative is the spreadsheet: a mapping from this proxy's reason
strings to techniques, kept by somebody else, going stale the first time a
listener kind gains a reason. So the mapping lives in the code
(`internal/attack`), the tagging happens at the two points every event
passes through -- the security log and the refusal counter -- and this
page is generated from the same table, which is why it cannot disagree
with what a log line says.

## What is deliberately not tagged

**A reason that is protocol hygiene stays untagged.** A malformed frame, a
TLS handshake that failed, a datagram over the size bound: those are the
noise floor and a bound an operator set. A technique label on them would
show up in a coverage report as a detection this proxy does not have,
which is worse than an empty cell. The table below is the subset where the
reason itself implies the adversary behaviour.

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
| Security log | `technique`, `technique_name`, `tactic` beside `action` and `reason` |
| SIEM export | the same fields, because the export is the same record |
| Snapshot (`xproxyctl status -json`, `/v1/status`) | `techniques`, technique identifier to count |
| Metrics | `xproxy_attack_technique_total{technique,name,tactic}` |

The refusal itself is still counted where it was
(`xproxy_refusals_total{kind,reason}`): the technique is an additional
reading of the same event, not a replacement for the one an engineer
debugging a listener needs.

**Shadow mode is not tagged.** A listener in shadow mode did not detect a
technique, it decided not to act on one, and the two readings are kept
apart the way the two refusal tables are. What it would have refused is
in the shadow ledger (`xproxyctl policy report`).

**Nothing here reaches the ban ladder.** An OT detection is a line in a
log and a number in a counter; banning a plant's master over a technique
label would take the process away from the control room, which is a worse
outcome than the one being guarded against.

## The techniques this proxy can observe

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

## What maps to what

The reason is the canonical form: the same string the refusal counter
labels and the security log's `reason` carries, with the kind's own prefix
removed where a kind spells one. A reason not listed here carries no
technique.
#### bacnet

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883 |  |
| `forwarded_origin_mismatch` | T0856 |  |
| `rule_denied` | T0855 |  |
| `too_many_broadcasts` | T0846 | who-is with no range, repeated, is how a building's device list is collected |
| `unsolicited_broadcast` | T0846 |  |
| `unsolicited_reply` | T0856 |  |

#### coap

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `amplified` | T0814 |  |
| `client_not_allowed` | T0883 |  |
| `default_deny` | T0855 |  |
| `device_not_allowed` | T0856 |  |
| `discovery_not_allowed` | T0846, T0861 | /.well-known/core exists to list everything the device has, which is the object model rather than the network |
| `method_not_allowed` | T0855 |  |
| `no_security_name` | T0859 |  |
| `path_not_allowed` | T0855 |  |
| `proxying_not_allowed` | T0884 | Proxy-Uri tells the device to fetch a URI of the client's choosing: an open forward proxy with an amplifier attached |
| `rule` | T0855 |  |
| `unknown_psk_identity` | T0859 | a pre-shared key identity nobody enrolled, which on a shared segment is either a misprovisioned device or somebody trying names |
| `unsolicited` | T0856 |  |

#### dhcp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `boot_file_not_allowed` | T0857, T0867 |  |
| `boot_server_not_allowed` | T0857, T0867 |  |
| `option_denied` | T0836 |  |
| `rogue_server` | T0856, T0886 | an answer from an address that is not a server this estate runs is the provisioning path being taken over |

#### dhcp6

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `denied_option` | T0836 |  |
| `reconfigure_not_allowed` | T0836, T0858 |  |
| `server_not_allowed` | T0856, T0886 |  |

#### iec104

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883 |  |
| `command_rate_limited` | T0806 |  |
| `common_address` | T0846 |  |
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
| `file_denied` | T0802, T0867 | the file services are how COMTRADE records and SCL descriptions leave an IED, which is the plant's own description of itself |
| `file_not_allowed` | T0802, T0867 |  |
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
| `client_not_allowed` | T0883 |  |
| `coil_clear_not_allowed` | T0831, T0835 |  |
| `coil_set_not_allowed` | T0831, T0835 |  |
| `no_rule` | T0855 |  |
| `read_only` | T0855, T0835 | a write on a listener that grants none: the command was not authorised, and what it would have changed is the I/O image |
| `read_only_unknown_function` | T0855 |  |
| `rule_deny` | T0855 |  |
| `unit_not_allowed` | T0846 | a unit identifier the policy does not name is a sweep or a misroute, and a sweep of 1 to 247 is how a segment is mapped |
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
| `application_not_allowed` | T0886 |  |
| `attribute_not_allowed` | T0836 | a write to `value` moves an actuator and a write to `access_level` changes who may, which is why the attribute is a policy field |
| `certificate_uri_mismatch` | T0859 |  |
| `empty_user` | T0859 |  |
| `endpoint_not_allowed` | T0886 |  |
| `method_denied` | T0871 |  |
| `method_not_allowed` | T0871 |  |
| `namespace_not_allowed` | T0861 |  |
| `node_denied` | T0836 |  |
| `node_not_allowed` | T0836 |  |
| `plaintext_password` | T0859 |  |
| `publishing_interval` | T0814 | a subscription asking for a publishing interval below the bound is amplification the server pays for |
| `sampling_interval` | T0814 |  |
| `service_denied` | T0855 |  |
| `service_not_allowed` | T0855 |  |
| `token_kind_not_allowed` | T0859 |  |
| `user_not_allowed` | T0859 |  |

#### rdp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `no_grant` | T0886 |  |

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
| `rack_not_allowed` | T0846 |  |
| `rule_denied` | T0855 |  |
| `s7comm_plus_denied` | T0855 |  |
| `s7comm_plus_not_allowed` | T0855 |  |
| `slot_not_allowed` | T0846 |  |

#### snmp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883 |  |
| `community` | T0812, T0859 | a community string this listener does not hold is the vendor default being tried more often than not |
| `default_deny` | T0855 |  |
| `max_repetitions` | T0888, T0814 | a GETBULK repetition count above the bound is a walk of the whole tree and an amplifier at the same time |
| `read_only` | T0836 | an SNMP SET on network or field equipment is a configuration change, which is what this protocol's writes are |
| `response_ratio` | T0814 |  |
| `response_too_large` | T0814 |  |
| `rule` | T0855 |  |
| `security_level` | T0859 |  |
| `tsm_level` | T0859 |  |
| `tsm_no_name` | T0859 |  |
| `unsolicited_response` | T0856 |  |
| `user` | T0859 |  |
| `var_binds` | T0888 |  |

#### ssh

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `no_grant` | T0886 |  |

#### telnet

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `no_grant` | T0886 |  |

#### tftp

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `client_not_allowed` | T0883 |  |
| `directory_denied` | T0867 |  |
| `directory_not_allowed` | T0867 |  |
| `filename_denied` | T0857, T0839 | on this protocol a filename is a firmware or configuration image, in one direction or the other |
| `filename_not_allowed` | T0857, T0839 |  |
| `operation_not_allowed` | T0867 |  |
| `transfer_too_large` | T0814 |  |

#### vnc

| Reason | Technique | Why this one |
|--------|-----------|--------------|
| `no_grant` | T0886 |  |

## Reading a coverage question

"Which ATT&CK for ICS techniques does this estate detect?" has two honest
answers, and they are different questions:

- **What this proxy can see at all**: the catalogue above, which is what
  `internal/attack.All()` returns.
- **What the estate's own policy would catch**: the subset whose reasons
  its listeners can actually produce, which depends on what is configured.
  A listener with no `read_only` and no rules refuses nothing, so it
  detects nothing; the same listener with a positive policy detects T0855
  every time somebody writes where they may not.

The second is the one worth reporting, and it is why the technique
counters are per process rather than per catalogue: a zero against T0843
on a plant that has no engineering listener means "nothing tried", and on
one that does it means "nothing tried *yet*".
