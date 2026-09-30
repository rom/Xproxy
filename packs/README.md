# Behaviour packs

A behaviour pack is a signed, versioned document that says a shape of events
from one actor inside one window is one MITRE ATT&CK technique. It is **data**:
no expression language, no negation, no regular expression, nothing that can
name a symbol in the binary. [docs/CONFIG.md](../docs/CONFIG.md#packs) documents
the format field by field.

This directory is the set that ships with the product. It installs to
`/usr/share/xproxy/packs`, and a daemon reads it with:

```yaml
packs:
  directory: /usr/share/xproxy/packs
  keys:
    - {name: sysctl, file: /etc/xproxy/packs/sysctl.pub}
```

## The set

Ten **technique packs**, one per ATT&CK for ICS technique, written to be true of
any tool that uses the technique rather than of one tool:

| Pack | Technique | What the shape is |
|------|-----------|-------------------|
| `t0846-control-network-sweep` | T0846 Remote System Discovery | A peer nobody has seen, addressing device after device |
| `t0861-point-enumeration` | T0861 Point & Tag Identification | The point list walked, then a point driven |
| `t0843-download-with-no-work-order` | T0843 Program Download | Control logic written in with no approved change open |
| `t0845-logic-leaving-the-site` | T0845 Program Upload | Control logic read out with no change open |
| `t0858-controller-taken-out-of-run` | T0858 Change Operating Mode | A mode change from a client that had not used the service |
| `t0857-firmware-pushed-to-the-boot-server` | T0857 System Firmware | An image written to the server the estate boots from |
| `t0816-restart-after-a-refusal` | T0816 Device Restart/Shutdown | Refusals, then a restart |
| `t0832-a-screen-made-to-look-alive` | T0832 Manipulation of View | Frozen or replayed telemetry beside a write |
| `t0806-write-storm` | T0806 Brute Force I/O | Writes across the address space, then a value outside the envelope |
| `t0804-reporting-turned-off` | T0804 Block Reporting Message | Reporting disabled, then a change made behind it |

Six **named-malware packs**, each written against published analysis:

| Pack | What it is about |
|------|------------------|
| `tool-frostygoop-modbus` | A host that had only read, writing holding registers (Lviv, January 2024) |
| `tool-industroyer-iec104` | The information object walk and then a command |
| `tool-industroyer-mms` | The IEC 61850 model walk and then a control write |
| `tool-pipedream-modbus` | A UMAS stop or program transfer inside Modbus function 90 |
| `tool-pipedream-opcua` | An anonymous OPC UA session, a browse storm, a write |
| `tool-stuxnet-s7` | Blocks read out, blocks written in, then the parameters |

Nine **tooling packs**, for the software an estate actually meets — including its
own auditors':

| Pack | What it is about |
|------|------------------|
| `tool-nmap-ics-scripts` | The NSE control-protocol scripts, across kinds |
| `tool-plcscan` | A unit, rack and slot sweep |
| `tool-smod-modbus` | Function codes enumerated, then written |
| `tool-metasploit-modbusclient` | A unit-identifier walk, then a single register written |
| `tool-redpoint-enumeration` | Digital Bond's device and property enumeration |
| `tool-snap7-programmer` | A programmer connection from somewhere new, then blocks listed |
| `tool-opcua-browse-storm` | An OPC UA address space browsed exhaustively |
| `tool-iec104-hand-client` | Commands from an IEC 104 master with no scan rhythm |
| `tool-cosmicenergy-iec104` | A database session, then IEC 104 commands from the same host |

## What these are not

**They are not signatures.** None of the named tooling exploited a protocol.
FrostyGoop wrote registers, Industroyer sent select-then-execute properly,
Stuxnet downloaded a block — every one of them used the protocol as designed,
which is why there is nothing in a frame to match on. A pack is a statement
about the *shape* of a sequence, and a shape has false positives: the first
legitimate thing a plant does after a quiet year looks very like the first
illegitimate one.

**Most of them therefore only alert**, and say so in `enforcement`. The four
that may deny rest on something named on the wire — an engineering operation
that happened, with no approved work order covering it — rather than on a
novelty model, and even they do nothing until an operator sets
`packs.enforce: true`. A pack's deny is a **quarantine and not a ban**: the
actor is held out of this daemon's listeners for the length of that pack's own
window and then it is over, nothing reaches the ban list, and a restart clears
it. OT detections have never fed the ban ladder in this project.

**They are not the policy.** A pack notices; a policy refuses. The listener
configurations in [examples/ot/packs](../examples/ot/packs) are the other half
— complete `modbus`, `iec104`, `s7`, `mms` and `opcua` sections written against
the same published behaviour, which is what actually stops a program download.
Read those when writing a policy and load these when you want to know that
something happened.

**They are not complete coverage.** Two of PIPEDREAM's modules speak protocols
this proxy does not parse (CODESYS on UDP 1740-1743 and TCP 2455, Omron FINS on
UDP 9600), and TRITON speaks TriStation. A `kind: udp` listener in front of
those ports is a bound and a rate limit, which is worth having and is not a
detection. Segmentation is the control there, and saying so is better than
shipping a pack that implies otherwise.

## Signing

What is in this tree is the pack **source**: a release, a package build or an
estate's own configuration management signs it, because a private key in a git
repository is not a private key.

```
xproxyctl packs keygen -name sysctl -out /etc/xproxy/packs/sysctl
xproxyctl packs sign   -key /etc/xproxy/packs/sysctl.key -name sysctl /usr/share/xproxy/packs
xproxyctl packs verify -key /etc/xproxy/packs/sysctl.pub -name sysctl /usr/share/xproxy/packs
```

`verify` needs only the public half, which is the case that matters: an operator
checking a directory they were handed should not have to hold anything secret to
do it. A daemon with no key configured and no `allow_unsigned` refuses to start
on any pack here, which is the intended default.

## They are tested

`testdata/<pack>.replay` is one trace per pack: the sequence of security events
the pack is about, which must report, and the same sequence one signal short,
which must not. `internal/packs` replays every one of them on every test run, so
a pack edit that changes what the pack needs — a count raised, a reason renamed
in a kind, a window shortened past its own signals — fails a test rather than
quietly becoming a detection that never fires.

The trace format is one event per line:

```
fire
  s7 engineering engineering_program_upload
  s7 engineering engineering_program_download
  s7 engineering engineering_configuration
hold
  s7 engineering engineering_program_upload
  s7 engineering engineering_program_download
```

`internal/packs` also refuses, at load, a pack naming a technique this build
cannot observe, a reason it cannot emit, or a reason no listener kind of that
signal emits — so a pack cannot sit in this directory claiming a detection the
binary is not capable of making.
