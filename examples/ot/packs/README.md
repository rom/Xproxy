# Behaviour packs: the policy half

A behaviour pack is a configuration for one listener, written against the
published behaviour of one piece of ICS tooling. It exists because nobody
should have to read the Industroyer analysis to write a policy that would have
refused it.

**These are the policy half.** The other half is [`packs/`](../../../packs) at
the top of the tree: the same behaviour as signed, versioned *detection*
documents the daemon loads at start, which notice a shape of events and report
it in ATT&CK terms. The two answer different questions and an estate wants both.
A configuration here is what actually refuses a program download, and it has to
be merged into a policy somebody has already tuned — which happens once. A pack
there is a file that can be updated next quarter without touching either the
policy or the binary, and it tells you that something happened rather than
stopping it. Read these when writing a policy; load those to know what is going
on.

Each pack is a complete, loadable document. Copy the listener's body into your
own configuration, replace the example addresses, and read the comments: most
of what a pack contains is the reasoning, because a rule an engineer cannot
argue with is a rule nobody maintains.

| Pack | Listener kind | What it is about |
|------|---------------|------------------|
| [`frostygoop-modbus.yaml`](frostygoop-modbus.yaml) | `modbus` | A host that had only ever read starts writing holding registers |
| [`pipedream-modbus.yaml`](pipedream-modbus.yaml) | `modbus` | PIPEDREAM's Schneider module: UMAS inside function code 90 — stop the PLC, transfer the program |
| [`industroyer-iec104.yaml`](industroyer-iec104.yaml) | `iec104` | Industroyer and Industroyer2: the information object walk, the blinding, the station reset |
| [`industroyer-mms.yaml`](industroyer-mms.yaml) | `mms` | Industroyer's IEC 61850 module: enumerate the device model, then write a control object |
| [`stuxnet-s7.yaml`](stuxnet-s7.yaml) | `s7` | Read the program out, write one in, hook the cyclic block, write the parameter block |
| [`pipedream-opcua.yaml`](pipedream-opcua.yaml) | `opcua` | PIPEDREAM's OPC UA module: anonymous sessions, the address space walk, node writes |

## What a pack is not

**It is not a signature.** None of this tooling exploited a protocol. Every one
of them used the protocol as designed, which is why there is nothing to match
on: FrostyGoop wrote registers, Industroyer sent select-then-execute properly,
Stuxnet downloaded a block. A pack is therefore a statement about what the
estate's traffic *is*, and everything outside it.

**It is not a substitute for reading it.** The addresses, register ranges,
information object addresses, data block numbers and node identifiers in these
files are examples. A pack installed unedited refuses the wrong traffic, which
is how a security control gets switched off and stays off. Run the listener's
`learn` mode for a week first: the report says what the plant actually does,
and that is the list the rules should hold.

**It is not complete coverage of the tooling.** Two of PIPEDREAM's modules
speak protocols this proxy does not parse — CODESYS on UDP 1740-1743 and TCP
2455, and Omron FINS on UDP 9600. A `kind: udp` listener in front of those
ports is a bound on who may reach them and a rate limit, which is worth having
and is not a detection. Segmentation is the control there, and saying so is
better than shipping a pack that implies otherwise.

## How a finding is named

Where the listener kind has rule names, the pack puts the technique in the rule
name (`industroyer-object-walk-t0861`), because the rule name is what the
security event's `rule` attribute carries and what a SIEM query is written
against. Where the kind also has a rule `comment`, the technique is spelled out
there too, and the comment reaches the log.

Two kinds work differently and the packs say so in place:

- An `iec104` rule carries no `comment` field, so the technique is in the rule
  name alone.
- An `s7` rule matches a *session* — the client, the rack, the slot — and its
  own lists then bound everything that session does. So there is no rule that
  matches one write, and the finding is the refusal *reason*
  (`operation_denied`, `db_not_allowed`) with the matched rule's comment beside
  it.

The technique identifiers are MITRE ATT&CK for ICS. The mapping from a pack's
rules to them is the pack author's reading of published analysis, not MITRE's.
Every refusal and detection these listeners make now carries its technique on
the security event itself, in both matrices where a refusal means something in
each — see [docs/ATTACK.md](../../../docs/ATTACK.md).

## They are tested

Each pack has a test in its listener kind's package (`packs_test.go`) that
loads the file as it ships, points it at a fabricated device, and sends what
the tool sent. Two substitutions are made and no others: the listener binds a
loopback port, and the network of the host whose behaviour is under test
becomes the loopback. The rules are the file's own.

That is the part worth having. A pack nobody runs is a document of intentions,
and writing these tests found a real mistake in one of them: the OPC UA pack
first demanded `sign_and_encrypt`, which leaves the relay nothing to read and
makes its own service and node rules silent.
