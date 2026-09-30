# IEC 61850 MMS

The protocol a substation speaks. `kind: mms`, served by **xot**, TCP 102.

## On the wire

Six layers, and five of them have to be traversed before anything worth a policy
appears.

**TPKT** (RFC 1006) frames the stream: a version octet, a reserved octet, and a
two-octet length that counts its own header.

**COTP** (ISO 8073 class 0, X.224) gives it a connection. On S7comm the called
TSAP holds the rack and slot of the CPU and is therefore an address worth a
policy; on IEC 61850 the transport selectors are a convention — a single octet
`0x01` at both ends across most of the estate, and whatever the SCL file said on
the rest. So this layer is read to be traversed and to be bounded.

**ISO 8327 session** is four octets on a data frame: a GIVE TOKENS SPDU and a
DATA TRANSFER SPDU, each with an identifier of 1 and a length of 0. Both carry
the same identifier and are told apart by their order, which is the standard's
own arrangement.

**ISO 8823 presentation** decides what the octets above it *are*. The connect PDU
carries a context definition list: pairs of (identifier, abstract syntax) that
the two ends agree on, and every data PDU after it names an identifier rather
than a syntax. So a relay that wants to know an MMS payload from an ACSE one has
to read the list at association time and remember it — which is also how it knows
that a payload arrived on a context the two ends never defined.

**ACSE** (ISO 8650) is the first layer with an identity in it. See below.

**MMS** (ISO 9506) is the service layer: about eighty confirmed services, of
which a substation uses a dozen.

## What the protocol gives you

**An AP-title.** An object identifier naming the calling application process,
which on IEC 61850 is what an SCL file configured. Nothing proves it — there is
no signature, no certificate, no challenge — so it is an address rather than a
credential. That is still worth a great deal: it is the field an estate's own
drawings are written in and the field the IEDs themselves check, exactly as a
Modbus unit identifier is.

**An AE-qualifier.** An integer distinguishing application entities inside one
application, which in a substation usually separates a control-centre client from
an engineering one.

**A password in the clear.** Where an estate configured ACSE authentication at
all, IEC 61850-8-1 specifies the `charstring` form of the authentication value: a
GraphicString, on the wire, as the operator typed it. IEC 62351-4 exists to
replace it and most of the installed base has not moved. Anything on the path
between the client and the IED has read it — this relay included.

**Object names that carry the semantics.** This is the thing that makes a useful
policy possible for an estate whose SCL files nobody has read. An MMS object name
is a domain identifier and an item identifier, both opaque to MMS itself; IEC
61850-8-1 maps the data model onto them:

```
domain: AA1J1Q01A1LD0          the logical device
item:   XCBR1$CO$Pos$Oper      logical node, functional constraint, object, attribute
```

The **functional constraint** is the whole of it. The same service — a Write —
means entirely different things depending on it:

- `ST`, `MX` — status and measurands. Read every second by a control centre.
- `CO` — control. `XCBR1$CO$Pos$Oper` operates a circuit breaker.
- `SP` — a setpoint. `CF` — configuration, which includes `ctlModel`.
- `SG`, `SE` — setting groups: a protection relay's trip characteristics.
  Changing these is the most consequential write in a substation and the least
  likely to be noticed, because nothing moves until the fault that was meant to
  be cleared.
- `BR`, `RP` — report control blocks. Disabling one does not change the plant; it
  stops the control centre hearing about it.

And within `CO` the attribute says whether a request **selects** or **operates**:
`SBO` and `SBOw` select, `Oper` operates, `Cancel` cancels a selection.

## What this listener decides

**The connection**: which networks reach it, the session bounds, the rate.

**The association**: the AP-title against `ap_titles`, the AE-qualifier against
`ae_qualifiers`, and whether the authentication value is a cleartext password.
That last decision is the one to get right, and it is the reverse of the
equivalent decision on the `opcua` listener: `refuse_plaintext_passwords`
defaults **off** here, because on most of the installed base that password is the
only authentication the IED has and refusing it removes the only check there is.
What the listener does by default is **count it and raise a finding**
(`mms_plaintext_passwords`), which is what an honest relay can do about it. An
estate that has moved to IEC 62351-4 turns the refusal on.

The password's **length** is recorded and its value never is — not in a log, not
in a learning report, not in the parsed association this relay holds. A relay that
kept it would be the most valuable thing on the substation network.

**The request**: the service, the service class, the logical device, the object,
the functional constraint, the file path, and how many names one request carries.
An operate is a separate decision from a control-constraint write, so that
turning `CO` on does not silently turn operating on.

**Select before operate**, which is the one check in this protocol a relay can
make that the device may not. IEC 61850 leaves it to each object's `ctlModel`;
`ctlModel` lives in `$CF$`; `$CF$` is writable. So a client with configuration
access can set an object to direct-operate and then operate it. With
`require_select_before_operate` the listener tracks the selection itself, and
records it on the IED's **positive answer** rather than on the client's asking —
so a client that asked to select an object the IED refused holds no selection and
its operate is refused.

A refusal is answered in the protocol's own form: a confirmed-error PDU echoing
the request's invoke identifier, which a client's library turns into "object
access denied" rather than a timeout. A refusal at a layer below the service
closes instead, because there is no invoke identifier there to echo and an ACSE
reject would arrive as something the client's stack matches against a request it
has not finished sending.

## What it does not do

**It does not terminate TLS.** MMS on TCP 102 has none. IEC 62351-4 adds TLS
beneath the session layer, and a listener that terminated it would be terminating
the only end-to-end protection this protocol has. A deployment that wants TLS in
front of the relay puts a `tcp` listener with a `tls` section there.

**It does not verify the password.** Checking it would mean holding it, and the
whole reason this relay records a length rather than a value is that a relay
holding a substation's ACSE passwords is worth attacking for them.

**It does not read values.** A Write's payload is a process value and a control's
`ctlVal` is a breaker position. The object, the constraint and the count are
logged and recorded, because those are what a policy is written about; the value
is not, because a log at poll rate is not the place for a substation's data.

**It does not rewrite anything.** The octets that were read are the octets that
are forwarded. There is no general encoder in the wire package — the only thing
this kind encodes is the refusal it composes — because a relay that could
re-render a request could be asked to rewrite one.

### What is not here yet

**GOOSE and Sampled Values** (IEC 61850-8-1 §A, 9-2) are layer-2 multicast with
their own security model in IEC 62351-6, and are not a natural extension of a TCP
reverse proxy. The `GO` and `MS` functional constraints are visible here because
the *control blocks* for them are MMS objects — enabling a GOOSE publisher is an
MMS Write — but the published frames themselves never cross this listener.

**IEC 62351-4's certificate-based authentication** is a different association
exchange, and a listener that claimed to enforce it would have to terminate the
TLS beneath it. What this listener does about 62351-4 today is tell an estate how
far from it they are.

## Standards

- **IEC 61850-8-1** — the mapping onto MMS, ACSE and the ISO stack, including the
  object-name form and the authentication value.
- **IEC 61850-7-2** — the abstract services, the functional constraints and
  `sboTimeout`.
- **IEC 61850-7-3, 7-4** — the common data classes and the logical nodes, which
  is where `XCBR`, `PTOC` and `MMXU` come from.
- **IEC 62351-4** — security for the profiles including MMS: what replaces the
  cleartext authentication value.
- **ISO 9506-1, 9506-2** — MMS itself: the services and the ASN.1.
- **ISO 8650 / X.227** — ACSE.
- **ISO 8823 / X.226** — the presentation layer.
- **ISO 8327 / X.225** — the session layer.
- **ISO 8073 / X.224** — COTP.
- **RFC 1006** — ISO transport over TCP: TPKT.

## See also

- [The configuration reference](../CONFIG.md#serverlistenersmms-kind-mms) for
  every key.
- [`examples/ot/mms.yaml`](../../examples/ot/mms.yaml) for a substation with a
  control centre, an engineering station and a learning run.
- [`examples/ot/packs/industroyer-mms.yaml`](../../examples/ot/packs/industroyer-mms.yaml),
  a behaviour pack for Industroyer's IEC 61850 module, with
  [what a pack is and is not](../../examples/ot/packs/README.md).
- [S7comm](s7.md), which shares the TPKT and COTP layers and nothing above them.
- [OPC UA](opcua.md), the other industrial protocol with security of its own —
  and the one where the equivalent password knob defaults the other way, for the
  reason given above.
