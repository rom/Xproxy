# xproxy-simulate

## NAME

xproxy-simulate - what a configuration would decide, and what a change to it would decide differently

## SYNOPSIS

`xproxy-simulate` `-offline` `-a` *FILE* [`-b` *FILE*]
(`-requests` *FILE* | `-frames` *FILE* | `-pcap` *FILE* `-listener` *NAME*)
[`-listener` *NAME*] [`-quiet`] [`-json`]

## DESCRIPTION

`xproxy-simulate` answers one question about a configuration change: what
would it decide differently. Given one configuration it reports the
decision for each piece of traffic it is handed. Given two it reports only
what moved between them, and exits non-zero when anything did, so a change
can be gated on it in review or in a pipeline.

It is not a linter and it does not reason about the rules. It starts the
engine — this configuration, in this process, offline — and sends the
traffic through it, so the answer comes from the same code that would
decide it in production: the same WAF profiles and rule files, the same
route matching, the same protocol policies, the same filters. A rule that
matches here matches there.

Every listener kind is linked into this program, so it answers about a
configuration file naming any role's listeners without the operator having
to work out which of `xproxy`(8), `xgate`(8), `xrelay`(8) or `xot`(8)
would have served it. It opens no management socket and needs no running
daemon.

Nothing reaches a real upstream. Every pool is pointed at a sink inside
this process, keeping the pool names and the per-route assignments —
which pool a request goes to is part of the policy — and changing only
where that pool is. A TLS listener is given a throwaway certificate; the
estate's private keys are not read. Every section that reaches outside the
machine is switched off, and the output names each one that was, so the
answer is never quietly narrower than it looks.

Nothing is written outside the simulation's own directory. The state a
decision depends on — the ban store, the access ledger, the asset and API
inventories — is copied into it, so the run starts from what the estate has:
a banned address stays banned, a grant still approves, a device already in
the inventory is not a new device. What a run produces — a learning report,
a session recording — is redirected into it. Those change no decision, which
is why they are easy to overlook; a learning report overwritten with a
simulation's traffic would be the worst of them, since those get promoted
into policies.

## WHY -offline IS REQUIRED

Neutralising a configuration is not the same as making it inert. The
policy itself runs: the filters, any WebAssembly modules, the rule files
and the secrets provider are loaded exactly as the daemon would load them.
That is the point — a simulation of something other than the real policy
answers the wrong question — and it is also a decision about this machine
that belongs to the operator rather than to this program. `-offline` is
that assertion. Without it nothing is started and nothing is read.

## OPTIONS

| Option | Description |
|--------|-------------|
| `-offline` | Assert that this configuration may be started here. Required; see above. |
| `-a` *FILE* | The configuration to ask about. |
| `-b` *FILE* | A second configuration. With it, only the decisions that differ between the two are reported. |
| `-requests` *FILE* | A corpus of HTTP requests (see **CORPUS FORMATS**). |
| `-frames` *FILE* | A corpus of protocol frames, written as hex. |
| `-pcap` *FILE* | A pcapng file written by `xproxyctl capture`: the requests it recorded are replayed as inputs. Needs `-listener`. |
| `-listener` *NAME* | The listener to send to, for inputs that do not name one. A configuration with exactly one listener needs no `-listener` at all. |
| `-quiet` | Print only what changed. |
| `-json` | Print the whole answer — what was switched off, every outcome, every event, and the differences — as JSON. |
| `-version` | Print the version and exit. |

## CORPUS FORMATS

Both text formats are line based, take comments, and separate items with
`>>>`, which may carry `listener=`, `name=`, `client=` and `raw`.

HTTP requests, for `-requests`:

```
# a comment between items is ignored
>>> listener=edge name="what the scanner report flagged"
GET /?id=1%27+OR+1%3D1-- HTTP/1.1
Host: shop.example.com

>>> listener=edge name="the checkout that has to keep working"
POST /checkout HTTP/1.1
Host: shop.example.com
Content-Length: 9

qty=99999
```

Line endings are normalised to CRLF and an item with no blank line in it
gets the terminator a request head needs, because a request refused for a
bare newline would be a finding about the corpus rather than about the
policy. `raw` on the separator line skips both, which is how to send
something deliberately malformed.

Protocol frames, for `-frames`:

```
>>> listener=line1 name="write multiple registers at 40001"
0002 0000 0009 01 10 0000 0001 02 0064
```

Whitespace inside a frame is ignored, so bytes can be grouped the way the
protocol's own documentation groups them, and several lines concatenate
into one payload.

## DECISIONS

Each input is reported as `allowed`, `refused` or `error`.

`refused` is an event that refused it, named with the reason the security
log uses, or an HTTP status of 400 or more. An alert that did not refuse is
not a refusal — the whole point of the alert-only modes is that the
operation went through — but it is carried in the output, since a rule
about to start refusing usually alerts first.

`allowed` is asserted only on evidence: the listener relayed the input to
the sink, or answered the client itself. Absence of a refusal is not
evidence. A listener that speaks bytes rather than HTTP answers only when
the device does, so an input it could not finish reading produces no reply
and no event at all, and reading that as `allowed` would put a hole in the
report exactly where an operator would rely on it.

`error` is therefore a real answer and not a failure of the tool: nothing
was relayed, answered or refused, so no decision was taken. Usually the
input is incomplete — a frame whose length field disagrees with its
contents, a request head that was never terminated.

## WHAT IT DOES NOT SIMULATE

Inputs are sent one at a time, and every security event between the write
and the reply is attributed to that input. That is what makes the
attribution exact, and it is the one deliberate difference from real
traffic: a rate limit, a correlation window or an abuse sequence sees a
serial client rather than whatever concurrency the estate has. Policy that
depends on concurrency is not policy this answers.

The sink does not pretend to be a PLC, a mail server or a directory.
Synthesising a plausible reply for thirty protocols would mean inventing
answers, so policy that decides on what the device replied is outside what
this covers.

A client address labels the outcome and reaches the policy only where the
listener parses a PROXY protocol header. A simulation cannot forge a
source address on a loopback connection, and pretending otherwise would
make an address-based allow list look as though it had been tested when it
had not.

## EXIT STATUS

0 when one configuration ran, or when two decided everything the same.
1 when the two configurations differ, or on an error. 2 on a usage
mistake, which includes the missing `-offline`.

## EXAMPLES

What a new WAF profile would change, before it is deployed:

```
xproxy-simulate -offline -a /etc/xproxy/xproxy.yaml -b /tmp/with-waf.yaml \
    -requests corpus/edge.http
```

What tightening a Modbus write window would change on the plant:

```
xproxy-simulate -offline -a /etc/xproxy/xot.yaml -b /tmp/narrower.yaml \
    -frames corpus/line1.hex -listener line1
```

The traffic the proxy actually handled, out of a capture window, under the
configuration that is about to replace the running one:

```
xproxyctl capture start -duration 10m
xproxy-simulate -offline -a /etc/xproxy/xproxy.yaml -b /tmp/new.yaml \
    -pcap /var/lib/xproxy/capture/xproxy-20260930-101500.pcapng -listener edge
```

In a pipeline, where a non-zero exit is the review trigger:

```
xproxy-simulate -offline -a active.yaml -b proposed.yaml -requests corpus/edge.http -json \
  > report.json || echo "the policy decides differently; see report.json"
```

## SEE ALSO

`xproxyctl`(8), `xproxy`(8), `xgate`(8), `xrelay`(8), `xot`(8),
`xproxy-replay`(8), `xproxy.yaml`(5)
