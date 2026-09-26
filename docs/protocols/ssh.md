# SSH and SFTP — the way in

`kind: ssh`, served by **xgate**, TCP port **22**.

SSH is the protocol an estate's people use to reach its machines, and it is the
best-designed protocol in this set. It is also the one that grants the most: a
shell on a host is everything that host can do, and the protocol multiplexes
several other things through the same connection that nobody remembers to think
about.

## On the wire

A version exchange in plain text, a key exchange, and then a binary packet
protocol inside which everything else happens.

**Authentication** (RFC 4252) is a small set of methods: `publickey`,
`password`, `keyboard-interactive`, `hostbased`, `none`. OpenSSH adds
**certificates** — a signed public key carrying principals, validity dates and
critical options, which is how an estate with more than a handful of hosts
should be doing this.

**The connection protocol** (RFC 4254) is where the interesting part is. A
connection carries **channels**, and channels come in kinds:

| Channel | What it is |
|---------|-----------|
| `session` | A shell, an `exec` command, or a **subsystem** |
| `direct-tcpip` | **Local forwarding**: `ssh -L`. The client asks the server to open a TCP connection somewhere and pipe it back |
| `forwarded-tcpip` | **Remote forwarding**: `ssh -R`. The server listens and pipes connections to the client |
| `direct-streamlocal`, `forwarded-streamlocal` | The same for Unix sockets |
| `x11` | X11 forwarding |
| `auth-agent` | Agent forwarding — which lets the far end use the client's keys |

And a session channel carries **requests**: `pty-req`, `shell`, `exec`,
`subsystem`, `env`, `x11-req`, `agent-req`, `signal`, `window-change`.

`exec` and `subsystem` are where the two things that look like file transfer
live. **SFTP** is `subsystem sftp`: a separate binary protocol inside the
channel, with its own `OPEN`, `READ`, `WRITE`, `REMOVE`, `RENAME`, `MKDIR`,
`STAT`, `READDIR` and `SETSTAT` requests. And `scp` and `rsync` are just
`exec` of a command — which is why a policy that allows `exec` at all has
allowed file transfer whether it meant to or not.

## What the protocol gives you

Strong cryptography, mutual host authentication if the client checks the host
key, and a good authentication model. Certificates with principals and critical
options are genuinely expressive, and `permitopen`/`permitlisten` in a
certificate restrict forwarding.

What it does not give you is anything below the channel: once a session channel
is open and a shell is running, the protocol has no opinion about what happens.
`authorized_keys` can pin a `command=`, and that is the whole of the
in-protocol command control.

The pieces that surprise people:

- **Agent forwarding** lets whoever controls the far end use the client's private
  keys for as long as the session lasts.
- **Remote forwarding** turns a jump host into an inbound listener.
- **`env`** lets a client set environment variables the server may accept, and
  `LD_PRELOAD` is an environment variable.

## What this listener decides

The gate kinds differ from the relays in one respect: a session here belongs to
a **named person**, is recorded, and can require a second factor. So the policy
is about that person and what their session may become.

**The identity.** `authorized_keys`, `users_file`, `principals`,
`trusted_user_ca_keys` for certificate authorities, `revoked_keys`, and
`max_certificate_lifetime` — because a certificate valid for a year is a
credential nobody can withdraw. `@cert-authority` lines in `upstream_known_hosts`
are honoured, so host certificates work on the far side too.

**A second factor**, with `mfa`, which is the thing SSH itself has no notion of
beyond `keyboard-interactive`, and the reason this is a gate rather than a relay.
Either a one-time code or, with `mfa.push`, an approval on the device the person
already carries -- a keyboard-interactive round with no questions is how the
protocol shows a message, which is where the number to compare goes. The push
factor's bounds are about MFA fatigue rather than about guessing: one request in
flight per user, a bound per window, and a number the user has to recognise.

**Where the key lives**, with `require_hardware_key`: only a FIDO2 key held in a
security token (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`,
or a certificate over one) authenticates. It is the one property of a credential
this gateway can actually check -- every other key it accepts is a file, and a
file has copies. `require_touch`, on by default, keeps the presence assertion and
refuses the two opt-outs that would waive it.

**The channels**, with `allow_channels`. This is the setting that matters most,
and the default is the point: a listener that allows `session` and nothing else
has refused local forwarding, remote forwarding, X11 and agent forwarding in one
line. `forward` and `remote_forward` then name the destinations where forwarding
is wanted, with `max_forwards` bounding them.

**The requests and subsystems**, with `allow_requests` and `allow_subsystems`,
so a listener that exists for SFTP can be `subsystem` and nothing else — no
`shell`, no `exec`, no `pty-req`.

**The environment**, with `allow_env`, because the alternative is trusting the
far end's `AcceptEnv`.

**The commands, parsed structurally.** `allow_commands` and `command_rules` are
matched against a **parsed** command, not against the string: the shell's own
quoting, redirection, pipelines and substitutions are read, so `rm -rf /` cannot
be smuggled as `r""m -rf /` or `$(echo rm) -rf /`. `allow_shell_syntax` decides
whether the constructs that make a command line into a program — pipes,
substitutions, `;` — are permitted at all, and on a restricted listener the
answer is no.

**`allow_file_transfer_commands`** is the explicit line for the `scp`/`rsync`
hole: a listener that allows `exec` but not file transfer commands has closed
it, and one that allows both has said so where a reviewer can see it.

**SFTP as its own policy.** The `sftp` section reads the subsystem's requests:
per-user path templates so each person is confined to their own tree, a file
operation policy (whether a delete, a rename or a `SETSTAT` may happen at all),
extension and size bounds, and YARA or ICAP over what is written — because a
file arriving through SFTP is a file arriving in the estate.

**Recording**, with `recording`: the session captured as asciicast for the
record, with terminal control sequences sanitised in every replay path, because
a replay is eventually rendered in somebody's terminal.

**The session's shape**: `max_auth_tries`, `max_channels`, `max_sessions`,
`max_sessions_per_principal`, `rekey_bytes`, and the handshake, idle and total
timeouts.

## What it does not do

- **It does not sit inside the shell.** Once a shell is running, what the person
  types is recorded, not policed. The command policy applies to `exec` and to
  the shell's own invocation; a shell is by definition a way to run anything.
- **It does not terminate the far end's host key trust for the client.** The
  client validates this listener's host key; the listener validates the far
  host's against `upstream_known_hosts`. Both halves are real, and
  `upstream_insecure_host_key` is the explicit line for a lab.
- **It does not read a forwarded stream.** A permitted forward is a tunnel;
  YARA over it is available, and the destinations are what the policy is about.
- **It does not rewrite SFTP data.** Paths are decided and content is scanned;
  bytes are not modified.
- **It does not implement `hostbased` authentication.** It relies on the client's
  host having a key the server trusts, which makes the trust boundary the client
  host rather than the person.
- **It is not a substitute for the far host's own configuration.** `sshd_config`,
  sudo policy and file permissions still matter.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 4251 | The SSH protocol architecture |
| RFC 4252 | The authentication protocol |
| RFC 4253 | The transport layer protocol: key exchange, the binary packet protocol |
| RFC 4254 | The connection protocol: channels, requests, forwarding |
| RFC 4256 | `keyboard-interactive` authentication |
| RFC 4335, 4344, 4345 | The session channel break, counter mode, Arcfour |
| RFC 8308 | Extension negotiation |
| RFC 8332 | RSA keys with SHA-256 and SHA-512 |
| RFC 8709 | Ed25519 and Ed448 |
| `PROTOCOL.certkeys` (OpenSSH) | The user and host certificate format, principals and critical options |
| draft-ietf-secsh-filexfer-02 | SFTP version 3, which is what deployments use |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].ssh`](../CONFIG.md#serverlistenersssh-kind-ssh)
- A worked configuration: [`examples/bastion/ssh.yaml`](../../examples/bastion/ssh.yaml)
- The other interactive protocols: [telnet](telnet.md), [vnc](vnc.md),
  [rdp](rdp.md)
