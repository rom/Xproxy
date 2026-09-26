# xsigner

## NAME

xsigner - hold TLS private keys so the proxies do not have to

## SYNOPSIS

`xsigner` [`-config` *FILE*] [`-validate`] [`-print-keys`] [`-version`]

## DESCRIPTION

`xsigner` listens on a Unix socket and answers signature requests. A proxy
sends a digest and gets a signature back, and the private key never crosses
the socket.

What that buys is custody. A TLS private key in the proxy's memory is
reachable by anything that can read that memory — a core dump, a debugger, a
read primitive in a bug. Moving the key into another process means there is
nothing there to read: an attacker who owns the proxy can ask for signatures
while they own it, which is bounded in time, and that is not the same as
walking away with the key.

It is also where cgo belongs. A PKCS#11 module is a vendor C library and
`xproxy`(8) and its siblings are built with `CGO_ENABLED=0` on purpose, so an
HSM, a TPM or a smartcard is reached from here rather than from the process
that terminates TLS for the estate. This build serves keys it can read as PEM
— from a file, the environment or a vault. The protocol is one JSON object
each way over a Unix socket and is specified in `docs/SIGNER.md`, so a helper
for a device this build cannot reach can be written in whatever language that
device has bindings for.

**The socket's permissions are the authentication.** A digest says nothing
about what it is a digest of, so anything that can connect to the socket can
have anything signed by the keys this helper holds. There is no credential on
the wire and there is deliberately no request that returns a key. The shipped
arrangement is `/run/xsigner` at mode 2750 owned `xsigner:xsigner-clients`
with the socket inside it at 0660 — the proxy daemons are members of that
group, connecting to a Unix socket needs write permission on it, and the
directory is what keeps everything else away. Widen neither.

Every key is resolved and parsed before the socket is bound, so a helper that
could not answer for one of its keys is found out by an operator rather than
by a handshake.

## OPTIONS

| Option | Description |
|--------|-------------|
| `-config` *FILE* | Configuration file. Default `/etc/xsigner/xsigner.yaml`. |
| `-validate` | Load the configuration and every key, report what loaded, and exit. |
| `-print-keys` | Print the public half of each key that loaded, in PEM, with its name and type. This is the answer to the one question the protocol cannot answer from the proxy's side without a certificate in hand: which key is behind this name. |
| `-version` | Print the version and exit. |

## CONFIGURATION

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | path | required | The Unix socket to listen on. Absolute. |
| `socket_mode` | octal string | `0600` | The socket's permission mode. `0600` is the safe default and no proxy can connect to it; the shipped arrangement uses `0660` with the group from a setgid directory. A world-writable mode is refused, because it makes this a signing oracle for anything on the machine. |
| `keys[].name` | name | required | What a request names this key by. One helper may hold several; a name twice is refused. |
| `keys[].key` | reference | required | Where the private key comes from: an absolute path, `file:`, `env:NAME` or `vault:mount/path#field`. PEM, in PKCS#1, SEC 1 or PKCS#8. An encrypted legacy PEM is refused rather than prompted for — a helper started by systemd has nowhere to prompt, and a passphrase in the configuration is not a passphrase. |
| `secrets.vault` | object | none | Where a `vault:` reference resolves from: `address` (https only — there is no insecure escape hatch here, unlike the proxy's own vault client, because this process exists to hold private keys), `mount`, `kv_version`, exactly one of `token_file` or `token_env`, `namespace`, `ca_file`, `server_name`. |

## THE PROXY SIDE

A certificate in `xproxy.yaml`(5) names this helper instead of a key file:

```yaml
certificates:
  - cert_file: /etc/xproxy/certs/pay.example.com.pem
    signer:
      socket: /run/xsigner/signer.sock
      key: pay-p256
      timeout: 2s
      max_conns: 16
```

At start the proxy asks the helper to sign a known value and checks the
signature against the public key in `cert_file`. A helper that cannot prove it
holds the matching key fails the proxy's load, because the alternative is a
listener that comes up and then fails every handshake — which looks to
everyone else like the listener being down. So the helper must be running
before the proxy starts; the shipped unit orders itself `Before=` the three
daemons.

## SIGNALS

`SIGTERM` and `SIGINT` shut down. A signature in flight fails rather than
holding the shutdown open: a handshake waiting on a socket has already lost.

## EXIT STATUS

0 on success, 1 on a configuration or key error, 2 on a usage mistake.

## EXAMPLES

Check the configuration and every key without binding anything:

```
xsigner -config /etc/xsigner/xsigner.yaml -validate
```

Check what loaded against the certificate that will use it:

```
xsigner -config /etc/xsigner/xsigner.yaml -print-keys
openssl x509 -in /etc/xproxy/certs/pay.example.com.pem -noout -pubkey
```

The two public keys must be identical. If they are not, the proxy will refuse
to start and say so, which is the same check from the other side.

## SEE ALSO

`xproxy`(8), `xgate`(8), `xrelay`(8), `xproxy.yaml`(5),
`docs/SIGNER.md`, `docs/HARDENING.md`
