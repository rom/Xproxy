# The signer protocol

How a process that holds a private key answers a proxy that needs a signature,
and how to write one for a device this project does not support.

`xsigner`(8) is the helper this project ships. It serves keys it can read as
PEM. If your key lives in an HSM, a TPM, a smartcard, a cloud KMS or anything
else, the answer is not a patch to the proxy — it is a helper of your own
speaking what is below, which is deliberately small enough to write in an
afternoon in whatever language your device has bindings for.

## Why there is a protocol at all

A TLS private key in the proxy's memory is reachable by anything that can read
that memory: a core dump, a debugger, a read primitive in a bug, a colleague
with `gdb`. There is no way to keep a key in a process and also keep it from
that process.

So the strongest arrangement available is the one where the proxy never holds
the key. It sends a digest; something else signs it. What an attacker who owns
the proxy can then do is ask for signatures for as long as they own it — which
is bounded in time, is visible in the helper's counters, and is not the same as
walking away with the key and using it for the certificate's remaining life.

There is a second reason, and on this project it is nearly as important. A
PKCS#11 module is a vendor C library. The daemons are built with
`CGO_ENABLED=0` on purpose: no `dlopen`, no vendor library's bugs, no cgo
stack-switching in the process that terminates TLS for the estate. A helper
process is the right home for all three.

## What the protocol is

One JSON object each way over a Unix domain socket, newline framed. The proxy
opens a connection, sends a request, reads an answer, and keeps the connection
for the next one.

**Request** (proxy to helper):

```json
{"v":1,"key":"pay-p256","alg":"ECDSA-SHA256","digest":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}
```

| Field | Type | Meaning |
|-------|------|---------|
| `v` | int | Protocol version. `1`. A helper must refuse anything else rather than guess. |
| `key` | string | Which of the helper's keys to use. One helper may hold several. |
| `alg` | string | The signature scheme, from the table below. |
| `digest` | base64 | The hash to sign — **except for Ed25519**, where it is the message; see below. |
| `salt_len` | int | RSA-PSS only: the salt length in bytes. Absent or ≤ 0 means "equal to the hash length". |

**Answer** (helper to proxy), one or the other:

```json
{"v":1,"sig":"MEUCIQD..."}
{"v":1,"error":"the key is not loaded"}
```

`sig` is the signature in the encoding the scheme uses — ASN.1 DER for ECDSA,
as Go's `crypto/ecdsa` and OpenSSL both produce; the raw 64 bytes for Ed25519;
the modulus-length block for RSA. In other words, exactly what the platform's
own signing call returns: there is no re-encoding step, by design.

### The algorithms

| `alg` | Key | What to sign |
|-------|-----|--------------|
| `ECDSA-SHA256`, `ECDSA-SHA384`, `ECDSA-SHA512` | ECDSA | the digest, as given |
| `RSA-PSS-SHA256`, `RSA-PSS-SHA384`, `RSA-PSS-SHA512` | RSA | the digest, with PSS and `salt_len` |
| `RSA-PKCS1-SHA256`, `RSA-PKCS1-SHA384`, `RSA-PKCS1-SHA512` | RSA | the digest, with PKCS#1 v1.5 |
| `Ed25519` | Ed25519 | **the message**, not a digest |
| `…-SHA1` | RSA, ECDSA | the digest. A TLS 1.2 client can still ask for SHA-1; whether to offer such a client anything is the listener's `min_version` and `cipher_suites`, not the helper's business |

Two of these are where a helper gets written wrongly, so they are worth saying
twice.

**Ed25519 signs a message.** Ed25519 hashes internally, so there is no
pre-hash and the `digest` field carries the whole thing to be signed. A helper
that hashed it first would produce a signature that verifies against nothing.

**RSA-PSS needs the salt length.** PSS is randomised and the verifier has to
know how much salt to expect; a verifier that assumes the wrong length rejects
a perfectly correct signature. That is why it is on the wire rather than
implied. TLS 1.3 requires salt length equal to the hash length, which is what
the absent-or-zero default means.

### What a helper must check

Three things, and each of them turns a failure three layers away into a
failure here:

1. **The key exists.** Refuse a name you do not hold. Do *not* list the names
   you do hold in the error: a caller that can enumerate them learns which
   certificates the machine serves, and it is not needed to fix a typo.
2. **The algorithm suits the key.** `RSA-PSS-SHA256` asked of an ECDSA key is
   a misconfiguration. Signing it anyway with whatever the key does produces a
   signature the verifier rejects, and the operator then goes looking at the
   client, the cipher suites and the certificate before they get here.
3. **The digest is a digest.** Bound its length. A helper is a signing oracle
   for the keys it holds, and the one thing that keeps it from being a general
   purpose one is refusing to sign something the size of a document. The
   shipped helper allows 4 KiB, which is generous for a TLS 1.3
   CertificateVerify transcript and nowhere near a contract.

### What a helper must not do

- **Never return a key.** There is no request for one and there must be no
  extension that adds one. If the key can leave the helper, the helper is a
  file with extra steps.
- **Never log a digest or a signature.** Neither is secret, but a log of every
  handshake's digest is a side channel nobody asked for, and a log line per
  handshake is a write amplification on the busiest path in the estate.
- **Never echo an unbounded field into a log.** A client can send a megabyte
  of `alg`. Clip before logging.
- **Never hang up on a bad request.** Answer with an `error`. Hanging up costs
  the proxy a pooled connection and tells it nothing. (A frame with no newline
  at all is the exception: that is not this protocol, and reading the rest of
  it is the client's decision about your memory.)

## Authentication is the socket's permissions

There is no credential on the wire, and adding one would not help: whatever
the proxy could present, anything that has taken the proxy can present too.

So the boundary is the file system. Anything that can connect to the socket
can have anything signed by the keys the helper holds, because a digest says
nothing about what it is a digest of. That means:

- The socket belongs in a directory nothing else can enter.
- Connecting to a Unix socket needs **write** permission on the socket, so a
  0600 socket is one only its owner can use. The shipped arrangement is a
  setgid directory at 2750 `xsigner:xsigner-clients` with the socket at 0660,
  so the group is the access list and the directory is the wall.
- A world-writable socket is a signing oracle for every key the helper holds.
  `xsigner` refuses that mode outright rather than warning about it; there is
  no deployment where it is right.
- The helper's user must not be the proxy's user. If it is, the proxy can read
  the key files and the whole arrangement is decorative.
- Give the helper no network. `PrivateNetwork=yes` in the shipped unit is the
  strongest single line in it: a bug in a process that cannot send anywhere
  cannot exfiltrate a key. (A helper that fetches keys from a vault needs the
  network, and is correspondingly weaker — prefer key files the helper can
  read and let the *proxy* be the thing that talks to the vault, unless the
  estate's reason for the vault is that the keys must not be in files at all.)

## Proving the key before serving with it

The proxy does not take the helper's word for it. At load it signs a random
value and verifies the signature against the public key in `cert_file`, and it
refuses to start if that fails.

This matters more than it looks. "The socket answers" and "the helper holds
the matching key" are different questions, and the second is the one an
operator gets wrong — one name for two keys, a helper restarted with a stale
configuration, two certificates whose names were swapped. Without the proof
those all come up clean and then fail every handshake, which looks from
outside exactly like the listener being down.

It also means the helper must be running before the proxy starts. The shipped
unit orders itself `Before=xproxy.service xgate.service xrelay.service`; add
`After=xsigner.service` to a drop-in on the proxy's unit if you start them
another way.

To check the two halves by hand from opposite directions:

```
xsigner -config /etc/xsigner/xsigner.yaml -print-keys
openssl x509 -in /etc/xproxy/certs/pay.example.com.pem -noout -pubkey
```

The two public keys must be identical.

## Timing, pooling and failure

One signature is on the handshake path. The proxy bounds it with `timeout`
(default 3s, 100ms to 1m) and holds `max_conns` connections (default 8, 1 to
256). A connection carries one request at a time, so `max_conns` is the
parallel signing capacity; a handshake that finds the pool empty opens a
connection of its own rather than queueing, because a handshake waiting on a
socket pool has already failed.

A helper that stops answering fails handshakes on the certificates it holds.
Handshakes on the listener's other certificates, and every connection already
established, are unaffected — a TLS connection does not revisit its
certificate. This is the trade the arrangement makes: the key is safer and the
availability of new connections now depends on a second process. Run the
helper under a unit with `Restart=on-failure`, and if that trade is not
acceptable for a given certificate, keep that one in a `key_file` and say so
in the configuration where a reader can see it.

## A minimal helper

Enough to be worth reading; not enough to deploy. The shape is the point.

```python
#!/usr/bin/env python3
# A helper is small. This one signs with one ECDSA key from a file; replace
# load() and sign() with your device's calls. What it must not do is in
# docs/SIGNER.md: no key ever leaves, no digest is logged, the algorithm is
# checked against the key, and the digest's length is bounded.
import base64, json, os, socket, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HASHES = {"SHA256": hashes.SHA256, "SHA384": hashes.SHA384, "SHA512": hashes.SHA512}
MAX_DIGEST = 4096

with open(sys.argv[2], "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)

def answer(req):
    if req.get("v") != 1:
        return {"v": 1, "error": "unsupported version"}
    if req.get("key") != "edge":            # the one key this helper holds
        return {"v": 1, "error": "the key is not loaded"}
    alg = req.get("alg", "")
    if not alg.startswith("ECDSA-"):        # check the alg against the key
        return {"v": 1, "error": f"alg {alg} was asked of an ECDSA key"}
    h = HASHES.get(alg[len("ECDSA-"):])
    if h is None:
        return {"v": 1, "error": "unsupported hash"}
    digest = base64.b64decode(req.get("digest", ""), validate=True)
    if not digest or len(digest) > MAX_DIGEST:
        return {"v": 1, "error": "the digest is not a digest"}
    sig = key.sign(digest, ec.ECDSA(Prehashed(h())))
    return {"v": 1, "sig": base64.b64encode(sig).decode()}

path = sys.argv[1]
if os.path.exists(path):
    os.unlink(path)
old = os.umask(0o117)                        # 0660, for the setgid directory
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
os.umask(old)
srv.listen(8)
while True:
    conn, _ = srv.accept()
    with conn, conn.makefile("rwb") as f:    # many requests per connection
        for line in f:
            try:
                resp = answer(json.loads(line))
            except Exception:
                resp = {"v": 1, "error": "the request is not this protocol"}
            f.write((json.dumps(resp) + "\n").encode())
            f.flush()
```

(`Prehashed` comes from `cryptography.hazmat.primitives.asymmetric.utils`; the
import is left out above only to keep the example to one screen.)

## What this does not solve

- **The proxy can still be asked to sign while it is owned.** Custody bounds
  the damage in time; it does not prevent use. Watch
  `xproxy_private_keys{custody="signer"}` alongside the helper's own
  signature count: a count far above the handshake rate is somebody using the
  socket for something else.
- **The helper is a single point of failure for its certificates.** See the
  timing section above; this is a deliberate trade, not an oversight.
- **A digest is opaque.** The helper cannot tell a TLS handshake from a
  software release it is being tricked into signing. Only the socket's
  permissions decide who may ask, which is why so much of this document is
  about file modes.

## See also

`xsigner`(8), the `secrets` and `fips` sections of
[CONFIG.md](CONFIG.md), [HARDENING.md](HARDENING.md) §5a,
`examples/security/key-custody.yaml`.
