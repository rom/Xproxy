# Releasing

How a version of Xproxy is cut, built, signed and published. The
security checklist in [SECURITY.md](SECURITY.md) is the gate; this is
the procedure around it.

## 1. Freeze

- Every roadmap item for the release is delivered or explicitly moved
  (ROADMAP.md, "Remaining" list) and the ASR table shows the release
  status per requirement.
- CHANGELOG.md has a section for the version with the date; nothing is
  left under "Unreleased".
- `VERSION` holds the version (`1.0.0`); the RPM spec's `%changelog`
  has an entry.
- RELEASE_NOTES_<version>.md exists for a major or minor release.

## 2. Verify

```sh
make check              # fmt, vet, race tests, lint
make cover-gate         # coverage gate
make mutate             # mutation gate (idle machine)
make fuzz FUZZTIME=5m   # every fuzz target
make scale              # 1000 hosts, 10 000 endpoints
make vuln               # govulncheck (needs vuln.go.dev)
./bin/xproxy -config deploy/config/xproxy.yaml -validate
```

`TestConfigReferenceComplete` fails when a configuration key is missing
from CONFIG.md, so the reference cannot fall behind the schema. On a
Fedora host with SELinux enforcing, install the RPMs, run traffic and
confirm `ausearch -m AVC` is empty and `systemd-analyze security
xproxy.service` is in the OK band; record the result in the release
notes.

## 3. Tag

```sh
git tag -s v1.0.0 -m "Xproxy 1.0.0"      # signed tag by the release manager
git push origin v1.0.0
```

A tag is a signed statement by a person; it is never created by
automation. The version in the binaries (`xproxy -version`) comes from
`git describe`, so build from the tagged commit.

## 4. Build

```sh
make release            # dist/: Linux binaries tarball, macOS tarballs (arm64, amd64), source tarball, RPMs when rpmbuild exists, SHA256SUMS, SBOM
make release SIGN_KEY=~/.ssh/release_ed25519   # also SHA256SUMS.sig (ssh-keygen -Y sign)
```

`make release` builds with `CGO_ENABLED=0 -trimpath`, produces
`xproxy-<version>-darwin-arm64.tar.gz` and `-darwin-amd64.tar.gz` (the
three binaries with `deploy/macos`, the example configuration and the
documentation, installed with `deploy/macos/install.sh`),
`xproxy-<version>-linux-amd64.tar.gz` (the three binaries, the deploy
tree, the documentation, the licence), the vendored source tarball from
`make dist`, the RPMs when `rpmbuild` is installed (on Fedora with the
build dependencies from SETUP.md), the software bill of materials from
`go version -m`, and `SHA256SUMS` over everything. With `SIGN_KEY` the
checksum file is signed with an SSH key (`ssh-keygen -Y sign`,
namespace `xproxy-release`); a GPG signature can be added by hand with
`gpg --detach-sign --armor SHA256SUMS`.

Verify a download:

```sh
sha256sum -c SHA256SUMS
ssh-keygen -Y verify -f allowed_signers -I release@sysctl.se -n xproxy-release -s SHA256SUMS.sig < SHA256SUMS
```

where `allowed_signers` holds `release@sysctl.se <public key>`.

## 5. Publish

- Attach the `dist/` contents to the release entry; the release text is
  RELEASE_NOTES_<version>.md.
- Update the package repository with the RPMs and their signatures.
- Open the next "Unreleased" section in CHANGELOG.md and bump `VERSION`
  to the next development version.

## Support policy

The latest minor release receives security fixes; the previous minor for
three months after the next one. Security fixes ship as patch releases
with an entry under "Security" in the changelog and, where a threat model
row changes, an update to THREAT_MODEL.md and SECURITY_REVIEW.md.
