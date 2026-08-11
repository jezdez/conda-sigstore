# Installation verification across package managers

Package hashes and Sigstore attestations answer different questions. A hash
checks that downloaded bytes match a previously selected digest. A Sigstore
attestation checks that an authenticated identity signed a statement about
those bytes. Neither check alone establishes that the identity was authorized
to publish a package.

## Current client behavior

| Client | Artifact check during installation | Sigstore attestation check during installation |
| --- | --- | --- |
| pip | Checks an index-advertised download hash for corruption. `--require-hashes` requires locally supplied hashes for all resolved requirements. | None. PyPI documents a separate `pypi-attestations verify pypi` command for consumer verification. |
| uv | Records selected index hashes in `uv.lock` and verifies hashes supplied in requirements files. `--require-hashes` requires complete hash coverage. | None. `uv publish` discovers and uploads adjacent PEP 740 attestations, but does not generate them or verify them during installation. |
| Pixi | Verifies conda and PyPI package checksums recorded in `pixi.lock` when an artifact is installed or reused from cache. | None. Pixi creates or uploads Sigstore attestations for Prefix.dev publishing and documents external consumer verification with `gh` or `cosign`. |
| conda with conda-sigstore | Conda retains its package digest checks. | No install-time attestation check is registered. A future package verifier requires upstream conda support. |

The relevant primary documentation is:

- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [PyPI consuming attestations](https://docs.pypi.org/attestations/consuming-attestations/)
- [uv package publishing](https://docs.astral.sh/uv/guides/package/#uploading-attestations-with-your-package)
- [uv package-index hashes](https://docs.astral.sh/uv/concepts/indexes/#requiring-a-hash-algorithm)
- [Pixi supply-chain security](https://github.com/prefix-dev/pixi/blob/b91a274c9db6d8ca3586bc763f04354e927d971d/docs/security.md)
- [Pixi Prefix.dev upload options](https://github.com/prefix-dev/pixi/blob/b91a274c9db6d8ca3586bc763f04354e927d971d/docs/reference/cli/pixi/upload/prefix.md)

PyPI is the repository in this comparison, not pip. PyPI validates supported
attestations at upload, associates publish attestations with Trusted Publisher
identities, and exposes provenance through its Integrity API. That gives a
consumer enough repository context to perform an authorization check. pip does
not consume that evidence during an ordinary install.

uv's attestation support is also on the producer side. Its publisher passes
adjacent PEP 740 JSON objects to a supporting index. Its
[current upload implementation](https://github.com/astral-sh/uv/blob/a50af60fb4162d7f94812d64c481c30a0200b6d8/crates/uv-publish/src/lib.rs)
notes that it does not validate the interior attestation structure beyond JSON
before upload. This is transport behavior, not consumer verification.

Pixi checks locked artifact digests during installation. Its Sigstore path is
separate and producer-oriented. `pixi publish --generate-attestation` and
`pixi upload prefix --generate-attestation` create and upload evidence for
Prefix.dev. The Pixi security guide directs consumers to external Sigstore
tools instead of claiming that `pixi install` verifies those attestations.

The closest existing consumer pattern is PyPI's separate
`pypi-attestations verify pypi --repository ...` command. The repository is an
independent trust input. `conda sigstore verify` offers the corresponding
low-level choice through paired `--cert-identity` and
`--cert-oidc-issuer` options. They apply to one command and do not create
channel policy.

## What a future install verifier must check

An installation decision has two independent parts:

1. Evidence validity asks whether a bundle is cryptographically valid and
   binds a strict CEP 27 statement to the exact package filename, SHA-256, and
   supplied target channel.
2. Publisher authorization asks whether that authenticated signer was allowed
   to publish this package to this channel and what the absence of evidence
   means.

`conda-sigstore` implements the first part for explicit verification. It does
not invent the second part. CEP 27 defines the signed publication statement,
but no accepted conda standard currently distributes channel publisher
delegation to clients.

The future verifier uses only a repodata `attestations` descriptor preserved on
the selected `PackageRecord`. It fetches `<artifact>.sigs`, validates the
advertised size and SHA-256 before parsing, verifies the Sigstore material, and
requires at least one strict CEP 27 statement for the exact artifact filename
and SHA-256. An included target-channel claim must match the selected channel.

Missing, unavailable, malformed, invalid, or nonmatching evidence will fail
closed. A `MatchSpec` will also fail because it does not carry a repodata
descriptor. That includes local files and explicit URLs which cannot prove
which channel metadata selected their evidence. The verifier will never probe
for a sidecar or use Prefix.dev `.v0.sigs` compatibility input.

This behavior requires two conda changes that are not available in current
released conda versions:

- preserve the opaque repodata `attestations` mapping on `PackageRecord` through
  solver, cache, and prefix record paths
- provide an always-run package verifier after artifact digest validation and
  before extraction, independent of `safety_checks`

Once both contracts ship, the hook must prevent the rejected archive from being
extracted and fail before prefix unlink or link actions. Other package archives
can already have completed cache extraction because those operations run
concurrently.

Rejecting a cryptographically valid signer as unauthorized still requires a
standardized channel delegation that identifies authorized publishers.

The exact upstream contract is listed in
[Upstream integration contracts](../reference/upstream-contracts.md).
