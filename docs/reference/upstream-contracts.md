# Upstream integration contracts

The plugin signs, verifies, and audits evidence explicitly. Its disabled-by-
default install verifier depends on coordinated conda, solver, and channel
work. The verifier enforces evidence validity, not publisher authorization.

## Package-record preservation

Conda needs an optional opaque `attestations` mapping on `PackageRecord`. It
must survive:

- monolithic and sharded repodata
- package-cache records
- prefix records and `repodata_record.json`
- classic and libmamba solver conversion

The libmamba bridge should preserve the mapping by exact artifact URL and
filename. Conda package identity alone can collide across `.conda` and
`.tar.bz2` artifacts.

Preservation enables `conda sigstore audit` and the install verifier to discover
the exact sidecar descriptor selected by repodata. Unknown fields are currently
discarded in several paths.

## Channel sidecars

Channel implementations need to:

- accept one or more complete Sigstore bundles associated with an immutable
  package artifact
- serve a deterministic JSON bundle array at `<artifact>.sigs`
- compute `attestations.sha256` and `attestations.size` from the exact served
  bytes
- add the descriptor to every relevant repodata representation and shard
- preserve it through patching, JLAP, compression, mirroring, and indexing
- publish sidecars before or atomically with referencing repodata
- prevent sidecar changes under an unchanged descriptor

Server-side cryptographic validation is repository hygiene. It is not itself a
portable proof that the signer was authorized to publish.

## Publisher delegation

Future channel-authoritative enforcement needs a standard answer to these
questions:

- Which admitted bundle represents the authorized package publisher?
- Was the signer matched to a trusted-publisher or uploader identity?
- Can a channel admit third-party review or provenance bundles without making
  them publication authorization?
- How are delegation, rotation, revocation, and historical records represented?
- Which evidence is mirrored and how is its meaning preserved?

The draft in conda/ceps#142 deliberately leaves upload authorization outside
its scope. A bare array of valid bundles cannot answer these questions.

Prefix.dev's public client separates uploader authentication from Sigstore
signing. Public information does not establish whether its proprietary server
requires the bundle signer to match the uploader. The plugin does not infer
that behavior.

## Conda package-verifier hook

Install-time validation of repodata-advertised evidence needs an always-run
conda verifier boundary that:

1. runs after the final artifact and repodata record are available
2. runs before extraction, script execution, unlinking, or linking
3. covers classic and libmamba solves, explicit URLs, local files, cache hits,
   restored transactions, and `--download-only`
4. receives the artifact path, immutable digest, source channel, subdirectory,
   filename, and repodata descriptor
5. can abort without prefix side effects
6. remains independent of `safety_checks`
7. binds the verified artifact through extraction to prevent replacement

When only an extracted cache entry remains, the verifier must be able to force
an online redownload or fail offline. A package record digest cannot
authenticate extracted contents.

`conda-sigstore` requires this boundary and does not substitute a transaction
hook. With `conda_sigstore_enforce` disabled, it performs no Sigstore work
during ordinary installation.

This verifier does not need publisher delegation merely to reject advertised
evidence that is malformed, cryptographically invalid, or bound to different
artifact bytes. Enabling `conda_sigstore_enforce` also makes a missing descriptor
a failure. That is an explicit consumer requirement for evidence coverage, not
a claim that the channel authorized the signer. Rejecting a valid signer as
unauthorized needs the separate delegation contract above.

## Publisher tooling

Pixi and Rattler-Build use `rattler_upload` to create CEP 27 bundles during
Prefix uploads. A standard producer contract should:

- sign the final immutable artifact bytes
- emit one Bundle v0.3 object
- include exactly one CEP 27 subject
- set the intended target channel when known
- expose the certificate identity and issuer without exposing tokens
- keep channel-upload OIDC and Sigstore-signing OIDC exchanges separate

Channel tooling, not the signer, assembles one or more bundle objects into the
array served at `<artifact>.sigs`.

## Source-evidence handoff

Recipe source attestations and SLSA provenance need typed, independently
verified evidence. Builders should preserve predicate type, subject digest,
builder identity, source repository and revision, and verification results.

The draft in [conda/ceps#168](https://github.com/conda/ceps/pull/168) is a
separate audit integration. It does not authorize a CEP 27 publisher and does
not assign a SLSA level.

## Compatibility contract

Prefix `.v0.sigs` input remains explicit to verification and audit commands.
The install verifier never probes for or consumes it. Repodata discovery must
never probe a Prefix-specific name after a descriptor is missing, unavailable,
or invalid. This keeps the downgrade boundary visible.

## End-to-end conformance

The conda and channel integration should demonstrate that:

1. valid, exact artifact-bound CEP 27 evidence succeeds
2. artifact substitution fails before extraction
3. sidecar substitution fails before parsing
4. a missing descriptor fails without sidecar probing
5. target-channel replay fails
6. classic and libmamba solver paths cannot bypass verification
7. local-file and explicit `MatchSpec` inputs fail closed
8. retained archives and `--download-only` cannot bypass verification
9. strict failure causes zero unlink or link actions
10. package-controlled code or files are never processed before the decision

An unrelated but cryptographically valid Sigstore identity can satisfy this
validity-only verifier. Authorization conformance requires a future delegation
standard and is not part of this contract.
