# Upstream integration contracts

The plugin signs, verifies, and audits evidence explicitly. It also registers a
direct, opt-in package verifier against the unreleased API in conda/conda#16518.
The verifier enforces evidence validity, not publisher authorization.

## Optional package-record preservation

The draft repodata transport benefits from an optional opaque `attestations`
mapping on `PackageRecord`. When implemented, it must survive:

- monolithic and sharded repodata
- package-cache records
- prefix records and `repodata_record.json`
- classic and libmamba solver conversion

The libmamba bridge should preserve the mapping by exact artifact URL and
filename. Conda package identity alone can collide across `.conda` and
`.tar.bz2` artifacts.

Preservation enables `conda sigstore audit` and the install verifier to use the
exact sidecar descriptor selected by repodata. It is an optional strengthening,
not an install-enforcement prerequisite. Without the field, strict installation
uses the selected package URL to require the deterministic adjacent sidecar.
Unknown fields are currently discarded in several paths.

## Channel sidecars

`conda sigstore attest` emits one raw Bundle v0.3 object. The plugin does not
assemble a sidecar array, modify repodata, or upload channel files. This section
defines the draft integration contract, not a runnable publication workflow.

Channel implementations need to:

- accept one or more complete Sigstore bundles associated with an immutable
  package artifact
- serve a deterministic JSON bundle array at `<artifact>.sigs`
- serialize the final array once, then calculate the descriptor from those
  exact served bytes
- compute `attestations.sha256` and `attestations.size` from the exact served
  bytes
- add the descriptor to every relevant repodata representation and shard
- preserve it through patching, JLAP, compression, mirroring, and indexing
- publish sidecars before or atomically with referencing repodata
- prevent sidecar changes under an unchanged descriptor

The exact descriptor and container formats are defined in
[Standards and formats](standards.md).

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

[conda/conda#16518](https://github.com/conda/conda/pull/16518) provides the
package-verifier boundary used by this plugin. The locked developer environments
use `jezdez/conda` branch `feature/package-verifiers`. Conda validates the
recorded size and strongest available artifact digest before invoking the
registered verifiers. Every verifier must accept before extraction proceeds.

Each callback receives the selected `PackageRecord` or explicit `MatchSpec`,
the archive path, and the computed SHA-256. It rejects the archive by raising a
`CondaError` before extraction. Callbacks run in name order for each archive,
may run concurrently across archives, may be called more than once, and must
treat the archive as read-only. Repodata-specific fields are available only if
the selected record preserves them.

When only an extracted cache entry remains, the verifier must be able to force
an online redownload or fail offline. A package record digest cannot
authenticate extracted contents.

`conda-sigstore` registers this hook directly, without an optional compatibility
declaration or transaction-hook substitute. It yields no verifier unless the
flat `plugins.conda_sigstore_enforce` setting is true. The standard environment
override is `CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true`.

When enabled, missing, unavailable, malformed, invalid, or nonmatching evidence
fails closed. A preserved repodata descriptor selects the integrity-pinned
`.sigs` input. Without one, the verifier requires the deterministic adjacent
`.v0.sigs` input. A present descriptor is authoritative, so descriptor,
retrieval, size, or digest failure never falls back.

This verifier does not need publisher delegation merely to reject evidence that
is missing, malformed, cryptographically invalid, or bound to different
artifact bytes. That is not a claim that the channel authorized the signer.
Rejecting a valid signer as unauthorized needs the separate delegation contract
above.

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
The strict install verifier also requires that deterministic adjacent name when
no repodata descriptor exists. Repodata discovery itself never probes. A
present descriptor must be satisfied and cannot downgrade to the adjacent
transport after an error.

## End-to-end conformance

The following matrix is a prerequisite for stable end-to-end enforcement.
Exercise every applicable case with both package formats, classic and libmamba
solves, monolithic and sharded repodata, authenticated channels and mirrors,
and online and offline cache states.

The conda and channel integration must demonstrate that:

1. valid, exact artifact-bound CEP 27 evidence succeeds
2. artifact substitution fails before extraction
3. descriptor-pinned sidecar substitution fails before parsing
4. an absent descriptor selects required adjacent evidence
5. a missing adjacent sidecar fails closed
6. target-channel replay fails
7. classic and libmamba solver paths cannot bypass verification
8. local-file and unsupported explicit `MatchSpec` inputs fail closed
9. retained archives and `--download-only` cannot bypass verification
10. dry runs and remove-only transactions perform no package verification or
   prefix mutation
11. force reinstalls reverify the incoming archive
12. verification remains mandatory when `safety_checks` and transaction
    rollback are disabled
13. strict failure causes zero unlink or link actions
14. package-controlled code or files are never processed before the decision

An unrelated but cryptographically valid Sigstore identity can satisfy this
validity-only verifier. Authorization conformance requires a future delegation
standard and is not part of this contract.
