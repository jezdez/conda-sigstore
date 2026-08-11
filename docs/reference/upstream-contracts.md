# Upstream integration contracts

This page separates the interfaces used by the current plugin from open
proposals.

## Status summary

| Interface | Status | Required by the plugin |
| --- | --- | --- |
| CEP 27 publication statement | Accepted | yes |
| [conda package-verifier hook](https://github.com/conda/conda/pull/16518) | Draft conda pull request | yes for install enforcement |
| [Repodata `attestations` descriptor](https://github.com/conda/ceps/pull/142) | Open CEP proposal | optional strengthening |
| Prefix.dev adjacent `.v0.sigs` | Current service-specific compatibility | install transport when no descriptor exists |
| [Recipe source attestations](https://github.com/conda/ceps/pull/168) | Open CEP proposal | optional audit input |
| Channel publisher delegation | No conda standard | unavailable |

## Current plugin contract

### Conda package-verifier hook

The plugin registers `conda_package_verifiers` directly against the draft API
in [conda/conda#16518](https://github.com/conda/conda/pull/16518). The locked
developer environments use `jezdez/conda` branch
`feature/package-verifiers`. Released conda versions do not provide this hook.

The hook is disabled unless `plugins.conda_sigstore_enforce` is true. When
enabled, conda invokes the named verifier after validating the package size and
strongest available package digest and before extraction. Every registered
verifier must return successfully for extraction to proceed.

The callback receives:

- the selected `PackageRecord` or an explicit URL `MatchSpec`
- the read-only archive path
- the SHA-256 computed by conda

The callback raises `CondaVerificationError` to reject the archive. Callbacks
may run concurrently for different archives, may run more than once, and must
not mutate the archive.

The plugin requires the archive filename to match the selected record or URL.
It uses the selected package URL and conda-supplied SHA-256 to locate and bind
evidence. It does not depend on conda preserving the optional repodata
descriptor.

When only an extracted cache entry remains, conda must redownload the archive
or fail offline. A package-record digest does not authenticate extracted files.

### Install evidence selection

When enforcement is enabled:

1. a present repodata `attestations` descriptor selects `<artifact>.sigs`
2. without a descriptor, the verifier requires adjacent
   `<artifact>.v0.sigs`
3. any selected descriptor, retrieval, container, cryptographic, statement, or
   binding failure rejects the package
4. a present descriptor never falls back to `.v0.sigs`

One cryptographically valid CEP 27 statement must bind the exact filename and
SHA-256. This is evidence-validity enforcement. It does not establish that the
channel authorized the authenticated signer.

### Prefix.dev compatibility

Prefix.dev `.v0.sigs` is explicit in verification and audit commands. The
install verifier also uses that deterministic adjacent name when no repodata
descriptor exists. Repodata discovery itself never probes for an undeclared
`.sigs` file.

## Open integration proposals

### Repodata descriptor preservation

The proposal in [conda/ceps#142](https://github.com/conda/ceps/pull/142)
defines an optional opaque `attestations` mapping on package records. To remain
usable after a solve, that mapping would need to survive:

- monolithic and sharded repodata
- classic and libmamba solver conversion
- package-cache records
- prefix records and `repodata_record.json`
- repodata patching, JLAP, compression, mirroring, and indexing

The libmamba bridge would need to associate it with the exact artifact URL and
filename because `.conda` and `.tar.bz2` artifacts can otherwise share package
identity fields.

Preservation would let audits and install verification retain the exact
descriptor selected by repodata. It is not required for the current adjacent
install path.

### Channel sidecar publication

`conda sigstore attest` emits one raw Bundle v0.3 object. It does not assemble
a sidecar array, modify repodata, or upload channel files.

An implementation of the draft repodata transport would need to:

- associate one or more complete bundles with an immutable package artifact
- serialize the final nonempty bundle array once
- publish it at `<artifact>.sigs`
- calculate `attestations.sha256` and `attestations.size` from the exact served
  bytes
- place that descriptor in every relevant repodata representation
- publish the sidecar before or atomically with referencing repodata
- prevent sidecar changes under an unchanged descriptor

The exact descriptor and container rules are in
[Standards and formats](standards.md).

### Source-evidence handoff

The proposal in [conda/ceps#168](https://github.com/conda/ceps/pull/168) is a
separate recipe and package-audit integration. `conda-sigstore` reads only its
embedded audit subset. See
[Source-attestation audit format](source-attestations.md).

Source and SLSA evidence do not authorize a CEP 27 publication signer and do
not assign a SLSA level.

Publisher delegation is a separate design problem. See
{ref}`publisher-delegation`.
