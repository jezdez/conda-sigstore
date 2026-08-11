# Design

`conda-sigstore` keeps four questions separate:

1. What package bytes are being described?
2. What statement was signed about those bytes?
3. Which identity did Sigstore authenticate?
4. Was that identity authorized to publish to this channel?

The plugin answers the first three. Current conda standards do not provide the
delegation needed to answer the fourth without consumer-authored policy or
undocumented trust in channel admission.

## Signing boundary

Signing binds the final package bytes and requested target channel in a CEP 27
statement, then uses Sigstore to authenticate the signer and record the event.
The package is hashed again before output is committed so a package changed
during the interactive signing flow cannot produce successful evidence.

The result is one portable Sigstore bundle. Channel tooling remains responsible
for publishing the package and assembling any channel sidecar. This separation
lets other CEP 27 producers and consumers interoperate without sharing an
upload implementation. See [Commands](../reference/commands.md) and
[Standards and formats](../reference/standards.md) for the exact contracts.

The upload credential and signing identity are separate. A publishing tool may
acquire one OIDC token for a channel and another for Sigstore. Neither token is
reused or logged by this plugin.

## Cryptographic implementation

The plugin delegates Bundle v0.3 parsing, DSSE signing and verification,
Fulcio, Rekor, certificate-transparency checks, RFC 3161 timestamps, and TUF
trust material to official `sigstore-python` 4.x APIs. It implements no custom
cryptography and no second Sigstore network stack.

Pixi and Rattler-Build use the `rattler_upload` crate for Prefix.dev publishing.
The shared boundary is the standard Sigstore bundle and CEP 27 statement, so
the Python plugin does not embed `sigstore-rs` or duplicate the Rust upload
client.

## Verification boundary

Verification has three layers: the sidecar must be acquired without ambiguity,
Sigstore must authenticate its cryptographic material, and a strict CEP 27
statement must bind the result to the package bytes and requested channel.
Keeping those layers separate makes failures attributable and keeps transport
metadata out of the signed statement.

Sidecar entries are independent because a channel can publish evidence from
more than one signer. An invalid or unrelated sibling remains visible without
overturning a valid artifact-bound statement. The container itself must still
be well formed so a verifier never has to guess which bytes constitute an
entry.

## Installation boundary

The package-verifier hook places the check after download but before extraction.
That is the last point where conda has the selected URL, the expected digest,
and the final archive while it can still reject the package before modifying a
prefix. The selected URL and SHA-256 are also sufficient for adjacent discovery,
so this path does not depend on conda preserving a new repodata field.

The hook is an integration preview against conda/conda#16518 and remains
disabled by default. See
[Installation verification across package managers](install-verification.md)
and [Upstream integration contracts](../reference/upstream-contracts.md).

## Transport choices

The draft repodata transport lets channel metadata commit to the exact sidecar
bytes. That commitment makes sidecar discovery explicit and protects the
container before it is parsed.

Prefix.dev already publishes deterministic adjacent sidecars without that
repodata commitment. Supporting the existing convention provides useful
interoperability and install enforcement without waiting for channel metadata
changes, but the weaker discovery property must remain visible.

When a descriptor is present, it stays authoritative. Falling back after an
advertised sidecar fails would let an attacker replace stronger metadata-bound
evidence with an unpinned adjacent file. Exact filenames and discovery rules
belong in [Standards and formats](../reference/standards.md).

## Cache design

The cache stores evidence bytes and enough artifact context to rediscover them.
It does not store a verification verdict. Every read rehashes and
cryptographically reverifies the evidence because trust material and verifier
behavior can change. Auditing also needs the original archive bytes, which an
extracted-only package cache entry cannot provide.

## Separate evidence classes

Publication, build, and source claims answer different questions:

| Evidence | Question answered |
| --- | --- |
| CEP 27 publication | Which identity signed this exact artifact, and for which target channel? |
| SLSA provenance | Which builder reports producing the artifact from which inputs? |
| Recipe source attestation | Which identities signed the source evidence required by the recipe? |

`audit --sources` reports source evidence from retained package archives. It
does not assign a SLSA level, prove benign source contents, or turn source
evidence into package publisher authorization.

(publisher-delegation)=
## Publisher delegation belongs in a standard

A consumer-authored allowlist cannot establish what a channel delegated. Future
publisher authorization therefore needs either a standard channel-admission
proof or a standard channel-independent identity delegation. Keeping that work
out of local plugin configuration avoids turning every consumer into a policy
authority with different answers for the same channel.

Such a standard would need to define which admitted bundle represents the
publisher, how that signer maps to an uploader identity, and how delegation,
rotation, revocation, history, and mirrors behave. It would also need to admit
review or provenance bundles without accidentally granting publication
authority. The repodata sidecar proposal deliberately leaves those questions
out of scope.
