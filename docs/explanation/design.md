# Design

`conda-sigstore` keeps four questions separate:

1. What package bytes are being described?
2. What statement was signed about those bytes?
3. Which identity did Sigstore authenticate?
4. Was that identity authorized to publish to this channel?

The plugin answers the first three. Current conda standards do not provide the
delegation needed to answer the fourth without consumer-authored policy or
undocumented trust in channel admission.

## Signing flow

`conda sigstore attest`:

1. hashes the final package bytes
2. builds an in-toto Statement v1 with the CEP 27 predicate type
3. records the requested target channel
4. obtains an OIDC identity and short-lived Fulcio certificate
5. DSSE signs the statement and records the event in Rekor
6. verifies the completed bundle locally
7. confirms that the package did not change during signing
8. writes one Bundle v0.3 object as `<artifact>.sigstore.json`

Channel tooling assembles one or more complete bundle objects in the JSON array
served as `<artifact>.sigs`. Signing and channel publication remain separate.

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

## Verification flow

Direct verification proceeds in this order:

1. Hash the exact artifact bytes.
2. Read one bounded Bundle v0.3 object or nonempty bundle array.
3. Process every array element independently.
4. Let sigstore-python verify DSSE, certificate trust, transparency-log, and
   timestamp evidence.
5. Extract the authenticated certificate identity and OIDC issuer.
6. Validate the strict CEP 27 statement shape, artifact filename, and digest.
7. If the statement includes `targetChannel` and the caller supplied a channel,
   require them to match.
8. Report every verified predicate, signer, timestamp, and failure.

One valid artifact-bound CEP 27 bundle is sufficient for a verified result.
Malformed or unrelated siblings remain visible but do not create a denial of
service against a valid sibling. A malformed sidecar container still fails.

## Future install verification flow

Install verification is not registered in the current release. The adapter is
retained for the conda package-verifier and record-preservation contracts that
remain upstream work.

For each selected package, the verifier:

1. requires a `PackageRecord` carrying the repodata `attestations` descriptor
2. uses the archive filename and SHA-256 supplied by conda's verifier boundary
3. derives only the advertised `<artifact>.sigs` URL
4. checks the exact advertised sidecar size and SHA-256 before parsing
5. performs normal Sigstore and CEP 27 verification
6. accepts when at least one valid CEP 27 statement binds the exact artifact

Missing evidence and `MatchSpec` inputs will fail closed. The verifier will
never probe for an undeclared `.sigs` file or consume Prefix.dev `.v0.sigs`
sidecars. It authenticates the bundle signer but does not treat that identity as
an authorized publisher.

This flow requires conda to preserve the descriptor and provide an always-run
verifier before extraction. It does not run through a transaction hook and is
independent of `safety_checks`.

## Repodata discovery

The draft repodata mode uses an `attestations` descriptor in repodata to select
the sidecar by exact SHA-256 and byte size. Consumers fetch `<artifact>.sigs`
only when the descriptor exists and validate both fields before JSON parsing.

The repodata-advertised `.sigs` transport is proposed in conda/ceps#142. The
implementation calls this mode `repodata`.

Prefix.dev compatibility mode uses only the `.v0.sigs` naming convention. It
can verify the bundle and artifact binding but cannot bind the selected
sidecar bytes to repodata. It remains explicit and is never an automatic
fallback.

## Cache design

Repodata-advertised sidecar bytes are content-addressed and rehashed on every
read. A future install verifier cannot accept an extracted-only package cache
entry because the archive bytes are unavailable.

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

## Standard publisher delegation is out of scope

Sigstore authenticates identities but intentionally expects a verifier to know
which identity it trusts. CEP 27 leaves trust distribution open. The draft
sidecar proposal distributes bundles but explicitly leaves upload authorization
outside its scope.

No accepted conda standard distributes publisher delegation to consumers.
Prefix.dev's public client does not establish whether server admission binds
the uploader to the certificate identity. An operator can require an exact
certificate identity and issuer for one explicit `verify` invocation, but the
plugin does not persist that requirement or infer it from a channel. Future
publisher authorization needs either a standard channel-admission proof or a
standard channel-independent identity delegation. The install verifier does
not supply that missing delegation.
