# Security model and threat model

The plugin verifies that a Sigstore-authenticated identity signed a strict CEP
27 statement for exact conda package bytes. It reports that identity and the
available evidence. An explicit verification may require an exact identity and
issuer supplied independently by the operator. The plugin does not discover a
channel's publisher delegation. Its optional install verifier enforces valid
repodata-advertised evidence without authorizing the signer.

## Protected assets

- package bytes supplied for verification
- repodata-advertised sidecar bytes
- target-channel claims in CEP 27 statements
- Sigstore trust material
- cached sidecars
- retained package archives inspected for source evidence

## Trust anchors

Cryptographic verification depends on:

- the selected Sigstore production or local trust configuration
- Fulcio certificate validation
- Rekor transparency-log evidence and checkpoints
- signed timestamps present in the bundle
- SHA-256 binding between the CEP 27 subject and package bytes

Repodata can additionally bind exact `.sigs` bytes by SHA-256 and size. That
binding is only as strong as the channel metadata path, including TLS.

A channel server's claim that an uploader was authorized is not currently a
trust anchor. The public `rattler_upload` client does not compare an attached
bundle signer with the uploader identity. Public information does not
establish whether Prefix.dev's server makes that comparison.

## Adversaries and assumptions

The model includes:

- a mirror or network intermediary substituting or removing artifacts,
  sidecars, or repodata
- a channel uploader attaching a bundle signed by another identity
- a holder of an unrelated but cryptographically valid Sigstore identity
- a signer replaying an attestation across channels
- a local attacker modifying caches between reads
- malformed or oversized evidence intended to exhaust client resources
- stale trust material
- a compromised signer workflow

The model does not assume that every Sigstore identity is trusted or that a
valid signature makes package contents safe.

## Threats and mitigations

| Threat | Mitigation | Remaining risk |
| --- | --- | --- |
| Artifact substitution | CEP 27 subject SHA-256 must match exact artifact bytes | SHA-256 or signer compromise |
| Repodata sidecar substitution | Repodata advertises exact size and SHA-256 before parsing | Compromised or unauthenticated repodata |
| Prefix.dev sidecar substitution | Bundle still binds the package digest | No repodata commitment to the selected sidecar |
| Missing future install evidence | The future verifier fails closed without a repodata descriptor | A channel can make packages unavailable by omitting evidence |
| Future install transport downgrade | The future verifier uses only the advertised `.sigs` sidecar | Prefix.dev compatibility remains available only to explicit commands |
| Cross-channel replay | An included `targetChannel` must match the supplied channel | CEP 27 permits an absent target channel |
| Transparency-log omission | Sigstore verification requires supported verification material | Trust-root or verifier compromise |
| Converted PyPI bundle without canonical Rekor entry | Verification fails closed without authenticated conversion provenance | A future standard must define the exception |
| Oversized or malformed input | Bounded reads, descriptor checks, duplicate-key rejection, and strict parsing | Limits must fit the deployment |
| Invalid sibling denial | One valid CEP 27 sibling is sufficient | A malformed container still fails |
| Unrelated valid identity | An explicit verification can require an exact certificate identity and issuer | No channel standard distributes that requirement |
| Time-of-check package replacement during signing | The artifact is rehashed before bundle output is committed | An authorized signer can still sign malicious bytes |
| Embedded source path escape | Bounded reads, path containment, and symlink rejection | Source evidence remains report-only |

## Authorization gap

A cryptographically valid bundle authenticates the certificate identity and
OIDC issuer. It does not authorize that identity for a package or channel.

`conda sigstore verify` can apply an exact identity and issuer supplied for that
invocation. This is an explicit consumer requirement, not a discovered channel
delegation, and it is not stored in `.condarc`.

The plugin rejects two unsafe shortcuts:

- accepting any valid Fulcio identity as a publisher
- asking every consumer to maintain package and identity allowlists in
  `.condarc`

It also does not assume undocumented channel admission behavior. The optional
install verifier requires evidence but accepts any signer whose Sigstore bundle
and exact artifact-bound CEP 27 statement are valid. That is evidence-validity
enforcement, not publisher authorization.

The plugin does not register install enforcement until conda preserves the
repodata attestation descriptor and provides the always-run package-verifier
hook. The future verifier fails closed for missing evidence and inputs
represented only by a `MatchSpec`.

## Offline risk

Offline verification can validate embedded certificate and transparency-log
evidence against available local trust material. It cannot learn about a newly
rotated root, incident, or verifier update without an authenticated update
process.

A local trust configuration is not self-authenticating. Operators must protect
its distribution, freshness, and rollback behavior. Cached sidecars are
rehashed on read and never authorize offline reuse.

## Non-goals

The plugin does not prove:

- that a channel authorized a signer
- that signed package contents are benign or vulnerability-free
- that a recipe or source repository was reviewed
- reproducible or hermetic builds
- a SLSA level
- that a channel compared signer and uploader identities
- protection when local trust roots or the verifier itself are compromised
- repodata transparency

Those properties require separate standards, controls, and evidence.

## Incident response

When a signing identity, workflow, trust root, or channel is compromised:

1. stop relying on affected evidence
2. rotate the affected credentials or trust material
3. identify artifacts and cached sidecars associated with the incident
4. remove or supersede affected channel records and sidecars
5. update the verifier and trust material through an authenticated path
6. re-audit retained artifacts and environments

Report verifier bypasses privately as described in the repository security
policy.
