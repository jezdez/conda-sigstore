# Standards and formats

`conda-sigstore` separates an accepted statement format from draft channel
transport, source-evidence, and publisher-delegation work.

## Accepted CEP 27 statement

[CEP 27](https://github.com/conda/ceps/blob/main/cep-0027.md) defines a
publication attestation as an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
The strict shape is:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "example-1.0-0.conda",
      "digest": {
        "sha256": "<artifact digest>"
      }
    }
  ],
  "predicateType": "https://schemas.conda.org/attestations-publish-1.schema.json",
  "predicate": {
    "targetChannel": "https://conda.example.org/team"
  }
}
```

The statement has exactly one subject. Its name is the artifact filename and
its digest is the SHA-256 of the exact artifact bytes. `targetChannel` is
optional in CEP 27. When a caller supplies a channel, the plugin checks an
included target-channel claim against it.

CEP 27 is a publication claim. It is not SLSA build provenance and must not be
presented as proof of source, recipe, builder, or build process.

## Sigstore Bundle v0.3

The CEP 27 statement is DSSE signed and stored in a
[Sigstore Bundle v0.3](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto).
The bundle carries the signing certificate and transparency-log verification
material needed for offline verification against a trusted root.

`conda sigstore attest` outputs one bundle object as
`<artifact>.sigstore.json`. A channel publisher wraps one or more complete
bundle objects in the JSON array served as `<artifact>.sigs`. The array permits
more than one signer or countersignature without changing the package artifact.

## Tool responsibilities

| Tool | Standard behavior | Conda-specific limit |
| --- | --- | --- |
| `sigstore sign` | Creates a message signature over a blob | The result is not a CEP 27 publication statement |
| `sigstore verify identity` | Verifies Sigstore material, an expected identity and issuer, and a matching in-toto subject digest | It does not enforce CEP 27's exact filename, single subject, predicate type, or target channel |
| `conda sigstore attest` | Uses sigstore-python to DSSE-sign one strict CEP 27 statement | It creates evidence but does not upload it |
| `conda sigstore verify` | Verifies Sigstore material, artifact binding, the full CEP 27 statement contract, and an optional exact signer requirement | It cannot discover a channel's publisher delegation |
| opt-in conda package verifier | Requires valid CEP 27 evidence from a descriptor-pinned or deterministic adjacent sidecar before extraction | It validates evidence but does not authorize the signer |
| Rattler-Build `--generate-attestation` | Creates one CEP 27 bundle per package and uploads it through Prefix Trusted Publishing | This is a Prefix-specific producer path |
| `actions/attest` | Creates a custom Sigstore-backed in-toto attestation and stores it in GitHub | `subject-path` must resolve to one package for CEP 27 |
| `gh attestation verify` | Retrieves GitHub-hosted evidence and applies GitHub owner and predicate criteria | It is not a replacement for CEP 27 target-channel validation |

See [Verify with sigstore-python](../how-to/verify-with-sigstore.md)
and [Publish attestations to Prefix.dev](../how-to/publish-prefix.md) for complete
workflows.

## Draft served-attestation transport

[conda/ceps#142](https://github.com/conda/ceps/pull/142) proposes how channels
serve attestation sidecars. The plugin calls this mechanism the `repodata`
transport.

For an artifact named `example-1.0-0.conda`:

- the sidecar is `example-1.0-0.conda.sigs`
- the sidecar is a JSON array
- the package's repodata record contains `attestations.sha256` and
  `attestations.size`
- absence of the descriptor means no repodata sidecar is advertised
- clients do not probe for `.sigs`
- clients check exact response size and SHA-256 before JSON parsing

The draft makes the HTTP `Content-Type` advisory and says clients must not
reject solely because of that header. Each array element is instead parsed by
sigstore-python as a Sigstore bundle, including its bundle `mediaType`. A bad
element remains a bundle-local failure and cannot hide a valid CEP 27 sibling.

The descriptor object is:

```json
{
  "attestations": {
    "sha256": "<SHA-256 of exact sidecar bytes>",
    "size": 12345
  }
}
```

Because the proposal is open, the plugin may need an incompatible transport
update before 1.0.

## Prefix.dev `.v0.sigs` transport

The Prefix.dev producer stack in Pixi, Rattler-Build, and `rattler_upload`
publishes `<artifact>.v0.sigs`, also as a JSON array of Bundle v0.3 objects.
Existing Prefix channels do not advertise the sidecar hash and size in
repodata.

Explicit `.v0.sigs` input preserves interoperability while making the weaker
discovery and integrity model visible. Strict install enforcement also requires
this deterministic adjacent input when repodata has no descriptor. A present
descriptor selects `.sigs` and any descriptor or retrieval failure remains
fatal instead of falling back.

The pinned public client paths are documented in
[Publish attestations to Prefix.dev](../how-to/publish-prefix.md). They do not
compare a supplied bundle's signer identity with the Prefix upload identity.
Public information does not establish whether the server performs that
comparison. The plugin reports the signer without claiming Prefix authorized
it.

## Source and build evidence

[conda/ceps#168](https://github.com/conda/ceps/pull/168) proposes recipe source
attestation validation. Rattler-Build has separate experimental source
verification. Both are distinct from CEP 27 publication attestations.

The `audit --sources` view can summarize separate source or SLSA evidence when
present. It does not reinterpret that evidence as CEP 27 and does not let it
authorize a publication signer.

Generic SLSA Provenance v1 does not designate the first
`resolvedDependencies` entry as the source. The plugin reports all materials as
stated without guessing which one represents the source.

Converted PEP 740 or PyPI bundles without canonical Rekor entries are reported
as invalid. The draft source index does not carry authenticated conversion
provenance that can justify disabling Sigstore transparency-log checks, so the
plugin does not apply that exception automatically.
