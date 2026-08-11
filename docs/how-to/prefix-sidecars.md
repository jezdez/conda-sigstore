# Verify Prefix.dev sidecars

Prefix.dev channels currently expose a sidecar at:

```text
<channel>/<subdir>/<artifact>.v0.sigs
```

The file is a JSON array of Sigstore Bundle v0.3 objects. The bundle layer is
standard, but this channel format does not bind the sidecar's hash and size in
repodata.

The live interoperability check uses Prefix.dev's public
[`prefix-dev/sigstore-example`](https://github.com/prefix-dev/sigstore-example)
repository and fixed example:

```text
https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda
https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs
```

The test pins both response digests, then verifies the CEP 27 statement with
Sigstore's production trust root.

## Verify a Prefix.dev sidecar explicitly

Pass the `.v0.sigs` URL directly instead of enabling a channel-wide fallback:

```console
conda sigstore verify \
  signed-package-2.1.0-hb0f4dca_0.conda \
  --bundle https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs \
  --channel https://prefix.dev/sigstore-example
```

This verifies the package digest, CEP 27 statement, certificate, transparency
log, signer identity, issuer, and included target channel. It does not claim
that the signer was authorized by Prefix.dev. JSON output sets
`prefix_sidecar` to `true` so downstream reports retain the transport
distinction.

## Understand the weaker transport guarantee

The signed statement binds the package bytes, but repodata does not commit to
the selected `.v0.sigs` bytes. An intermediary can remove the sidecar or serve a
different valid sidecar. Direct verification still reports the actual signer
and statement, but it cannot prove which sidecar the channel index selected.

## Do not infer server admission policy

The open-source `rattler_upload` crate used by `rattler-build upload prefix`
and `pixi upload prefix` authenticates an uploader and can submit a bundle. Its
public code does not compare the bundle signer with the upload identity, and
public information does not establish whether Prefix.dev's server makes that
comparison. Treat signer-to-uploader matching as unknown.

## Avoid silent fallback

Do not probe `.v0.sigs` after a missing or invalid repodata-advertised `.sigs`
descriptor. That turns descriptor stripping into a downgrade. Prefix.dev
sidecar discovery must remain an explicit user action.

Follow
[Add draft repodata-advertised sidecars](repodata-sidecars.md) to publish
integrity-bound sidecars.
For the producer workflow, see
[Publish attestations to Prefix.dev](publish-prefix.md).
