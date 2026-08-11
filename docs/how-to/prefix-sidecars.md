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

The scheduled test enables strict verification, creates an environment from the
fixed package, then audits it and checks the exact artifact digest, sidecar
digest, signer, issuer, predicate, and transport label.

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

## Require evidence during installation

Enable strict installation verification for one command:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda create \
  -n verified \
  --override-channels \
  -c https://prefix.dev/sigstore-example \
  signed-package=2.1.0=hb0f4dca_0
```

When the selected package record has no repodata attestation descriptor, the
verifier requires `<artifact>.v0.sigs`. A missing, unavailable, malformed,
invalid, or nonmatching sidecar blocks extraction. When a descriptor is
present, its `.sigs` sidecar is authoritative and any error fails without
falling back.

## Understand the weaker transport guarantee

The signed statement binds the package bytes, but repodata does not commit to
the selected `.v0.sigs` bytes. An intermediary can remove the sidecar or serve a
different valid sidecar. Direct verification still reports the actual signer
and statement, but it cannot prove which sidecar the channel index selected.

## Do not infer server admission policy

The pinned public client paths are documented in
[Publish attestations to Prefix.dev](publish-prefix.md). They do not compare the
bundle signer with the upload identity. Public information does not establish
whether Prefix.dev's server makes that comparison. Treat signer-to-uploader
matching as unknown.

## Keep descriptor failures fatal

An absent descriptor and a broken descriptor are different states. Strict mode
uses the deterministic adjacent sidecar only when the descriptor is absent. It
never probes `.v0.sigs` after an advertised `.sigs` sidecar fails retrieval,
size, digest, parsing, or verification checks.

Read [Standards and formats](../reference/standards.md) for the draft
integrity-bound `.sigs` format and
[Upstream integration contracts](../reference/upstream-contracts.md) for the
channel requirements.
For the producer workflow, see
[Publish attestations to Prefix.dev](publish-prefix.md).
