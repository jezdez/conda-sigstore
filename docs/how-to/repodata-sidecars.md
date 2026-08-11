# Add draft repodata-advertised sidecars to a channel

This guide shows how a channel could add the repodata-advertised `.sigs`
transport proposed in conda/ceps#142 alongside Prefix.dev's current
`.v0.sigs` files. The proposal is still a draft, not a migration target that
supersedes Prefix.dev's format.

## 1. Inventory current evidence

For every package record, capture:

- the artifact filename and SHA-256
- whether `<artifact>.v0.sigs` exists
- whether each bundle contains a strict CEP 27 statement for that artifact
- the certificate identity and issuer
- whether the statement contains the intended target channel

Do not rename a `.v0.sigs` sidecar without validating every bundle. A valid
Sigstore bundle can still contain the wrong predicate, subject, digest, or
target channel.

## 2. Produce `.sigs` sidecars

For each artifact, either validate and reuse conforming Bundle v0.3 objects or
create a new publication attestation:

```console
conda sigstore attest PACKAGE \
  --target-channel CHANNEL \
  --output PACKAGE.sigstore.json
```

The command produces one raw Bundle v0.3 object. Channel tooling must wrap one
or more complete bundle objects in a JSON array and serialize that array once
as `PACKAGE.sigs`. Compute its SHA-256 and byte length from the exact bytes the
channel serves.

## 3. Add repodata descriptors

Add this object to the corresponding package record:

```json
{
  "attestations": {
    "sha256": "<lowercase hex SHA-256 of the exact .sigs bytes>",
    "size": 12345
  }
}
```

The descriptor selects `<artifact>.sigs` without probing and binds the response
before JSON and Sigstore processing.

Update every repodata representation clients can select, including compressed,
patched, and sharded forms. Publish sidecars before or atomically with the
repodata that references them.

## 4. Validate the published evidence

Fetch the published artifact and sidecar, then verify them directly:

```console
conda sigstore verify PACKAGE \
  --bundle PACKAGE.sigs \
  --channel CHANNEL
```

Check the reported artifact digest, signer identity, issuer, predicate,
timestamps, and target channel. This confirms the evidence but does not prove
that the signer was authorized by the channel.

## 5. Keep transport choice explicit

If a channel serves both forms:

1. keep generating `.v0.sigs` files while Prefix.dev requires them
2. retrieve `.v0.sigs` only when Prefix.dev discovery is explicitly selected
3. monitor descriptor, digest, size, and bundle failures
4. do not announce either transport as superseded until its provider does

Do not probe `.v0.sigs` after a missing or invalid repodata descriptor. That
would turn descriptor stripping into a downgrade to an unpinned transport.
