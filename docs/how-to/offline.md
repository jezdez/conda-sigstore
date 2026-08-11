# Verify offline

Sigstore bundles contain the signing certificate and transparency-log evidence,
so cryptographic verification can run without contacting Fulcio or Rekor.
Offline verification still needs the exact artifact, bundle or cached sidecar,
and trusted Sigstore material.

## Prepare while online

Before disconnecting:

1. Retain each package artifact and its SHA-256.
2. Run strict verification online once so an adjacent sidecar can be cached, or
   retain repodata and each descriptor-advertised `.sigs` file.
3. Provision a trusted Sigstore client configuration through an authenticated
   process if production TUF material will not already be cached.
4. Verify representative artifacts with the same files and trust material that
   will be available offline.

With `trust_config: null`, the verifier uses Sigstore's production trust
configuration. Do not assume it can bootstrap for the first time without
network access. A local `trust_config` is more explicit, but parsing that file
does not prove authenticated distribution, freshness, or rollback protection.

## Understand the sidecar cache

A cached repodata sidecar is addressed and rechecked by SHA-256. A successfully
verified adjacent sidecar is stored by content digest and referenced by the
artifact SHA-256, credential-free channel, and filename. Both are
cryptographically reverified when reused. Neither cache path substitutes for
retained artifact bytes or a current verification decision. An extracted-only
package cache entry remains `record-digest-only`.
Online adjacent verification fetches the current sidecar instead of preferring
the offline cache.

`conda sigstore verify --bundle PATH` verifies the supplied file directly. It
does not copy that file into the digest cache. Descriptor-selected sidecars are
cached after their advertised digest is checked. Adjacent sidecars receive an
artifact reference only after successful Sigstore and CEP 27 verification.

## Verify local inputs

Pass a local bundle or sidecar path:

```console
conda sigstore verify /mirror/linux-64/example-1.0-0.conda \
  --bundle /mirror/linux-64/example-1.0-0.conda.sigs \
  --channel https://conda.example.org/engineering
```

Audit an installed environment with the same local trust configuration:

```console
conda sigstore audit -p /srv/conda/envs/runtime --json
```

`--sources` inspects separate build or source evidence when retained package
archives contain it. That evidence does not authorize the package publisher.

Strict installation can reuse a cached adjacent `.v0.sigs` sidecar offline by
artifact SHA-256, channel, and filename. Missing cache data still fails closed
and offline mode never attempts a network request.

## Plan trust-root updates

Offline operation trades freshness for availability. Define how operators
receive authenticated Sigstore trust-root updates, verifier updates, and
incident notices. Test both rotation and rollback recovery before relying on
offline verification.
