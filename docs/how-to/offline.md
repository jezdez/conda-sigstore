# Verify offline

Sigstore bundles contain the signing certificate and transparency-log evidence,
so cryptographic verification can run without contacting Fulcio or Rekor.
Offline verification still needs the exact artifact, bundle or cached sidecar,
and trusted Sigstore material.

## Prepare while online

Before disconnecting:

1. Retain each package artifact and its SHA-256.
2. Retain repodata containing each sidecar descriptor.
3. Retain each advertised `.sigs` file alongside the package artifact.
4. Provision a trusted Sigstore client configuration through an authenticated
   process if production TUF material will not already be cached.
5. Verify representative artifacts with the same files and trust material that
   will be available offline.

With `trust_config: null`, the verifier uses Sigstore's production trust
configuration. Do not assume it can bootstrap for the first time without
network access. A local `trust_config` is more explicit, but parsing that file
does not prove authenticated distribution, freshness, or rollback protection.

## Understand the sidecar cache

A cached repodata sidecar is addressed and rechecked by SHA-256. It cannot
substitute for retained artifact bytes or new cryptographic verification. An
extracted-only package cache entry remains `record-digest-only`.

`conda sigstore verify --bundle PATH` verifies the supplied file directly. It
does not copy that file into the digest cache. The cache is populated only when
the repodata transport loads a descriptor-selected sidecar. Released conda
versions do not yet preserve that descriptor on package records, so keep local
sidecar files instead of relying on an audit command to warm the cache.

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

Once conda preserves repodata descriptors, automatic offline lookup will be
available only for `repodata` sidecars already stored under the advertised
digest. Prefix `.v0.sigs` sidecars are unpinned Prefix.dev inputs and must be
supplied explicitly.

## Plan trust-root updates

Offline operation trades freshness for availability. Define how operators
receive authenticated Sigstore trust-root updates, verifier updates, and
incident notices. Test both rotation and rollback recovery before relying on
offline verification.
