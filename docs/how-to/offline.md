# Verify offline

Sigstore bundles contain the signing certificate and transparency-log evidence,
so cryptographic verification can run without contacting Fulcio or Rekor.
Offline verification still needs the exact artifact, bundle or cached sidecar,
and trusted Sigstore material.

## Prepare while online

Before disconnecting:

1. Retain each package artifact and its SHA-256.
2. Retain repodata containing each sidecar descriptor.
3. Fetch each advertised `.sigs` file so the plugin can cache its exact bytes by
   digest.
4. Provision a trusted Sigstore client configuration through an authenticated
   process if production TUF material will not already be cached.
5. Verify representative artifacts with the same files and trust material that
   will be available offline.

With `trust_config: null`, the verifier uses Sigstore's production trust
configuration. Do not assume it can bootstrap for the first time without
network access. A local `trust_config` is more explicit, but parsing that file
does not prove authenticated distribution, freshness, or rollback protection.

## Preserve cached sidecars

A cached repodata sidecar is addressed and rechecked by SHA-256. It cannot
substitute for retained artifact bytes or new cryptographic verification. An
extracted-only package cache entry remains `record-digest-only`.

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

Automatic offline retrieval is available only for `repodata` sidecars whose
descriptor provides the cache digest. Prefix `.v0.sigs` sidecars are unpinned
Prefix.dev inputs and must be supplied explicitly.

## Enforce installation offline

Use the same flat setting:

```console
CONDA_OFFLINE=true \
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true \
conda install PACKAGE
```

Every selected package must have a preserved repodata descriptor, a retained
archive, the exact sidecar bytes in the content-addressed cache, and available
Sigstore trust material. A cache miss, a `MatchSpec`, or an extracted-only cache
entry fails closed. The verifier never makes a network request, substitutes an
evidence source, or falls back to Prefix.dev `.v0.sigs` input.

## Plan trust-root updates

Offline operation trades freshness for availability. Define how operators
receive authenticated Sigstore trust-root updates, verifier updates, and
incident notices. Test both rotation and rollback recovery before relying on
offline verification.
