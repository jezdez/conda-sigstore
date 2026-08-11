# Sign and verify a package

This tutorial signs one existing conda package, verifies it against a local
bundle, and interprets the reported evidence.

## Prerequisites

You need:

- conda 25.5 or newer
- `conda-sigstore` available to the Python runtime that runs conda, as described
  in [Install conda-sigstore](../how-to/install.md)
- a `.conda` or `.tar.bz2` package that you are authorized to publish
- an OIDC identity accepted by Sigstore, such as a browser identity or GitHub
  Actions workload identity

Use a test artifact and test channel for this tutorial.

## 1. Create a publication attestation

Sign the package and write one raw Sigstore bundle:

```console
conda sigstore attest ./demo-package-1.0-0.conda \
  --target-channel https://repo.example.invalid/test \
  --output ./demo-package-1.0-0.conda.sigstore.json
```

Sigstore obtains a short-lived signing certificate from Fulcio using your OIDC
identity and records the signature in Rekor. The output is one Sigstore Bundle
v0.3 JSON object containing a DSSE-signed CEP 27 publication statement. It is a
producer artifact, not the channel sidecar array.

The statement has one subject. Its name is the exact package filename and its
digest is the SHA-256 of the package bytes. The target-channel claim is set from
`--target-channel`.

## 2. Verify the package and bundle

Verify the package, bundle, and target channel together:

```console
conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test
```

Use `--json` when another program consumes the result:

```console
conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test \
  --json
```

A successful result means the artifact digest, Sigstore evidence, CEP 27
statement, and included target-channel claim passed. The output reports the
certificate identity and OIDC issuer that Sigstore authenticated.

It does not establish that the signer was authorized to upload to this channel.
That requires a channel-publisher delegation contract that current conda
standards do not define.

For an explicit one-off signer requirement, obtain the expected certificate SAN
and OIDC issuer independently from the publisher's release configuration:

```console
conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test \
  --cert-identity EXPECTED_CERTIFICATE_IDENTITY \
  --cert-oidc-issuer EXPECTED_OIDC_ISSUER
```

Both values are exact matches and must be supplied together. This requirement
applies only to the current command and does not create publisher policy.

## 3. Inspect the evidence

Human output lists every verified predicate, signer identity, issuer, and
timestamp. JSON output adds artifact and sidecar digests, structured failures,
and any audit-only provenance found in sibling bundles.

An invalid sibling remains visible but does not overturn a valid CEP 27 bundle
for the same artifact.

## 4. Choose a publishing workflow

You now have a complete Bundle v0.3 object. Channel tooling is responsible for
uploading it with the package and serving the channel-specific sidecar format.

- Read [Upstream integration contracts](../reference/upstream-contracts.md) for
  the draft integrity-bound `.sigs` proposal.
- Follow [Publish attestations to Prefix.dev](../how-to/publish-prefix.md) for
  Prefix Trusted Publishing and `.v0.sigs`.
- Use [sigstore-python](../how-to/verify-with-sigstore.md) to inspect the bundle
  with an independent verifier before publication.
