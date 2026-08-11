# Use standard Sigstore tools with conda packages

This tutorial uses the `sigstore-python` command-line interface installed with
`conda-sigstore`. You will inspect a CEP 27 bundle, verify it with both tools,
repeat verification offline, and compare it with a plain Sigstore blob
signature.

## Prerequisites

You need:

- `conda-sigstore` and `sigstore-python` in the environment that runs conda
- `jq`
- one `.conda` or `.tar.bz2` package
- an interactive or ambient OIDC identity accepted by Sigstore

The examples use `demo-package-1.0-0.conda` and
`https://repo.example.invalid/test`. Replace both values.

## 1. Create a CEP 27 bundle

Use the conda-specific command because it constructs and validates the strict
CEP 27 statement around Sigstore's standard DSSE signing operation:

```console
conda sigstore attest ./demo-package-1.0-0.conda \
  --target-channel https://repo.example.invalid/test \
  --output ./demo-package-1.0-0.conda.sigstore.json
```

The signer first looks for an ambient OIDC credential, such as the workload
identity available in GitHub Actions. When none is available, Sigstore starts
its interactive identity flow.

Inspect the standard bundle media type and DSSE payload type:

```console
jq -r '.mediaType, .dsseEnvelope.payloadType' \
  ./demo-package-1.0-0.conda.sigstore.json
```

The result is a Sigstore Bundle v0.3 carrying an in-toto JSON statement:

```text
application/vnd.dev.sigstore.bundle.v0.3+json
application/vnd.in-toto+json
```

## 2. Verify the conda publication statement

Run the conda-aware verifier and save its machine-readable report:

```console
conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test \
  --json > verification.json
```

Inspect the authenticated signer, issuer, predicate type, and timestamps:

```console
jq '.evidence[] | {identity, issuer, predicate_type, timestamps}' \
  verification.json
```

This command checks Sigstore cryptography and the conda-specific contract. The
statement must name exactly one subject, use the exact package filename and
SHA-256, use the CEP 27 predicate type, and match the supplied channel when it
contains `targetChannel`.

## 3. Verify the same bundle with sigstore-python

The standard Sigstore verifier requires an expected certificate identity and
OIDC issuer. Obtain them independently from the publisher's documented
workflow or your own release configuration. Do not derive an authorization
decision from values inside the bundle being checked.

For a GitHub Actions release, the expected values look like this:

```console
export EXPECTED_CERTIFICATE_IDENTITY='https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v1.0.0'
export EXPECTED_OIDC_ISSUER='https://token.actions.githubusercontent.com'

sigstore verify identity \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

`sigstore verify identity` verifies the bundle, identity, issuer, and that an
in-toto subject matches the package digest. It prints the verified statement.
It does not apply CEP 27's exact filename, single-subject, predicate, or target
channel rules. That semantic validation is the extra work performed by
`conda sigstore verify`.

## 4. Repeat Sigstore verification offline

After one online operation has initialized the production trust material, the
bundle contains the certificate, transparency-log evidence, and timestamps
needed for offline verification:

```console
sigstore verify identity --offline \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

Offline verification still fails closed when the local trust material is
unavailable. It does not silently retrieve data or replace verification with a
cached success result.

## 5. Compare a plain blob signature

Sigstore also signs arbitrary blobs without an in-toto statement:

```console
sigstore sign \
  --bundle ./demo-package-1.0-0.conda.raw.sigstore.json \
  ./demo-package-1.0-0.conda
```

Verify that raw signature with the standard identity verifier:

```console
sigstore verify identity \
  --bundle ./demo-package-1.0-0.conda.raw.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

The raw signature authenticates the blob and signer. It is not a conda publish
attestation because it has no DSSE in-toto statement or CEP 27 predicate. Do
not upload it as package publication evidence.

## What you learned

- Sigstore's bundle, certificate, transparency-log, and identity verification
  remain standard Sigstore behavior.
- CEP 27 adds a strict conda publication statement around those primitives.
- `sigstore verify identity` checks cryptography and an expected identity.
- `conda sigstore verify` additionally checks the conda statement contract and
  reports the signer without deciding whether a channel authorized it.

Continue with [Publish attestations to Prefix.dev](../how-to/publish-prefix.md)
to use these bundles in a channel workflow.
