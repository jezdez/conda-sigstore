# Verify with sigstore-python

Use the standard `sigstore` command to check the same bundle independently of
the conda-specific verifier. Start with a package and raw Bundle v0.3 object
created by [Sign and verify a package](../tutorials/getting-started.md).

## Inspect the bundle

Confirm the standard bundle media type and DSSE payload type:

```console
jq -r '.mediaType, .dsseEnvelope.payloadType' \
  ./demo-package-1.0-0.conda.sigstore.json
```

The expected values are:

```text
application/vnd.dev.sigstore.bundle.v0.3+json
application/vnd.in-toto+json
```

## Supply an independent signer requirement

`sigstore verify identity` requires the expected certificate identity and OIDC
issuer. Obtain both from the publisher's documented workflow or your own
release configuration. Do not copy them from the bundle being checked.

For a public GitHub Actions release, the values have this form:

```console
export EXPECTED_CERTIFICATE_IDENTITY='https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v1.0.0'
export EXPECTED_OIDC_ISSUER='https://token.actions.githubusercontent.com'
```

## Verify the package

Pass the bundle, expected signer, and exact package artifact:

```console
sigstore verify identity \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

The command verifies the Sigstore material, identity, issuer, and an in-toto
subject digest matching the package. It prints the verified statement. It does
not enforce CEP 27's exact filename, single subject, predicate type, or target
channel rules.

Run the conda-specific verifier when those checks are required:

```console
conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER"
```

## Repeat verification offline

After an online operation has initialized the production trust material, use
Sigstore's offline mode:

```console
sigstore verify identity --offline \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

Offline verification still fails when the local trust material is unavailable.
It does not silently retrieve data or replace verification with a cached
success result.

Continue with [Publish attestations to Prefix.dev](publish-prefix.md) to upload
a CEP 27 bundle through current Prefix.dev tooling.
