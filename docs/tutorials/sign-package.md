# Sign a package

This tutorial creates a
{ref}`CEP 27 publication statement <cep-27-publication-statement>`
for one existing conda package, signs it with Sigstore, verifies it locally,
and checks an expected signer identity.

## Prerequisites

You need:

- `conda sigstore` from [Install conda-sigstore](../how-to/install.md)
- one `.conda` or `.tar.bz2` package that you are authorized to publish
- an OpenID Connect identity accepted by Sigstore, such as a browser identity
  or GitHub Actions workload identity
- the intended channel URL

Use a test artifact and test channel while learning this workflow. Sigstore's
public, append-only transparency log records the signing identity and signed
statement. The command does not upload the package bytes.

The commands below use `demo-package-1.0-0.conda`. Replace that filename with
your package.

## 1. Create the bundle

Sign the package and write one raw Sigstore bundle:

```console
conda sigstore attest ./demo-package-1.0-0.conda \
  --target-channel https://repo.example.invalid/test \
  --output ./demo-package-1.0-0.conda.sigstore.json
```

Complete the browser identity flow if Sigstore prompts for one. A successful
command prints the output path:

```text
demo-package-1.0-0.conda.sigstore.json
```

The bundle contains the statement in DSSE, Sigstore's standard signed-envelope
format. Its single subject names the exact package filename and records the
package SHA-256.

## 2. Verify the bundle

Verify the package, bundle, and target channel together:

```console
conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test
```

The first output line should end in `verified`. Record the reported certificate
identity and OIDC issuer. Obtain expected values independently from the release
workflow before turning them into a requirement.

## 3. Require the expected signer

Both signer options are exact matches and must be supplied together.

::::{tab-set}
:::{tab-item} Linux and macOS

```console
export EXPECTED_CERTIFICATE_IDENTITY='https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v1.0.0'
export EXPECTED_OIDC_ISSUER='https://token.actions.githubusercontent.com'

conda sigstore verify ./demo-package-1.0-0.conda \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --channel https://repo.example.invalid/test \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER"
```

:::
:::{tab-item} PowerShell

```powershell
$env:EXPECTED_CERTIFICATE_IDENTITY = 'https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v1.0.0'
$env:EXPECTED_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'

conda sigstore verify ./demo-package-1.0-0.conda `
  --bundle ./demo-package-1.0-0.conda.sigstore.json `
  --channel https://repo.example.invalid/test `
  --cert-identity $env:EXPECTED_CERTIFICATE_IDENTITY `
  --cert-oidc-issuer $env:EXPECTED_OIDC_ISSUER
```

:::
::::

This requirement applies only to this command. It does not create a persistent
publisher policy.

## 4. Choose a publishing workflow

The output is one Bundle v0.3 object. Channel tooling assembles and serves the
channel-specific sidecar.

- Follow [Publish attestations to Prefix.dev](../how-to/publish-prefix.md) for
  Prefix Trusted Publishing.
- Use [sigstore-python](../how-to/verify-with-sigstore.md) for an independent
  check of the standard bundle.
- Read [Upstream integration contracts](../reference/upstream-contracts.md) if
  you implement a channel or publisher integration.
