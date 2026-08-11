# Verify with sigstore-python

Use the standard `sigstore` command to check a raw bundle independently of the
conda-specific verifier.

## Install the inspection tools

The owning `conda-sigstore` environment already contains the `sigstore` CLI.
The inspection command also needs `jq`, which you can install with your system
package manager. Confirm that both commands are available:

```console
sigstore --version
jq --version
```

Start with a package and raw Bundle v0.3 object created by
[Sign a package](../tutorials/sign-package.md).

## Inspect the bundle

```console
jq -r '.mediaType, .dsseEnvelope.payloadType' \
  ./demo-package-1.0-0.conda.sigstore.json
```

The expected values are:

```text
application/vnd.dev.sigstore.bundle.v0.3+json
application/vnd.in-toto+json
```

## Supply the expected signer

Obtain the certificate identity and issuer from the publisher's documented
release workflow, not from the bundle being checked.

::::{tab-set}
:::{tab-item} Linux and macOS

```console
export EXPECTED_CERTIFICATE_IDENTITY='https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v1.0.0'
export EXPECTED_OIDC_ISSUER='https://token.actions.githubusercontent.com'

sigstore verify identity \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

:::
:::{tab-item} PowerShell

```powershell
$env:EXPECTED_CERTIFICATE_IDENTITY = 'https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v1.0.0'
$env:EXPECTED_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'

sigstore verify identity `
  --bundle ./demo-package-1.0-0.conda.sigstore.json `
  --cert-identity $env:EXPECTED_CERTIFICATE_IDENTITY `
  --cert-oidc-issuer $env:EXPECTED_OIDC_ISSUER `
  ./demo-package-1.0-0.conda
```

:::
::::

A successful command prints the verified in-toto statement. It checks the
Sigstore material, expected identity, issuer, and subject digest. It does not
enforce CEP 27's exact filename, single-subject, predicate, or target-channel
rules.

Run `conda sigstore verify` as well when those checks are required.

## Repeat the independent check offline

After an online verification initializes Sigstore's production trust material,
add `--offline`:

::::{tab-set}
:::{tab-item} Linux and macOS

```console
sigstore verify identity --offline \
  --bundle ./demo-package-1.0-0.conda.sigstore.json \
  --cert-identity "$EXPECTED_CERTIFICATE_IDENTITY" \
  --cert-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  ./demo-package-1.0-0.conda
```

:::
:::{tab-item} PowerShell

```powershell
sigstore verify identity --offline `
  --bundle ./demo-package-1.0-0.conda.sigstore.json `
  --cert-identity $env:EXPECTED_CERTIFICATE_IDENTITY `
  --cert-oidc-issuer $env:EXPECTED_OIDC_ISSUER `
  ./demo-package-1.0-0.conda
```

:::
::::

Missing local trust material causes the command to fail.
