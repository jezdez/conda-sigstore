# Verify a public package

This tutorial verifies a real package from a public Prefix.dev channel. It does
not require a channel account, signing identity, or package build.

## Prerequisites

You need:

- `conda sigstore` from the [source preview](../how-to/install.md), or a future
  supported installation
- `curl`, or PowerShell's `Invoke-WebRequest`

## 1. Download the package and its evidence

Create a working directory and download the fixed public example.

::::{tab-set}
:::{tab-item} Linux and macOS

```console
mkdir conda-sigstore-tutorial
cd conda-sigstore-tutorial
curl --fail --location --remote-name \
  https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda
curl --fail --location --remote-name \
  https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs
```

:::
:::{tab-item} PowerShell

```powershell
New-Item -ItemType Directory -Path conda-sigstore-tutorial
Set-Location conda-sigstore-tutorial
Invoke-WebRequest `
  -Uri https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda `
  -OutFile signed-package-2.1.0-hb0f4dca_0.conda
Invoke-WebRequest `
  -Uri https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs `
  -OutFile signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs
```

:::
::::

The `.conda` file is the package. The `.v0.sigs` file is a JSON array of
Sigstore bundles served next to it by Prefix.dev.

## 2. Verify the package

Verify both local files and supply the channel claimed by the publication
statement:

```console
conda sigstore verify signed-package-2.1.0-hb0f4dca_0.conda \
  --bundle signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs \
  --channel https://prefix.dev/sigstore-example
```

The first line should end in `verified`. The evidence includes these values:

```text
Predicate      https://schemas.conda.org/attestations-publish-1.schema.json
Identity       https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main
Issuer         https://token.actions.githubusercontent.com
Target channel https://prefix.dev/sigstore-example
```

Here, the predicate names the kind of signed claim. The issuer is the service
that issued the signer's OpenID Connect credential. The command exits with
status 0 because at least one valid
{ref}`CEP 27 publication statement <cep-27-publication-statement>`
binds the exact filename and SHA-256 to the supplied channel.

## 3. Inspect machine-readable output

Run the same verification with JSON output:

```console
conda sigstore verify signed-package-2.1.0-hb0f4dca_0.conda \
  --bundle signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs \
  --channel https://prefix.dev/sigstore-example \
  --json
```

The top-level `status` is `verified`. The `evidence` array contains the signer,
issuer, predicate type, timestamp, and target channel. Read
[JSON output and exit status](../reference/json-output.md) before consuming the
result from another program.

## What you verified

Sigstore authenticated the reported workflow identity. The CEP 27 statement
bound that signature to the downloaded package and claimed channel. The result
does not establish that Prefix.dev authorized that workflow to publish the
package and does not assess whether the package is safe to run.

Next, [sign a package](sign-package.md),
[verify during installation](../how-to/configure-verification.md), or
[audit an installed environment](../how-to/audit-environment.md).
