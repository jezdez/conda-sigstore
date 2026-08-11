# Verify and install packages offline

Offline verification needs the package, its bundle or cached sidecar, and
Sigstore trust material. Prepare all three while connected.

## Prepare local files while online

Download the public example and its sidecar:

::::{tab-set}
:::{tab-item} Linux and macOS

```console
curl --fail --location --remote-name \
  https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda
curl --fail --location --remote-name \
  https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs
```

:::
:::{tab-item} PowerShell

```powershell
Invoke-WebRequest `
  -Uri https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda `
  -OutFile signed-package-2.1.0-hb0f4dca_0.conda
Invoke-WebRequest `
  -Uri https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs `
  -OutFile signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs
```

:::
::::

Verify the local files once while online. This also initializes Sigstore's
production trust material for the owning conda runtime.

```console
conda sigstore verify signed-package-2.1.0-hb0f4dca_0.conda \
  --bundle signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs \
  --channel https://prefix.dev/sigstore-example
```

Do not disconnect until the command reports `verified`.

## Repeat the verification offline

Disable network access, then enable conda's offline mode explicitly:

::::{tab-set}
:::{tab-item} Linux and macOS

```console
CONDA_OFFLINE=true conda sigstore verify \
  signed-package-2.1.0-hb0f4dca_0.conda \
  --bundle signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs \
  --channel https://prefix.dev/sigstore-example
```

:::
:::{tab-item} PowerShell

```powershell
$env:CONDA_OFFLINE = 'true'
conda sigstore verify signed-package-2.1.0-hb0f4dca_0.conda `
  --bundle signed-package-2.1.0-hb0f4dca_0.conda.v0.sigs `
  --channel https://prefix.dev/sigstore-example
Remove-Item Env:CONDA_OFFLINE
```

:::
::::

The command should again report `verified`. Because both inputs are local and
conda is offline, the plugin does not fetch a sidecar or update trust material.

## Use operator-managed trust material

Set `trust_config` to a complete Sigstore client trust configuration when your
operator provisions trust material independently:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: /etc/conda/sigstore/client-trust-config.json
```

The file must contain both the trusted root and service configuration expected
by sigstore-python. A standalone trusted-root document is not sufficient.
Parsing the file does not prove that it was distributed authentically or is
current.

## Prepare strict installation separately

Direct `verify --bundle PATH` does not populate the adjacent-sidecar cache.
Warm the package, repodata, trust-material, and adjacent-sidecar caches with an
online strict install:

::::{tab-set}
:::{tab-item} Linux and macOS

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda create \
  --name sigstore-online \
  --yes \
  --override-channels \
  --channel https://prefix.dev/sigstore-example \
  --subdir linux-64 \
  --solver classic \
  --no-deps \
  signed-package=2.1.0=hb0f4dca_0
```

:::
:::{tab-item} PowerShell

```powershell
$env:CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE = 'true'
conda create `
  --name sigstore-online `
  --yes `
  --override-channels `
  --channel https://prefix.dev/sigstore-example `
  --subdir linux-64 `
  --solver classic `
  --no-deps `
  signed-package=2.1.0=hb0f4dca_0
Remove-Item Env:CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE
```

:::
::::

After disconnecting, create a second prefix from the prepared caches:

::::{tab-set}
:::{tab-item} Linux and macOS

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda create \
  --name sigstore-offline \
  --yes \
  --offline \
  --override-channels \
  --channel https://prefix.dev/sigstore-example \
  --subdir linux-64 \
  --solver classic \
  --no-deps \
  signed-package=2.1.0=hb0f4dca_0
```

:::
:::{tab-item} PowerShell

```powershell
$env:CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE = 'true'
conda create `
  --name sigstore-offline `
  --yes `
  --offline `
  --override-channels `
  --channel https://prefix.dev/sigstore-example `
  --subdir linux-64 `
  --solver classic `
  --no-deps `
  signed-package=2.1.0=hb0f4dca_0
Remove-Item Env:CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE
```

:::
::::

The second command must not contact the channel. If any offline verification
reports `offline-cache-miss` or unavailable trust material, reconnect and
repeat the online preparation with the same conda runtime. Do not treat an
earlier successful result as a verification receipt.

Plan authenticated trust-config updates and test both rotation and rollback
recovery before relying on offline verification in production.
