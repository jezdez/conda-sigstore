# Verify locked environments during installation

`conda-sigstore` composes with `conda-lockfiles` and `conda-workspaces` through
conda's package-verifier hook. Install the plugins in the Python environment of
the conda executable that will run the command. Installing `conda-sigstore` in
one named environment does not enable it for a different conda installation.

Follow [Install conda-sigstore](install.md) for that conda installation.

## Install from a lockfile

Enable verification for one `conda create` invocation. `conda-lockfiles`
converts the selected lockfile records into conda package operations, so no
separate conda-sigstore lockfile integration is required.

::::{tab-set}
:::{tab-item} pixi.lock

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true \
  conda create --name example --file pixi.lock --format rattler-lock-v6
```

:::
:::{tab-item} conda-lock.yml

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true \
  conda create --name example --file conda-lock.yml --format conda-lock-v1
```

:::
::::

Every conda package archive extracted by that command must have one valid,
exact artifact-bound CEP 27 statement. Missing or invalid evidence fails the
installation.

## Install a workspace

Run the locked install from the workspace root:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true \
  conda workspace install --locked
```

`conda-workspaces` uses conda transactions for solved packages and
`conda-lockfiles` models when reading `conda.lock`. Both paths reach the same
pre-extraction verifier. The workspace manifest still defines intent and the
lockfile still defines the selected package set.

## Boundaries

- Keep SHA-256 lockfile entries. Lock hashes select exact bytes, while Sigstore
  verifies signed evidence for those bytes. Neither check authenticates the
  lockfile or establishes that a channel authorized the signer. See
  [Installation verification](../explanation/install-verification.md).
- The supported lockfile formats do not retain the optional repodata
  `attestations` descriptor. Strict locked installs therefore require the
  adjacent `<artifact>.v0.sigs` sidecar when the descriptor is absent.
- Workspace archives do not bundle sidecars or Sigstore trust material. Before
  an offline locked install, run an online strict install to populate the
  adjacent-sidecar cache and provision the required trust material. See
  [Verify offline](offline.md).
- The hook covers conda package archives that the command extracts. External
  pip installs are outside it, local artifacts fail closed, and unchanged
  prefixes are not reverified. Use [Audit an environment](audit-environment.md)
  for an existing prefix.
