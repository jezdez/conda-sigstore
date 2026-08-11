# Install conda-sigstore

The plugin must run in conda's base Python environment. Installing it in a
separate named environment does not register `conda sigstore` with the `conda`
executable from base.

:::{warning}
This preview requires the unreleased package-verifier API from
[conda/conda#16518](https://github.com/conda/conda/pull/16518). No released
conda version provides it yet.
:::

## Install a release

Install pip and the plugin into conda's base environment:

```console
conda install -n base pip
conda run -n base python -m pip install conda-sigstore
conda sigstore --help
```

If `conda-pypi` is already installed with conda, use its target-environment
option before the install subcommand:

```console
conda pypi -n base install conda-sigstore
conda sigstore --help
```

## Check plugin discovery

Ask conda to load the installed plugin:

```console
conda sigstore --help
```

The help output lists `attest`, `verify`, and `audit`. The package-verifier hook
is registered directly, but enforcement defaults to false and therefore yields
no verifier during ordinary package operations.

Continue with [Sign and verify a package](../tutorials/getting-started.md), or
read [Configure verification](configure-verification.md) before enabling the
integration preview.
