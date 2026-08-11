# Install conda-sigstore

The plugin must run in conda's base Python environment. Installing it in a
separate named environment does not register `conda sigstore` with the `conda`
executable from base.

:::{warning}
The current source checkout requires the unreleased package-verifier API from
[conda/conda#16518](https://github.com/conda/conda/pull/16518). The locked Pixi
environments use `jezdez/conda` branch `feature/package-verifiers`. Do not
install the checkout into a released conda environment.
:::

## Install a release

Install pip and the plugin into conda's base environment:

```console
conda install -n base pip
conda run -n base python -m pip install conda-sigstore
```

If `conda-pypi` is already installed with conda, use its target-environment
option before the install subcommand:

```console
conda pypi -n base install conda-sigstore
```

The PyPI command becomes available with the first release. There is no
published package yet.

## Use a source checkout

Before the first release, use the checkout's locked Pixi environment:

```console
pixi install --locked -e test
pixi run --locked -e test conda sigstore --help
```

## Check plugin discovery

Ask the compatible `conda` executable to load the plugin. From a source
checkout, use the locked environment:

```console
pixi run --locked -e test conda sigstore --help
```

The help output lists `attest`, `verify`, and `audit`. The package-verifier hook
is registered directly, but enforcement defaults to false and therefore yields
no verifier during ordinary package operations.

Continue with [Sign and verify a package](../tutorials/getting-started.md), or
read [Configure verification](configure-verification.md) before enabling the
integration preview.
