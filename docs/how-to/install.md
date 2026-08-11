# Install conda-sigstore

The plugin must run in conda's base Python environment. Installing it in a
separate named environment does not register `conda sigstore` with the `conda`
executable from base.

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

## Install from a source checkout

Before the first release, install a local checkout into conda's base
environment:

```console
conda run -n base python -m pip install /path/to/conda-sigstore
```

Use the checkout's locked Pixi environment when developing the plugin:

```console
pixi install --locked -e test
pixi run --locked -e test conda sigstore --help
```

## Check plugin discovery

Ask the base `conda` executable to load the plugin:

```console
conda sigstore --help
```

The help output lists `attest`, `verify`, and `audit`. Installation alone does
not change ordinary package operations. Install enforcement is not registered
in the current release.

Continue with [Sign and verify a package](../tutorials/getting-started.md).
