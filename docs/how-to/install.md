# Install conda-sigstore

`conda-sigstore` must be installed in the Python environment that owns the
`conda` executable. That environment is usually conda's base environment. A
plugin installed in an unrelated named environment is not discovered by that
`conda` executable.

:::{warning}
There is no supported end-user installation yet. `conda-sigstore` has no PyPI
or conda release, and its install verifier requires the unreleased API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518). Do not overlay
the draft conda branch onto a working base installation.
:::

## Run the source preview

Use the repository's locked test environment to evaluate the current source
without changing your normal conda installation. You need
[Pixi](https://pixi.sh) and Git.

```console
git clone https://github.com/jezdez/conda-sigstore.git
cd conda-sigstore
pixi install --locked --all
pixi shell -e test
conda init --install
conda sigstore --help
```

`conda init --install` is a one-time setup for the source environment. It
replaces the pip bootstrap entry point inside `.pixi/envs/test` with conda's
normal command wrappers. It does not initialize your shell profile.

The help output should list `attest`, `verify`, and `audit`. The locked
environment uses `jezdez/conda` branch `feature/package-verifiers`, the branch
behind the draft hook pull request.

Exit the preview shell when finished:

```console
exit
```

## Wait for a supported installation

A normal installation will be documented after both of these are available:

1. a released conda version that provides the package-verifier hook
2. a published `conda-sigstore` distribution

At that point, install the plugin into the owning conda environment and confirm
discovery with `conda sigstore --help`. Until then, commands that install
`conda-sigstore` from PyPI are not valid.

The verifier is disabled by default even when the plugin is installed. Start
with [Verify a public package](../tutorials/getting-started.md). Read
[Configure verification](configure-verification.md) before enabling install
enforcement.
