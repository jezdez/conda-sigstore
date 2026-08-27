# Install conda-sigstore

`conda-sigstore` must be installed in the Python environment that owns the
`conda` executable. A plugin installed in an unrelated environment is not
discovered by that `conda` executable.

## Install 0.1.0 from PyPI

Create a dedicated environment that contains both conda and the plugin:

```console
conda create --name conda-sigstore conda pip
conda activate conda-sigstore
python -m pip install "conda-sigstore==0.1.0"
conda sigstore --help
```

The PyPI distribution does not install conda. If you instead add the plugin to
an existing conda installation, run pip with that installation's Python
interpreter.

The help output should list `attest`, `verify`, and `audit`. Start with
[Verify a public package](../tutorials/getting-started.md).

:::{warning}
The opt-in pre-extraction verifier requires the unreleased package-verifier API
in [conda/conda#16518](https://github.com/conda/conda/pull/16518). Released
conda versions can load the other plugin commands, but they cannot enable that
install hook.

Current conda `PackageRecord` objects also do not preserve PR 142's
`attestations_sha256` field. A corresponding conda change is required before
real solver and install flows can select the draft content-addressed sidecar.
`plugins.conda_sigstore_enforce` remains false by default.
:::

## Preview install enforcement from source

Use the repository's locked test environment to evaluate the unreleased conda
integration without changing your normal conda installation. You need
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

The locked environment uses `jezdez/conda` branch
`feature/package-verifiers`, the branch behind the draft hook pull request.

Exit the preview shell when finished:

```console
exit
```

Read [Configure verification](configure-verification.md) before enabling
install enforcement.
