# conda-sigstore

`conda-sigstore` is a conda plugin for creating and verifying Sigstore
attestations for conda packages.

It follows accepted [CEP 27](https://github.com/conda/ceps/blob/main/cep-0027.md)
for publication statements and implements the draft repodata-advertised
`.sigs` transport proposed in
[conda/ceps#142](https://github.com/conda/ceps/pull/142). The plugin also
supports Prefix.dev's current `.v0.sigs` sidecars as explicit compatibility
input.

The project is alpha software. Draft transport and source-evidence formats may
still change incompatibly.

## What it does

- Creates a CEP 27 publication statement for one conda package and signs it as
  a Sigstore Bundle v0.3.
- Verifies artifact digests, bundle signatures, certificate chains,
  transparency-log evidence, CEP 27 structure, and an optional target channel.
- Reports the authenticated certificate identity and OIDC issuer without
  claiming that either is authorized to publish to a channel.
- Reads `.sigs` sidecars only when repodata advertises their exact SHA-256 and
  size.
- Reads Prefix.dev `.v0.sigs` sidecars only when explicitly requested.
- Audits installed environments and reports available publication, SLSA, and
  recipe source evidence.
- Provides an opt-in pre-extraction verifier for conda's draft package-verifier
  hook.
- Caches integrity-bound sidecars by digest and rehashes them on every read.

A CEP 27 publication attestation identifies who signed an artifact and may name
an intended channel. It is not build provenance, publisher authorization, or a
claim that the package is safe.

## Install

Install the plugin into conda's base environment, which owns the `conda`
executable. For a released version, install the PyPI package with that
environment's Python:

```console
conda install -n base pip
conda run -n base python -m pip install conda-sigstore
conda sigstore --help
```

If `conda-pypi` is already installed with conda, the equivalent tracked install
targets base explicitly:

```console
conda pypi -n base install conda-sigstore
```

The PyPI command becomes available with the first release. The current source
checkout requires the unreleased conda package-verifier API from
[conda/conda#16518](https://github.com/conda/conda/pull/16518). Do not install
it into a released conda environment.

For development, clone this repository and use its locked Pixi environment:

```console
pixi install --locked -e test
pixi run --locked -e test conda sigstore --help
```

Installing into a separate named environment does not register the plugin with
the `conda` executable from base.

See the
[installation guide](https://jezdez.github.io/conda-sigstore/how-to/install/)
for the supported paths.

The locked environments use `jezdez/conda` branch `feature/package-verifiers`.
Install verification is disabled by default, so the hook yields no verifier
unless `plugins.conda_sigstore_enforce` is enabled.

## Commands

```console
conda sigstore attest PACKAGE --target-channel URL [--output PATH]
conda sigstore verify ARTIFACT --bundle PATH_OR_URL [--channel URL] \
  [--cert-identity IDENTITY --cert-oidc-issuer URL] [--json]
conda sigstore audit [-n ENV | -p PREFIX] [--sources] [--prefix-sidecars] [--json]
```

Start with the
[tutorial](https://jezdez.github.io/conda-sigstore/tutorials/getting-started/)
and the
[standard Sigstore verification guide](https://jezdez.github.io/conda-sigstore/how-to/verify-with-sigstore/).
For Prefix.dev publishing, follow the
[Prefix publishing guide](https://jezdez.github.io/conda-sigstore/how-to/publish-prefix/)
or [audit an installed environment](https://jezdez.github.io/conda-sigstore/how-to/audit-environment/).
Consult the
[command reference](https://jezdez.github.io/conda-sigstore/reference/commands/)
for exact interfaces.

## Authorization and installation

Sigstore authenticates a signer but does not authorize that signer for a conda
channel. CEP 27 does not standardize how publisher trust is distributed, and
the draft `.sigs` transport does not identify which admitted bundle represents
an authorized publisher.

The plugin reports signer evidence and can apply an exact signer requirement to
one explicit verification. It does not discover channel publisher delegation.

The plugin registers a direct package-verifier hook against the API proposed in
[conda/conda#16518](https://github.com/conda/conda/pull/16518). Set
`plugins.conda_sigstore_enforce: true` or
`CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true` to opt in. Enabled verification
requires repodata-advertised evidence and fails closed. It never falls back to
Prefix.dev `.v0.sigs` sidecars.

This is an integration preview. PR #16518 does not preserve the repodata
`attestations` descriptor on `PackageRecord`, so ordinary solved records cannot
currently pass enabled verification. A separate upstream preservation change
must land first. Even after that change, this verifier establishes evidence
validity, not publisher authorization. See
[Upstream integration contracts](https://jezdez.github.io/conda-sigstore/reference/upstream-contracts/).

## Security boundary

A successful result proves that Sigstore verified the bundle and that a strict
CEP 27 statement binds the exact package bytes and filename. When a channel is
supplied, the command also checks an included target-channel claim. The result
reports signer evidence. Paired `--cert-identity` and `--cert-oidc-issuer`
options require an exact signer for that invocation without creating policy.

Read the
[security model](https://jezdez.github.io/conda-sigstore/explanation/security-model/)
and report vulnerabilities according to the
[security policy](https://github.com/jezdez/conda-sigstore/security/policy).

## Development

```console
pixi run --locked -e dev check
pixi run --locked -e test test
pixi run --locked -e docs docs
```

See the
[contribution guide](https://github.com/jezdez/conda-sigstore/blob/main/CONTRIBUTING.md)
for the full development and release workflow. `conda-sigstore` is licensed
under the BSD 3-Clause License.
