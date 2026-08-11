# conda-sigstore

`conda-sigstore` creates and verifies Sigstore attestations for conda packages.
It can also audit installed environments and, when explicitly enabled, reject a
package before extraction when acceptable evidence is unavailable or invalid.

The project is alpha software. No release has been published yet. The install
integration requires the unreleased package-verifier API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518), and draft
transport and source-evidence formats may still change incompatibly.

## What it does

- Verify a package against a local or remote Sigstore bundle.
- Create a signed [CEP 27](https://github.com/conda/ceps/blob/main/cep-0027.md)
  publication statement.
- Audit installed packages for publication, provenance, and recipe source
  evidence.
- Require valid CEP 27 evidence before conda extracts a package.
- Read the draft repodata-advertised `.sigs` transport and Prefix.dev's current
  `.v0.sigs` convention.

## Install

There is no supported end-user installation yet. The
[installation status](https://jezdez.github.io/conda-sigstore/how-to/install/)
lists the two releases required before `conda sigstore` can be installed and
documents the source preview.

## Commands

```console
conda sigstore attest PACKAGE --target-channel URL [--output PATH]
conda sigstore verify ARTIFACT --bundle PATH_OR_URL [--channel URL] \
  [--cert-identity IDENTITY --cert-oidc-issuer URL] [--json]
conda sigstore audit [-n ENV | -p PREFIX] [--sources] [--prefix-sidecars] [--json]
```

Choose the path that matches your task:

- [Verify a public package](https://jezdez.github.io/conda-sigstore/tutorials/getting-started/)
- [Sign a package](https://jezdez.github.io/conda-sigstore/tutorials/sign-package/)
- [Audit an installed environment](https://jezdez.github.io/conda-sigstore/how-to/audit-environment/)
- [Configure install verification](https://jezdez.github.io/conda-sigstore/how-to/configure-verification/)
- [Publish attestations to Prefix.dev](https://jezdez.github.io/conda-sigstore/how-to/publish-prefix/)
- [Look up commands and output formats](https://jezdez.github.io/conda-sigstore/reference/commands/)

## Security boundary

A successful result proves that Sigstore verified the bundle and that its CEP
27 statement binds the package filename and SHA-256. It reports the
authenticated signer and can compare an included target-channel claim.

It does not prove that the signer was authorized to publish to that channel,
that the package was built safely, or that its contents are benign.

Read the
[security model](https://jezdez.github.io/conda-sigstore/explanation/security-model/)
and report vulnerabilities according to the
[security policy](https://github.com/jezdez/conda-sigstore/security/policy).

## Development

```console
pixi run --locked -e dev check
pixi run --locked -e test test
pixi run --locked -e test bench
pixi run --locked -e docs docs
```

See the
[contribution guide](https://github.com/jezdez/conda-sigstore/blob/main/CONTRIBUTING.md)
for the full development and release workflow. `conda-sigstore` is licensed
under the BSD 3-Clause License.
