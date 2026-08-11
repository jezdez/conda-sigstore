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
- Optionally rejects packages before extraction unless repodata advertises a
  valid, exact artifact-bound CEP 27 sidecar.
- Audits installed environments and reports available publication, SLSA, and
  recipe source evidence.
- Caches integrity-bound sidecars by digest and rehashes them on every read.

A CEP 27 publication attestation identifies who signed an artifact and may name
an intended channel. It is not build provenance, publisher authorization, or a
claim that the package is safe.

## Install

Install the plugin into the Python environment that runs conda. Once a conda
package is published, current standalone conda installations can use:

```console
conda self install conda-sigstore
```

There is no published package yet.

For development, clone this repository and use its locked Pixi environment:

```console
pixi install -e test
pixi run -e test conda sigstore --help
```

Direct `pip install` into an unrelated Python environment does not register the
plugin with the conda installation you use.

Installing the plugin does not change package operations. Released conda
versions do not yet provide the package-verifier hook and repodata descriptor
preservation required for install enforcement.

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
[Sigstore tools tutorial](https://jezdez.github.io/conda-sigstore/tutorials/sigstore-tools/).
For Prefix.dev publishing, follow the
[Prefix publishing guide](https://jezdez.github.io/conda-sigstore/how-to/publish-prefix/)
and consult the
[command reference](https://jezdez.github.io/conda-sigstore/reference/commands/)
for exact interfaces.

## Authorization and installation

Sigstore authenticates a signer but does not authorize that signer for a conda
channel. CEP 27 does not standardize how publisher trust is distributed, and
the draft `.sigs` transport does not identify which admitted bundle represents
an authorized publisher.

The plugin reports signer evidence and can apply an exact signer requirement to
one explicit verification. It does not discover channel publisher delegation.

Install enforcement is not registered in the current release. The future
adapter will require repodata-advertised evidence only after conda releases
both the pre-extraction verifier hook and opaque attestation descriptor
preservation. Publisher authorization still needs a standard
channel-publisher delegation contract.

The required upstream contracts are documented in
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
