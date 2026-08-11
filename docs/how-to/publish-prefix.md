# Publish attestations to Prefix.dev

Prefix.dev currently supports Trusted Publishing and Sigstore attestations in
its Rattler-Build upload path. This guide shows the recommended automatic path,
then the manual path for a bundle created by `conda-sigstore`.

These are Prefix-specific producer workflows. Prefix.dev serves uploaded
bundles through its `.v0.sigs` transport, not the draft repodata-advertised
`.sigs` transport.

## Configure Repository Access

Create the target channel, then open **Settings → Repository Access** and add a
trusted publisher. Specify the GitHub owner, repository, and exact workflow
filename allowed to upload. Prefix documents this setup in its
[Repository Access guide](https://prefix.dev/docs/prefix/channels/access).

The workflow needs `id-token: write` so Rattler-Build can obtain an ambient
OIDC identity. It does not need a long-lived Prefix API key.

## Use Rattler-Build's automatic path

Prefix recommends Rattler-Build's `--generate-attestation` option. It creates
one CEP 27 bundle per package and uploads each package and bundle together.

```yaml
name: Publish conda package

on:
  push:
    tags:
      - "v*"

permissions: {}

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: prefix-dev/rattler-build-action@1ca5f45832f419a46d1326ccc5861d7e14d67c44 # v0.2.39
        with:
          setup-only: true
      - name: Build, attest, and publish
        run: |
          rattler-build publish ./recipe.yaml \
            --to https://prefix.dev/MY-CHANNEL \
            --generate-attestation
```

Replace `MY-CHANNEL` and the recipe path. The trusted-publisher configuration
must name this workflow file. The option works only with Prefix Trusted
Publishing in a supported CI environment. It cannot be combined with an API
key.

Rattler-Build's current
[Sigstore guide](https://rattler-build.prefix.dev/latest/sigstore/) documents
this as the preferred path, especially for multi-output recipes because each
package requires its own CEP 27 statement.

## Upload a conda-sigstore bundle manually

Use this path when the package has already been built or when you need to create
the CEP 27 bundle separately. Both commands use the ambient CI workload
identity and request their own service-specific OIDC tokens:

```console
conda sigstore attest ./output/linux-64/example-1.0-0.conda \
  --target-channel https://prefix.dev/MY-CHANNEL

rattler-build upload prefix \
  --channel MY-CHANNEL \
  ./output/linux-64/example-1.0-0.conda \
  --attestation ./output/linux-64/example-1.0-0.conda.sigstore.json
```

Attach attestations to exactly one package per upload. A CEP 27 statement has
exactly one subject, so do not sign a glob that resolves to multiple packages
as one statement.

The open-source `rattler_upload` client obtains a trusted-publishing upload
token separately from the supplied attestation. Its `create_upload_form`
function adds the attestation as multipart text, then
`upload_package_to_prefix` sends that form with the bearer token. The
[pinned client implementation](https://github.com/conda/rattler/blob/a1120c0ff11eb50dd2f6c075dee04a652cc162a7/crates/rattler_upload/src/upload/prefix.rs)
does not compare the upload identity with the bundle certificate identity.
Public server behavior does not establish that comparison either. Treat server
admission as repository hygiene, not as consumer authorization.

## Use GitHub's attestation action manually

GitHub's standard attestation action can also create the custom CEP 27
predicate. Invoke it once for each package and pass its `bundle-path` output to
Rattler-Build. This example is for a public repository, where the action uses
the public Sigstore instance. GitHub uses a separate Sigstore instance for
private and internal repositories, whose Prefix interoperability is not
established here.

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

steps:
  - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
    id: attest
    with:
      subject-path: ./output/linux-64/example-1.0-0.conda
      predicate-type: https://schemas.conda.org/attestations-publish-1.schema.json
      predicate: '{"targetChannel":"https://prefix.dev/MY-CHANNEL"}'
  - name: Upload package and bundle
    run: |
      rattler-build upload prefix \
        --channel MY-CHANNEL \
        ./output/linux-64/example-1.0-0.conda \
        --attestation "${{ steps.attest.outputs.bundle-path }}"
```

The action also stores the attestation in GitHub's attestation API. Verify that
copy with the GitHub CLI:

```console
gh attestation verify ./example-1.0-0.conda \
  --owner MY-GITHUB-OWNER \
  --predicate-type https://schemas.conda.org/attestations-publish-1.schema.json
```

GitHub verifies against the selected repository owner and predicate type. Use
`conda sigstore verify` as well when you need CEP 27's exact filename,
single-subject, SHA-256, and target-channel checks.

## Verify the Prefix-served copy

Download the package bytes and the currently served Prefix.dev sidecar:

```console
curl --fail --location --remote-name \
  https://prefix.dev/MY-CHANNEL/linux-64/example-1.0-0.conda
curl --fail --location --remote-name \
  https://prefix.dev/MY-CHANNEL/linux-64/example-1.0-0.conda.v0.sigs
```

Verify them together and supply the intended channel:

```console
conda sigstore verify ./example-1.0-0.conda \
  --bundle ./example-1.0-0.conda.v0.sigs \
  --channel https://prefix.dev/MY-CHANNEL
```

The result verifies the package binding and reports the actual certificate
identity and issuer. It labels no signer as authorized. The `.v0.sigs` bytes
are not pinned by repodata, so keep this transport explicit and do not use it
as fallback after a draft repodata descriptor failure.

For the transport limitation and live fixture, see
[Verify Prefix.dev sidecars](prefix-sidecars.md).
