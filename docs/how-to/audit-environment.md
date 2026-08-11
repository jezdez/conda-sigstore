# Audit an installed environment

`conda sigstore audit` reports evidence available for packages already installed
in one conda prefix. It does not prove that conda checked the evidence before
installation.

## Select the environment

Audit the active target prefix:

```console
conda sigstore audit
```

Select an environment by name or path when needed:

```console
conda sigstore audit -n runtime
conda sigstore audit -p /srv/conda/envs/runtime
```

The command needs each original package archive in conda's package cache. An
extracted cache record or prefix record contains a digest claim, not the package
bytes. Packages without a retained archive report `record-digest-only`.

## Audit repodata-advertised evidence

The default mode reads only a draft `attestations` descriptor preserved on the
installed package record. The descriptor selects `<artifact>.sigs` and binds
its exact SHA-256 and byte size:

```console
conda sigstore audit -n runtime --json
```

Released conda versions do not preserve this unknown repodata field through
solver, cache, and prefix records. With a retained archive but no preserved
descriptor, the default mode reports `missing`. It never probes for an
undeclared sidecar. The required conda changes are listed in
[Upstream integration contracts](../reference/upstream-contracts.md).

## Audit Prefix.dev evidence

Select Prefix.dev's current `.v0.sigs` convention explicitly:

```console
conda sigstore audit -n runtime --prefix-sidecars
```

This mode derives `<artifact>.v0.sigs` from each installed record's artifact
URL. Prefix.dev does not bind those sidecar bytes in repodata, so the report
sets `prefix_sidecar` to `true`. This mode is never an automatic fallback from
repodata mode.

## Inspect SLSA provenance

Every sidecar bundle is verified cryptographically before its predicate is
reported. A SLSA Provenance v1 statement must bind the installed package
SHA-256. The report includes its builder, build type, invocation, parameters,
materials, and timestamps. It does not assign a SLSA level or infer that the
first material is the source.

SLSA provenance is report-only. A valid provenance statement does not replace
the required CEP 27 publication statement and does not authorize its signer.

## Inspect embedded source attestations

Add `--sources` to inspect draft source evidence retained inside a package
archive:

```console
conda sigstore audit -n runtime --prefix-sidecars --sources --json
```

Source inspection runs only after the package has a verified CEP 27 publication
statement and a retained archive. It reads
`info/recipe/rendered_recipe.yaml`. A URL source can declare evidence in this
form:

```yaml
source:
  url: https://example.org/source.tar.gz
  sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  attestation:
    publishers:
      - identity: https://github.com/example/project
        issuer: https://token.actions.githubusercontent.com
    predicate_type: https://example.org/source/v1
    verified:
      - path: attestations/source.sigstore.json
        sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

Each bundle path is relative to `info/recipe`, must have the form
`attestations/<name>.sigstore.json`, and must match its declared SHA-256. The
verified in-toto statement must bind the source SHA-256 and match an optional
predicate type. Every declared publisher must match a verified bundle
certificate and literal issuer. GitHub and GitLab repository shorthands are
also accepted as `github:OWNER/REPOSITORY` and
`gitlab:OWNER/REPOSITORY`.

The verifier uses the bundle certificate identity. It does not trust embedded
identity, issuer, or status claims. Source evidence remains separate from
package publication authorization.

## Interpret the result

| Status | Meaning |
| --- | --- |
| `verified` | At least one valid CEP 27 statement binds the retained package archive |
| `missing` | No descriptor or explicitly selected Prefix.dev sidecar is available |
| `retrieval-failed` | Advertised evidence could not be retrieved or failed its size or digest binding |
| `invalid` | A descriptor, container, bundle, or required statement is malformed or nonmatching |
| `untrusted-identity` | A required signer identity and literal issuer did not match verified publication or source evidence |
| `record-digest-only` | The original package archive is not retained |
| `evidence-unavailable` | Required trust material, cached offline evidence, or another required input is unavailable |

Audit exits with status 0 after producing a report even when package statuses
are not `verified`. Command setup and configuration errors still fail the conda
command. See [JSON output and exit status](../reference/json-output.md) for the
machine-readable contract.
