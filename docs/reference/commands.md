# Commands

The plugin registers one `conda sigstore` subcommand. It uses the active conda
configuration and target prefix.

Human output uses terminal styling when supported. `--json` writes one
unstyled JSON value without human status lines or ANSI escapes. See
[JSON output and exit status](json-output.md) for the machine contract.

## `conda sigstore attest`

```console
conda sigstore attest PACKAGE --target-channel URL [--output PATH]
```

Create and keylessly sign one strict CEP 27 publication statement for
`PACKAGE`. The command writes one Sigstore Bundle v0.3 JSON object. It does not
upload the package or assemble a channel sidecar.

| Argument | Required | Meaning |
| --- | --- | --- |
| `PACKAGE` | yes | Local `.conda` or `.tar.bz2` package archive |
| `--target-channel URL` | yes | Credential-free HTTP or HTTPS channel recorded as `targetChannel` |
| `--output PATH` | no | Bundle output path, defaulting to `<PACKAGE>.sigstore.json` |

The command refuses to replace the input package or an existing output file.
It rehashes the package before committing the output so a package changed
during the OIDC and signing flow cannot produce a successful command.

The output is a single bundle object. Channel tooling wraps one or more
complete bundle objects in the JSON array served as `<PACKAGE>.sigs` or, for
the current Prefix.dev compatibility transport, `<PACKAGE>.v0.sigs`.

## `conda sigstore verify`

```console
conda sigstore verify ARTIFACT --bundle PATH_OR_URL [--channel URL] \
  [--cert-identity IDENTITY --cert-oidc-issuer URL] [--json]
```

Verify a local package archive against a local or remote Bundle v0.3 object or
nonempty bundle array.

| Argument | Required | Meaning |
| --- | --- | --- |
| `ARTIFACT` | yes | Local package archive whose filename and SHA-256 must match the statement |
| `--bundle PATH_OR_URL` | yes | Local file or HTTP or HTTPS URL containing one bundle object or a nonempty bundle array |
| `--channel URL` | no | Expected channel for an included `targetChannel` claim |
| `--cert-identity IDENTITY` | paired | Exact certificate Subject Alternative Name required for this invocation |
| `--cert-oidc-issuer URL` | paired | Exact certificate OIDC issuer required for this invocation |
| `--json` | no | Write the version 1 verification result as JSON |
| `--console {classic,json}` | no | Select human output or structured plugin result output |
| `-v`, `--verbose` | no | Increase conda logging verbosity, repeatable up to trace output |
| `-q`, `--quiet` | no | Disable conda progress output |

`--cert-identity` and `--cert-oidc-issuer` must be supplied together. Their
values must come from an independent publisher or release configuration, not
from the bundle being checked. They apply only to this command and are not
stored as channel policy.

`--json` and `--console json` select the same `conda-sigstore` result after
verification runs. Only `--json` also selects conda's JSON error reporter for
argument, input, and configuration failures. `--verbose` controls conda
logging. `--quiet` controls conda progress output, although this command does
not create a progress bar.

Verification checks:

- the SHA-256 and exact filename of the artifact
- the bundle structure and DSSE signature
- the Fulcio certificate chain and OIDC issuer evidence
- Rekor inclusion and checkpoint material
- supported signed timestamp material
- the strict CEP 27 statement structure
- an included target-channel claim
- the exact signer pair when both signer options are supplied

When `--channel` is supplied, an included `targetChannel` must match it.
Without `--channel`, the claim is validated and reported but is not compared
with an expected channel.

The result reports the authenticated certificate identity and issuer. It does
not claim that the channel authorized that signer.

## `conda sigstore audit`

```console
conda sigstore audit [-n ENVIRONMENT | -p PREFIX] [--sources] \
  [--prefix-sidecars] [--json]
```

Audit package records in an existing conda environment. If neither target
option is supplied, conda's active target prefix is used.

| Argument | Required | Meaning |
| --- | --- | --- |
| `-n ENVIRONMENT`, `--name ENVIRONMENT` | no | Named conda environment to audit |
| `-p PREFIX`, `--prefix PREFIX` | no | Environment prefix to audit |
| `--sources` | no | Audit draft embedded source-attestation evidence after package publication verification succeeds |
| `--prefix-sidecars` | no | Use Prefix.dev's current adjacent `.v0.sigs` convention instead of repodata discovery |
| `--json` | no | Write the version 1 audit report as JSON |
| `--console {classic,json}` | no | Select human output or structured plugin result output |
| `-v`, `--verbose` | no | Increase conda logging verbosity, repeatable up to trace output |
| `-q`, `--quiet` | no | Disable conda progress output |

`--name` and `--prefix` are mutually exclusive. `--json` and `--console json`
select the same audit report after auditing runs. Only `--json` also selects
conda's JSON error reporter for command setup failures. `--verbose` controls
conda logging. `--quiet` controls conda progress output, although this command
does not create a progress bar.

By default, audit reads only repodata-advertised `.sigs` sidecars. The package
record must preserve an `attestations` descriptor with the exact sidecar
SHA-256 and size. Missing descriptors are not probed. Released conda versions
do not preserve that proposed field through every solver, cache, and prefix
record path, so an audit can report `missing` even when a channel serves a
sidecar.

`--prefix-sidecars` explicitly selects Prefix.dev's current, repodata-unpinned
`.v0.sigs` convention. It never runs as an automatic audit fallback.

`--sources` reads draft source-attestation declarations and embedded bundles
from a retained package archive. See
[Source-attestation audit format](source-attestations.md) for the exact input
contract. SLSA and source evidence are report-only. The audit does not assign a
SLSA level or authorize a package publisher.

An audit describes evidence currently available to the client. It does not
prove that a package was verified before extraction or installation.

## Opt-in package verification

The plugin registers a direct package-verifier hook against the unreleased
conda API in [conda/conda#16518](https://github.com/conda/conda/pull/16518).
It yields no verifier unless `plugins.conda_sigstore_enforce` is true. The
standard environment override is:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

Enabled verification rejects a package unless its selected evidence verifies.
See [Upstream integration contracts](upstream-contracts.md) for the hook and
evidence-selection rules.
