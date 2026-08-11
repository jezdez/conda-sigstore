# Commands

The plugin registers one `conda sigstore` subcommand. Commands use conda's
active operational settings and plugin discovery.

Human output uses terminal styling when supported and remains readable without
color. Status words carry the meaning independently of color. `--json` writes
one unstyled JSON object without human status lines or ANSI escapes.

## `conda sigstore attest`

```console
conda sigstore attest PACKAGE --target-channel URL [--output PATH]
```

Create a strict CEP 27 publication statement for `PACKAGE`, obtain a Sigstore
keyless signing identity, and write one Sigstore Bundle v0.3 JSON object. The
default output path is `<PACKAGE>.sigstore.json`.

`--target-channel` records the intended publication channel. The command does
not upload the package or assemble a channel sidecar. Channel tooling wraps one
or more complete bundle objects in the JSON array served as `<PACKAGE>.sigs`.

The command refuses to replace the input package or an existing output file. It
rehashes the package before committing the output so a package changed during
the OIDC and signing flow cannot produce a successful command.

## `conda sigstore verify`

```console
conda sigstore verify ARTIFACT --bundle PATH_OR_URL [--channel URL] \
  [--cert-identity IDENTITY --cert-oidc-issuer URL] [--json]
```

Verify an artifact against a local or remote Bundle v0.3 object or nonempty
bundle array. Verification covers:

- artifact SHA-256 and exact filename
- bundle structure and DSSE signature
- Fulcio certificate chain and OIDC issuer evidence
- Rekor and supported timestamp evidence
- strict CEP 27 statement structure
- an included target-channel claim

When `--channel` is supplied, an included `targetChannel` must match it. Without
`--channel`, the claim is validated and reported but is not compared with an
expected channel.

The result reports the authenticated certificate identity and issuer. It does
not call the signer authorized for the channel. `--json` emits the versioned
result described in [JSON output and exit status](json-output.md).

Pass `--cert-identity` and `--cert-oidc-issuer` together to require one exact
certificate SAN and literal OIDC issuer for this verification. These option
names match `sigstore verify identity`. The values must come from an independent
publisher or release configuration, not from the bundle being verified. A
cryptographically valid bundle from another signer remains visible as evidence
but produces the top-level `untrusted-identity` status when no matching CEP 27
publication statement exists. The requirement is not stored as channel policy.
JSON records the two supplied values under `expected_signer` and reports
authorization as `verified` or `failed`.

## `conda sigstore audit`

```console
conda sigstore audit [-n ENV | -p PREFIX] [--sources] [--prefix-sidecars] [--json]
```

Audit package records in an existing conda environment. `-n` selects an
environment by name and `-p` selects a prefix. They are mutually exclusive.

By default, audit reads only repodata-advertised `.sigs` sidecars. The package
record must contain an `attestations` descriptor with the exact sidecar SHA-256
and size. Missing descriptors are not probed.

Released conda versions do not preserve that unknown repodata field through
solver, cache, and prefix records. Default audits therefore report `missing`
when a retained archive has no preserved descriptor.

`--prefix-sidecars` explicitly selects Prefix.dev's current, unpinned
`.v0.sigs` naming convention. It never runs as an automatic fallback.

`--sources` inspects draft source-attestation evidence in a retained package
archive. SLSA and source evidence are report-only and do not assign a SLSA level
or authorize the package publisher.

An audit describes currently available evidence. It does not prove that the
package was verified before extraction or installation. See
[Audit an installed environment](../how-to/audit-environment.md) for the full
workflow and [JSON output and exit status](json-output.md) for status meanings.

## Opt-in package verification

The plugin registers a direct package-verifier hook against the unreleased conda
API in conda/conda#16518. It yields no verifier unless
`plugins.conda_sigstore_enforce` is true. The standard environment override is
`CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true`.

Enabled verification uses descriptor-pinned `.sigs` evidence when advertised
and otherwise requires the deterministic adjacent `.v0.sigs` sidecar. Missing,
unavailable, malformed, invalid, or nonmatching evidence fails closed. A
present but broken descriptor never falls back. The verifier establishes
evidence validity but does not authorize the signer. See
[Upstream integration contracts](upstream-contracts.md).
