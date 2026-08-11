# Audit an installed environment

`conda sigstore audit` verifies evidence available for packages already
installed in one conda prefix. It does not prove that evidence was checked
before installation.

## Select the environment

Audit conda's current target prefix:

```console
conda sigstore audit
```

Select an environment by name or path when needed:

```console
conda sigstore audit -n runtime
conda sigstore audit -p /srv/conda/envs/runtime
```

The original package archives must still be present in a conda package cache.
An installed prefix record contains a digest claim, not the original bytes.
Packages without a retained archive report `record-digest-only`.

## Audit repodata-advertised evidence

The default mode uses only a draft `attestations` descriptor preserved on the
installed package record:

```console
conda sigstore audit -n runtime --json
```

The descriptor selects an integrity-bound `.sigs` sidecar. A record without a
descriptor reports `missing`. The default mode does not probe for an adjacent
sidecar.

## Audit Prefix.dev evidence

Select Prefix.dev's current adjacent convention explicitly:

```console
conda sigstore audit -n runtime --prefix-sidecars
```

This derives `<artifact>.v0.sigs` from each installed package URL. Reports mark
that transport with `prefix_sidecar: true` because current Prefix.dev repodata
does not bind the sidecar bytes.

## Include source evidence

Add `--sources` when retained package archives contain draft source-attestation
declarations:

```console
conda sigstore audit -n runtime --prefix-sidecars --sources --json
```

Source inspection runs only after the package has verified publication evidence
and a retained archive. See
[Source-attestation declarations](../reference/source-attestations.md) for the
recipe syntax, supported publisher forms, path rules, and result fields.

Source and provenance evidence remain separate from package publication. They
do not authorize the package signer.

## Interpret the report

Human output shows one row per installed package. Use `--json` for automation.
Common statuses are:

| Status | Action |
| --- | --- |
| `verified` | Inspect the reported signer and predicates for the evidence you expected |
| `missing` | Confirm the selected transport and whether the channel publishes a sidecar |
| `retrieval-failed` | Check channel access and any advertised size or digest |
| `invalid` | Treat the sidecar or required statement as unusable |
| `untrusted-identity` | Check the independently supplied signer requirement |
| `record-digest-only` | Restore or redownload the exact package archive before auditing again |
| `evidence-unavailable` | Restore offline evidence or trust material before auditing again |

Audit exits with status 0 after producing a report even when package statuses
are not `verified`. Command setup and configuration errors still fail the conda
command. See [JSON output and exit status](../reference/json-output.md) for the
machine-readable contract.
