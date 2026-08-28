# Contributing

Contributions are welcome through issues and pull requests.

## Set up the repository

Install [Pixi](https://pixi.sh), clone the repository, then install the locked
development environments:

```console
pixi install --locked --all
```

Run the focused checks while developing:

```console
pixi run --locked -e dev check
pixi run --locked -e test test
pixi run --locked -e test bench
pixi run --locked -e docs docs
```

The test matrix covers Python 3.11 through 3.14 on Ubuntu, macOS, Windows x64,
and Windows ARM64. The Windows ARM64 jobs run the locked win-64 environments
through Prism because conda-forge does not yet provide the complete native
win-arm64 dependency chain. Run a specific environment with
`pixi run --locked -e test-py314 test`.

## Live interoperability

Normal pull request tests exclude the `live_interop` marker. A scheduled and
manually dispatched workflow performs a strict install of the fixed Prefix.dev
example, audits the resulting environment, and runs a fresh signing round trip
against Sigstore staging.

Run the Prefix.dev check locally with:

```console
CONDA_SIGSTORE_PREFIX_INTEROP=1 pixi run --locked -e test test-interop
```

The staging check requires a workload identity and is intended for the GitHub
Actions workflow. It runs only when `CONDA_SIGSTORE_STAGING_INTEROP=1` and
`CONDA_SIGSTORE_STAGING_IDENTITY` contains the expected certificate identity.

## Benchmarks

Normal tests exclude the `benchmark` marker. The `bench` task measures disabled
hook collection, warm and cold verification of captured Prefix evidence, and
the hashing and extraction cost of a retained 32 MiB package. It writes
`benchmark-results.json`. The benchmark workflow preserves that file as an
artifact without making hosted-runner timing a correctness threshold.

The scheduled interoperability workflow measures cached Prefix installs in
disabled and enabled pairs, alternating their order between rounds. The JSON
artifact includes each pair and its delta. The workflow has no pass or fail
threshold because network and hosted-runner variance are part of that live
measurement.

## Change the lock file

Edit dependency constraints in `pyproject.toml`, then run:

```console
pixi lock
```

Commit `pixi.lock` with the manifest change. Do not hand-edit the lock file.

## Documentation

Documentation uses Sphinx, MyST Markdown, `conda-sphinx-theme`, and
`sphinx-design`. It follows Diátaxis. Put learning-oriented work in
`docs/tutorials`, task instructions in `docs/how-to`, exact contracts in
`docs/reference`, and design context in `docs/explanation`.

## Package-verifier conformance

Before claiming stable end-to-end enforcement, exercise both package formats,
classic and libmamba solves, monolithic and sharded repodata, authenticated
channels and mirrors, and online and offline cache states.

The integration must demonstrate that:

1. valid, exact artifact-bound CEP 27 evidence succeeds
2. artifact substitution fails before extraction
3. repodata-hash-pinned sidecar substitution fails before parsing
4. an absent `attestations_sha256` field selects required adjacent evidence
5. a missing adjacent sidecar fails closed
6. target-channel replay fails
7. classic and libmamba solver paths cannot bypass verification
8. local-file and unsupported explicit `MatchSpec` inputs fail closed
9. retained archives and `--download-only` cannot bypass verification
10. dry runs and remove-only transactions perform no package verification or
    prefix mutation
11. force reinstalls reverify the incoming archive
12. disabling `safety_checks` or transaction rollback does not disable
    verification
13. verification failure causes no unlink or link actions
14. package-controlled code or files are not processed before the decision

An unrelated but cryptographically valid Sigstore identity can satisfy the
current validity-only verifier. Authorization conformance requires a future
delegation standard and is not part of this matrix.

## Releases

Follow [RELEASING.md](RELEASING.md). Prepare and merge the curated changelog,
then create an annotated bare version tag from the exact commit that passed CI.
The release workflow builds the distributions once before it creates a draft
GitHub release. It publishes those same files to PyPI through trusted publishing
and makes the GitHub release public only after PyPI succeeds.
