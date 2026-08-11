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

The test matrix covers Python 3.10 through 3.14. Run a specific environment
with `pixi run --locked -e test-py314 test`.

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

## Releases

Maintainers create a version tag after CI succeeds. The release workflow builds
the distributions once, records GitHub build provenance, creates a draft
release, publishes to PyPI through trusted publishing, and then publishes the
GitHub release. Release immutability must be enabled in the repository settings.

Add a curated changelog entry before creating the tag.
