# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `conda sigstore attest`, `verify`, and `audit` commands backed by
  sigstore-python.
- Strict CEP 27 statement construction and validation for conda package
  publication attestations.
- Support for the draft repodata-advertised `.sigs` transport proposed in
  <https://github.com/conda/ceps/pull/142> and Prefix.dev `.v0.sigs` sidecar
  discovery.
- Offline verification and installed-environment, SLSA provenance, and recipe
  source-evidence auditing.
- Scheduled live interoperability checks for the fixed Prefix.dev example and
  Sigstore staging.
- Hermetic verification benchmarks and a separate workflow that preserves
  benchmark results without imposing hosted-runner timing thresholds.
- A scheduled informational benchmark comparing cached Prefix.dev installs
  with strict verification disabled and enabled.
- Sphinx documentation using MyST, `conda-sphinx-theme`, `sphinx-design`, and a
  Diátaxis structure.
- Installation, environment-audit, standard sigstore-python verification, and
  Prefix.dev publishing guides.
- Optional exact signer identity and OIDC issuer verification for
  `conda sigstore verify`.
- Versioned JSON output with artifact and observed sidecar SHA-256 digests, plus
  an exact output and exit-status reference.
- A direct, opt-in pre-extraction verifier for the package-verifier API in
  <https://github.com/conda/conda/pull/16518>, controlled by
  `plugins.conda_sigstore_enforce` and disabled by default. It accepts a
  descriptor-pinned `.sigs` sidecar when advertised and otherwise requires the
  deterministic adjacent `.v0.sigs` sidecar.
- Rich terminal rendering for human-readable command output.
- A tag-driven release workflow that builds once, records GitHub provenance,
  stages an immutable GitHub release, and publishes the same distributions to
  PyPI with Trusted Publishing and attestations.

### Changed

- Removed the permanently unavailable `source` field from SLSA evidence output.
- Expanded the live Prefix interoperability check into a real strict
  pre-extraction installation followed by an environment audit.
