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
  conda/ceps#142 and explicit Prefix.dev `.v0.sigs` sidecar discovery.
- Offline verification and installed-environment, SLSA provenance, and recipe
  source-evidence auditing.
- Scheduled live interoperability checks for the fixed Prefix.dev example and
  Sigstore staging.
- Sphinx documentation using MyST, `conda-sphinx-theme`, `sphinx-design`, and a
  Diátaxis structure.
- Installation, environment-audit, standard sigstore-python verification, and
  Prefix.dev publishing guides.
- Optional exact signer identity and OIDC issuer verification for
  `conda sigstore verify`.
- Versioned JSON output with artifact and observed sidecar SHA-256 digests, plus
  an exact output and exit-status reference.
- A direct, opt-in pre-extraction verifier for the package-verifier API in
  conda/conda#16518, controlled by `plugins.conda_sigstore_enforce` and disabled
  by default. Ordinary solved records remain blocked until conda also preserves
  repodata attestation descriptors.
- Rich terminal rendering for human-readable command output.
