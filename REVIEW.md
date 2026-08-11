# Code review findings

This checklist records the full repository review completed on 2026-08-11. Each numbered item is resolved in its own commit. Items that depend on unreleased conda work are fixed locally by removing claims that the unavailable behavior works and retaining only code that can be tested honestly.

## Release contract

- [x] 1. Stop registering or documenting install enforcement until conda provides both the package-verifier hook and opaque `PackageRecord.attestations` preservation. Replace simulated future-hook tests with tests of the currently supported entry point.

## Correctness and security

- [x] 2. Make `targetChannel` validation conditional on the caller supplying an expected channel while retaining the explicit requirement mode.
- [x] 3. Commit attestation output atomically without replacing a destination created during signing.
- [x] 4. Convert expected command failures to a dedicated `CondaError` while preserving transport failure codes and leaving programming errors visible.
- [x] 5. Detect an artifact that changes during direct verification.
- [x] 6. Require SHA-256 values to contain exactly 64 hexadecimal characters.
- [x] 7. Select only the exact retained package filename during audit.
- [x] 8. Parse sidecars and statements as strict UTF-8 JSON and reject nonstandard numeric constants.
- [x] 9. Distinguish unavailable source evidence from invalid evidence and avoid exposing raw parser input in failures.
- [x] 10. Replace broad orchestration catches with the domain exceptions expected at each boundary.
- [x] 11. Align draft repodata transport result statuses with the current proposal.
- [x] 21. Report a bundle certificate without a supported Subject Alternative Name as invalid evidence.

## Structure and dependency boundaries

- [x] 12. Delete unused receipt-era verifier state and private Sigstore configuration access.
- [x] 13. Declare directly imported dependencies and document dependencies supplied by conda.
- [x] 14. Bound trust configuration and source archive input before parsing.
- [x] 15. Resolve the unused cache-lock seam by using conda's disk lock for production writes or documenting and simplifying the atomic content-addressed design.
- [x] 16. Move draft embedded source-attestation behavior out of `audit.py` into one cohesive module.
- [x] 17. Remove unused internal surfaces and align entry-point, prefix resolution, and Sphinx setup with the peer plugins.

## Tests, CI, and documentation

- [x] 18. Add real installed-entry-point command coverage and retain the unavailable transaction matrix as an explicit upstream prerequisite.
- [x] 19. Run coverage in one CI matrix job and publish the report.
- [x] 20. Correct install, sidecar digest, offline cache, tutorial, and Prefix workflow documentation.
- [x] 22. Expand the signer identity variables in the raw Sigstore verification tutorial command.

## Baseline

- Normal suite: 116 passed, 2 live interoperability tests deselected.
- Measured coverage: 81 percent.
- Ruff, formatting, ty, Pixi lock validation, strict Sphinx, actionlint, and package builds passed.
