# Code review findings

This checklist records the repository reviews completed on 2026-08-11. Each
numbered item is resolved in a focused commit. Items that depend on unreleased
conda work are fixed locally by removing claims that the unavailable behavior
works and retaining only code that can be tested honestly.

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

## Coverage, documentation, and redundancy follow-up

- [x] 23. Remove the mapping round trip from operational settings parsing.
- [x] 24. Remove unused SLSA source fields and cover malformed provenance.
- [x] 25. Cover malformed embedded source-attestation declarations.
- [x] 26. Cover installed-environment audit ordering, isolation, cache, and source dispatch.
- [x] 27. Cover fail-closed network transport behavior and preserve oversized local-input status.
- [x] 28. Cover sidecar-cache misses, bounds, locking, and write-failure recovery.
- [x] 29. Cover verification command exit status for accepted and rejected evidence.
- [x] 30. Remove duplicate transport test scaffolding.
- [x] 31. Restore the CLI test package marker required for pytest module isolation.
- [x] 32. Use conda's channel-token parser for target-channel validation.
- [x] 33. Cover install-adapter filename and hook-digest rejection.
- [x] 34. Reuse conda's artifact hashing primitive in standalone paths.
- [x] 35. Cover malformed signer material and authenticated but unusable bundle evidence.
- [x] 36. Deduplicate installed-record audit test setup.
- [x] 37. Complete the Diátaxis documentation, exact JSON reference, install guidance, and runnable audit workflows.
- [x] 38. Cover strict generic in-toto and CEP 27 statement rejection paths.

## Baseline

- Normal suite: 235 passed, 2 live interoperability tests deselected.
- Measured coverage: 92 percent.
- Ruff, formatting, ty, Pixi lock validation, strict Sphinx, actionlint, and package builds passed.
