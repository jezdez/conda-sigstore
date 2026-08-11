# conda-sigstore

`conda-sigstore` creates and verifies Sigstore publication attestations for
conda packages without replacing conda's existing package hashes.

It has three jobs:

1. A publisher creates a strict CEP 27 statement for one package and signs it
   with a short-lived Sigstore certificate.
2. A consumer verifies the package, signed statement, certificate, and
   transparency-log evidence, then receives the authenticated signer details.
3. An operator audits an installed environment for available publication,
   provenance, and embedded source evidence.

The plugin supports two sidecar transports:

| Transport | Discovery | Integrity binding | Status |
| --- | --- | --- | --- |
| `repodata` | `attestations` descriptor in `repodata.json` | SHA-256 and exact sidecar size | Draft proposal |
| Prefix.dev | `<artifact>.v0.sigs` by convention | None in `repodata.json` | Current service-specific compatibility |

:::{warning}
The repodata-advertised `.sigs` transport remains a draft proposal in
[conda/ceps#142](https://github.com/conda/ceps/pull/142) and may change
incompatibly.
:::

New users should [install the plugin](how-to/install.md), run
`conda sigstore --help`, then follow the signing and verification tutorial.

## Choose a documentation path

::::{grid} 2
:gutter: 3

:::{grid-item-card} {octicon}`rocket` Tutorial
:link: tutorials/getting-started
:link-type: doc

Create, inspect, and verify package publication attestations.
:::

:::{grid-item-card} {octicon}`tools` How-to guides
:link: how-to/configure-verification
:link-type: doc

Install the plugin, audit environments, configure inputs, and work offline.
:::

:::{grid-item-card} {octicon}`list-unordered` Reference
:link: reference/commands
:link-type: doc

Look up commands, configuration, standards, and upstream contracts.
:::

:::{grid-item-card} {octicon}`book` Explanation
:link: explanation/design
:link-type: doc

Understand the design and security boundaries.
:::

::::

## What verification proves

A successful CEP 27 verification establishes that:

- the package has the reported SHA-256 digest
- a Sigstore Bundle v0.3 is valid against the selected trust root
- certificate and transparency-log evidence verify
- the signed statement names the exact package filename and digest
- an included target-channel claim matches the supplied channel
- the result accurately reports the certificate identity and OIDC issuer

It does not establish that the signer was authorized to publish to the channel,
that the package was built safely, that its source was reviewed, or that its
contents are benign.

## Authorization and installation

CEP 27 requires trust in a signer but does not standardize how channels delegate
publisher identities. The draft sidecar proposal distributes bundles but does
not identify which admitted bundle represents an authorized publisher.

`conda-sigstore` reports signer evidence and can apply an exact signer
requirement to one explicit verification. It does not discover channel
publisher delegation.

Install enforcement is not registered in the current release. See
[Installation verification across package managers](explanation/install-verification.md)
for the current package-manager comparison and
[Upstream integration contracts](reference/upstream-contracts.md) for the
required conda changes.

```{toctree}
:hidden:
:caption: Tutorial

tutorials/getting-started
```

```{toctree}
:hidden:
:caption: How-to guides

how-to/install
how-to/audit-environment
how-to/configure-verification
how-to/publish-prefix
how-to/prefix-sidecars
how-to/verify-with-sigstore
how-to/offline
```

```{toctree}
:hidden:
:caption: Reference

reference/commands
reference/configuration
reference/json-output
reference/standards
reference/upstream-contracts
```

```{toctree}
:hidden:
:caption: Explanation

explanation/design
explanation/security-model
explanation/install-verification
```

```{toctree}
:hidden:
:caption: Project

changelog
```
