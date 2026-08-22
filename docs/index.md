# conda-sigstore

`conda-sigstore` creates and verifies Sigstore attestations for conda packages.
Use it to verify a downloaded package, sign a package for publication, audit an
installed environment, or require valid evidence before conda extracts a
package.

:::{warning}
This is alpha software with no published release. Install verification requires
the unreleased conda API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518). The draft
repodata and source-attestation formats may change incompatibly.
:::

Check the [installation status](how-to/install.md), then follow the
public-package verification tutorial after a supported installation is
available. Source contributors can run the same commands from the repository
environment.

## Choose a documentation path

::::{grid} 2
:gutter: 3

:::{grid-item-card} {octicon}`rocket` Tutorial
:link: tutorials/getting-started
:link-type: doc

Verify a real public package and inspect its signer evidence.
:::

:::{grid-item-card} {octicon}`tools` How-to guides
:link: how-to/install
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

## What a verified result means

A verified result binds the package filename and SHA-256 to a valid Sigstore
bundle and reports the authenticated certificate identity and issuer. It does
not establish that the signer was authorized to publish to a channel or that
the package is safe. Read the [security model](explanation/security-model.md)
for the complete boundary.

```{toctree}
:hidden:
:caption: Tutorial

tutorials/getting-started
tutorials/sign-package
```

```{toctree}
:hidden:
:caption: How-to guides

how-to/install
how-to/audit-environment
how-to/configure-verification
how-to/verify-locked-environments
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
reference/library-api
reference/source-attestations
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
