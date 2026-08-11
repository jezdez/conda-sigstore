# Configuration

The plugin registers a structured setting for operational inputs and a flat
boolean for opt-in package verification:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: null
  conda_sigstore_enforce: false
```

Omitting either setting uses the values shown above. With enforcement false,
the package-verifier hook yields no verifier and package operations are
unchanged.

## Operational fields

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_sidecar_bytes` | positive integer | `10485760` | Maximum bundle or sidecar bytes read before parsing |
| `trust_config` | local path or `null` | `null` | Optional Sigstore client trust configuration |

Unknown fields are rejected. `trust_config` must identify an existing local
file no larger than 1 MiB. With `null`, verification uses Sigstore's production
trust configuration.

Source auditing also bounds package-controlled input. Retained package archives
larger than 4 GiB and rendered recipes larger than 1 MiB are reported as
unavailable evidence before parsing.

## Enforcement setting

| Setting | Type | Default | Meaning |
| --- | --- | --- | --- |
| `plugins.conda_sigstore_enforce` | boolean | `false` | Require valid CEP 27 evidence from a descriptor-pinned or deterministic adjacent sidecar before package extraction |

Conda also accepts the standard environment-variable override:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

The hook is registered directly against the unreleased API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518). It is not an
optional compatibility hook. When enabled, missing, unavailable, malformed,
invalid, or nonmatching evidence fails the package. A repodata descriptor
selects the integrity-pinned `.sigs` transport. Without one, the verifier
requires the deterministic adjacent `.v0.sigs` sidecar. A present but invalid
descriptor never falls back.

The hook supplies the selected package URL and SHA-256, so enabled verification
does not depend on a new `PackageRecord` field.

Publisher authorization is not configured by this plugin. CEP 27 does not
standardize how conda channels distribute publisher delegation. The `verify`
command can apply an exact identity and issuer for one invocation without
persisting either value in this setting. Install verification establishes
evidence validity, not signer authorization.

## Trust configuration responsibility

A local trust configuration changes the cryptographic root used by
sigstore-python. Parsing the file is not proof that it was distributed
authentically or that it is current. Operators own authenticated provisioning,
rotation, rollback protection, and incident response for custom trust material.
