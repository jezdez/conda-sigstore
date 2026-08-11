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
| `plugins.conda_sigstore_enforce` | boolean | `false` | Require valid repodata-advertised CEP 27 evidence before package extraction |

Conda also accepts the standard environment-variable override:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

The hook is registered directly against the unreleased API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518). It is not an
optional compatibility hook. When enabled, missing, unavailable, malformed,
invalid, or nonmatching evidence fails the package. Only the draft
repodata-advertised `.sigs` transport is accepted. Prefix.dev `.v0.sigs` is not
a fallback.

PR #16518 does not preserve the repodata `attestations` descriptor on
`PackageRecord`. Ordinary solved records therefore cannot currently pass the
enabled verifier until a separate upstream preservation change lands.

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
