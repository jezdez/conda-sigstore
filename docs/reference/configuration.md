# Configuration

The plugin registers one structured setting for operational inputs and one
flat boolean for package-verifier activation:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: null
  conda_sigstore_enforce: false
```

Omitting either setting uses the values shown above. Installing the plugin does
not change package operations.

## Fields

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_sidecar_bytes` | positive integer | `10485760` | Maximum bundle or sidecar bytes read before parsing |
| `trust_config` | local path or `null` | `null` | Optional Sigstore client trust configuration |

The separate `plugins.conda_sigstore_enforce` setting is a boolean and defaults
to `false`. With `true`, the plugin registers conda's package verifier and
requires valid repodata-advertised CEP 27 evidence before extraction.

Conda exposes the flat setting as an environment variable:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

The environment variable applies normal conda configuration precedence and is
suited to one command. The structured `conda_sigstore` object is not duplicated
in a plugin-specific environment-variable format.

Unknown fields are rejected. `trust_config` must identify an existing local
file. With `null`, verification uses Sigstore's production trust configuration.

Publisher authorization is not configured by this plugin. CEP 27 does not
standardize how conda channels distribute publisher delegation. The `verify`
command can apply an exact identity and issuer for one invocation without
persisting either value in this setting.

Install verification uses conda's required always-run package-verifier hook and
the repodata `attestations` descriptor preserved on the selected
`PackageRecord`. When enabled, these conditions fail closed:

- the selected input is a `MatchSpec`, including a local or explicit input
- repodata does not advertise an attestation descriptor
- the sidecar is missing, unavailable, malformed, or does not match its
  advertised size and SHA-256
- no bundle contains a valid CEP 27 statement bound to the exact artifact
  filename and SHA-256
- an included target-channel claim does not match the selected channel

The install verifier reads only the repodata-advertised `.sigs` sidecar. It
never probes for or consumes Prefix.dev `.v0.sigs` sidecars. A successful check
cryptographically authenticates the bundle signer but does not authorize that
signer for the channel.

## Trust configuration responsibility

A local trust configuration changes the cryptographic root used by
sigstore-python. Parsing the file is not proof that it was distributed
authentically or that it is current. Operators own authenticated provisioning,
rotation, rollback protection, and incident response for custom trust material.
