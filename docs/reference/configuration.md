# Configuration

The plugin registers one structured setting for operational inputs:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: null
```

Omitting the setting uses the values shown above. Installing the plugin does
not change package operations.

## Fields

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

Publisher authorization is not configured by this plugin. CEP 27 does not
standardize how conda channels distribute publisher delegation. The `verify`
command can apply an exact identity and issuer for one invocation without
persisting either value in this setting.

## Trust configuration responsibility

A local trust configuration changes the cryptographic root used by
sigstore-python. Parsing the file is not proof that it was distributed
authentically or that it is current. Operators own authenticated provisioning,
rotation, rollback protection, and incident response for custom trust material.
