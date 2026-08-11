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

Install enforcement is not registered because released conda versions do not
yet provide both the required package-verifier hook and opaque
`PackageRecord.attestations` preservation. The future adapter is designed to
fail closed for these conditions:

- the selected input is a `MatchSpec`, including a local or explicit input
- repodata does not advertise an attestation descriptor
- the sidecar is missing, unavailable, malformed, or does not match its
  advertised size and SHA-256
- no bundle contains a valid CEP 27 statement bound to the exact artifact
  filename and SHA-256
- an included target-channel claim does not match the selected channel

The future install verifier reads only the repodata-advertised `.sigs` sidecar.
It never probes for or consumes Prefix.dev `.v0.sigs` sidecars. A successful
check cryptographically authenticates the bundle signer but does not authorize
that signer for the channel.

## Trust configuration responsibility

A local trust configuration changes the cryptographic root used by
sigstore-python. Parsing the file is not proof that it was distributed
authentically or that it is current. Operators own authenticated provisioning,
rotation, rollback protection, and incident response for custom trust material.
