# Configuration

The plugin registers one structured setting for operational inputs and one
flat boolean for opt-in package verification:

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

## Operational settings

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_sidecar_bytes` | positive integer | `10485760` | Maximum bundle or sidecar bytes read before parsing |
| `trust_config` | local path or `null` | `null` | Complete Sigstore client trust configuration used for signing and verification |

Unknown fields are rejected. A configured `trust_config` path is expanded from
`~` and must identify an existing regular file. The file is read with a 1 MiB
limit before JSON parsing.

Source auditing has separate package-controlled input limits. Retained package
archives larger than 4 GiB and rendered recipes larger than 1 MiB are reported
as unavailable evidence before parsing.

## `trust_config` file contract

`trust_config` must contain the complete JSON object accepted by
`sigstore.models.ClientTrustConfig.from_json()` in the supported
`sigstore-python` 4.x series. A `TrustedRoot` object by itself is not a valid
value.

The required top-level shape is:

```json
{
  "mediaType": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
  "trustedRoot": {
    "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "tlogs": [],
    "certificateAuthorities": [],
    "ctlogs": [],
    "timestampAuthorities": []
  },
  "signingConfig": {
    "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.1+json",
    "caUrls": [],
    "oidcUrls": [],
    "rekorTlogUrls": [],
    "rekorTlogConfig": null,
    "tsaUrls": [],
    "tsaConfig": null
  }
}
```

This example shows the fields, not a usable trust configuration. The arrays
must contain the keys, certificates, validity intervals, operators, and
service endpoints for the Sigstore instance. Binary keys and certificates use
the base64 encoding defined by the Sigstore protobuf JSON mapping.

| Top-level field | Required value |
| --- | --- |
| `mediaType` | Exactly `application/vnd.dev.sigstore.clienttrustconfig.v0.1+json` |
| `trustedRoot` | A Sigstore `TrustedRoot` containing transparency-log keys, Fulcio certificate authorities, certificate-transparency log keys, and optional timestamp authorities |
| `signingConfig` | A Sigstore `SigningConfig` containing the Fulcio, OIDC, Rekor, and optional timestamp-authority service configuration |

The nested `TrustedRoot`, `SigningConfig`, certificate, public-key, service,
and validity structures are defined by the
[Sigstore trust-root protobuf](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto).
The parser rejects unknown fields and unsupported media types.

Verification reads `trustedRoot`. `conda sigstore attest` also reads
`signingConfig` to obtain OIDC, Fulcio, Rekor, and timestamp service
configuration. This is why the setting requires the complete client trust
configuration even when an operator only plans to verify locally.

With `trust_config: null`, the plugin obtains Sigstore's production client
trust configuration. Verification honors conda's offline setting and uses the
local Sigstore TUF cache when offline. A configured file is read directly and
is not updated through TUF by this plugin.

Parsing a local file proves only that it has the expected structure. Operators
are responsible for authenticated provisioning, freshness, rotation, rollback
protection, and incident response for custom trust material.

## Install-enforcement setting

| Setting | Type | Default | Meaning |
| --- | --- | --- | --- |
| `plugins.conda_sigstore_enforce` | boolean | `false` | Require valid CEP 27 evidence before package extraction |

Conda accepts its standard environment-variable override:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

The hook is registered against the unreleased API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518). See
[Upstream integration contracts](upstream-contracts.md) for its inputs,
evidence selection, and rejection behavior.
