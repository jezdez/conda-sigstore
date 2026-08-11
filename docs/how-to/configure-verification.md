# Configure verification

`conda-sigstore` uses Sigstore's production trust configuration and a 10 MiB
sidecar limit by default. Install verification is disabled by default. No
`.condarc` entry is required for signing, explicit verification, or auditing.

The optional `plugins.conda_sigstore` setting controls only operational inputs:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: null
```

It does not contain publisher identities, package rules, transport selection,
or install-verifier activation.

## Enable the package verifier

The flat `plugins.conda_sigstore_enforce` setting controls the opt-in verifier:

```yaml
plugins:
  conda_sigstore_enforce: true
```

For one process, use conda's environment-variable form instead:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

When enabled, the verifier requires a repodata `attestations` descriptor,
fetches only the descriptor-selected `.sigs` sidecar, and fails closed for
missing, unavailable, malformed, invalid, or nonmatching evidence. It never
probes for a sidecar and never falls back to Prefix.dev `.v0.sigs` input.

:::{warning}
This is an integration preview. It requires the unreleased conda API in
[conda/conda#16518](https://github.com/conda/conda/pull/16518), provided by the
locked developer environments through `jezdez/conda` branch
`feature/package-verifiers`. PR #16518 does not preserve the repodata
`attestations` descriptor on `PackageRecord`. Ordinary solved records therefore
cannot currently pass when enforcement is enabled. A separate upstream change
must add that preservation.
:::

The verifier establishes that valid evidence binds the exact package. It does
not establish that the signer was authorized to publish it.

## Change the input limit

Set `max_sidecar_bytes` to a positive integer when your channel's bundle arrays
need a different bound:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 20971520
    trust_config: null
```

The limit applies before JSON and bundle parsing. Repodata-advertised sidecars
must also match their descriptor's exact size and SHA-256.

## Use managed trust material

Set `trust_config` to a local Sigstore client trust configuration when an
operator manages trust material outside Sigstore's production TUF service:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: /etc/conda/sigstore/trusted-root.json
```

The file must exist and parse as a Sigstore trust configuration. Successful
parsing does not prove authenticated distribution, freshness, or rollback
protection. Provision and update it through a separate authenticated process.

## Keep authorization separate

Do not add certificate allowlists to this setting. Sigstore authenticates the
signer reported by a bundle, but current conda standards do not distribute a
channel's publisher delegation policy. The plugin reports signer identity and
issuer without turning local configuration into an invented authorization
protocol. Use the paired `verify --cert-identity` and `--cert-oidc-issuer`
options for an explicit one-off signer requirement.

See [Configuration](../reference/configuration.md) for the exact setting
contract and [Security model](../explanation/security-model.md) for the trust
boundary.
