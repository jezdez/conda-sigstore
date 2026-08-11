# Configure verification

`conda-sigstore` uses Sigstore's production trust configuration and a 10 MiB
sidecar limit by default. Install verification is disabled. No `.condarc` entry
is required.

The optional `plugins.conda_sigstore` setting controls only operational inputs:

```yaml
plugins:
  conda_sigstore:
    max_sidecar_bytes: 10485760
    trust_config: null
```

It does not contain publisher identities, package rules, transport selection,
or install-verifier activation.

## Require evidence for one package operation

Use conda's environment variable for the flat activation setting:

```console
CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE=true conda install PACKAGE
```

The plugin requires conda's package-verifier hook and preservation of repodata
attestation descriptors. Every selected package must have a
repodata-advertised `.sigs` sidecar containing at least one valid CEP 27
statement for its exact filename and SHA-256.

The operation fails if evidence is missing, unavailable, malformed, invalid, or
bound to another artifact or target channel. Local files and other explicit
inputs represented by a `MatchSpec` fail because they have no repodata
descriptor. The install verifier does not probe for an undeclared `.sigs` file
and never uses Prefix.dev `.v0.sigs` sidecars.

## Enable verification persistently

Set the flat plugin setting with conda's configuration command:

```console
conda config --set plugins.conda_sigstore_enforce true
```

Disable it again with:

```console
conda config --set plugins.conda_sigstore_enforce false
```

Persistent activation is global to every package operation that uses that
configuration source. Installing the plugin alone does not activate it.

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

The install verifier therefore enforces evidence validity and coverage, not
signer authorization. Any Sigstore identity with a valid, exact artifact-bound
CEP 27 statement can satisfy the install check.

See [Configuration](../reference/configuration.md) for the exact setting
contract and [Security model](../explanation/security-model.md) for the trust
boundary.
