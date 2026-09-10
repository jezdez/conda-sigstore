# Source-attestation audit format

`conda sigstore audit --sources` implements an audit-only subset of the open
[conda/ceps#168](https://github.com/conda/ceps/pull/168) proposal. The proposal
is not an accepted CEP and its recipe and package layout may change.

This page describes the current `conda-sigstore` parser. It is not a stable
recipe-format standard.

## Audit preconditions

Source auditing runs for a package only when:

1. the package has a verified, artifact-bound CEP 27 publication statement
2. the exact package archive remains in conda's package cache
3. the archive contains `info/recipe/rendered_recipe.yaml`

If a precondition fails, `source_evidence` contains an
`evidence-unavailable` result. Source evidence never substitutes for package
publication verification.

## Archive inspection

The auditor copies the retained archive to a temporary snapshot and checks its
SHA-256 against the verified package digest before inspecting it. It reads only
regular rendered-recipe and embedded-bundle files, without general package
extraction. For `.conda` packages, the original package filename selects the
exact `info-<package-filename-without-.conda>.tar.zst` component.

Unsafe archive paths are rejected. Selected recipe and bundle entries must be
regular files with unique paths. Links and special files at those paths are
invalid. Unrelated members are never copied or used as evidence. A malformed
archive, including an invalid bzip2 stream, produces an `invalid` source result.
A missing or unreadable archive produces `evidence-unavailable`.

Sparse files are unsupported. Skipped regular-file payload still counts toward
the expanded-byte limit but does not consume the tar metadata budget.

(source-audit-limits)=
## Source-audit limits

The fixed limits apply only to source auditing and do not restrict package
installation. Embedded bundles use the existing
`plugins.conda_sigstore.max_sidecar_bytes` setting. None of these limits
authorizes a signer.

| Input | Maximum | Result when exceeded |
| --- | --- | --- |
| Compressed retained package archive | 4 GiB | `evidence-unavailable` |
| Expanded tar stream, including headers and skipped payload in legacy `.tar.bz2` packages | 256 MiB | `invalid` |
| Tar parser reads outside regular-file payload reads | 16 MiB | `invalid` |
| Tar members | 10,000 | `invalid` |
| One ZIP metadata read | 1 MiB | `invalid` |
| ZIP entries | 16 | `invalid` |
| Zstandard decoder window | 64 MiB | `invalid` |
| Rendered recipe | 1 MiB of UTF-8 bytes | `invalid` |
| YAML collection nesting | 32 levels | `invalid` |
| YAML parsing events | 10,000 | `invalid` |
| Source mappings per recipe | 100 | `invalid` |
| Publishers per source | 16 | `invalid` |
| Embedded bundle descriptors per source | 32 | `invalid` |
| Publisher and embedded bundle declarations combined across a recipe | 256 | `invalid` |
| Each embedded bundle | Configured `max_sidecar_bytes` | `invalid` |

YAML aliases are rejected. The auditor checks YAML events and nesting before
constructing the recipe mapping, then counts publisher and bundle declarations
before constructing source-attestation requirements.

## Rendered recipe declaration

The rendered recipe may declare `attestation` on one or more URL sources:

```yaml
source:
  url: https://github.com/example/project/archive/v1.0.0.tar.gz
  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  attestation:
    publishers:
      - github:example/project
      - identity: release@example.org
        issuer: https://accounts.example.org
    predicate_type: https://slsa.dev/provenance/v1
    verified:
      - path: attestations/project-1.0.0.sigstore.json
        sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

`source` may be one mapping or a list of mappings. A source without
`attestation` is ignored.

| Field | Required | Current parser contract |
| --- | --- | --- |
| `source.url` | yes | Marks this as a URL source. `git` and `path` must be absent |
| `source.sha256` | yes | 64 hexadecimal characters, normalized to lowercase |
| `attestation.publishers` | yes | Nonempty list of publisher strings or explicit identity mappings |
| `attestation.predicate_type` | no | Nonempty string that every counted embedded statement must match |
| `attestation.verified` | no | List of embedded bundle descriptors, defaulting to an empty list |

An empty or omitted `verified` list produces a `missing` source result. The
auditor does not fetch `bundle_url`, derive PyPI Integrity API URLs, or convert
PEP 740 responses. Those are builder-side parts of the draft proposal.

## Publisher identities

An explicit publisher contains exactly two fields:

```yaml
identity: https://github.com/example/project
issuer: https://token.actions.githubusercontent.com
```

Both values must be nonempty strings. The issuer is compared exactly.

For an identity beginning with `https://`, matching is case-insensitive. An
authenticated certificate identity matches when it is equal to the configured
identity or continues it with `/` or `@`.
This lets a repository identity match its workflow SAN without also matching a
similarly prefixed repository. Other identity forms, including email SANs, are
compared exactly and case-sensitively.

The parser also accepts two hosted-provider shorthands:

| Shorthand | Identity expansion | Issuer expansion |
| --- | --- | --- |
| `github:OWNER/REPOSITORY` | `https://github.com/OWNER/REPOSITORY` | `https://token.actions.githubusercontent.com` |
| `gitlab:NAMESPACE/REPOSITORY` | `https://gitlab.com/NAMESPACE/REPOSITORY` | `https://gitlab.com` |

Nested repository paths are accepted. An `@REF` suffix is rejected because the
draft does not yet define ref matching. Unknown providers are rejected.

Every declared publisher must match at least one cryptographically verified
embedded bundle.

## Embedded bundle descriptor

Each `attestation.verified` entry must provide:

```yaml
path: attestations/project-1.0.0.sigstore.json
sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

| Field | Contract |
| --- | --- |
| `path` | POSIX path relative to `info/recipe`, with exactly two components, first component `attestations`, and filename ending in `.sigstore.json` |
| `sha256` | 64-character hexadecimal digest of the exact embedded file bytes |

Absolute paths, backslashes, parent traversal, NUL characters, symlinks, and
non-regular files are rejected. Bundle bytes are bounded by
`plugins.conda_sigstore.max_sidecar_bytes` before parsing.

The draft proposal also shows copied `predicate_type`, `san`, and `issuer`
fields in `verified` entries. The auditor deliberately does not trust those
claims. It reads only `path` and `sha256`, then obtains the predicate type,
certificate identity, and issuer from the cryptographically verified bundle.

## Bundle acceptance

Every listed embedded bundle must pass all of these checks:

1. its bytes match the descriptor SHA-256
2. Sigstore verifies its certificate chain, transparency-log material, and
   DSSE signature against the selected trust configuration
3. its DSSE payload is an in-toto Statement v1 JSON object
4. at least one statement subject has a SHA-256 matching `source.sha256`
5. its `predicateType` matches `attestation.predicate_type` when configured

Missing, invalid, or unavailable sibling bundles make the source result
nonverified. When all bundles verify, every declared publisher must match an
authenticated bundle signer.

The auditor does not disable transparency-log verification for converted PyPI
bundles because the embedded index has no authenticated conversion-provenance
field.

## Result contract

Source results and embedded bundle variants are defined in
[JSON output and exit status](json-output.md). They report verified evidence
from a package archive. They do not authorize the package publisher, assign a
SLSA level, or prove that source contents are safe.
