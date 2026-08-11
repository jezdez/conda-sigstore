# JSON output and exit status

`conda sigstore verify --json` and `conda sigstore audit --json` write one JSON
value to stdout. They do not mix human-readable status lines or ANSI styling
with that value. The top-level `version` selects the output schema described
here.

## Verification result version 1

The verification command returns this object shape:

```json
{
  "version": 1,
  "artifact": "example-1.0-0.conda",
  "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sidecar_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "channel": "https://conda.example.org/team",
  "status": "verified",
  "authorization": "not-evaluated",
  "expected_signer": null,
  "prefix_sidecar": false,
  "evidence": [
    {
      "bundle_index": 0,
      "identity": "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.0.0",
      "issuer": "https://token.actions.githubusercontent.com",
      "predicate_type": "https://schemas.conda.org/attestations-publish-1.schema.json",
      "verified": true,
      "timestamps": ["2026-08-10T12:00:00Z"],
      "details": {
        "target_channel": "https://conda.example.org/team"
      }
    }
  ],
  "failures": []
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | integer | Schema version, currently `1` |
| `artifact` | string | Exact package filename without its input path |
| `artifact_sha256` | string or `null` | SHA-256 computed from artifact bytes when available, otherwise the installed record's digest claim |
| `sidecar_sha256` | string or `null` | SHA-256 computed from the exact bundle or sidecar input bytes |
| `channel` | string or `null` | Credential-free normalized channel supplied to verification |
| `status` | string | Overall verification status |
| `authorization` | string | Result of an explicit signer requirement, not channel authorization |
| `expected_signer` | object or `null` | Supplied exact `identity` and literal `issuer` pair |
| `prefix_sidecar` | boolean | Whether the input used Prefix.dev's `.v0.sigs` convention |
| `evidence` | array | Cryptographically authenticated bundle evidence |
| `failures` | array | Rejected bundle and verification-stage failures |

`authorization` is `not-evaluated` when no signer requirement was supplied,
`verified` when a valid CEP 27 statement has the required signer, and `failed`
otherwise. It never means that the channel authorized the signer.

## Evidence objects

Each `evidence` item has every field shown here:

```json
{
  "bundle_index": 0,
  "identity": "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.0.0",
  "issuer": "https://token.actions.githubusercontent.com",
  "predicate_type": "https://schemas.conda.org/attestations-publish-1.schema.json",
  "verified": true,
  "timestamps": ["2026-08-10T12:00:00Z"],
  "details": {
    "target_channel": "https://conda.example.org/team"
  }
}
```

`bundle_index` is the zero-based position in the sidecar array. `identity` and
`issuer` come from the verified signing certificate. `predicate_type` is a
string or `null`. `verified` means that the parsed statement passed the checks
for its predicate. It does not mean that the predicate satisfies the top-level
CEP 27 publication requirement or that its signer is authorized.

For CEP 27, `details` contains `target_channel` as a string or `null`. For SLSA
Provenance v1, it contains `subjects` and this `provenance` object:

```json
{
  "builder": "https://example.org/builder",
  "build_type": "https://example.org/build/v1",
  "invocation": "run-1",
  "materials": [
    {
      "uri": "git+https://example.org/project",
      "digest": {"gitCommit": "abc123"}
    }
  ],
  "external_parameters": {},
  "internal_parameters": {},
  "started_on": "2026-08-10T10:00:00Z",
  "finished_on": "2026-08-10T10:01:00Z"
}
```

`invocation`, `started_on`, and `finished_on` may be `null`.
`subjects` is the statement's array of `{name, digest}` objects. The plugin
reports all provenance materials and does not assign a SLSA level.

## Failure objects

Every failure contains `code` and `message`. `bundle_index` is present only
when the failure belongs to one array element:

```json
{
  "code": "invalid-cep27",
  "message": "subject sha256 does not match the package",
  "bundle_index": 1
}
```

Failure codes identify the rejected condition for machines. Messages are
diagnostic text and may gain detail without changing the schema.

## Status values

| Status | Meaning |
| --- | --- |
| `verified` | At least one valid CEP 27 statement binds the exact artifact and satisfies any explicit signer requirement |
| `missing` | Audit found no advertised descriptor or explicitly selected Prefix.dev sidecar |
| `retrieval-failed` | Advertised audit evidence could not be read or failed size or digest checks |
| `invalid` | Evidence is malformed, cryptographically invalid, unsupported, or not bound to the artifact |
| `untrusted-identity` | A required identity and issuer did not match verified evidence |
| `record-digest-only` | Audit found no retained package archive to hash |
| `evidence-unavailable` | Required trust material, cached offline evidence, or another input is unavailable |

## Audit report version 1

The audit command wraps one verification result for each installed package:

```json
{
  "version": 1,
  "prefix": "/srv/conda/envs/runtime",
  "packages": []
}
```

`prefix` is the resolved absolute environment path. `packages` is ordered by
normalized package name. Every item has the verification result version 1
fields above.

With `--sources`, each package also has `source_evidence`. A parsed source
requirement uses this shape:

```json
{
  "source_index": 0,
  "source_sha256": "<64 lowercase hexadecimal characters>",
  "status": "verified",
  "predicate_type": "https://example.org/source/v1",
  "required_publishers": [
    {"identity": "https://github.com/example/project", "issuer": "https://token.actions.githubusercontent.com"}
  ],
  "matched_publishers": [
    {"identity": "https://github.com/example/project", "issuer": "https://token.actions.githubusercontent.com"}
  ],
  "bundles": [],
  "package_publication": "verified",
  "verification_scope": "draft-source-attestation"
}
```

An unsuccessful source result also has `failure`. Each `bundles` item always
has `path`, `sha256`, and `status`. A verified bundle adds `identity`, `issuer`,
`predicate_type`, and `timestamps`. A rejected bundle adds `failure`. When the
package publication, retained archive, or rendered recipe prevents source
inspection, the result contains only `status`, `failure`, and
`verification_scope`.

Without `--sources`, `source_evidence` is absent.

## Exit status

| Command | Exit status |
| --- | --- |
| `attest` | `0` after writing and locally verifying the bundle |
| `verify` | `0` only when the top-level status is `verified`, otherwise `1` |
| `audit` | `0` after producing a report, regardless of individual package statuses |

Argument, input, configuration, and command setup failures are conda errors and
exit nonzero. Do not use the audit process status as a package-verification
decision. Read each package's `status` field instead.
