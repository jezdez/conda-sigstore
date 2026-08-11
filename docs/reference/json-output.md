# JSON output and exit status

When verification or auditing produces a plugin result, `--json` and
`--console json` write the same JSON value to stdout without human status lines
or ANSI styling. Only `--json` also selects conda's JSON error reporter for an
argument, input, configuration, or command setup failure. Those conda error
objects are outside the contracts on this page.

Every top-level `conda-sigstore` result has a `version`. Consumers must select
the contract by that integer. The current verification and audit contract is
version `1`.

## Verification result version 1

The verification result always has these fields:

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
  "evidence": [],
  "failures": []
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `version` | integer | Exactly `1` |
| `artifact` | string | Package filename without its local input path |
| `artifact_sha256` | string or `null` | Lowercase SHA-256 computed from the archive, or an installed record digest when no archive is retained |
| `sidecar_sha256` | string or `null` | Lowercase SHA-256 of the exact bundle or sidecar input bytes, or `null` when no sidecar was loaded |
| `channel` | string or `null` | Credential-free normalized channel or audit channel label |
| `status` | verification status | Overall result from the enumeration below |
| `authorization` | authorization result | Result of an explicit signer requirement, not channel authorization |
| `expected_signer` | signer object or `null` | Exact `identity` and `issuer` pair supplied to `verify` |
| `prefix_sidecar` | boolean | Whether the selected input used Prefix.dev's `.v0.sigs` convention |
| `evidence` | array of evidence objects | Cryptographically authenticated bundle contents |
| `failures` | array of failure objects | Rejected bundles and verification-stage failures |

An `expected_signer` object always has this shape:

```json
{
  "identity": "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.0.0",
  "issuer": "https://token.actions.githubusercontent.com"
}
```

### Verification status

| Value | Meaning |
| --- | --- |
| `verified` | At least one cryptographically valid CEP 27 statement binds the exact package and satisfies any explicit signer requirement |
| `missing` | Audit found no advertised descriptor or no explicitly selected Prefix.dev sidecar |
| `retrieval-failed` | Advertised or selected audit evidence could not be retrieved or failed its transport size or digest check |
| `invalid` | No acceptable CEP 27 statement exists because the descriptor, container, bundle, statement, or artifact binding is invalid or unsupported |
| `untrusted-identity` | A valid CEP 27 statement exists, but its signer does not match the explicit identity and issuer requirement |
| `record-digest-only` | Audit has an installed record digest but no retained package archive to hash and verify |
| `evidence-unavailable` | Required trust material, offline cached evidence, the package archive, or another verification input is unavailable |

### Authorization result

| Value | Meaning |
| --- | --- |
| `not-evaluated` | No explicit signer pair was supplied |
| `verified` | A valid CEP 27 statement has the required signer pair |
| `failed` | An explicit signer pair was supplied and the top-level status is not `verified` |

This field never means that a channel delegated publication authority to the
signer.

## Evidence objects

Every `evidence` item has these fields:

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

| Field | Type | Contract |
| --- | --- | --- |
| `bundle_index` | nonnegative integer | Zero-based position in the sidecar array |
| `identity` | string | Subject Alternative Name from the verified signing certificate |
| `issuer` | string | OIDC issuer from the verified signing certificate |
| `predicate_type` | string or `null` | Parsed in-toto `predicateType`, or `null` when no statement could be parsed |
| `verified` | boolean | Whether checks for this recognized predicate passed |
| `timestamps` | array of strings | Reported verified Rekor integrated times and supported RFC 3161 times, normalized to UTC when possible |
| `details` | object | Predicate-specific facts from one of the variants below |

An evidence object appears only after Sigstore cryptographic verification has
succeeded. `verified: false` means that the authenticated payload type,
statement, predicate, or artifact binding was not accepted. It does not mean
that the certificate identity was unauthenticated.

`details` has one of these variants:

| Predicate result | `predicate_type` | `verified` | `details` |
| --- | --- | --- | --- |
| Valid CEP 27 | CEP 27 predicate URI | `true` | `{"target_channel": string or null}` |
| Valid SLSA Provenance v1 | `https://slsa.dev/provenance/v1` | `true` | `{"subjects": [...], "provenance": {...}}` |
| Invalid or unsupported authenticated payload | string or `null` | `false` | `{}` |

A SLSA `subjects` entry has `name` and `digest`, where `digest` maps algorithm
names to string values. The `provenance` object always has every field shown
here:

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

`builder` and `build_type` are strings. `invocation`, `started_on`, and
`finished_on` are strings or `null`. `materials` is an array of objects with a
string `uri` and string-to-string `digest` mapping. `external_parameters` and
`internal_parameters` are JSON objects. The plugin reports these facts without
assigning a SLSA level.

## Failure objects

Every failure has `code` and `message`. `bundle_index` is included only when
the failure belongs to one sidecar element:

```json
{
  "code": "invalid-cep27",
  "message": "subject sha256 does not match the package",
  "bundle_index": 1
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `code` | failure code | Stable machine identifier from the enumeration below |
| `message` | string | Diagnostic text whose wording may gain detail |
| `bundle_index` | nonnegative integer, optional | Sidecar position responsible for the failure |

Version 1 can emit these failure codes:

| Code | Meaning |
| --- | --- |
| `artifact-changed` | The artifact SHA-256 changed while direct verification was running |
| `artifact-digest-mismatch` | A retained archive does not match its installed package record |
| `digest-mismatch` | Sidecar bytes do not match the repodata descriptor SHA-256 |
| `evidence-unavailable` | Trust material or another input required to verify evidence is unavailable |
| `invalid-bundle` | Sigstore bundle parsing or cryptographic verification failed |
| `invalid-cep27` | CEP 27 structure, filename, digest, or target-channel binding failed |
| `invalid-descriptor` | The repodata `attestations` descriptor has the wrong type, fields, or values |
| `invalid-provenance` | SLSA Provenance v1 structure or artifact binding failed |
| `invalid-response` | A sidecar fetch implementation returned a value other than bytes |
| `invalid-sidecar` | Sidecar JSON, duplicate-key handling, or bundle-array structure is invalid |
| `invalid-statement` | The authenticated payload is not a valid in-toto Statement v1 |
| `invalid-url` | A package or sidecar URL is invalid or uses an unsupported scheme |
| `missing-attestations` | An audit record does not advertise the draft repodata descriptor |
| `missing-publish-attestation` | Authenticated evidence contains no CEP 27 publication statement |
| `missing-sidecar` | The selected adjacent or advertised sidecar does not exist |
| `offline-cache-miss` | Offline mode has no matching cached sidecar |
| `record-digest-only` | No retained package archive is available for audit verification |
| `retrieval-failed` | A local or remote sidecar could not be read |
| `sidecar-too-large` | Input exceeds `max_sidecar_bytes` or its advertised size exceeds that limit |
| `size-mismatch` | Sidecar bytes do not match the repodata descriptor size |
| `unsupported-payload-type` | A valid bundle carries a DSSE payload type other than in-toto JSON |
| `unsupported-predicate` | A valid in-toto statement uses an unrecognized predicate type |
| `untrusted-identity` | Certificate identity and issuer do not match the explicit signer requirement |

A local or remote `verify --bundle` transport failure occurs before a
verification result exists. Conda reports it as a nonzero command error and
preserves the transport code where available. Audit converts per-package
transport failures into the version 1 package result above.

## Audit report version 1

The audit command wraps one verification result for each installed package:

```json
{
  "version": 1,
  "prefix": "/srv/conda/envs/runtime",
  "packages": []
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `version` | integer | Exactly `1` |
| `prefix` | string | Resolved absolute environment prefix |
| `packages` | array | Version 1 verification results ordered by installed record name |

Without `--sources`, package results have exactly the verification fields
defined above. With `--sources`, every package result also has a
`source_evidence` array. The array may be empty when no source declares draft
attestation evidence.

## Parsed source result

A parsed source requirement has this complete shape:

```json
{
  "source_index": 0,
  "source_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "status": "verified",
  "predicate_type": "https://slsa.dev/provenance/v1",
  "required_publishers": [
    {
      "identity": "https://github.com/example/project",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  ],
  "matched_publishers": [
    {
      "identity": "https://github.com/example/project",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  ],
  "bundles": [
    {
      "path": "attestations/project-1.0.0.sigstore.json",
      "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "status": "verified",
      "identity": "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.0.0",
      "issuer": "https://token.actions.githubusercontent.com",
      "predicate_type": "https://slsa.dev/provenance/v1",
      "timestamps": ["2026-08-10T12:00:00Z"]
    }
  ],
  "package_publication": "verified",
  "verification_scope": "draft-source-attestation"
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `source_index` | nonnegative integer | Position in the rendered recipe's source list |
| `source_sha256` | string | Lowercase SHA-256 declared by the recipe source |
| `status` | source status | Overall source result from the enumeration below |
| `predicate_type` | string or `null` | Optional predicate requirement declared by the recipe |
| `required_publishers` | array of signer objects | Expanded recipe publisher requirements |
| `matched_publishers` | array of signer objects | Required publisher objects that matched authenticated bundle signers |
| `bundles` | array of embedded bundle results | One result for every `verified` descriptor in the rendered recipe |
| `package_publication` | string | Exactly `verified` for a parsed source result |
| `verification_scope` | string | Exactly `draft-source-attestation` |
| `failure` | string, optional | Present when the source status is not `verified` |

When more than one bundle outcome applies, version 1 selects the source status
in this order: `missing`, `invalid`, `evidence-unavailable`, then
`untrusted-identity`.

| Value | Meaning |
| --- | --- |
| `verified` | Every embedded bundle verifies and every required publisher matches |
| `missing` | No bundle was listed or at least one listed bundle is absent |
| `invalid` | At least one embedded bundle or its source binding is invalid |
| `evidence-unavailable` | Trust material or bundle bytes could not be read |
| `untrusted-identity` | Not every required publisher matched a verified bundle signer |

Each embedded bundle result always has `path`, `sha256`, and `status`.

| Bundle `status` | Additional fields |
| --- | --- |
| `verified` | `identity`, `issuer`, `predicate_type`, and `timestamps` |
| `missing` | none |
| `invalid` | `failure` |
| `evidence-unavailable` | `failure` |

The exact rendered-recipe input is defined in
[Source-attestation audit format](source-attestations.md).

## Source inspection failure

When package publication, archive retention, extraction, or rendered-recipe
parsing prevents a source requirement from being produced, the array contains
this smaller variant:

```json
{
  "status": "evidence-unavailable",
  "failure": "verified package publication evidence is unavailable",
  "verification_scope": "draft-source-attestation"
}
```

This variant has exactly `status`, `failure`, and `verification_scope`.
`status` is `evidence-unavailable` for missing operational inputs or `invalid`
for malformed package-controlled input.

## Exit status

| Command | Exit status |
| --- | --- |
| `attest` | `0` after writing and locally verifying the bundle |
| `verify` | `0` only when the top-level status is `verified`, otherwise `1` |
| `audit` | `0` after producing a report, regardless of individual package statuses |

Argument, input, configuration, and command setup failures are conda errors and
exit nonzero. Do not use the audit process status as a package-verification
decision. Read each package `status` instead.
