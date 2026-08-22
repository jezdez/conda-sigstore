# Library API

The library API exposes a generic in-toto signing and verification boundary for
conda tools that define their own statement predicates. Package publication
continues to use the stricter CEP 27 models and command interface.

## Sign an in-toto statement

Parse the statement before asking Sigstore to sign it:

```python
from conda_sigstore.attestation import sign_in_toto_statement
from conda_sigstore.statements import InTotoStatement

statement = InTotoStatement.from_payload(
    {
        "_type": InTotoStatement.STATEMENT_TYPE,
        "subject": [
            {
                "name": "conda.lock",
                "digest": {"sha256": lockfile_sha256},
            }
        ],
        "predicateType": "https://example.org/workspace/v1",
        "predicate": {"workspace": "example"},
    }
)
bundle_json = sign_in_toto_statement(statement)
```

`InTotoStatement.payload()` produces stable UTF-8 JSON bytes. The signing call
uses Sigstore's ambient credential discovery, returns one raw Bundle v0.3 JSON
object, and locally verifies that the bundle contains the exact statement
payload. It does not write a sidecar or accept an identity token as an
argument.

`sign_statement()` remains the CEP 27 wrapper. It accepts a
`PublishStatement`, requires `targetChannel`, and delegates the cryptographic
operation to the generic signer.

## Verify an in-toto statement

```python
from conda_sigstore.verification import SigstoreVerifier

verified = SigstoreVerifier(
    offline=offline,
    trust_config=trust_config,
).verify_statement(bundle_json)

statement = verified.statement
signer = verified.signer
timestamps = verified.timestamps
```

`verify_statement()` verifies the Sigstore bundle and transparency material,
requires the DSSE in-toto payload type, and strictly parses an in-toto Statement
v1. Its result also preserves the exact `payload` bytes.

The result reports authenticated signer evidence. It does not decide whether
that signer is authorized for the caller's predicate or resource. A consuming
tool must validate its predicate, bind every subject to the exact bytes it will
use, and apply any explicit authorization policy separately.

## File ownership

The generic API accepts and returns in-memory values. The consuming tool owns
bounded reads, path safety, source-generation checks, and atomic output. Use
`DEFAULT_MAX_SIDECAR_BYTES` from `conda_sigstore.settings` as the default
10 MiB bundle limit unless the integration defines a smaller bound.
