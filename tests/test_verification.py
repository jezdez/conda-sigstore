from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.x509 import (
    Extension,
    Extensions,
    ObjectIdentifier,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
    UnrecognizedExtension,
)
from cryptography.x509.oid import ExtensionOID
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.char import UTF8String

from conda_sigstore.evidence import (
    AuthorizationStatus,
    Sidecar,
    SignerIdentity,
    VerificationStatus,
)
from conda_sigstore.exceptions import (
    BundleVerificationError,
    TrustMaterialUnavailableError,
)
from conda_sigstore.provenance import SlsaProvenance
from conda_sigstore.statements import InTotoStatement, PublishStatement
from conda_sigstore.verification import (
    CryptographicVerification,
    SigstoreBundleMaterial,
    SigstoreVerifier,
    verify_artifact,
    verify_bundles,
)

FILENAME = "pkg-1.0-0.conda"
DIGEST = "ab" * 32
IDENTITY = (
    "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1"
)
ISSUER = "https://token.actions.githubusercontent.com"
CHANNEL = "https://prefix.dev/example"


class FakeVerifier:
    def __init__(self, results: dict[str, CryptographicVerification | Exception]):
        self.results = results

    def verify(self, bundle_json):
        result = self.results[bundle_json]
        if isinstance(result, Exception):
            raise result
        return result


def verified(payload: bytes, *, payload_type: str = InTotoStatement.PAYLOAD_TYPE):
    return CryptographicVerification(payload_type, payload, IDENTITY, ISSUER, ("time",))


def certificate_material(extensions: Extensions) -> SigstoreBundleMaterial:
    return SigstoreBundleMaterial(
        SimpleNamespace(signing_certificate=SimpleNamespace(extensions=extensions)),
        "{}",
    )


def test_one_verified_bundle_suffices_despite_invalid_sibling() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    verifier = FakeVerifier(
        {"bad": BundleVerificationError("bad signature"), "good": verified(payload)}
    )
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bad", "good"), prefix_sidecar=True),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=verifier,
        channel=CHANNEL,
    )
    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].verified
    assert result.to_dict()["authorization"] == "not-evaluated"
    assert result.to_dict()["sidecar_sha256"] == "cd" * 32
    assert result.failures[0].code == "invalid-bundle"
    assert result.prefix_sidecar


def test_verifier_programming_errors_are_not_security_results() -> None:
    verifier = FakeVerifier({"bundle": AssertionError("verifier bug")})

    with pytest.raises(AssertionError, match="verifier bug"):
        verify_bundles(
            Sidecar("url", "cd" * 32, ("bundle",)),
            artifact_name=FILENAME,
            artifact_sha256=DIGEST,
            verifier=verifier,
        )


def test_bundle_certificate_requires_a_subject_alternative_name() -> None:
    material = certificate_material(Extensions([]))

    with pytest.raises(BundleVerificationError, match="supported SAN"):
        material.signer()


def test_bundle_certificate_requires_one_supported_identity() -> None:
    extensions = Extensions(
        [
            Extension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                False,
                SubjectAlternativeName(
                    [
                        UniformResourceIdentifier(IDENTITY),
                        RFC822Name("publisher@example.org"),
                    ]
                ),
            )
        ]
    )

    with pytest.raises(BundleVerificationError, match="exactly one supported SAN"):
        certificate_material(extensions).signer()


@pytest.mark.parametrize(
    "value",
    [b"not DER", b"\x0c\x00"],
    ids=("invalid-der", "empty"),
)
def test_bundle_certificate_rejects_malformed_other_name_san(
    value: bytes,
) -> None:
    extensions = Extensions(
        [
            Extension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                False,
                SubjectAlternativeName(
                    [
                        OtherName(
                            ObjectIdentifier("1.3.6.1.4.1.57264.1.7"),
                            value,
                        )
                    ]
                ),
            )
        ]
    )
    material = certificate_material(extensions)

    with pytest.raises(BundleVerificationError, match="malformed SAN"):
        material.signer()


@pytest.mark.parametrize(
    ("oid", "value"),
    [
        ("1.3.6.1.4.1.57264.1.1", b"\xff"),
        ("1.3.6.1.4.1.57264.1.1", b""),
        ("1.3.6.1.4.1.57264.1.8", b"not DER"),
        ("1.3.6.1.4.1.57264.1.8", b"\x0c\x00"),
    ],
    ids=("v1-invalid", "v1-empty", "v2-invalid", "v2-empty"),
)
def test_bundle_certificate_rejects_malformed_oidc_issuer(
    oid: str,
    value: bytes,
) -> None:
    issuer_oid = ObjectIdentifier(oid)
    extensions = Extensions(
        [
            Extension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                False,
                SubjectAlternativeName([UniformResourceIdentifier(IDENTITY)]),
            ),
            Extension(
                issuer_oid,
                False,
                UnrecognizedExtension(issuer_oid, value),
            ),
        ]
    )
    material = certificate_material(extensions)

    with pytest.raises(BundleVerificationError, match="malformed OIDC issuer"):
        material.signer()


def test_bundle_certificate_requires_an_oidc_issuer() -> None:
    extensions = Extensions(
        [
            Extension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                False,
                SubjectAlternativeName([UniformResourceIdentifier(IDENTITY)]),
            )
        ]
    )

    with pytest.raises(BundleVerificationError, match="does not contain an OIDC"):
        certificate_material(extensions).signer()


def test_bundle_certificate_accepts_v2_oidc_issuer() -> None:
    issuer_oid = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
    extensions = Extensions(
        [
            Extension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                False,
                SubjectAlternativeName([UniformResourceIdentifier(IDENTITY)]),
            ),
            Extension(
                issuer_oid,
                False,
                UnrecognizedExtension(issuer_oid, der_encode(UTF8String(ISSUER))),
            ),
        ]
    )

    assert certificate_material(extensions).signer() == SignerIdentity(
        IDENTITY,
        ISSUER,
    )


def test_malformed_target_channel_does_not_hide_valid_sibling() -> None:
    malformed = PublishStatement(FILENAME, DIGEST).payload()
    malformed_value = json.loads(malformed)
    malformed_value["predicate"] = {"targetChannel": "https://[invalid"}
    good = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bad", "good")),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "bad": verified(json.dumps(malformed_value).encode()),
                "good": verified(good),
            }
        ),
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.failures[0].code == "invalid-cep27"


def test_valid_signature_with_wrong_artifact_is_invalid() -> None:
    payload = PublishStatement("other-1.0-0.conda", DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel=CHANNEL,
    )
    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-cep27"


def test_target_channel_cannot_be_replayed_to_another_channel() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()

    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel="https://prefix.dev/other",
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-cep27"


def test_direct_verification_rejects_artifact_changed_by_verifier(tmp_path) -> None:
    artifact = tmp_path / FILENAME
    artifact.write_bytes(b"before")
    digest = hashlib.sha256(b"before").hexdigest()
    payload = PublishStatement(FILENAME, digest, CHANNEL).payload()

    class MutatingVerifier:
        def verify(self, bundle_json):
            artifact.write_bytes(b"after")
            return verified(payload)

    result = verify_artifact(
        artifact,
        Sidecar("bundle", "cd" * 32, ("bundle",)),
        verifier=MutatingVerifier(),
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[-1].code == "artifact-changed"


def test_local_trust_configuration_is_bounded(tmp_path) -> None:
    from conda_sigstore.settings import MAX_TRUST_CONFIG_BYTES

    trust_config = tmp_path / "trust.json"
    trust_config.write_bytes(b"x" * (MAX_TRUST_CONFIG_BYTES + 1))

    with pytest.raises(ValueError, match="trust configuration exceeds"):
        SigstoreVerifier(trust_config=trust_config).trust_model


def test_sigstore_parser_rejects_unsupported_bundle_media_type() -> None:
    result = verify_bundles(
        Sidecar(
            "url",
            "cd" * 32,
            ('{"mediaType":"unsupported"}',),
        ),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=SigstoreVerifier(offline=True),
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-bundle"


def test_unsupported_dsse_payload_type_is_reported() -> None:
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "bundle": verified(
                    b"not an in-toto statement",
                    payload_type="application/octet-stream",
                )
            }
        ),
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "unsupported-payload-type"
    assert not result.evidence[0].verified


def test_malformed_in_toto_statement_is_reported() -> None:
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(b"not JSON")}),
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-statement"
    assert not result.evidence[0].verified


def test_unknown_predicate_is_reported() -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    statement["predicateType"] = "https://example.org/unknown"
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(json.dumps(statement).encode())}),
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "unsupported-predicate"
    assert result.evidence[0].predicate_type == "https://example.org/unknown"
    assert not result.evidence[0].verified


def test_any_authenticated_signer_is_reported_without_authorization_claim() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "bundle": CryptographicVerification(
                    InTotoStatement.PAYLOAD_TYPE,
                    payload,
                    "https://github.com/not-the-publisher/workflow",
                    ISSUER,
                    ("time",),
                )
            }
        ),
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].identity.endswith("not-the-publisher/workflow")
    assert result.evidence[0].predicate_type == PublishStatement.PREDICATE_TYPE
    assert result.evidence[0].timestamps == ("time",)
    assert result.evidence[0].verified
    assert result.to_dict()["authorization"] == "not-evaluated"


def test_explicit_identity_and_issuer_authorize_exact_signer() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel=CHANNEL,
        expected_signer=SignerIdentity(IDENTITY, ISSUER),
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.authorization is AuthorizationStatus.VERIFIED
    assert result.to_dict()["authorization"] == "verified"


@pytest.mark.parametrize(
    "expected_signer",
    [
        SignerIdentity("publisher@example.org", ISSUER),
        SignerIdentity(IDENTITY, "https://issuer.example"),
    ],
)
def test_explicit_identity_rejects_other_signer_without_hiding_evidence(
    expected_signer,
) -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel=CHANNEL,
        expected_signer=expected_signer,
    )

    assert result.status is VerificationStatus.UNTRUSTED_IDENTITY
    assert result.authorization is AuthorizationStatus.FAILED
    assert result.to_dict()["expected_signer"] == expected_signer.to_dict()
    assert result.evidence[0].verified
    assert result.evidence[0].identity == IDENTITY
    assert result.evidence[0].issuer == ISSUER
    assert result.failures[0].code == "untrusted-identity"


def test_unavailable_sibling_takes_precedence_over_untrusted_identity() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("untrusted", "unavailable")),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "untrusted": verified(payload),
                "unavailable": TrustMaterialUnavailableError("trust root unavailable"),
            }
        ),
        channel=CHANNEL,
        expected_signer=SignerIdentity("publisher@example.org", ISSUER),
    )

    assert result.status is VerificationStatus.EVIDENCE_UNAVAILABLE
    assert result.evidence[0].verified
    assert [failure.code for failure in result.failures] == [
        "untrusted-identity",
        "evidence-unavailable",
    ]


def test_missing_offline_trust_material_is_evidence_unavailable() -> None:
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {"bundle": TrustMaterialUnavailableError("trust root unavailable")}
        ),
    )

    assert result.status is VerificationStatus.EVIDENCE_UNAVAILABLE
    assert result.failures[0].code == "evidence-unavailable"


def test_slsa_provenance_preserves_untrusted_signer_evidence() -> None:
    payload = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": FILENAME, "digest": {"sha256": DIGEST}}],
            "predicateType": SlsaProvenance.PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://example.org/build/v1",
                    "resolvedDependencies": [],
                },
                "runDetails": {"builder": {"id": "https://example.org/builder"}},
            },
        }
    ).encode()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        expected_signer=SignerIdentity("publisher@example.org", ISSUER),
    )
    assert result.status is VerificationStatus.INVALID
    assert result.authorization is AuthorizationStatus.FAILED
    assert result.evidence[0].verified
    assert (
        result.evidence[0].details["provenance"]["builder"]
        == "https://example.org/builder"
    )
    assert [failure.code for failure in result.failures] == [
        "untrusted-identity",
        "missing-publish-attestation",
    ]


def test_unrelated_slsa_provenance_is_not_reported_for_package() -> None:
    payload = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": FILENAME, "digest": {"sha256": "cd" * 32}}],
            "predicateType": SlsaProvenance.PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://example.org/build/v1",
                    "resolvedDependencies": [],
                },
                "runDetails": {"builder": {"id": "https://example.org/builder"}},
            },
        }
    ).encode()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
    )
    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-provenance"
    assert result.evidence[0].details == {}


# Captured from Prefix on 2026-08-10. This fixture is never fetched by tests.
def test_captured_prefix_bundle_verifies_offline() -> None:
    raw_sidecar = (
        (Path(__file__).parent / "fixtures" / "prefix-actionlint.v0.sigs")
        .read_bytes()
        .removesuffix(b"\n")
    )
    sidecar_sha256 = hashlib.sha256(raw_sidecar).hexdigest()
    assert sidecar_sha256 == (
        "d6dfbfcf1f3fdc2821ddaf525427461b9a68b879d70c265b67454cfbdcdb9c16"
    )
    bundle_json = json.dumps(json.loads(raw_sidecar)[0])
    expected_identity = (
        "https://github.com/hunger/octoconda/.github/workflows/"
        "octoconda.yaml@refs/heads/main"
    )
    identity = SigstoreBundleMaterial.from_json(bundle_json).signer()
    assert identity.identity == expected_identity
    assert identity.issuer == ISSUER

    result = verify_bundles(
        Sidecar(
            "https://prefix.dev/actionlint.v0.sigs",
            sidecar_sha256,
            (bundle_json,),
            prefix_sidecar=True,
        ),
        artifact_name="actionlint-1.7.12-h60d57d3_0.conda",
        artifact_sha256=(
            "e3e0f35dec5b09b18baac8729d14115903b5adfd25065f8bbb90a2b3be5401e4"
        ),
        verifier=SigstoreVerifier(offline=True),
        channel="https://prefix.dev/github-releases",
    )
    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].identity == expected_identity
    assert "2026-03-31T02:58:32Z" in result.evidence[0].timestamps
    assert result.evidence[0].predicate_type == PublishStatement.PREDICATE_TYPE
    assert result.to_dict()["authorization"] == "not-evaluated"
