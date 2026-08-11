from __future__ import annotations

import pytest

from conda_sigstore.model import (
    AttestationDescriptor,
    VerificationResult,
    VerificationStatus,
    VerifiedEvidence,
    validate_sha256,
)


def test_validate_sha256_normalizes_hexadecimal() -> None:
    assert validate_sha256("AB" * 32) == "ab" * 32


@pytest.mark.parametrize("value", ["not-a-digest", "ab" * 31 + "  "])
def test_validate_sha256_rejects_non_hexadecimal(value: str) -> None:
    with pytest.raises(ValueError, match="64-character hexadecimal"):
        validate_sha256(value)


def test_attestation_descriptor_requires_lowercase_digest() -> None:
    with pytest.raises(ValueError, match="lowercase"):
        AttestationDescriptor("AB" * 32, 1)


def test_verification_json_reports_evidence_without_authorization() -> None:
    result = VerificationResult(
        status=VerificationStatus.VERIFIED,
        artifact="package-1-0.conda",
        artifact_sha256="ab" * 32,
        evidence=(
            VerifiedEvidence(
                bundle_index=0,
                identity="https://github.com/example/project/workflow",
                issuer="https://token.actions.githubusercontent.com",
                predicate_type="https://example.org/predicate",
                verified=True,
            ),
        ),
    )

    assert result.verified
    assert result.to_dict()["authorization"] == "not-evaluated"
    assert result.to_dict()["expected_signer"] is None
    assert result.to_dict()["evidence"][0]["verified"] is True
