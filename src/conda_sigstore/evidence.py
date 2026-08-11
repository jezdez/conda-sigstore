"""Small data models shared by the conda-sigstore core."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


def validate_sha256(value: object, *, field_name: str = "sha256") -> str:
    """Validate and normalize one SHA-256 hexadecimal digest."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not all(character in "0123456789abcdefABCDEF" for character in value)
    ):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal string")
    return value.lower()


@dataclass(frozen=True, slots=True)
class AttestationDescriptor:
    """The draft integrity descriptor stored in repodata."""

    sha256: str
    size: int

    def __post_init__(self) -> None:
        if isinstance(self.sha256, str) and self.sha256 != self.sha256.lower():
            raise ValueError("attestation sha256 must use lowercase hexadecimal")
        object.__setattr__(self, "sha256", validate_sha256(self.sha256))
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 1
        ):
            raise ValueError("attestation size must be a positive integer")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> AttestationDescriptor:
        """Parse a descriptor without silently accepting missing fields."""
        if set(value) != {"sha256", "size"}:
            raise ValueError("attestations must contain exactly sha256 and size")
        sha256 = value["sha256"]
        size = value["size"]
        if not isinstance(sha256, str):
            raise ValueError("attestation sha256 must be a string")
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError("attestation size must be an integer")
        return cls(sha256=sha256, size=size)


@dataclass(frozen=True, slots=True)
class SignerIdentity:
    """The certificate SAN and OIDC issuer reported by Sigstore."""

    identity: str
    issuer: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not self.identity:
            raise ValueError("signer identity cannot be empty")
        if not isinstance(self.issuer, str) or not self.issuer:
            raise ValueError("signer issuer cannot be empty")

    def to_dict(self) -> dict[str, str]:
        return {"identity": self.identity, "issuer": self.issuer}


class VerificationStatus(str, Enum):
    """Stable statuses used by human and JSON output."""

    VERIFIED = "verified"
    MISSING = "missing"
    RETRIEVAL_FAILED = "retrieval-failed"
    INVALID = "invalid"
    UNTRUSTED_IDENTITY = "untrusted-identity"
    RECORD_DIGEST_ONLY = "record-digest-only"
    EVIDENCE_UNAVAILABLE = "evidence-unavailable"


@dataclass(frozen=True, slots=True)
class VerificationFailure:
    """One rejected bundle or verification-stage failure."""

    code: str
    message: str
    bundle_index: int | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"code": self.code, "message": self.message}
        if self.bundle_index is not None:
            result["bundle_index"] = self.bundle_index
        return result


@dataclass(frozen=True, slots=True)
class VerifiedEvidence:
    """Evidence extracted only after successful Sigstore verification."""

    bundle_index: int
    signer: SignerIdentity
    predicate_type: str | None
    verified: bool
    timestamps: tuple[str, ...] = ()
    details: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_index": self.bundle_index,
            **self.signer.to_dict(),
            "predicate_type": self.predicate_type,
            "verified": self.verified,
            "timestamps": list(self.timestamps),
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Complete result for one conda package artifact."""

    status: VerificationStatus
    artifact: str
    artifact_sha256: str | None
    sidecar_sha256: str | None = None
    channel: str | None = None
    evidence: tuple[VerifiedEvidence, ...] = ()
    failures: tuple[VerificationFailure, ...] = ()
    prefix_sidecar: bool = False
    expected_signer: SignerIdentity | None = None

    def __post_init__(self) -> None:
        if self.artifact_sha256 is not None:
            object.__setattr__(
                self,
                "artifact_sha256",
                validate_sha256(
                    self.artifact_sha256,
                    field_name="artifact_sha256",
                ),
            )
        if self.sidecar_sha256 is not None:
            object.__setattr__(
                self,
                "sidecar_sha256",
                validate_sha256(
                    self.sidecar_sha256,
                    field_name="sidecar_sha256",
                ),
            )

    @property
    def verified(self) -> bool:
        """Whether a cryptographically valid, artifact-bound statement exists."""
        return self.status is VerificationStatus.VERIFIED

    @property
    def authorization(self) -> str:
        """Return the result derived from an explicit signer requirement."""
        if self.expected_signer is None:
            return "not-evaluated"
        return "verified" if self.verified else "failed"

    def to_dict(self) -> dict[str, object]:
        """Return the versioned JSON representation used by the CLI."""
        return {
            "version": 1,
            "artifact": self.artifact,
            "artifact_sha256": self.artifact_sha256,
            "sidecar_sha256": self.sidecar_sha256,
            "channel": self.channel,
            "status": self.status.value,
            "authorization": self.authorization,
            "expected_signer": (
                self.expected_signer.to_dict()
                if self.expected_signer is not None
                else None
            ),
            "prefix_sidecar": self.prefix_sidecar,
            "evidence": [item.to_dict() for item in self.evidence],
            "failures": [item.to_dict() for item in self.failures],
        }


@dataclass(frozen=True, slots=True)
class Sidecar:
    """A bounded bundle collection with the observed sidecar digest."""

    sha256: str
    bundles: tuple[str, ...]
    prefix_sidecar: bool = False
    body: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sha256", validate_sha256(self.sha256))
        if not self.bundles:
            raise ValueError("sidecar must contain at least one bundle")
        if self.body is not None:
            if not isinstance(self.body, bytes):
                raise TypeError("sidecar body must be bytes")
            if hashlib.sha256(self.body).hexdigest() != self.sha256:
                raise ValueError("sidecar body does not match its SHA-256")
