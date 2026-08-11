"""Optional pre-extraction package evidence verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .audit import EnvironmentAuditor
from .model import validate_sha256

if TYPE_CHECKING:
    from conda.common.path import PathType
    from conda.models.match_spec import MatchSpec
    from conda.models.records import PackageRecord


@dataclass(frozen=True, slots=True)
class InstallVerifier:
    """Require valid repodata-advertised CEP 27 evidence before extraction."""

    auditor: EnvironmentAuditor

    def __post_init__(self) -> None:
        if self.auditor.transport != "repodata":
            raise ValueError("install verification requires repodata transport")

    @classmethod
    def current(cls) -> InstallVerifier:
        """Create a verifier from the active conda context."""
        return cls(EnvironmentAuditor.current(transport="repodata"))

    def verify(
        self,
        record_or_spec: PackageRecord | MatchSpec,
        package_path: PathType,
        sha256: str,
    ) -> None:
        """Reject a package unless its advertised evidence verifies."""
        from conda.exceptions import CondaVerificationError
        from conda.models.records import PackageRecord

        archive_name = Path(package_path).name
        if not isinstance(record_or_spec, PackageRecord):
            raise CondaVerificationError(
                f"Sigstore verification rejected {archive_name}: "
                "explicit packages do not carry repodata attestation metadata"
            )

        artifact_name = str(record_or_spec.fn)
        if artifact_name != archive_name:
            raise CondaVerificationError(
                f"Sigstore verification rejected {archive_name}: "
                "the archive filename does not match its package record"
            )

        try:
            artifact_sha256 = validate_sha256(
                sha256,
                field_name="artifact_sha256",
            )
        except ValueError as exc:
            raise CondaVerificationError(
                f"Sigstore verification rejected {archive_name}: {exc}"
            ) from exc

        result = self.auditor.verify_record_evidence(
            record_or_spec,
            artifact_sha256,
        )
        if result.verified:
            return

        details = ", ".join(
            f"{failure.code}: {failure.message}" for failure in result.failures
        )
        suffix = f" ({details})" if details else ""
        raise CondaVerificationError(
            f"Sigstore verification rejected {archive_name}: "
            f"{result.status.value}{suffix}"
        )
