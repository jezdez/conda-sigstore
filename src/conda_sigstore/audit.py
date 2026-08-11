"""Installed-environment and source-evidence audit orchestration."""

from __future__ import annotations

import hashlib
import hmac
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

from .cache import DigestCache
from .exceptions import TransportError
from .model import (
    AttestationDescriptor,
    VerificationFailure,
    VerificationResult,
    VerificationStatus,
    validate_sha256,
)
from .settings import SigstoreSettings
from .source_attestations import SourceAttestationRequirement, resolve_embedded_file
from .transport import (
    SidecarTransport,
    read_bounded_file,
)
from .verification import SigstoreVerifier, verify_bundles

if TYPE_CHECKING:
    from typing import Any

    from .verification import BundleVerifier

MAX_RENDERED_RECIPE_BYTES = 1024 * 1024
MAX_PACKAGE_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
AuditTransport = Literal["repodata", "prefix"]


@dataclass(slots=True)
class EnvironmentAuditor:
    """Audit installed package evidence without enforcing installation policy."""

    settings: SigstoreSettings
    verifier: BundleVerifier
    transport: AuditTransport = "repodata"
    sidecars: SidecarTransport | None = None

    def __post_init__(self) -> None:
        if self.transport not in {"repodata", "prefix"}:
            raise ValueError("transport must be repodata or prefix")
        if self.sidecars is None:
            self.sidecars = SidecarTransport(
                max_bytes=self.settings.max_sidecar_bytes,
            )

    @classmethod
    def current(cls, *, transport: AuditTransport = "repodata") -> EnvironmentAuditor:
        """Create an auditor from conda's operational context."""
        from conda.base.context import context
        from conda.core.package_cache_data import PackageCacheData
        from conda.exceptions import NoWritablePkgsDirError

        settings = SigstoreSettings.current()
        try:
            package_cache = PackageCacheData.first_writable()
            cache = DigestCache(Path(package_cache.pkgs_dir) / ".conda-sigstore")
        except NoWritablePkgsDirError:
            cache = None
        return cls(
            settings=settings,
            verifier=SigstoreVerifier(
                offline=context.offline,
                trust_config=settings.trust_config,
            ),
            transport=transport,
            sidecars=SidecarTransport(
                max_bytes=settings.max_sidecar_bytes,
                cache=cache,
            ),
        )

    @staticmethod
    def channel_url(record: Any) -> str:
        """Return a credential-free HTTP channel or a redacted scheme label."""
        from conda.models.channel import Channel

        raw = str(getattr(record.channel, "base_url", None) or record.channel)
        scheme = urlsplit(raw).scheme.lower()
        if scheme not in {"http", "https"}:
            return f"{scheme}://" if scheme else "unsupported"
        return str(Channel(raw).base_url)

    @staticmethod
    def retained_archive(record: Any) -> Path | None:
        """Find a fetched archive in conda's package caches."""
        from conda.core.package_cache_data import PackageCacheData

        cached = next(
            (
                entry
                for entry in PackageCacheData.query_all(record)
                if entry.is_fetched and entry.fn == record.fn
            ),
            None,
        )
        return Path(cached.package_tarball_full_path) if cached is not None else None

    def audit_record(self, record: Any) -> VerificationResult:
        """Verify sidecar evidence for one installed package record."""
        archive = self.retained_archive(record)
        if archive is None:
            return VerificationResult(
                status=VerificationStatus.RECORD_DIGEST_ONLY,
                artifact=record.fn,
                artifact_sha256=getattr(record, "sha256", None),
                channel=self.channel_url(record),
                failures=(
                    VerificationFailure(
                        "record-digest-only",
                        "the package archive is not retained in the package cache",
                    ),
                ),
            )

        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        artifact_sha256 = digest.hexdigest()
        record_sha256 = getattr(record, "sha256", None)
        if record_sha256 and not hmac.compare_digest(
            str(record_sha256).lower(),
            artifact_sha256,
        ):
            return VerificationResult(
                status=VerificationStatus.INVALID,
                artifact=record.fn,
                artifact_sha256=artifact_sha256,
                channel=self.channel_url(record),
                failures=(
                    VerificationFailure(
                        "artifact-digest-mismatch",
                        "the retained archive does not match its package record",
                    ),
                ),
            )

        return self.verify_record_evidence(record, artifact_sha256)

    def verify_record_evidence(
        self,
        record: Any,
        artifact_sha256: str,
    ) -> VerificationResult:
        """Verify advertised evidence against a SHA-256 supplied by conda."""

        record_url = getattr(record, "url", None)
        artifact_url = (
            str(record_url)
            if record_url
            else (f"{self.channel_url(record)}/{record.subdir}/{record.fn}")
        )
        try:
            if self.transport == "repodata":
                getter = getattr(record, "get", None)
                raw_descriptor = (
                    getter("attestations", None)
                    if callable(getter)
                    else getattr(record, "attestations", None)
                )
                if raw_descriptor is None:
                    return VerificationResult(
                        status=VerificationStatus.MISSING,
                        artifact=record.fn,
                        artifact_sha256=artifact_sha256,
                        channel=self.channel_url(record),
                        failures=(
                            VerificationFailure(
                                "missing-attestations",
                                "repodata does not advertise an attestation sidecar",
                            ),
                        ),
                    )
                if not isinstance(raw_descriptor, Mapping):
                    raise TransportError(
                        "invalid-descriptor",
                        "repodata attestations must be an object",
                    )
                descriptor = AttestationDescriptor.from_mapping(raw_descriptor)

                assert self.sidecars is not None
                sidecar = self.sidecars.load_repodata(
                    artifact_url,
                    descriptor,
                )
            else:
                assert self.sidecars is not None
                sidecar = self.sidecars.load_prefix(artifact_url)
        except TransportError as exc:
            if exc.code == "missing-sidecar" and self.transport == "prefix":
                status = VerificationStatus.MISSING
            elif exc.code == "offline-cache-miss":
                status = VerificationStatus.EVIDENCE_UNAVAILABLE
            elif exc.code in {
                "digest-mismatch",
                "missing-sidecar",
                "retrieval-failed",
                "sidecar-too-large",
                "size-mismatch",
            }:
                status = VerificationStatus.RETRIEVAL_FAILED
            else:
                status = VerificationStatus.INVALID
            return VerificationResult(
                status=status,
                artifact=record.fn,
                artifact_sha256=artifact_sha256,
                channel=self.channel_url(record),
                failures=(VerificationFailure(exc.code, str(exc)),),
                prefix_sidecar=self.transport == "prefix",
            )
        except (TypeError, ValueError) as exc:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                artifact=record.fn,
                artifact_sha256=artifact_sha256,
                channel=self.channel_url(record),
                failures=(VerificationFailure("invalid-descriptor", str(exc)),),
            )
        return verify_bundles(
            sidecar,
            artifact_name=record.fn,
            artifact_sha256=artifact_sha256,
            verifier=self.verifier,
            channel=self.channel_url(record),
        )

    def audit_sources(
        self,
        record: Any,
        *,
        package_verified: bool,
        package_sha256: str | None,
    ) -> list[dict[str, object]]:
        """Audit draft source evidence from the verified package archive."""
        from conda.common.serialize import yaml
        from conda_package_handling.api import extract
        from ruamel.yaml import YAMLError

        if not package_verified or package_sha256 is None:
            return [
                {
                    "status": "evidence-unavailable",
                    "failure": "verified package publication evidence is unavailable",
                    "verification_scope": "draft-source-attestation",
                }
            ]
        archive = self.retained_archive(record)
        if archive is None or not archive.is_file():
            return [
                {
                    "status": "evidence-unavailable",
                    "failure": "the retained package archive is unavailable",
                    "verification_scope": "draft-source-attestation",
                }
            ]
        archive_too_large = {
            "status": "evidence-unavailable",
            "failure": (
                "the retained package archive exceeds the "
                f"{MAX_PACKAGE_ARCHIVE_BYTES}-byte audit limit"
            ),
            "verification_scope": "draft-source-attestation",
        }
        if archive.stat().st_size > MAX_PACKAGE_ARCHIVE_BYTES:
            return [archive_too_large]
        try:
            expected_package_sha256 = validate_sha256(
                package_sha256,
                field_name="package_sha256",
            )
            extension = ".conda" if record.fn.endswith(".conda") else ".tar.bz2"
            if not record.fn.endswith(extension):
                raise ValueError("retained archive is not a conda package")
            with tempfile.TemporaryDirectory(
                prefix="conda-sigstore-audit-"
            ) as temporary:
                root = Path(temporary)
                snapshot = root / f"package{extension}"
                digest = hashlib.sha256()
                copied = 0
                with archive.open("rb") as source, snapshot.open("wb") as destination:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        copied += len(block)
                        if copied > MAX_PACKAGE_ARCHIVE_BYTES:
                            return [archive_too_large]
                        digest.update(block)
                        destination.write(block)
                if not hmac.compare_digest(
                    digest.hexdigest(),
                    expected_package_sha256,
                ):
                    raise ValueError(
                        "retained archive does not match the verified package digest"
                    )
                extracted = root / "extracted"
                extract(str(snapshot), dest_dir=str(extracted), components="info")
                recipe = resolve_embedded_file(
                    extracted,
                    "info/recipe/rendered_recipe.yaml",
                )
                if recipe is None:
                    return [
                        {
                            "status": "evidence-unavailable",
                            "failure": "the retained archive has no rendered recipe",
                            "verification_scope": "draft-source-attestation",
                        }
                    ]
                rendered_recipe = yaml.loads(
                    read_bounded_file(
                        recipe,
                        MAX_RENDERED_RECIPE_BYTES,
                        description="rendered recipe",
                    ).decode("utf-8")
                )
                if not isinstance(rendered_recipe, Mapping):
                    raise ValueError("rendered recipe must be an object")
                return [
                    requirement.audit(
                        recipe.parent,
                        verifier=self.verifier,
                        max_bytes=self.settings.max_sidecar_bytes,
                    )
                    for requirement in SourceAttestationRequirement.from_recipe(
                        rendered_recipe
                    )
                ]
        except YAMLError:
            return [
                {
                    "status": "invalid",
                    "failure": "rendered recipe is not valid YAML",
                    "verification_scope": "draft-source-attestation",
                }
            ]
        except OSError as exc:
            error_name = type(exc).__name__
            return [
                {
                    "status": "evidence-unavailable",
                    "failure": f"source evidence could not be read ({error_name})",
                    "verification_scope": "draft-source-attestation",
                }
            ]
        except (UnicodeDecodeError, ValueError) as exc:
            return [
                {
                    "status": "invalid",
                    "failure": str(exc),
                    "verification_scope": "draft-source-attestation",
                }
            ]

    def audit_environment(
        self,
        prefix: str | Path,
        *,
        include_sources: bool = False,
    ) -> dict[str, object]:
        """Return a versioned evidence report for one conda prefix."""
        from conda.core.prefix_data import PrefixData
        from conda.exceptions import CondaError

        target = Path(prefix).expanduser().resolve()
        packages: list[dict[str, object]] = []
        for record in sorted(
            PrefixData(target).iter_records(),
            key=lambda item: item.name,
        ):
            try:
                result = self.audit_record(record)
            except (CondaError, OSError) as exc:
                result = VerificationResult(
                    status=VerificationStatus.EVIDENCE_UNAVAILABLE,
                    artifact=record.fn,
                    artifact_sha256=getattr(record, "sha256", None),
                    channel=self.channel_url(record),
                    failures=(
                        VerificationFailure(
                            "evidence-unavailable",
                            f"verification could not run ({type(exc).__name__})",
                        ),
                    ),
                )
            report = result.to_dict()
            if include_sources:
                report["source_evidence"] = self.audit_sources(
                    record,
                    package_verified=result.verified,
                    package_sha256=(
                        result.artifact_sha256 if result.verified else None
                    ),
                )
            packages.append(report)
        return {"version": 1, "prefix": str(target), "packages": packages}
