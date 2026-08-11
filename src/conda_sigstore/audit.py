"""Installed-environment and embedded source-evidence auditing."""

from __future__ import annotations

import hashlib
import hmac
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

from .cache import DigestCache
from .exceptions import TransportError
from .model import (
    AttestationDescriptor,
    SignerIdentity,
    VerificationFailure,
    VerificationResult,
    VerificationStatus,
    validate_sha256,
)
from .settings import SigstoreSettings
from .statements import InTotoStatement
from .transport import (
    SidecarTransport,
    read_bounded_file,
)
from .verification import SigstoreVerifier, verify_bundles

if TYPE_CHECKING:
    from typing import Any

    from .verification import BundleVerifier

MAX_RENDERED_RECIPE_BYTES = 1024 * 1024
AuditTransport = Literal["repodata", "prefix"]


def resolve_prefix(*, name: str | None = None, prefix: str | None = None) -> Path:
    """Resolve an explicit path, named environment, or conda target prefix."""
    if prefix:
        return Path(prefix).expanduser().resolve()
    if name:
        from conda.base.context import locate_prefix_by_name

        return Path(locate_prefix_by_name(name))
    from conda.base.context import context

    return Path(context.target_prefix)


def resolve_embedded_file(root: Path, relative: str) -> Path | None:
    """Resolve a regular embedded file without following any symlink."""
    parsed = PurePosixPath(relative)
    candidate = root
    for part in parsed.parts:
        candidate /= part
        try:
            mode = candidate.lstat().st_mode
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(mode):
            raise ValueError(f"embedded path contains a symlink: {relative}")
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ValueError(f"embedded path escapes the package: {relative}") from exc
    if not stat.S_ISREG(candidate.lstat().st_mode):
        raise ValueError(f"embedded path is not a regular file: {relative}")
    return candidate


@dataclass(frozen=True, slots=True)
class EmbeddedSourceBundle:
    """One recipe-indexed Sigstore bundle stored in a package archive."""

    path: str
    sha256: str

    @classmethod
    def from_mapping(cls, value: object) -> EmbeddedSourceBundle:
        """Parse only the path and digest from untrusted verified metadata."""
        if not isinstance(value, Mapping):
            raise ValueError("attestation.verified entries must be objects")
        path = value.get("path")
        if not isinstance(path, str) or not path or "\\" in path or "\0" in path:
            raise ValueError("verified.path must be a safe POSIX relative path")
        parsed = PurePosixPath(path)
        if (
            parsed.is_absolute()
            or ".." in parsed.parts
            or parsed.as_posix() != path
            or len(parsed.parts) != 2
            or parsed.parts[0] != "attestations"
            or not path.endswith(".sigstore.json")
        ):
            raise ValueError("verified.path must name an embedded Sigstore bundle")
        return cls(
            path=path,
            sha256=validate_sha256(
                value.get("sha256"),
                field_name="verified.sha256",
            ),
        )

    def audit(
        self,
        recipe_root: Path,
        requirement: SourceAttestationRequirement,
        *,
        verifier: BundleVerifier,
        max_bytes: int,
    ) -> tuple[dict[str, object], SignerIdentity | None]:
        """Verify this bundle against its bytes and source requirement."""
        report: dict[str, object] = {"path": self.path, "sha256": self.sha256}
        try:
            path = resolve_embedded_file(recipe_root, self.path)
            if path is None:
                return {**report, "status": "missing"}, None
            body = read_bounded_file(
                path,
                max_bytes,
                description="embedded bundle",
            )
            if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), self.sha256):
                raise ValueError("embedded bundle SHA-256 does not match the recipe")
            verified = verifier.verify(body.decode("utf-8"))
            if verified.payload_type != InTotoStatement.PAYLOAD_TYPE:
                raise ValueError("bundle payload is not an in-toto JSON statement")
            statement = InTotoStatement.from_payload(verified.payload)
            predicate_type = statement.predicate_type
            if (
                requirement.predicate_type is not None
                and predicate_type != requirement.predicate_type
            ):
                raise ValueError("predicate type does not match the recipe requirement")
            if not any(
                hmac.compare_digest(
                    subject.digest.get("sha256", ""),
                    requirement.source_sha256,
                )
                for subject in statement.subjects()
            ):
                raise ValueError("attestation subject does not bind the recipe source")
        except Exception as exc:
            return {**report, "status": "invalid", "failure": str(exc)}, None
        identity = SignerIdentity(verified.identity, verified.issuer)
        return (
            {
                **report,
                "status": "verified",
                "identity": identity.identity,
                "issuer": identity.issuer,
                "predicate_type": predicate_type,
                "timestamps": list(verified.timestamps),
            },
            identity,
        )


@dataclass(frozen=True, slots=True)
class SourceAttestationRequirement:
    """Publisher and predicate requirements declared by one recipe source."""

    source_index: int
    source_sha256: str
    publishers: tuple[SignerIdentity, ...]
    predicate_type: str | None
    bundles: tuple[EmbeddedSourceBundle, ...]

    @staticmethod
    def publisher(value: object) -> SignerIdentity:
        """Expand one explicit or draft shorthand publisher identity."""
        if isinstance(value, Mapping):
            if set(value) != {"identity", "issuer"}:
                raise ValueError("publisher mappings require identity and issuer")
            identity = value["identity"]
            issuer = value["issuer"]
            if not isinstance(identity, str) or not isinstance(issuer, str):
                raise ValueError("publisher identity and issuer must be strings")
            return SignerIdentity(identity, issuer)
        if not isinstance(value, str) or not value:
            raise ValueError("publishers must contain strings or mappings")
        shorthand, separator, _ref = value.partition("@")
        if separator:
            raise ValueError("publisher ref constraints are not supported")
        provider, separator, repository = shorthand.partition(":")
        if not separator:
            raise ValueError("publisher shorthand must name a provider")
        parts = repository.split("/")
        if len(parts) < 2 or any(not part for part in parts):
            raise ValueError("publisher shorthand must name an owner and repository")
        providers = {
            "github": (
                "https://github.com",
                "https://token.actions.githubusercontent.com",
            ),
            "gitlab": ("https://gitlab.com", "https://gitlab.com"),
        }
        try:
            identity_root, issuer = providers[provider]
        except KeyError as exc:
            raise ValueError(f"unsupported publisher provider: {provider}") from exc
        return SignerIdentity(f"{identity_root}/{repository}", issuer)

    @classmethod
    def from_source(
        cls,
        source: Mapping[str, object],
        source_index: int,
    ) -> SourceAttestationRequirement | None:
        """Parse one source that may declare draft source attestations."""
        raw_attestation = source.get("attestation")
        if raw_attestation is None:
            return None
        if not isinstance(raw_attestation, Mapping):
            raise ValueError(f"source[{source_index}].attestation must be an object")
        if "url" not in source or "git" in source or "path" in source:
            raise ValueError("source attestations require a URL source")
        raw_publishers = raw_attestation.get("publishers")
        if not isinstance(raw_publishers, Sequence) or isinstance(raw_publishers, str):
            raise ValueError("attestation.publishers must be a list")
        publishers = tuple(cls.publisher(item) for item in raw_publishers)
        if not publishers:
            raise ValueError("attestation.publishers must not be empty")
        predicate_type = raw_attestation.get("predicate_type")
        if predicate_type is not None and (
            not isinstance(predicate_type, str) or not predicate_type
        ):
            raise ValueError("attestation.predicate_type must be a nonempty string")
        raw_bundles = raw_attestation.get("verified", ())
        if not isinstance(raw_bundles, Sequence) or isinstance(raw_bundles, str):
            raise ValueError("attestation.verified must be a list")
        return cls(
            source_index=source_index,
            source_sha256=validate_sha256(
                source.get("sha256"),
                field_name=f"source[{source_index}].sha256",
            ),
            publishers=publishers,
            predicate_type=predicate_type,
            bundles=tuple(
                EmbeddedSourceBundle.from_mapping(item) for item in raw_bundles
            ),
        )

    @classmethod
    def from_recipe(
        cls,
        rendered_recipe: Mapping[str, object],
    ) -> tuple[SourceAttestationRequirement, ...]:
        """Parse every source-attestation requirement in a rendered recipe."""
        raw_sources = rendered_recipe.get("source", ())
        if isinstance(raw_sources, Mapping):
            sources: Sequence[object] = (raw_sources,)
        elif isinstance(raw_sources, Sequence) and not isinstance(raw_sources, str):
            sources = raw_sources
        else:
            raise ValueError("recipe source must be an object or list")
        requirements: list[SourceAttestationRequirement] = []
        for source_index, source in enumerate(sources):
            if not isinstance(source, Mapping):
                raise ValueError(f"source[{source_index}] must be an object")
            requirement = cls.from_source(source, source_index)
            if requirement is not None:
                requirements.append(requirement)
        return tuple(requirements)

    @staticmethod
    def publisher_matches(expected: SignerIdentity, actual: SignerIdentity) -> bool:
        """Apply the draft repository-boundary publisher matching rule."""
        if expected.issuer != actual.issuer:
            return False
        if not expected.identity.startswith("https://"):
            return expected.identity == actual.identity
        publisher = expected.identity.casefold()
        identity = actual.identity.casefold()
        return identity == publisher or (
            identity.startswith(publisher)
            and len(identity) > len(publisher)
            and identity[len(publisher)] in {"/", "@"}
        )

    def audit(
        self,
        recipe_root: Path,
        *,
        verifier: BundleVerifier,
        max_bytes: int,
    ) -> dict[str, object]:
        """Verify every indexed bundle and require every declared publisher."""
        bundle_results = [
            bundle.audit(
                recipe_root,
                self,
                verifier=verifier,
                max_bytes=max_bytes,
            )
            for bundle in self.bundles
        ]
        bundles = [report for report, _identity in bundle_results]
        identities = tuple(
            identity for _report, identity in bundle_results if identity is not None
        )
        matched = tuple(
            publisher
            for publisher in self.publishers
            if any(
                self.publisher_matches(publisher, identity) for identity in identities
            )
        )
        status = "verified"
        failure: str | None = None
        if not self.bundles or any(item["status"] == "missing" for item in bundles):
            status = "missing"
            failure = "embedded source attestation bundle is missing"
        elif any(item["status"] == "invalid" for item in bundles):
            status = "invalid"
            failure = "one or more embedded source attestations are invalid"
        elif len(matched) != len(self.publishers):
            status = "untrusted-identity"
            failure = "not every recipe publisher matched a verified bundle"
        report: dict[str, object] = {
            "source_index": self.source_index,
            "source_sha256": self.source_sha256,
            "status": status,
            "predicate_type": self.predicate_type,
            "required_publishers": [
                {"identity": publisher.identity, "issuer": publisher.issuer}
                for publisher in self.publishers
            ],
            "matched_publishers": [
                {"identity": publisher.identity, "issuer": publisher.issuer}
                for publisher in matched
            ],
            "bundles": bundles,
            "package_publication": "verified",
            "verification_scope": "draft-source-attestation",
        }
        if failure is not None:
            report["failure"] = failure
        return report


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

        settings = SigstoreSettings.current()
        try:
            package_cache = PackageCacheData.first_writable()
            cache = DigestCache(Path(package_cache.pkgs_dir) / ".conda-sigstore")
        except Exception:
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
            elif exc.code in {"missing-sidecar", "retrieval-failed"}:
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
                with archive.open("rb") as source, snapshot.open("wb") as destination:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
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
        except Exception as exc:
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

        target = Path(prefix).expanduser().resolve()
        packages: list[dict[str, object]] = []
        for record in sorted(
            PrefixData(target).iter_records(),
            key=lambda item: item.name,
        ):
            try:
                result = self.audit_record(record)
            except Exception as exc:
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


__all__ = [
    "AuditTransport",
    "EmbeddedSourceBundle",
    "EnvironmentAuditor",
    "MAX_RENDERED_RECIPE_BYTES",
    "SourceAttestationRequirement",
    "resolve_embedded_file",
    "resolve_prefix",
]
