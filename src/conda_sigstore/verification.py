"""Sigstore verification followed by application-specific statement checks."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from functools import cache
from threading import Lock
from typing import TYPE_CHECKING, Protocol

from conda.gateways.disk.read import compute_sum

from .evidence import (
    SignerIdentity,
    VerificationFailure,
    VerificationResult,
    VerificationStatus,
    VerifiedEvidence,
)
from .exceptions import (
    BundleVerificationError,
    PublishStatementError,
    StatementError,
    TrustMaterialUnavailableError,
)
from .provenance import SlsaProvenance
from .settings import MAX_TRUST_CONFIG_BYTES
from .statements import InTotoStatement, PublishStatement
from .transport import read_bounded_file

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from .evidence import Sidecar


@dataclass(frozen=True, slots=True)
class CryptographicVerification:
    payload_type: str
    payload: bytes
    signer: SignerIdentity
    timestamps: tuple[str, ...] = ()


class BundleVerifier(Protocol):
    def verify(self, bundle_json: str) -> CryptographicVerification:
        """Cryptographically verify one bundle and return its actual identity."""


@dataclass(frozen=True, slots=True)
class SigstoreBundleMaterial:
    """A parsed Sigstore bundle and its authenticated certificate evidence."""

    bundle: Any

    @classmethod
    def from_json(cls, bundle_json: str) -> SigstoreBundleMaterial:
        """Parse one bundle without weakening Sigstore media-type validation."""
        from sigstore.models import Bundle  # type: ignore[import-not-found]

        try:
            return cls(Bundle.from_json(bundle_json))
        except Exception as exc:
            raise BundleVerificationError(str(exc)) from exc

    def signer(self) -> SignerIdentity:
        """Return the exact SAN and OIDC issuer carried by the certificate."""
        from cryptography.x509 import (  # type: ignore[import-not-found]
            ObjectIdentifier,
            OtherName,
            RFC822Name,
            SubjectAlternativeName,
            UniformResourceIdentifier,
        )
        from cryptography.x509.extensions import (
            ExtensionNotFound,  # type: ignore[import-not-found]
        )
        from pyasn1.codec.der.decoder import (
            decode as der_decode,  # type: ignore[import-not-found]
        )
        from pyasn1.type.char import UTF8String  # type: ignore[import-not-found]

        certificate = self.bundle.signing_certificate
        extensions = certificate.extensions
        try:
            values = extensions.get_extension_for_class(SubjectAlternativeName).value
        except ExtensionNotFound as exc:
            raise BundleVerificationError(
                "certificate does not contain a supported SAN"
            ) from exc
        identities = list(values.get_values_for_type(RFC822Name))
        identities.extend(values.get_values_for_type(UniformResourceIdentifier))
        for other_name in values.get_values_for_type(OtherName):
            if other_name.type_id.dotted_string != "1.3.6.1.4.1.57264.1.7":
                continue
            try:
                identities.append(der_decode(other_name.value, UTF8String)[0].decode())
            except Exception as exc:
                raise BundleVerificationError(
                    "certificate has a malformed SAN"
                ) from exc
        identities = list(dict.fromkeys(identities))
        if len(identities) != 1:
            raise BundleVerificationError(
                "certificate must contain exactly one supported SAN, "
                f"found {len(identities)}"
            )
        if not identities[0]:
            raise BundleVerificationError("certificate has a malformed SAN")

        issuer_v1 = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
        issuer_v2 = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
        try:
            issuer = extensions.get_extension_for_oid(issuer_v1).value.value.decode()
        except ExtensionNotFound:
            try:
                raw = extensions.get_extension_for_oid(issuer_v2).value.value
                issuer = der_decode(raw, UTF8String)[0].decode()
            except ExtensionNotFound as exc:
                raise BundleVerificationError(
                    "certificate does not contain an OIDC issuer"
                ) from exc
            except Exception as exc:
                raise BundleVerificationError(
                    "certificate has a malformed OIDC issuer"
                ) from exc
        except (AttributeError, UnicodeDecodeError) as exc:
            raise BundleVerificationError(
                "certificate has a malformed OIDC issuer"
            ) from exc
        if not issuer:
            raise BundleVerificationError("certificate has a malformed OIDC issuer")
        return SignerIdentity(identities[0], issuer)

    def timestamps(self) -> tuple[str, ...]:
        """Report timestamps from already-verified Sigstore material."""
        try:
            value = json.loads(self.bundle.to_json())
            entries = value["verificationMaterial"]["tlogEntries"]
        except (KeyError, TypeError, json.JSONDecodeError):
            entries = ()
        result: list[str] = []
        for entry in entries:
            try:
                timestamp = int(entry["integratedTime"])
                result.append(
                    datetime.fromtimestamp(timestamp, timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            except (KeyError, TypeError, ValueError, OSError):
                continue

        try:
            timestamp_data = (
                self.bundle.verification_material.timestamp_verification_data
            )
            rfc3161_timestamps = (
                timestamp_data.rfc3161_timestamps if timestamp_data is not None else ()
            )
        except Exception:
            rfc3161_timestamps = ()
        for response in rfc3161_timestamps:
            try:
                generated = response.tst_info.gen_time
                if not isinstance(generated, datetime):
                    continue
                if generated.tzinfo is None:
                    generated = generated.replace(tzinfo=timezone.utc)
                result.append(
                    generated.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            except Exception:
                continue
        return tuple(dict.fromkeys(result))


class SigstoreVerifier:
    """Lazy adapter around sigstore-python 4.5's public verification API."""

    def __init__(
        self,
        *,
        offline: bool = False,
        trust_config: Path | None = None,
        verifier: object | None = None,
    ) -> None:
        self.offline = offline
        self.trust_config = trust_config
        self._verifier = verifier
        self._trust_model: Any | None = None
        self._initialization_lock = Lock()

    @classmethod
    @cache
    def shared(
        cls,
        *,
        offline: bool,
        trust_config: Path | None,
    ) -> SigstoreVerifier:
        """Reuse one thread-safe verifier for matching process configuration."""
        return cls(offline=offline, trust_config=trust_config)

    @property
    def trust_model(self) -> Any:
        """Load and retain the configured Sigstore client trust model."""
        if self._trust_model is not None:
            return self._trust_model
        with self._initialization_lock:
            if self._trust_model is None:
                from sigstore.models import (  # type: ignore[import-not-found]
                    ClientTrustConfig,
                )

                if self.trust_config is None:
                    config = ClientTrustConfig.production(offline=self.offline)
                else:
                    config = ClientTrustConfig.from_json(
                        read_bounded_file(
                            self.trust_config,
                            MAX_TRUST_CONFIG_BYTES,
                            description="trust configuration",
                        ).decode("utf-8")
                    )
                self._trust_model = config
        return self._trust_model

    def verify(self, bundle_json: str) -> CryptographicVerification:
        from sigstore.verify.policy import Identity  # type: ignore[import-not-found]

        material = SigstoreBundleMaterial.from_json(bundle_json)
        actual_identity = material.signer()
        identity_policy = Identity(
            identity=actual_identity.identity,
            issuer=actual_identity.issuer,
        )
        try:
            if self._verifier is None:
                from sigstore.verify import Verifier  # type: ignore[import-not-found]

                trusted_root = self.trust_model.trusted_root
                with self._initialization_lock:
                    if self._verifier is None:
                        self._verifier = Verifier(trusted_root=trusted_root)
            verifier: Any = self._verifier
        except Exception as exc:
            raise TrustMaterialUnavailableError(
                "Sigstore trust material is unavailable"
            ) from exc
        try:
            payload_type, payload = verifier.verify_dsse(
                material.bundle,
                identity_policy,
            )
        except Exception as exc:
            raise BundleVerificationError(str(exc)) from exc
        return CryptographicVerification(
            payload_type=payload_type,
            payload=payload,
            signer=actual_identity,
            timestamps=material.timestamps(),
        )


def verify_bundles(
    sidecar: Sidecar,
    *,
    artifact_name: str,
    artifact_sha256: str,
    verifier: BundleVerifier | None = None,
    channel: str | None = None,
    expected_signer: SignerIdentity | None = None,
) -> VerificationResult:
    """Verify package binding when one CEP 27 statement succeeds."""
    bundle_verifier = verifier or SigstoreVerifier()
    evidence: list[VerifiedEvidence] = []
    failures: list[VerificationFailure] = []
    package_verified = False
    saw_unavailable = False
    saw_untrusted_publish = False

    for index, bundle_json in enumerate(sidecar.bundles):
        try:
            verified = bundle_verifier.verify(bundle_json)
        except TrustMaterialUnavailableError as exc:
            saw_unavailable = True
            failures.append(
                VerificationFailure(
                    "evidence-unavailable", str(exc), bundle_index=index
                )
            )
            continue
        except BundleVerificationError as exc:
            failures.append(
                VerificationFailure("invalid-bundle", str(exc), bundle_index=index)
            )
            continue

        signer_matches = expected_signer is None or expected_signer == verified.signer
        if not signer_matches:
            failures.append(
                VerificationFailure(
                    "untrusted-identity",
                    "certificate identity and OIDC issuer do not match "
                    "the explicit signer requirement",
                    bundle_index=index,
                )
            )

        predicate_type: str | None = None
        details: dict[str, object] = {}
        evidence_verified = False
        if verified.payload_type != InTotoStatement.PAYLOAD_TYPE:
            failures.append(
                VerificationFailure(
                    "unsupported-payload-type",
                    f"unsupported DSSE payload type {verified.payload_type!r}",
                    bundle_index=index,
                )
            )
            evidence.append(
                VerifiedEvidence(
                    bundle_index=index,
                    signer=verified.signer,
                    predicate_type=None,
                    verified=False,
                    timestamps=verified.timestamps,
                )
            )
            continue
        try:
            parsed_statement = InTotoStatement.from_payload(verified.payload)
            predicate_type = parsed_statement.predicate_type
        except StatementError as exc:
            failures.append(
                VerificationFailure("invalid-statement", str(exc), bundle_index=index)
            )
            evidence.append(
                VerifiedEvidence(
                    bundle_index=index,
                    signer=verified.signer,
                    predicate_type=None,
                    verified=False,
                    timestamps=verified.timestamps,
                )
            )
            continue

        if predicate_type == PublishStatement.PREDICATE_TYPE:
            try:
                statement = PublishStatement.from_statement(parsed_statement).bind(
                    expected_filename=artifact_name,
                    expected_sha256=artifact_sha256,
                    accepted_target_channels=(channel,) if channel is not None else (),
                )
            except PublishStatementError as exc:
                failures.append(
                    VerificationFailure("invalid-cep27", str(exc), bundle_index=index)
                )
            else:
                evidence_verified = True
                details["target_channel"] = statement.target_channel
                if signer_matches:
                    package_verified = True
                else:
                    saw_untrusted_publish = True
        elif predicate_type == SlsaProvenance.PREDICATE_TYPE:
            try:
                subjects = parsed_statement.subjects()
                if not any(
                    hmac.compare_digest(
                        subject.digest.get("sha256", ""), artifact_sha256.lower()
                    )
                    for subject in subjects
                ):
                    raise StatementError(
                        "SLSA provenance subject sha256 does not match the package"
                    )
                details["provenance"] = SlsaProvenance.from_statement(
                    parsed_statement
                ).to_dict()
                details["subjects"] = [subject.to_dict() for subject in subjects]
                evidence_verified = True
            except StatementError as exc:
                failures.append(
                    VerificationFailure(
                        "invalid-provenance", str(exc), bundle_index=index
                    )
                )
        else:
            failures.append(
                VerificationFailure(
                    "unsupported-predicate",
                    f"unrecognized predicate type {predicate_type!r}",
                    bundle_index=index,
                )
            )

        evidence.append(
            VerifiedEvidence(
                bundle_index=index,
                signer=verified.signer,
                predicate_type=predicate_type,
                verified=evidence_verified,
                timestamps=verified.timestamps,
                details=details,
            )
        )

    if (
        not package_verified
        and evidence
        and not any(
            item.predicate_type == PublishStatement.PREDICATE_TYPE for item in evidence
        )
    ):
        failures.append(
            VerificationFailure(
                "missing-publish-attestation",
                "no valid artifact-bound CEP 27 publish attestation was found",
            )
        )

    if package_verified:
        status = VerificationStatus.VERIFIED
    elif saw_unavailable:
        status = VerificationStatus.EVIDENCE_UNAVAILABLE
    elif saw_untrusted_publish:
        status = VerificationStatus.UNTRUSTED_IDENTITY
    else:
        status = VerificationStatus.INVALID
    return VerificationResult(
        status=status,
        artifact=artifact_name,
        artifact_sha256=artifact_sha256,
        sidecar_sha256=sidecar.sha256,
        channel=channel,
        evidence=tuple(evidence),
        failures=tuple(failures),
        prefix_sidecar=sidecar.prefix_sidecar,
        expected_signer=expected_signer,
    )


def verify_artifact(
    artifact: Path,
    sidecar: Sidecar,
    *,
    verifier: BundleVerifier | None = None,
    channel: str | None = None,
    expected_signer: SignerIdentity | None = None,
) -> VerificationResult:
    """Hash an archive and verify its sidecar."""
    artifact_sha256 = compute_sum(artifact, "sha256")
    result = verify_bundles(
        sidecar,
        artifact_name=artifact.name,
        artifact_sha256=artifact_sha256,
        verifier=verifier,
        channel=channel,
        expected_signer=expected_signer,
    )
    if not hmac.compare_digest(
        compute_sum(artifact, "sha256"),
        artifact_sha256,
    ):
        return replace(
            result,
            status=VerificationStatus.INVALID,
            failures=result.failures
            + (
                VerificationFailure(
                    "artifact-changed",
                    "artifact changed while verification was running",
                ),
            ),
        )
    return result
