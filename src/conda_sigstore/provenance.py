"""Audit-only parsing of SLSA provenance evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar

from .exceptions import ProvenanceError, StatementError
from .statements import InTotoStatement


@dataclass(frozen=True, slots=True)
class ProvenanceMaterial:
    uri: str
    digest: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: object, index: int) -> ProvenanceMaterial:
        if not isinstance(value, Mapping):
            raise ProvenanceError(f"resolvedDependencies[{index}] must be an object")
        uri = value.get("uri")
        if not isinstance(uri, str) or not uri:
            raise ProvenanceError(
                f"resolvedDependencies[{index}].uri must be a nonempty string"
            )
        raw_digest = value.get("digest", {})
        if not isinstance(raw_digest, Mapping):
            raise ProvenanceError(
                f"resolvedDependencies[{index}].digest must be an object"
            )
        digest: dict[str, str] = {}
        for algorithm, digest_value in raw_digest.items():
            if (
                not isinstance(algorithm, str)
                or not isinstance(digest_value, str)
                or not digest_value
            ):
                raise ProvenanceError("material digests must map strings to strings")
            digest[algorithm] = digest_value
        return cls(uri, digest)

    def to_dict(self) -> dict[str, object]:
        return {"uri": self.uri, "digest": dict(self.digest)}


@dataclass(frozen=True, slots=True)
class SlsaProvenance:
    """Facts reported by SLSA Provenance v1 without a level claim."""

    PREDICATE_TYPE: ClassVar[str] = "https://slsa.dev/provenance/v1"

    builder_id: str
    build_type: str
    invocation_id: str | None
    source_uri: str | None
    source_digest: Mapping[str, str]
    materials: tuple[ProvenanceMaterial, ...]
    external_parameters: Mapping[str, object]
    internal_parameters: Mapping[str, object]
    started_on: str | None
    finished_on: str | None

    @classmethod
    def from_payload(
        cls,
        payload: bytes | str | Mapping[str, object],
    ) -> SlsaProvenance:
        try:
            statement = InTotoStatement.from_payload(payload)
        except StatementError as exc:
            raise ProvenanceError(str(exc)) from exc
        return cls.from_statement(statement)

    @classmethod
    def from_statement(cls, statement: InTotoStatement) -> SlsaProvenance:
        if statement.predicate_type != cls.PREDICATE_TYPE:
            raise ProvenanceError("unsupported SLSA provenance predicate type")

        predicate = statement.value.get("predicate")
        if not isinstance(predicate, Mapping):
            raise ProvenanceError("predicate must be an object")
        build_definition = predicate.get("buildDefinition")
        if not isinstance(build_definition, Mapping):
            raise ProvenanceError("buildDefinition must be an object")
        run_details = predicate.get("runDetails")
        if not isinstance(run_details, Mapping):
            raise ProvenanceError("runDetails must be an object")
        builder = run_details.get("builder")
        if not isinstance(builder, Mapping):
            raise ProvenanceError("runDetails.builder must be an object")
        metadata = run_details.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ProvenanceError("runDetails.metadata must be an object")

        build_type = build_definition.get("buildType")
        if not isinstance(build_type, str) or not build_type:
            raise ProvenanceError("buildDefinition.buildType must be a nonempty string")
        builder_id = builder.get("id")
        if not isinstance(builder_id, str) or not builder_id:
            raise ProvenanceError("runDetails.builder.id must be a nonempty string")

        optional_strings: dict[str, str | None] = {}
        for key in ("invocationId", "startedOn", "finishedOn"):
            value = metadata.get(key)
            if value is not None and (not isinstance(value, str) or not value):
                raise ProvenanceError(
                    f"runDetails.metadata.{key} must be a nonempty string"
                )
            optional_strings[key] = value

        dependencies = build_definition.get("resolvedDependencies", ())
        if not isinstance(dependencies, Sequence) or isinstance(
            dependencies,
            (str, bytes, bytearray),
        ):
            raise ProvenanceError("resolvedDependencies must be a list")
        materials = tuple(
            ProvenanceMaterial.from_mapping(value, index)
            for index, value in enumerate(dependencies)
        )

        external_parameters = build_definition.get("externalParameters", {})
        if not isinstance(external_parameters, Mapping):
            raise ProvenanceError("externalParameters must be an object")
        internal_parameters = build_definition.get("internalParameters", {})
        if not isinstance(internal_parameters, Mapping):
            raise ProvenanceError("internalParameters must be an object")

        return cls(
            builder_id=builder_id,
            build_type=build_type,
            invocation_id=optional_strings["invocationId"],
            source_uri=None,
            source_digest={},
            materials=materials,
            external_parameters=external_parameters,
            internal_parameters=internal_parameters,
            started_on=optional_strings["startedOn"],
            finished_on=optional_strings["finishedOn"],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "builder": self.builder_id,
            "build_type": self.build_type,
            "invocation": self.invocation_id,
            "source": (
                {"uri": self.source_uri, "digest": dict(self.source_digest)}
                if self.source_uri is not None
                else None
            ),
            "materials": [material.to_dict() for material in self.materials],
            "external_parameters": dict(self.external_parameters),
            "internal_parameters": dict(self.internal_parameters),
            "started_on": self.started_on,
            "finished_on": self.finished_on,
        }
