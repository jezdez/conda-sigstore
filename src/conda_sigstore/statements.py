"""In-toto statements used by conda package attestations."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .exceptions import PublishStatementError, StatementError
from .model import validate_sha256

if TYPE_CHECKING:
    from typing import NoReturn


@dataclass(frozen=True, slots=True)
class StatementSubject:
    """One named in-toto statement subject."""

    name: str
    digest: Mapping[str, str]

    @classmethod
    def from_mapping(cls, value: object, index: int) -> StatementSubject:
        if not isinstance(value, Mapping):
            raise StatementError(f"subject[{index}] must be an object")
        name = value.get("name")
        if not isinstance(name, str) or not name:
            raise StatementError(f"subject[{index}].name must be a nonempty string")
        raw_digest = value.get("digest")
        if not isinstance(raw_digest, Mapping):
            raise StatementError(f"subject[{index}].digest must be an object")
        if not raw_digest:
            raise StatementError(f"subject[{index}].digest must not be empty")
        digest: dict[str, str] = {}
        for algorithm, digest_value in raw_digest.items():
            if not isinstance(algorithm, str) or not algorithm:
                raise StatementError("subject digest algorithms must be strings")
            if not isinstance(digest_value, str) or not digest_value:
                raise StatementError("subject digest values must be strings")
            digest[algorithm] = (
                digest_value.lower() if algorithm == "sha256" else digest_value
            )
        return cls(name, digest)

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "digest": dict(self.digest)}


@dataclass(frozen=True, slots=True)
class InTotoStatement:
    """A minimally validated in-toto Statement v1."""

    STATEMENT_TYPE: ClassVar[str] = "https://in-toto.io/Statement/v1"
    PAYLOAD_TYPE: ClassVar[str] = "application/vnd.in-toto+json"

    value: Mapping[str, object]

    @staticmethod
    def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject duplicate keys while constructing one JSON object."""
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise StatementError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    @staticmethod
    def reject_json_constant(value: str) -> NoReturn:
        """Reject JavaScript numeric constants that JSON does not define."""
        raise StatementError(f"invalid JSON constant: {value}")

    @classmethod
    def from_payload(
        cls,
        payload: bytes | str | Mapping[str, object],
    ) -> InTotoStatement:
        """Parse one unambiguous in-toto Statement v1 JSON object."""
        if isinstance(payload, Mapping):
            value: object = dict(payload)
        else:
            try:
                value = json.loads(
                    payload,
                    object_pairs_hook=cls.unique_json_object,
                    parse_constant=cls.reject_json_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise StatementError(
                    "statement payload must be a UTF-8 JSON object"
                ) from exc
        if not isinstance(value, Mapping):
            raise StatementError("statement payload must be a JSON object")
        statement = cast("Mapping[str, object]", value)
        if statement.get("_type") != cls.STATEMENT_TYPE:
            raise StatementError("unsupported in-toto statement type")
        predicate_type = statement.get("predicateType")
        if not isinstance(predicate_type, str) or not predicate_type:
            raise StatementError("predicateType must be a nonempty string")
        return cls(statement)

    @property
    def predicate_type(self) -> str:
        return cast("str", self.value["predicateType"])

    def subjects(self) -> tuple[StatementSubject, ...]:
        raw_subjects = self.value.get("subject")
        if not isinstance(raw_subjects, Sequence) or isinstance(
            raw_subjects,
            (str, bytes, bytearray),
        ):
            raise StatementError("subject must be a list")
        if not raw_subjects:
            raise StatementError("subject must not be empty")
        return tuple(
            StatementSubject.from_mapping(value, index)
            for index, value in enumerate(raw_subjects)
        )


@dataclass(frozen=True, slots=True)
class PublishStatement:
    """A CEP 27 publication statement bound to one conda package."""

    PREDICATE_TYPE: ClassVar[str] = (
        "https://schemas.conda.org/attestations-publish-1.schema.json"
    )

    filename: str
    sha256: str
    target_channel: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "filename", self.validate_filename(self.filename))
        object.__setattr__(self, "sha256", self.validate_digest(self.sha256))
        if self.target_channel is not None:
            object.__setattr__(
                self,
                "target_channel",
                self.validate_target_channel(self.target_channel),
            )

    @staticmethod
    def validate_filename(value: object) -> str:
        if not isinstance(value, str) or not value:
            raise PublishStatementError("subject name must be a conda package filename")
        if "/" in value or "\\" in value or "\0" in value:
            raise PublishStatementError("subject name must not contain a path")
        extension = ".conda" if value.endswith(".conda") else ".tar.bz2"
        if not value.endswith(extension):
            raise PublishStatementError("subject name must end in .conda or .tar.bz2")
        stem = value[: -len(extension)]
        if stem.count("-") < 2 or any(not part for part in stem.split("-")):
            raise PublishStatementError(
                "subject name must contain name, version, and build"
            )
        return value

    @staticmethod
    def validate_digest(value: object) -> str:
        try:
            return validate_sha256(value, field_name="subject sha256")
        except ValueError as exc:
            raise PublishStatementError(str(exc)) from exc

    @staticmethod
    def validate_target_channel(value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > 2083:
            raise PublishStatementError("targetChannel must be a valid URL")
        if value.endswith("/"):
            raise PublishStatementError("targetChannel must not have a trailing slash")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise PublishStatementError("targetChannel must be a valid URL") from exc
        if (
            parsed.username
            or parsed.password
            or re.search(r"/t/[A-Za-z0-9-]+", parsed.path)
        ):
            raise PublishStatementError("targetChannel must not contain credentials")
        scheme = parsed.scheme.lower()
        if (
            scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
        ):
            raise PublishStatementError("targetChannel must be a valid URL")
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        if port is not None and not (
            (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        ):
            host = f"{host}:{port}"
        return urlunsplit(SplitResult(scheme, host, parsed.path, "", ""))

    @classmethod
    def from_payload(
        cls,
        payload: bytes | str | Mapping[str, object],
    ) -> PublishStatement:
        try:
            statement = InTotoStatement.from_payload(payload)
        except StatementError as exc:
            raise PublishStatementError(str(exc)) from exc
        return cls.from_statement(statement)

    @classmethod
    def from_statement(cls, statement: InTotoStatement) -> PublishStatement:
        if statement.predicate_type != cls.PREDICATE_TYPE:
            raise PublishStatementError("unsupported publish predicate type")
        try:
            subjects = statement.subjects()
        except StatementError as exc:
            raise PublishStatementError(str(exc)) from exc
        if len(subjects) != 1:
            raise PublishStatementError("CEP 27 requires exactly one subject")
        subject = subjects[0]
        if set(subject.digest) != {"sha256"}:
            raise PublishStatementError("subject digest must contain exactly sha256")

        target_channel: str | None = None
        if "predicate" in statement.value and statement.value["predicate"] is not None:
            predicate = statement.value["predicate"]
            if not isinstance(predicate, Mapping):
                raise PublishStatementError("predicate must be an object or null")
            if "targetChannel" not in predicate:
                raise PublishStatementError("predicate must contain targetChannel")
            target_channel_value = predicate["targetChannel"]
            if not isinstance(target_channel_value, str):
                raise PublishStatementError("targetChannel must be a valid URL")
            target_channel = target_channel_value

        return cls(subject.name, subject.digest["sha256"], target_channel)

    def bind(
        self,
        *,
        expected_filename: str,
        expected_sha256: str,
        accepted_target_channels: tuple[str, ...] = (),
        require_target_channel: bool = False,
    ) -> PublishStatement:
        filename = self.validate_filename(expected_filename)
        sha256 = self.validate_digest(expected_sha256)
        if self.filename != filename:
            raise PublishStatementError(
                f"subject filename {self.filename!r} does not match {filename!r}"
            )
        if not hmac.compare_digest(self.sha256, sha256):
            raise PublishStatementError("subject sha256 does not match the package")
        if self.target_channel is None:
            if require_target_channel:
                raise PublishStatementError(
                    "attestation does not declare a targetChannel"
                )
            return self

        accepted = tuple(
            self.validate_target_channel(channel)
            for channel in accepted_target_channels
        )
        if accepted and self.target_channel not in accepted:
            raise PublishStatementError(
                f"targetChannel {self.target_channel!r} does not match "
                "the supplied channel"
            )
        return self

    def to_dict(self) -> dict[str, object]:
        return {
            "_type": InTotoStatement.STATEMENT_TYPE,
            "subject": [{"name": self.filename, "digest": {"sha256": self.sha256}}],
            "predicateType": self.PREDICATE_TYPE,
            "predicate": (
                {"targetChannel": self.target_channel}
                if self.target_channel is not None
                else None
            ),
        }

    def payload(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


__all__ = ["InTotoStatement", "PublishStatement", "StatementSubject"]
