from __future__ import annotations

import json

import pytest

from conda_sigstore.exceptions import PublishStatementError, StatementError
from conda_sigstore.statements import (
    InTotoStatement,
    PublishStatement,
    StatementSubject,
)

FILENAME = "pkg-1.0RC1-PY_0.conda"
DIGEST = "ab" * 32
CHANNEL = "https://conda.example.org/channel"


def test_publish_statement_binds_exact_package() -> None:
    statement = PublishStatement(FILENAME, DIGEST.upper(), CHANNEL)

    assert statement.to_dict()["predicateType"] == PublishStatement.PREDICATE_TYPE
    parsed = PublishStatement.from_payload(statement.payload()).bind(
        expected_filename=FILENAME,
        expected_sha256=DIGEST,
        accepted_target_channels=(CHANNEL,),
        require_target_channel=True,
    )
    assert parsed == PublishStatement(FILENAME, DIGEST, CHANNEL)


def test_uppercase_version_and_build_characters_are_allowed() -> None:
    assert (
        PublishStatement.from_payload(
            PublishStatement(FILENAME, DIGEST).payload()
        ).filename
        == FILENAME
    )


@pytest.mark.parametrize(
    ("filename", "message"),
    [
        (None, "conda package filename"),
        ("pkg-1-0.whl", "must end in"),
        ("pkg.conda", "name, version, and build"),
        ("pkg-1-.conda", "name, version, and build"),
        ("dir/pkg-1-0.conda", "must not contain a path"),
        ("dir\\pkg-1-0.conda", "must not contain a path"),
        ("pkg-1-0.conda\0secret", "must not contain a path"),
    ],
)
def test_publish_statement_rejects_malformed_filename(
    filename: object,
    message: str,
) -> None:
    with pytest.raises(PublishStatementError, match=message):
        PublishStatement(filename, DIGEST)  # type: ignore[arg-type]


@pytest.mark.parametrize("predicate", [None, "absent"])
def test_predicate_may_be_null_or_absent(predicate: object) -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    if predicate == "absent":
        statement.pop("predicate")
    parsed = PublishStatement.from_payload(statement).bind(
        expected_filename=FILENAME,
        expected_sha256=DIGEST,
        accepted_target_channels=(CHANNEL,),
    )
    assert parsed.target_channel is None


@pytest.mark.parametrize(
    ("predicate", "message"),
    [
        ({}, "must contain targetChannel"),
        ([], "must be an object or null"),
        ({"targetChannel": 1}, "targetChannel must be a valid URL"),
    ],
)
def test_publish_statement_rejects_malformed_predicate(
    predicate: object,
    message: str,
) -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    statement["predicate"] = predicate
    with pytest.raises(PublishStatementError, match=message):
        PublishStatement.from_payload(statement)


def test_subject_must_have_one_sha256_and_match_artifact() -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    statement["subject"][0]["digest"]["sha512"] = "cd" * 64  # type: ignore[index]
    with pytest.raises(PublishStatementError, match="exactly sha256"):
        PublishStatement.from_payload(statement)

    with pytest.raises(PublishStatementError, match="does not match"):
        PublishStatement(FILENAME, DIGEST).bind(
            expected_filename="other-1.0-0.conda",
            expected_sha256=DIGEST,
        )


def test_subject_digest_must_match_artifact() -> None:
    with pytest.raises(PublishStatementError, match="sha256 does not match"):
        PublishStatement(FILENAME, DIGEST).bind(
            expected_filename=FILENAME,
            expected_sha256="cd" * 32,
        )


def test_required_target_channel_must_be_present() -> None:
    with pytest.raises(PublishStatementError, match="does not declare"):
        PublishStatement(FILENAME, DIGEST).bind(
            expected_filename=FILENAME,
            expected_sha256=DIGEST,
            require_target_channel=True,
        )


def test_target_channel_must_be_explicitly_allowed() -> None:
    with pytest.raises(
        PublishStatementError,
        match="does not match the supplied channel",
    ):
        PublishStatement(FILENAME, DIGEST, CHANNEL).bind(
            expected_filename=FILENAME,
            expected_sha256=DIGEST,
            accepted_target_channels=("https://mirror.example.org/channel",),
        )


def test_target_channel_is_reported_without_an_expected_channel() -> None:
    statement = PublishStatement(FILENAME, DIGEST, CHANNEL)

    assert (
        statement.bind(
            expected_filename=FILENAME,
            expected_sha256=DIGEST,
        )
        == statement
    )


def test_statement_model_normalizes_target_channel() -> None:
    statement = PublishStatement(
        FILENAME,
        DIGEST,
        "HTTPS://CONDA.EXAMPLE.ORG:443/channel",
    )

    assert statement.target_channel == CHANNEL
    assert PublishStatement.from_payload(statement.payload()) == statement


def test_duplicate_json_keys_are_rejected() -> None:
    payload = PublishStatement(FILENAME, DIGEST).payload().decode()
    payload = payload[:-1] + ', "predicateType": "wrong"}'
    with pytest.raises(PublishStatementError, match="duplicate JSON key"):
        PublishStatement.from_payload(payload)


@pytest.mark.parametrize(
    ("channel", "message"),
    [
        (1, "valid URL"),
        ("x" * 2084, "valid URL"),
        (f"{CHANNEL}/", "trailing slash"),
        ("https://conda.example.org:invalid/channel", "valid URL"),
        ("ftp://conda.example.org/channel", "valid URL"),
        ("https:///channel", "valid URL"),
        (f"{CHANNEL}?token=value", "valid URL"),
        (f"{CHANNEL}#fragment", "valid URL"),
    ],
)
def test_target_channel_rejects_malformed_url(
    channel: object,
    message: str,
) -> None:
    with pytest.raises(PublishStatementError, match=message):
        PublishStatement(FILENAME, DIGEST, channel)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "channel",
    [
        "https://conda.example.org/t/super-secret/channel",
        "https://conda.example.org/t//channel",
    ],
)
def test_target_channel_rejects_path_credentials(channel: str) -> None:
    with pytest.raises(PublishStatementError, match="credentials"):
        PublishStatement(FILENAME, DIGEST, channel)


def test_target_channel_preserves_explicit_port_zero() -> None:
    statement = PublishStatement(
        FILENAME,
        DIGEST,
        "https://conda.example.org:0/channel",
    )

    assert statement.target_channel == "https://conda.example.org:0/channel"


def test_in_toto_statement_owns_predicate_and_subject_parsing() -> None:
    statement = InTotoStatement.from_payload(
        {
            "_type": InTotoStatement.STATEMENT_TYPE,
            "predicateType": "https://example.org/predicate",
            "subject": [{"name": "artifact", "digest": {"sha256": DIGEST}}],
        }
    )

    assert statement.predicate_type == "https://example.org/predicate"
    assert statement.subjects()[0].digest["sha256"] == DIGEST


def test_in_toto_statement_serializes_stable_payload() -> None:
    statement = InTotoStatement.from_payload(
        {
            "subject": [{"digest": {"sha256": DIGEST}, "name": "artifact"}],
            "predicateType": "https://example.org/predicate",
            "predicate": {"label": "café"},
            "_type": InTotoStatement.STATEMENT_TYPE,
        }
    )

    assert (
        statement.payload()
        == json.dumps(
            statement.value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    assert InTotoStatement.from_payload(statement.payload()).value == statement.value


def test_in_toto_statement_rejects_non_json_signing_payload() -> None:
    statement = InTotoStatement.from_payload(
        {
            "_type": InTotoStatement.STATEMENT_TYPE,
            "predicateType": "https://example.org/predicate",
            "predicate": {"unsupported": object()},
            "subject": [{"name": "artifact", "digest": {"sha256": DIGEST}}],
        }
    )

    with pytest.raises(StatementError, match="only JSON values"):
        statement.payload()


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, r"subject\[0\] must be an object"),
        ({"name": "", "digest": {"sha256": DIGEST}}, "name must be"),
        ({"name": "artifact", "digest": []}, "digest must be an object"),
        ({"name": "artifact", "digest": {}}, "digest must not be empty"),
        ({"name": "artifact", "digest": {1: DIGEST}}, "algorithms must be strings"),
        ({"name": "artifact", "digest": {"sha256": 1}}, "values must be strings"),
    ],
)
def test_statement_subject_rejects_malformed_values(
    value: object,
    message: str,
) -> None:
    with pytest.raises(StatementError, match=message):
        StatementSubject.from_mapping(value, 0)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("[]", "must be a JSON object"),
        (
            {"_type": "https://example.org/wrong", "predicateType": "predicate"},
            "unsupported in-toto statement type",
        ),
        (
            {"_type": InTotoStatement.STATEMENT_TYPE, "predicateType": 1},
            "predicateType must be a nonempty string",
        ),
    ],
)
def test_in_toto_statement_rejects_malformed_structure(
    payload: str | dict[str, object],
    message: str,
) -> None:
    with pytest.raises(StatementError, match=message):
        InTotoStatement.from_payload(payload)


def test_publish_statement_rejects_wrong_predicate_type() -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    statement["predicateType"] = "https://example.org/wrong"

    with pytest.raises(PublishStatementError, match="unsupported publish predicate"):
        PublishStatement.from_payload(statement)


@pytest.mark.parametrize(
    ("subjects", "message"),
    [
        ({}, "subject must be a list"),
        ([], "subject must not be empty"),
        (
            [
                {"name": FILENAME, "digest": {"sha256": DIGEST}},
                {"name": FILENAME, "digest": {"sha256": DIGEST}},
            ],
            "exactly one subject",
        ),
    ],
)
def test_publish_statement_rejects_invalid_subject_cardinality(
    subjects: object,
    message: str,
) -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    statement["subject"] = subjects

    with pytest.raises(PublishStatementError, match=message):
        PublishStatement.from_payload(statement)


def test_in_toto_statement_rejects_duplicate_json_keys() -> None:
    payload = json.dumps(
        {
            "_type": InTotoStatement.STATEMENT_TYPE,
            "predicateType": "https://example.org/predicate",
            "subject": [{"name": "artifact", "digest": {"sha256": DIGEST}}],
        }
    )
    payload = payload[:-1] + ', "predicateType": "duplicate"}'

    with pytest.raises(StatementError, match="duplicate JSON key"):
        InTotoStatement.from_payload(payload)


def test_in_toto_statement_rejects_non_utf8_json() -> None:
    payload = PublishStatement(FILENAME, DIGEST).payload().decode().encode("utf-16")

    with pytest.raises(StatementError, match="UTF-8"):
        InTotoStatement.from_payload(payload)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_in_toto_statement_rejects_nonstandard_json_constants(constant: str) -> None:
    payload = PublishStatement(FILENAME, DIGEST).payload().decode()
    payload = payload[:-1] + f', "extension": {constant}}}'

    with pytest.raises(StatementError, match="invalid JSON constant"):
        InTotoStatement.from_payload(payload)
