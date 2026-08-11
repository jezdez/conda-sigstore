from __future__ import annotations

import json

import pytest

from conda_sigstore.exceptions import PublishStatementError, StatementError
from conda_sigstore.statements import InTotoStatement, PublishStatement

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


def test_present_predicate_requires_target_channel() -> None:
    statement = PublishStatement(FILENAME, DIGEST).to_dict()
    statement["predicate"] = {}
    with pytest.raises(PublishStatementError, match="must contain targetChannel"):
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


def test_target_channel_rejects_trailing_slash() -> None:
    with pytest.raises(PublishStatementError, match="trailing slash"):
        PublishStatement(FILENAME, DIGEST, f"{CHANNEL}/")


def test_target_channel_rejects_path_credentials() -> None:
    with pytest.raises(PublishStatementError, match="credentials"):
        PublishStatement(
            FILENAME,
            DIGEST,
            "https://conda.example.org/t/super-secret/channel",
        )


def test_target_channel_preserves_explicit_port_zero() -> None:
    statement = PublishStatement(
        FILENAME,
        DIGEST,
        "https://conda.example.org:0/channel",
    )

    assert statement.target_channel == "https://conda.example.org:0/channel"


def test_subject_filename_rejects_platform_path_separators() -> None:
    for filename in ("dir/pkg-1-0.conda", "dir\\pkg-1-0.conda"):
        with pytest.raises(PublishStatementError, match="must not contain a path"):
            PublishStatement(filename, DIGEST)


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


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_in_toto_statement_rejects_nonstandard_json_constants(constant: str) -> None:
    payload = PublishStatement(FILENAME, DIGEST).payload().decode()
    payload = payload[:-1] + f', "extension": {constant}}}'

    with pytest.raises(StatementError, match="invalid JSON constant"):
        InTotoStatement.from_payload(payload)
