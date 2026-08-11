from __future__ import annotations

from copy import deepcopy

import pytest

from conda_sigstore.exceptions import ProvenanceError
from conda_sigstore.provenance import SlsaProvenance
from conda_sigstore.statements import InTotoStatement


def slsa_statement() -> dict[str, object]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": "ab" * 32}}],
        "predicateType": SlsaProvenance.PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.org/build/v1",
                "externalParameters": {"target": "package"},
                "internalParameters": {"runner": "hosted"},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://example.org/repo",
                        "digest": {"gitCommit": "abc"},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": "https://example.org/builder"},
                "metadata": {
                    "invocationId": "run-1",
                    "startedOn": "2026-08-10T10:00:00Z",
                    "finishedOn": "2026-08-10T10:01:00Z",
                },
            },
        },
    }


def test_slsa_provenance_reports_facts_without_a_level() -> None:
    result = SlsaProvenance.from_statement(
        InTotoStatement.from_payload(slsa_statement())
    )
    output = result.to_dict()
    assert output["builder"] == "https://example.org/builder"
    assert output["build_type"] == "https://example.org/build/v1"
    assert output["source"] is None
    assert output["materials"] == [
        {
            "uri": "git+https://example.org/repo",
            "digest": {"gitCommit": "abc"},
        }
    ]
    assert "slsa_level" not in output


def test_slsa_provenance_rejects_missing_builder() -> None:
    statement = slsa_statement()
    del statement["predicate"]["runDetails"]["builder"]  # type: ignore[index]
    with pytest.raises(ProvenanceError, match="runDetails.builder"):
        SlsaProvenance.from_statement(InTotoStatement.from_payload(statement))


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("predicate",), None, "predicate must be an object"),
        (("predicate", "buildDefinition"), None, "buildDefinition"),
        (("predicate", "runDetails"), None, "runDetails must be an object"),
        (("predicate", "runDetails", "builder"), None, "runDetails.builder"),
        (("predicate", "runDetails", "metadata"), [], "metadata"),
        (
            ("predicate", "buildDefinition", "buildType"),
            "",
            "buildType",
        ),
        (("predicate", "runDetails", "builder", "id"), "", "builder.id"),
        (
            ("predicate", "runDetails", "metadata", "invocationId"),
            1,
            "invocationId",
        ),
        (
            ("predicate", "buildDefinition", "resolvedDependencies"),
            {},
            "resolvedDependencies must be a list",
        ),
        (
            ("predicate", "buildDefinition", "externalParameters"),
            [],
            "externalParameters",
        ),
        (
            ("predicate", "buildDefinition", "internalParameters"),
            [],
            "internalParameters",
        ),
    ],
)
def test_slsa_provenance_rejects_malformed_fields(
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    payload = deepcopy(slsa_statement())
    target = payload
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment,index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ProvenanceError, match=message):
        SlsaProvenance.from_statement(InTotoStatement.from_payload(payload))


@pytest.mark.parametrize(
    ("material", "message"),
    [
        (None, r"resolvedDependencies\[0\] must be an object"),
        ({"uri": ""}, r"resolvedDependencies\[0\].uri"),
        ({"uri": "source", "digest": []}, r"resolvedDependencies\[0\].digest"),
        (
            {"uri": "source", "digest": {"sha256": ""}},
            "material digests",
        ),
        (
            {"uri": "source", "digest": {1: "ab"}},
            "material digests",
        ),
    ],
)
def test_slsa_provenance_rejects_malformed_materials(
    material: object,
    message: str,
) -> None:
    payload = slsa_statement()
    payload["predicate"]["buildDefinition"]["resolvedDependencies"] = [material]  # type: ignore[index]

    with pytest.raises(ProvenanceError, match=message):
        SlsaProvenance.from_statement(InTotoStatement.from_payload(payload))


def test_slsa_provenance_rejects_other_predicate() -> None:
    payload = slsa_statement()
    payload["predicateType"] = "https://example.org/other"

    with pytest.raises(ProvenanceError, match="unsupported SLSA"):
        SlsaProvenance.from_statement(InTotoStatement.from_payload(payload))
