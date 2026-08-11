from __future__ import annotations

import pytest

from conda_sigstore.exceptions import ProvenanceError
from conda_sigstore.provenance import SlsaProvenance


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
    result = SlsaProvenance.from_payload(slsa_statement())
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
        SlsaProvenance.from_payload(statement)
