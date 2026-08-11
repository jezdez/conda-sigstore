from __future__ import annotations

import pytest

from conda_sigstore.source_attestations import (
    EmbeddedSourceBundle,
    SourceAttestationRequirement,
)


def source(
    *,
    attestation: object = None,
    sha256: object = "ab" * 32,
) -> dict[str, object]:
    if attestation is None:
        attestation = {
            "publishers": ["github:example/project"],
            "verified": [
                {
                    "path": "attestations/source.sigstore.json",
                    "sha256": "cd" * 32,
                }
            ],
        }
    return {
        "url": "https://example.org/source.tar.gz",
        "sha256": sha256,
        "attestation": attestation,
    }


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "entries must be objects"),
        ({"path": 1, "sha256": "ab" * 32}, "safe POSIX"),
        (
            {"path": "attestations/source.json", "sha256": "ab" * 32},
            "embedded Sigstore bundle",
        ),
        (
            {
                "path": "attestations/source.sigstore.json",
                "sha256": "invalid",
            },
            "verified.sha256",
        ),
    ],
)
def test_embedded_bundle_rejects_malformed_descriptor(
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        EmbeddedSourceBundle.from_mapping(value)


@pytest.mark.parametrize(
    ("publisher", "message"),
    [
        ({"identity": "publisher"}, "require identity and issuer"),
        ({"identity": 1, "issuer": "issuer"}, "must be strings"),
        (1, "strings or mappings"),
        ("github:example/project@main", "ref constraints"),
        ("example", "name a provider"),
        ("github:example", "owner and repository"),
        ("unknown:example/project", "unsupported publisher provider"),
    ],
)
def test_publisher_rejects_malformed_value(
    publisher: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        SourceAttestationRequirement.publisher(publisher)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("invalid", "attestation must be an object"),
        ({"publishers": [], "verified": []}, "must not be empty"),
        ({"publishers": "github:example/project"}, "publishers must be a list"),
        (
            {"publishers": ["github:example/project"], "predicate_type": ""},
            "predicate_type",
        ),
        (
            {"publishers": ["github:example/project"], "verified": {}},
            "verified must be a list",
        ),
    ],
)
def test_source_requirement_rejects_malformed_attestation(
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        SourceAttestationRequirement.from_source(
            source(attestation=value),
            0,
        )


@pytest.mark.parametrize(
    "value",
    [
        {"git": "https://example.org/repo", "sha256": "ab" * 32},
        {"path": "../source", "sha256": "ab" * 32},
        {"sha256": "ab" * 32},
    ],
)
def test_source_requirement_requires_url_source(value: dict[str, object]) -> None:
    value["attestation"] = {
        "publishers": ["github:example/project"],
        "verified": [],
    }
    with pytest.raises(ValueError, match="require a URL source"):
        SourceAttestationRequirement.from_source(value, 0)


@pytest.mark.parametrize(
    ("recipe", "message"),
    [
        ({"source": "source.tar.gz"}, "object or list"),
        ({"source": ["source.tar.gz"]}, r"source\[0\] must be an object"),
    ],
)
def test_recipe_rejects_malformed_sources(
    recipe: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        SourceAttestationRequirement.from_recipe(recipe)


def test_recipe_ignores_source_without_attestation() -> None:
    assert (
        SourceAttestationRequirement.from_recipe(
            {"source": {"url": "https://example.org/source.tar.gz"}}
        )
        == ()
    )
