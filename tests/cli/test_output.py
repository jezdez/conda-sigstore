from __future__ import annotations

from conda_sigstore.cli.output import print_evidence, print_source_evidence


def test_human_output_reports_evidence_without_interpreting_markup(
    rich_console,
) -> None:
    print_evidence(
        rich_console,
        {
            "evidence": [
                {
                    "bundle_index": 0,
                    "predicate_type": "https://example.org/predicate",
                    "verified": True,
                    "identity": "[bold]publisher[/bold]",
                    "issuer": "https://issuer.example",
                    "timestamps": ["2026-08-10T12:00:00Z"],
                    "details": {
                        "target_channel": "https://conda.example/channel",
                        "provenance": {
                            "builder": "https://builder.example",
                            "build_type": "https://example.org/build",
                            "invocation": "run-1",
                            "materials": [{"uri": "git+https://example.org/repo"}],
                        },
                    },
                }
            ],
            "failures": [{"code": "invalid-bundle", "message": "bad sibling"}],
        },
    )

    output = rich_console.file.getvalue()
    assert "https://example.org/predicate" in output
    assert "[bold]publisher[/bold]" in output
    assert "https://issuer.example" in output
    assert "2026-08-10T12:00:00Z" in output
    assert "https://conda.example/channel" in output
    assert "https://builder.example" in output
    assert "https://example.org/build" in output
    assert "git+https://example.org/repo" in output
    assert "invalid-bundle" in output
    assert "authorized" not in output


def test_human_output_reports_embedded_source_evidence(rich_console) -> None:
    print_source_evidence(
        rich_console,
        {
            "source_evidence": [
                {
                    "source_index": 0,
                    "status": "verified",
                    "required_publishers": [
                        {
                            "identity": "https://github.com/example/project",
                            "issuer": "https://token.actions.githubusercontent.com",
                        }
                    ],
                    "bundles": [
                        {
                            "path": "attestations/source.sigstore.json",
                            "status": "verified",
                            "identity": "publisher@example.org",
                            "issuer": "https://issuer.example",
                            "predicate_type": "https://example.org/source",
                            "timestamps": ["2026-08-10T12:00:00Z"],
                        }
                    ],
                }
            ]
        },
    )

    output = rich_console.file.getvalue()
    assert "https://github.com/example/project" in output
    assert "attestations/source.sigstore.json" in output
    assert "publisher@example.org" in output
    assert "https://example.org/source" in output
