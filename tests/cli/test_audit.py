from __future__ import annotations

import json
from types import SimpleNamespace

import conda.base.context
import pytest

import conda_sigstore.cli.audit as cli_audit
from conda_sigstore.exceptions import CondaSigstoreError


@pytest.mark.parametrize("output_option", [("--json",), ("--console", "json")])
def test_audit_uses_explicit_prefix_sidecars(
    monkeypatch, tmp_path, capsys, sigstore_parser, rich_console, output_option
) -> None:
    target = tmp_path.resolve()
    captured = {}
    report = {"version": 1, "prefix": str(target), "packages": []}

    class FakeAuditor:
        @classmethod
        def current(cls, *, transport):
            captured["transport"] = transport
            return cls()

        def audit_environment(self, prefix, *, include_sources):
            captured.update(prefix=prefix, include_sources=include_sources)
            return report

    monkeypatch.setattr(cli_audit, "EnvironmentAuditor", FakeAuditor)
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(target_prefix=target),
    )
    args = sigstore_parser.parse_args(
        [
            "audit",
            "--prefix",
            str(tmp_path),
            "--sources",
            "--prefix-sidecars",
            *output_option,
        ]
    )

    assert cli_audit.execute_audit(args, console=rich_console) == 0
    captured_output = capsys.readouterr()
    assert captured_output.out == json.dumps(report, indent=2, sort_keys=True) + "\n"
    assert captured_output.err == ""
    assert json.loads(captured_output.out) == report
    assert rich_console.file.getvalue() == ""
    assert captured == {
        "transport": "prefix",
        "prefix": target,
        "include_sources": True,
    }


def test_audit_human_output_uses_injected_console(
    monkeypatch, tmp_path, capsys, sigstore_parser, rich_console
) -> None:
    report = {
        "version": 1,
        "prefix": str(tmp_path),
        "packages": [
            {
                "artifact": "demo[1]-1-0.conda",
                "status": "verified",
                "evidence": [
                    {
                        "bundle_index": 0,
                        "predicate_type": "https://example.org/predicate",
                        "verified": True,
                        "identity": "publisher@example.org",
                        "issuer": "https://issuer.example",
                        "timestamps": [],
                        "details": {},
                    }
                ],
                "failures": [],
                "source_evidence": [],
            }
        ],
    }

    class FakeAuditor:
        @classmethod
        def current(cls, *, transport):
            return cls()

        def audit_environment(self, prefix, *, include_sources):
            return report

    monkeypatch.setattr(cli_audit, "EnvironmentAuditor", FakeAuditor)
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(target_prefix=tmp_path),
    )
    args = sigstore_parser.parse_args(["audit", "--prefix", str(tmp_path)])

    assert cli_audit.execute_audit(args, console=rich_console) == 0
    output = rich_console.file.getvalue()
    assert "demo[1]-1-0.conda" in output
    assert "verified" in output
    assert "publisher@example.org" in output
    assert capsys.readouterr().out == ""


def test_audit_reports_expected_configuration_failure(
    monkeypatch, sigstore_parser
) -> None:
    class FailingAuditor:
        @classmethod
        def current(cls, *, transport):
            raise ValueError("bad trust configuration")

    monkeypatch.setattr(cli_audit, "EnvironmentAuditor", FailingAuditor)
    args = sigstore_parser.parse_args(["audit"])

    with pytest.raises(CondaSigstoreError, match="bad trust configuration"):
        cli_audit.execute_audit(args)
