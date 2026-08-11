from __future__ import annotations

import importlib
from argparse import Namespace
from typing import TYPE_CHECKING

import pytest

from conda_sigstore.cli import execute
from conda_sigstore.exceptions import CondaSigstoreError

if TYPE_CHECKING:
    from pathlib import Path

    from conda.testing.fixtures import CondaCLIFixture


def test_parser_exposes_evidence_commands(sigstore_parser) -> None:
    attest = sigstore_parser.parse_args(
        ["attest", "demo-1-0.conda", "--target-channel", "https://example.test"]
    )
    verify = sigstore_parser.parse_args(
        [
            "verify",
            "demo-1-0.conda",
            "--bundle",
            "demo.sigstore.json",
            "--cert-identity",
            "publisher@example.org",
            "--cert-oidc-issuer",
            "https://issuer.example",
        ]
    )
    audit = sigstore_parser.parse_args(["audit", "--sources", "--prefix-sidecars"])

    assert attest.sigstore_command == "attest"
    assert verify.sigstore_command == "verify"
    assert verify.cert_identity == "publisher@example.org"
    assert verify.cert_oidc_issuer == "https://issuer.example"
    assert audit.sigstore_command == "audit"
    assert audit.sources
    assert audit.prefix_sidecars


@pytest.mark.parametrize(
    ("command", "module_name", "handler_name"),
    [
        ("attest", "conda_sigstore.cli.attest", "execute_attest"),
        ("verify", "conda_sigstore.cli.verify", "execute_verify"),
        ("audit", "conda_sigstore.cli.audit", "execute_audit"),
    ],
)
def test_execute_dispatches_to_command_module(
    monkeypatch,
    command: str,
    module_name: str,
    handler_name: str,
) -> None:
    calls = []

    def handler(args):
        calls.append(args)
        return 0

    module = importlib.import_module(module_name)
    monkeypatch.setattr(module, handler_name, handler)
    args = Namespace(sigstore_command=command)

    assert execute(args) == 0
    assert calls == [args]


def test_execute_rejects_unknown_command() -> None:
    with pytest.raises(AssertionError, match="unknown command: unknown"):
        execute(Namespace(sigstore_command="unknown"))


def test_installed_entry_point_exposes_commands(
    conda_cli: CondaCLIFixture,
) -> None:
    stdout, stderr, error = conda_cli(
        "sigstore",
        "--help",
        raises=SystemExit,
    )

    assert error.value.code == 0
    assert "usage: conda sigstore" in stdout
    assert "{attest,verify,audit}" in stdout
    assert "Sign and verify conda packages with Sigstore." in stdout
    assert stderr == ""


@pytest.mark.parametrize(
    ("artifact_contents", "expected_code", "expected_message"),
    [
        pytest.param(
            None,
            "conda-sigstore",
            "package does not exist:",
            id="missing-artifact",
        ),
        pytest.param(
            b"package",
            "retrieval-failed",
            "could not read bundle missing.json (FileNotFoundError)",
            id="missing-bundle",
        ),
    ],
)
def test_installed_entry_point_reports_expected_failures(
    conda_cli: CondaCLIFixture,
    tmp_path: Path,
    artifact_contents: bytes | None,
    expected_code: str,
    expected_message: str,
) -> None:
    artifact = tmp_path / "demo-1-0.conda"
    if artifact_contents is not None:
        artifact.write_bytes(artifact_contents)

    stdout, stderr, error = conda_cli(
        "sigstore",
        "verify",
        artifact,
        "--bundle",
        tmp_path / "missing.json",
        raises=CondaSigstoreError,
    )

    assert stdout == ""
    assert stderr == ""
    assert error.value.code == expected_code
    assert expected_message in str(error.value)
