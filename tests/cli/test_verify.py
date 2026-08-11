from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import conda_sigstore.cli.verify as cli_verify
from conda_sigstore.evidence import (
    AuthorizationStatus,
    Sidecar,
    VerificationResult,
    VerificationStatus,
    VerifiedEvidence,
)
from conda_sigstore.exceptions import CondaSigstoreError, TransportError


def test_verify_json_passes_explicit_signer_requirement(
    monkeypatch, tmp_path, capsys, sigstore_parser, rich_console
) -> None:
    artifact = tmp_path / "demo-1-0.conda"
    artifact.write_bytes(b"package")
    trust_config = tmp_path / "trust.json"
    configured = SimpleNamespace(
        max_sidecar_bytes=1024,
        trust_config=trust_config,
    )
    sidecar = Sidecar("bundle.json", "cd" * 32, ("{}",))
    captured = {}

    class FakeSidecarTransport:
        def __init__(self, *, max_bytes):
            captured["max_bytes"] = max_bytes

        def load_input(self, source):
            captured["bundle_source"] = source
            return sidecar

    def verify_artifact(artifact_path, loaded, *, verifier, channel, expected_signer):
        captured.update(
            artifact=artifact_path,
            sidecar=loaded,
            verifier=verifier,
            channel=channel,
            expected_signer=expected_signer,
        )
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            artifact=artifact_path.name,
            artifact_sha256="ab" * 32,
            sidecar_sha256=loaded.sha256,
            channel=channel,
            evidence=(
                VerifiedEvidence(
                    bundle_index=0,
                    identity="publisher@example.org",
                    issuer="https://issuer.example",
                    predicate_type="https://example.org/predicate",
                    verified=True,
                    timestamps=("2026-08-10T12:00:00Z",),
                ),
            ),
            authorization=AuthorizationStatus.VERIFIED,
            expected_signer=expected_signer,
        )
        captured["result"] = result
        return result

    monkeypatch.setattr(
        cli_verify.SigstoreSettings,
        "current",
        classmethod(lambda cls: configured),
    )
    monkeypatch.setattr(cli_verify, "SidecarTransport", FakeSidecarTransport)
    monkeypatch.setattr(cli_verify, "verify_artifact", verify_artifact)
    args = sigstore_parser.parse_args(
        [
            "verify",
            str(artifact),
            "--bundle",
            "bundle.json",
            "--channel",
            "https://user:password@example.test/t/super-secret/channel",
            "--cert-identity",
            "publisher@example.org",
            "--cert-oidc-issuer",
            "https://issuer.example",
            "--json",
        ]
    )

    assert cli_verify.execute_verify(args, console=rich_console) == 0
    captured_output = capsys.readouterr()
    output = captured_output.out
    report = json.loads(output)
    assert report == captured["result"].to_dict()
    expected_output = json.dumps(
        captured["result"].to_dict(),
        indent=2,
        sort_keys=True,
    )
    assert output == f"{expected_output}\n"
    assert captured_output.err == ""
    assert rich_console.file.getvalue() == ""
    assert report["authorization"] == "verified"
    assert report["sidecar_sha256"] == sidecar.sha256
    assert report["expected_signer"] == {
        "identity": "publisher@example.org",
        "issuer": "https://issuer.example",
    }
    assert report["evidence"][0]["identity"] == "publisher@example.org"
    assert report["evidence"][0]["issuer"] == "https://issuer.example"
    assert report["evidence"][0]["verified"] is True
    assert "authorized" not in report["evidence"][0]
    assert captured["bundle_source"] == "bundle.json"
    assert captured["max_bytes"] == 1024
    assert captured["artifact"] == artifact
    assert captured["sidecar"] is sidecar
    assert captured["verifier"].trust_config == trust_config
    assert captured["channel"] == "https://example.test/channel"
    assert captured["expected_signer"].identity == "publisher@example.org"
    assert captured["expected_signer"].issuer == "https://issuer.example"
    assert "password" not in output
    assert "super-secret" not in output


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [
        (VerificationStatus.VERIFIED, 0),
        (VerificationStatus.INVALID, 1),
    ],
)
def test_verify_human_output_and_exit_status(
    monkeypatch,
    tmp_path,
    capsys,
    sigstore_parser,
    rich_console,
    status,
    expected_exit,
) -> None:
    artifact = tmp_path / "demo[1]-1-0.conda"
    artifact.write_bytes(b"package")
    result = VerificationResult(
        status=status,
        artifact=artifact.name,
        artifact_sha256="ab" * 32,
        evidence=(
            VerifiedEvidence(
                bundle_index=0,
                identity="publisher@example.org",
                issuer="https://issuer.example",
                predicate_type="https://example.org/predicate",
                verified=True,
            ),
        ),
    )

    class FakeSidecarTransport:
        def __init__(self, *, max_bytes):
            pass

        def load_input(self, source):
            return Sidecar("bundle.json", "cd" * 32, ("{}",))

    monkeypatch.setattr(
        cli_verify.SigstoreSettings,
        "current",
        classmethod(
            lambda cls: SimpleNamespace(max_sidecar_bytes=1024, trust_config=None)
        ),
    )
    monkeypatch.setattr(cli_verify, "SidecarTransport", FakeSidecarTransport)
    monkeypatch.setattr(cli_verify, "verify_artifact", lambda *args, **kwargs: result)
    args = sigstore_parser.parse_args(
        ["verify", str(artifact), "--bundle", "bundle.json"]
    )

    assert cli_verify.execute_verify(args, console=rich_console) == expected_exit
    output = rich_console.file.getvalue()
    assert artifact.name in output
    assert status.value in output
    assert "publisher@example.org" in output
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--cert-identity", "publisher@example.org"),
        ("--cert-oidc-issuer", "https://issuer.example"),
    ],
)
def test_verify_requires_identity_and_issuer_together(
    tmp_path, option, value, sigstore_parser
) -> None:
    artifact = tmp_path / "demo-1-0.conda"
    artifact.write_bytes(b"package")
    args = sigstore_parser.parse_args(
        [
            "verify",
            str(artifact),
            "--bundle",
            "bundle.json",
            option,
            value,
        ]
    )

    with pytest.raises(
        CondaSigstoreError,
        match="--cert-identity and --cert-oidc-issuer must be used together",
    ):
        cli_verify.execute_verify(args)


def test_verify_preserves_transport_failure_code(
    monkeypatch, tmp_path, sigstore_parser
) -> None:
    artifact = tmp_path / "demo-1-0.conda"
    artifact.write_bytes(b"package")

    class FailingSidecarTransport:
        def __init__(self, *, max_bytes):
            pass

        def load_input(self, source):
            raise TransportError("invalid-sidecar", "bundle is malformed")

    monkeypatch.setattr(
        cli_verify.SigstoreSettings,
        "current",
        classmethod(
            lambda cls: SimpleNamespace(max_sidecar_bytes=1024, trust_config=None)
        ),
    )
    monkeypatch.setattr(cli_verify, "SidecarTransport", FailingSidecarTransport)
    args = sigstore_parser.parse_args(
        ["verify", str(artifact), "--bundle", "bundle.json"]
    )

    with pytest.raises(CondaSigstoreError, match="bundle is malformed") as error:
        cli_verify.execute_verify(args)

    assert error.value.code == "invalid-sidecar"
