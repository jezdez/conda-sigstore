from __future__ import annotations

from types import SimpleNamespace

import conda_sigstore.cli.attest as cli_attest


def test_attest_uses_operational_trust_config(
    monkeypatch, tmp_path, capsys, sigstore_parser, rich_console
) -> None:
    output = tmp_path / "bundle[1].json"
    trust_config = tmp_path / "trust.json"
    configured = SimpleNamespace(trust_config=trust_config)
    captured = {}

    def create_attestation(package, *, target_channel, output, trust_config_path):
        captured.update(
            package=package,
            target_channel=target_channel,
            output=output,
            trust_config_path=trust_config_path,
        )
        return output

    monkeypatch.setattr(
        cli_attest.SigstoreSettings,
        "current",
        classmethod(lambda cls: configured),
    )
    monkeypatch.setattr(cli_attest, "create_attestation", create_attestation)
    args = sigstore_parser.parse_args(
        [
            "attest",
            "demo-1-0.conda",
            "--target-channel",
            "https://example.test/channel",
            "--output",
            str(output),
        ]
    )

    assert cli_attest.execute_attest(args, console=rich_console) == 0
    assert captured == {
        "package": "demo-1-0.conda",
        "target_channel": "https://example.test/channel",
        "output": str(output),
        "trust_config_path": trust_config,
    }
    assert rich_console.file.getvalue().strip() == str(output)
    assert capsys.readouterr().out == ""
