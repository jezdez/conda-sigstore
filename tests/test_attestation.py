from __future__ import annotations

import hashlib
import json

import pytest

from conda_sigstore import attestation


def test_create_attestation_builds_and_writes_bundle(tmp_path, monkeypatch):
    package = tmp_path / "demo-1.0-0.conda"
    package.write_bytes(b"package")
    captured = {}

    def fake_sign(statement, *, trust_config_path=None):
        captured.update(statement.to_dict())
        assert trust_config_path is None
        return '{"mediaType":"test"}'

    monkeypatch.setattr(attestation, "sign_statement", fake_sign)

    output = attestation.create_attestation(
        package,
        target_channel="https://conda.anaconda.org/example",
    )

    assert output == tmp_path / "demo-1.0-0.conda.sigstore.json"
    assert json.loads(output.read_text()) == {"mediaType": "test"}
    assert captured["subject"] == [
        {
            "name": package.name,
            "digest": {"sha256": hashlib.sha256(b"package").hexdigest()},
        }
    ]


def test_create_attestation_rejects_non_conda_artifact(tmp_path):
    artifact = tmp_path / "demo.whl"
    artifact.write_bytes(b"package")

    with pytest.raises(ValueError, match="must end"):
        attestation.create_attestation(
            artifact,
            target_channel="https://conda.anaconda.org/example",
        )


def test_create_attestation_does_not_replace_package(tmp_path, monkeypatch):
    package = tmp_path / "demo-1.0-0.conda"
    package.write_bytes(b"package")
    monkeypatch.setattr(
        attestation,
        "sign_statement",
        lambda *args, **kwargs: '{"mediaType":"test"}',
    )

    with pytest.raises(ValueError, match="must not replace"):
        attestation.create_attestation(
            package,
            target_channel="https://conda.anaconda.org/example",
            output=package,
        )

    assert package.read_bytes() == b"package"


def test_create_attestation_does_not_overwrite_existing_output(tmp_path):
    package = tmp_path / "demo-1.0-0.conda"
    package.write_bytes(b"package")
    output = tmp_path / "bundle.json"
    output.write_text("keep")

    with pytest.raises(FileExistsError, match="already exists"):
        attestation.create_attestation(
            package,
            target_channel="https://conda.anaconda.org/example",
            output=output,
        )

    assert output.read_text() == "keep"


def test_create_attestation_does_not_overwrite_output_created_during_signing(
    tmp_path, monkeypatch
):
    package = tmp_path / "demo-1.0-0.conda"
    package.write_bytes(b"package")
    output = tmp_path / "bundle.json"

    def create_output(*args, **kwargs):
        output.write_text("keep")
        return '{"mediaType":"test"}'

    monkeypatch.setattr(attestation, "sign_statement", create_output)

    with pytest.raises(FileExistsError, match="already exists"):
        attestation.create_attestation(
            package,
            target_channel="https://conda.anaconda.org/example",
            output=output,
        )

    assert output.read_text() == "keep"


def test_create_attestation_refuses_package_changed_during_signing(
    tmp_path, monkeypatch
):
    package = tmp_path / "demo-1.0-0.conda"
    package.write_bytes(b"before")

    def change_package(*args, **kwargs):
        package.write_bytes(b"after")
        return '{"mediaType":"test"}'

    monkeypatch.setattr(attestation, "sign_statement", change_package)

    with pytest.raises(ValueError, match="changed"):
        attestation.create_attestation(
            package,
            target_channel="https://conda.anaconda.org/example",
        )

    assert not (tmp_path / "demo-1.0-0.conda.sigstore.json").exists()
