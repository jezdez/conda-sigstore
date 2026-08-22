from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
import sigstore.dsse
import sigstore.models
import sigstore.oidc
import sigstore.sign
import sigstore.verify

from conda_sigstore import attestation, verification
from conda_sigstore.exceptions import BundleVerificationError
from conda_sigstore.statements import InTotoStatement, PublishStatement

FILENAME = "demo-1.0-0.conda"
DIGEST = "ab" * 32
CHANNEL = "https://conda.anaconda.org/example"


@pytest.mark.parametrize("payload_matches", [True, False], ids=("exact", "changed"))
def test_generic_signing_locally_verifies_exact_statement(
    monkeypatch,
    payload_matches: bool,
) -> None:
    statement = InTotoStatement.from_payload(
        {
            "_type": InTotoStatement.STATEMENT_TYPE,
            "subject": [{"name": FILENAME, "digest": {"sha256": DIGEST}}],
            "predicateType": "https://example.org/workspace/v1",
            "predicate": {"version": 1},
        }
    )
    payload = statement.payload()
    captured = {}

    class FakeClientTrustConfig:
        trusted_root = object()

        @staticmethod
        def production():
            return FakeClientTrustConfig()

    class FakeStatement:
        def __init__(self, contents):
            self.contents = contents

    class FakeSigner:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def sign_dsse(self, dsse_statement):
            captured["payload"] = dsse_statement.contents
            return SimpleNamespace(to_json=lambda: '{"mediaType":"bundle"}')

    class FakeSigningContext:
        @staticmethod
        def from_trust_config(trust_config):
            captured["trust_config"] = trust_config
            return FakeSigningContext()

        def signer(self, token):
            captured["token"] = token
            return FakeSigner()

    class FakeSigstoreVerifier:
        def __init__(self, *, verifier):
            captured["verifier"] = verifier

        def verify_statement(self, bundle_json):
            captured["bundle"] = bundle_json
            return SimpleNamespace(payload=payload if payload_matches else b"changed")

    monkeypatch.setattr(sigstore.models, "ClientTrustConfig", FakeClientTrustConfig)
    monkeypatch.setattr(sigstore.dsse, "Statement", FakeStatement)
    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: "ambient-token")
    monkeypatch.setattr(sigstore.oidc, "IdentityToken", lambda value: ("token", value))
    monkeypatch.setattr(sigstore.sign, "SigningContext", FakeSigningContext)
    monkeypatch.setattr(
        sigstore.verify,
        "Verifier",
        lambda *, trusted_root: ("verifier", trusted_root),
    )
    monkeypatch.setattr(verification, "SigstoreVerifier", FakeSigstoreVerifier)

    if payload_matches:
        assert attestation.sign_in_toto_statement(statement) == '{"mediaType":"bundle"}'
        assert captured["payload"] == payload
        assert captured["token"] == ("token", "ambient-token")
        assert captured["bundle"] == '{"mediaType":"bundle"}'
    else:
        with pytest.raises(BundleVerificationError, match="does not match"):
            attestation.sign_in_toto_statement(statement)


def test_cep27_signing_delegates_to_generic_statement(monkeypatch):
    captured = {}

    def sign(statement, *, trust_config_path=None):
        captured["statement"] = statement
        captured["trust_config_path"] = trust_config_path
        return '{"mediaType":"test"}'

    monkeypatch.setattr(attestation, "sign_in_toto_statement", sign)
    trust_config = object()

    bundle = attestation.sign_statement(
        PublishStatement(FILENAME, DIGEST, CHANNEL),
        trust_config_path=trust_config,  # type: ignore[arg-type]
    )

    assert bundle == '{"mediaType":"test"}'
    assert isinstance(captured["statement"], InTotoStatement)
    assert captured["statement"].predicate_type == PublishStatement.PREDICATE_TYPE
    assert captured["trust_config_path"] is trust_config


def test_cep27_signing_requires_target_channel(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("generic signer must not run")

    monkeypatch.setattr(attestation, "sign_in_toto_statement", unexpected)

    with pytest.raises(ValueError, match="requires targetChannel"):
        attestation.sign_statement(PublishStatement(FILENAME, DIGEST))


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
