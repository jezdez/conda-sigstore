from __future__ import annotations

import pytest

from conda_sigstore.settings import DEFAULT_MAX_SIDECAR_BYTES, SigstoreSettings


def test_structured_setting_exposes_only_operational_values() -> None:
    setting = SigstoreSettings.conda_setting()
    value = setting.parameter.default.typify("test")

    assert setting.name == "conda_sigstore"
    assert value.max_sidecar_bytes == DEFAULT_MAX_SIDECAR_BYTES
    assert value.trust_config is None
    assert not hasattr(value, "policies")


def test_settings_validate_local_trust_path(tmp_path) -> None:
    trust_config = tmp_path / "trust.json"
    trust_config.write_text("{}")

    settings = SigstoreSettings.from_mapping(
        {"max_sidecar_bytes": 4096, "trust_config": str(trust_config)}
    )

    assert settings.max_sidecar_bytes == 4096
    assert settings.trust_config == trust_config


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"max_sidecar_bytes": 0}, "positive integer"),
        ({"max_sidecar_bytes": True}, "positive integer"),
        ({"trust_config": ""}, "local path or null"),
        ({"policies": []}, "unknown conda-sigstore setting"),
    ],
)
def test_settings_reject_invalid_or_policy_values(value, message) -> None:
    with pytest.raises(ValueError, match=message):
        SigstoreSettings.from_mapping(value)
