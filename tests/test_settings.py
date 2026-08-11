from __future__ import annotations

import pytest
from conda.common.configuration import EnvRawParameter
from conda.plugins.config import PluginConfig

from conda_sigstore.settings import (
    DEFAULT_MAX_SIDECAR_BYTES,
    ENFORCE_SETTING_NAME,
    SigstoreSettings,
)


@pytest.fixture
def plugin_config_type() -> type[PluginConfig]:
    class TestPluginConfig(PluginConfig):
        parameter_names = ()
        parameter_names_and_aliases = ()

    setting = SigstoreSettings.enforce_conda_setting()
    TestPluginConfig.add_plugin_setting(
        setting.name,
        setting.parameter,
        setting.aliases,
    )
    return TestPluginConfig


def test_structured_setting_exposes_only_operational_values() -> None:
    setting = SigstoreSettings.conda_setting()
    value = setting.parameter.default.typify("test")

    assert setting.name == "conda_sigstore"
    assert value.max_sidecar_bytes == DEFAULT_MAX_SIDECAR_BYTES
    assert value.trust_config is None
    assert not hasattr(value, "policies")


def test_enforcement_setting_defaults_to_false() -> None:
    setting = SigstoreSettings.enforce_conda_setting()

    assert setting.name == ENFORCE_SETTING_NAME
    assert setting.parameter.default.typify("test") is False


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [("true", True), ("false", False)],
)
def test_enforcement_setting_reads_environment(
    plugin_config_type: type[PluginConfig],
    raw_value: str,
    expected: bool,
) -> None:
    env_name = f"plugins_{ENFORCE_SETTING_NAME}"
    config = plugin_config_type(
        {
            EnvRawParameter.source: {
                env_name: EnvRawParameter(
                    EnvRawParameter.source,
                    env_name,
                    raw_value,
                )
            }
        }
    )

    assert getattr(config, ENFORCE_SETTING_NAME) is expected


def test_settings_validate_local_trust_path(tmp_path) -> None:
    trust_config = tmp_path / "trust.json"
    trust_config.write_text("{}")

    settings = SigstoreSettings(max_sidecar_bytes=4096, trust_config=trust_config)

    assert settings.max_sidecar_bytes == 4096
    assert settings.trust_config == trust_config


@pytest.mark.parametrize("value", [0, True])
def test_settings_reject_invalid_size(value: int) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        SigstoreSettings(max_sidecar_bytes=value)
