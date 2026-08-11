"""Operational conda settings for evidence verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import NoneType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from conda.plugins.types import CondaSetting

SETTING_NAME = "conda_sigstore"
DEFAULT_MAX_SIDECAR_BYTES = 10 * 1024 * 1024
MAX_TRUST_CONFIG_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SigstoreSettings:
    """Validated operational settings without identity or enforcement policy."""

    max_sidecar_bytes: int = DEFAULT_MAX_SIDECAR_BYTES
    trust_config: Path | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_sidecar_bytes, bool)
            or not isinstance(self.max_sidecar_bytes, int)
            or self.max_sidecar_bytes < 1
        ):
            raise ValueError("max_sidecar_bytes must be a positive integer")
        if self.trust_config is not None and not self.trust_config.is_file():
            raise ValueError(f"trust_config does not exist: {self.trust_config}")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> SigstoreSettings:
        """Validate a plain configuration mapping."""
        unknown = set(value) - {"max_sidecar_bytes", "trust_config"}
        if unknown:
            raise ValueError(f"unknown conda-sigstore setting: {sorted(unknown)[0]}")
        maximum = value.get("max_sidecar_bytes", DEFAULT_MAX_SIDECAR_BYTES)
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
            raise ValueError("max_sidecar_bytes must be a positive integer")
        trust_config = value.get("trust_config")
        if trust_config is not None and (
            not isinstance(trust_config, str) or not trust_config
        ):
            raise ValueError("trust_config must be a local path or null")
        return cls(
            max_sidecar_bytes=maximum,
            trust_config=(
                Path(trust_config).expanduser() if trust_config is not None else None
            ),
        )

    @classmethod
    def current(cls) -> SigstoreSettings:
        """Read the plugin setting from conda's active context."""
        from conda.base.context import context

        value = getattr(context.plugins, SETTING_NAME)
        return cls.from_mapping(
            {
                "max_sidecar_bytes": value.max_sidecar_bytes,
                "trust_config": value.trust_config,
            }
        )

    @classmethod
    def conda_setting(cls) -> CondaSetting:
        """Build the lightweight structured conda setting declaration."""
        from conda.common.configuration import (
            ConfigurationObject,
            ObjectParameter,
            PrimitiveParameter,
        )
        from conda.plugins.types import CondaSetting

        class SigstoreConfig(ConfigurationObject):
            def __init__(self) -> None:
                self.max_sidecar_bytes = PrimitiveParameter(
                    DEFAULT_MAX_SIDECAR_BYTES,
                    element_type=int,
                    validation=lambda value: (
                        value > 0 or "max_sidecar_bytes must be positive"
                    ),
                )
                self.trust_config = PrimitiveParameter(
                    None,
                    element_type=(str, NoneType),
                )

        return CondaSetting(
            name=SETTING_NAME,
            description="Sigstore trust material and evidence size limits.",
            parameter=ObjectParameter(SigstoreConfig()),
        )


__all__ = [
    "DEFAULT_MAX_SIDECAR_BYTES",
    "MAX_TRUST_CONFIG_BYTES",
    "SETTING_NAME",
    "SigstoreSettings",
]
