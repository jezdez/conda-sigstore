"""Operational conda settings for evidence verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import NoneType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from conda.plugins.types import CondaSetting

SETTING_NAME = "conda_sigstore"
ENFORCE_SETTING_NAME = "conda_sigstore_enforce"
DEFAULT_MAX_SIDECAR_BYTES = 10 * 1024 * 1024
MAX_TRUST_CONFIG_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SigstoreSettings:
    """Validated operational settings without publisher identity policy."""

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
    def current(cls) -> SigstoreSettings:
        """Read the plugin setting from conda's active context."""
        from conda.base.context import context

        value = getattr(context.plugins, SETTING_NAME)
        return cls(
            max_sidecar_bytes=value.max_sidecar_bytes,
            trust_config=(
                Path(value.trust_config).expanduser()
                if value.trust_config is not None
                else None
            ),
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

    @staticmethod
    def enforce_conda_setting() -> CondaSetting:
        """Build the opt-in install-verification setting declaration."""
        from conda.common.configuration import PrimitiveParameter
        from conda.plugins.types import CondaSetting

        return CondaSetting(
            name=ENFORCE_SETTING_NAME,
            description="Require valid Sigstore evidence before package extraction.",
            parameter=PrimitiveParameter(False, element_type=bool),
        )
