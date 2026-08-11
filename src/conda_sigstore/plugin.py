"""Conda plugin registration with lazy implementation imports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from conda.plugins import hookimpl

if TYPE_CHECKING:
    from collections.abc import Iterable

    from conda.plugins.types import CondaSetting, CondaSubcommand


@hookimpl
def conda_subcommands() -> Iterable[CondaSubcommand]:
    from conda.plugins.types import CondaSubcommand

    from .cli import configure_parser, execute

    yield CondaSubcommand(
        name="sigstore",
        summary="Sign and verify conda packages with Sigstore.",
        action=execute,
        configure_parser=configure_parser,
    )


@hookimpl
def conda_settings() -> Iterable[CondaSetting]:
    from .settings import SigstoreSettings

    yield SigstoreSettings.conda_setting()


__all__ = [
    "conda_settings",
    "conda_subcommands",
]
