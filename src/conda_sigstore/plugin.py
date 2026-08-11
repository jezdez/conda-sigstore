"""Conda plugin registration with lazy implementation imports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from conda.plugins import hookimpl

if TYPE_CHECKING:
    from collections.abc import Iterable

    from conda.plugins.types import (
        CondaPackageVerifier,
        CondaSetting,
        CondaSubcommand,
    )


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
    yield SigstoreSettings.enforce_conda_setting()


@hookimpl
def conda_package_verifiers() -> Iterable[CondaPackageVerifier]:
    from conda.base.context import context

    from .settings import ENFORCE_SETTING_NAME

    if not getattr(context.plugins, ENFORCE_SETTING_NAME):
        return

    from conda.plugins.types import CondaPackageVerifier

    from .install import InstallVerifier

    yield CondaPackageVerifier(
        name="sigstore",
        verify=InstallVerifier.current().verify,
    )
