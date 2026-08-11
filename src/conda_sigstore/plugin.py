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
    from conda.common.configuration import PrimitiveParameter
    from conda.plugins.types import CondaSetting

    from .settings import ENFORCE_SETTING_NAME, SigstoreSettings

    yield SigstoreSettings.conda_setting()
    yield CondaSetting(
        name=ENFORCE_SETTING_NAME,
        description="Require valid Sigstore evidence before package extraction.",
        parameter=PrimitiveParameter(
            False,
            element_type=bool,
        ),
    )


@hookimpl
def conda_package_verifiers() -> Iterable[object]:
    from conda.base.context import context

    from .settings import ENFORCE_SETTING_NAME

    if not getattr(context.plugins, ENFORCE_SETTING_NAME, False):
        return

    from conda.plugins import types

    from .install import InstallVerifier

    verifier_type = getattr(types, "CondaPackageVerifier")
    yield verifier_type(
        name="sigstore",
        verify=InstallVerifier.current().verify,
    )


__all__ = [
    "conda_package_verifiers",
    "conda_settings",
    "conda_subcommands",
]
