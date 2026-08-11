from __future__ import annotations

import builtins
import importlib
import socket
import sys
from dataclasses import dataclass
from types import SimpleNamespace

import conda.base.context
import conda.plugins.types

from conda_sigstore import plugin


def test_registers_subcommand_and_settings() -> None:
    (subcommand,) = plugin.conda_subcommands()
    settings = {setting.name for setting in plugin.conda_settings()}

    assert subcommand.name == "sigstore"
    assert callable(subcommand.action)
    assert callable(subcommand.configure_parser)
    assert settings == {"conda_sigstore", "conda_sigstore_enforce"}
    assert not hasattr(plugin, "conda_pre_commands")
    assert not hasattr(plugin, "conda_pre_transaction_actions")


def test_plugin_hooks_are_startup_safe(monkeypatch) -> None:
    command_modules = {
        "conda_sigstore.cli.attest",
        "conda_sigstore.cli.audit",
        "conda_sigstore.cli.output",
        "conda_sigstore.cli.verify",
        "conda_sigstore.install",
    }
    for module in command_modules:
        monkeypatch.delitem(sys.modules, module, raising=False)
    imported_before = {
        name
        for name in sys.modules
        if name == "sigstore" or name.startswith("sigstore.")
    }

    def refuse_network(*args, **kwargs):
        raise AssertionError("plugin registration attempted network access")

    original_import = builtins.__import__

    def refuse_rich(name, *args, **kwargs):
        if name == "rich" or name.startswith("rich."):
            raise AssertionError("plugin registration imported Rich")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(plugins=SimpleNamespace()),
    )
    monkeypatch.setattr(socket.socket, "connect", refuse_network)
    monkeypatch.setattr(builtins, "__import__", refuse_rich)
    importlib.reload(plugin)
    tuple(plugin.conda_subcommands())
    tuple(plugin.conda_settings())
    assert tuple(plugin.conda_package_verifiers()) == ()

    imported_after = {
        name
        for name in sys.modules
        if name == "sigstore" or name.startswith("sigstore.")
    }
    assert imported_after == imported_before
    assert command_modules.isdisjoint(sys.modules)


def test_enforcement_registers_future_package_verifier(monkeypatch) -> None:
    from conda_sigstore.install import InstallVerifier

    calls = []

    class RecordingVerifier:
        def verify(self, *args):
            calls.append(args)

    verifier = RecordingVerifier()

    @dataclass
    class CondaPackageVerifier:
        name: str
        verify: object

    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(
            plugins=SimpleNamespace(conda_sigstore_enforce=True),
        ),
    )
    monkeypatch.setattr(
        conda.plugins.types,
        "CondaPackageVerifier",
        CondaPackageVerifier,
        raising=False,
    )
    monkeypatch.setattr(
        InstallVerifier,
        "current",
        classmethod(lambda cls: verifier),
    )

    (registered,) = plugin.conda_package_verifiers()
    registered.verify("record", "archive", "ab" * 32)

    assert registered.name == "sigstore"
    assert calls == [("record", "archive", "ab" * 32)]
