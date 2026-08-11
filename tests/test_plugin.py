from __future__ import annotations

import builtins
import importlib
import socket
import sys
from types import SimpleNamespace

import conda.base.context
from conda.plugins.hookspec import CondaSpecs
from conda.plugins.manager import CondaPluginManager
from conda.plugins.types import CondaPackageVerifier

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


def test_package_verifier_is_disabled_by_default(monkeypatch) -> None:
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(
            plugins=SimpleNamespace(conda_sigstore_enforce=False),
        ),
    )

    assert tuple(plugin.conda_package_verifiers()) == ()


def test_package_verifier_registration(monkeypatch) -> None:
    from conda_sigstore.install import InstallVerifier

    calls = []
    verifier = SimpleNamespace(verify=lambda *_args: None)

    def current(cls):
        calls.append(cls)
        return verifier

    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(
            plugins=SimpleNamespace(conda_sigstore_enforce=True),
        ),
    )
    monkeypatch.setattr(InstallVerifier, "current", classmethod(current))
    plugin_manager = CondaPluginManager()
    plugin_manager.add_hookspecs(CondaSpecs)
    plugin_manager.register(plugin)

    (registered,) = plugin_manager.get_package_verifiers()

    assert isinstance(registered, CondaPackageVerifier)
    assert registered.name == "sigstore"
    assert registered.verify is verifier.verify
    assert calls == [InstallVerifier]


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
        SimpleNamespace(
            plugins=SimpleNamespace(conda_sigstore_enforce=False),
        ),
    )
    monkeypatch.setattr(socket.socket, "connect", refuse_network)
    monkeypatch.setattr(builtins, "__import__", refuse_rich)
    importlib.reload(plugin)
    tuple(plugin.conda_subcommands())
    tuple(plugin.conda_settings())
    tuple(plugin.conda_package_verifiers())

    imported_after = {
        name
        for name in sys.modules
        if name == "sigstore" or name.startswith("sigstore.")
    }
    assert imported_after == imported_before
    assert command_modules.isdisjoint(sys.modules)
