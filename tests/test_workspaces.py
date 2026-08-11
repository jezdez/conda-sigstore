"""Conda-workspaces interoperability tests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from conda.base.context import context, reset_context
from conda.exceptions import CondaVerificationError

from conda_sigstore.install import InstallVerifier

if TYPE_CHECKING:
    from pathlib import Path

    from conda.common.path import PathType
    from conda.testing.fixtures import CondaCLIFixture


@pytest.mark.parametrize("accept", [True, False], ids=("accepted", "rejected"))
def test_workspace_locked_install_uses_package_verifier(
    conda_cli: CondaCLIFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    locked_conda_package: tuple[Path, str, str, Path],
    accept: bool,
) -> None:
    """Route an actual locked workspace install through conda's verifier hook."""
    package_cache, digest, artifact_url, _extracted_payload = locked_conda_package
    channel = artifact_url.rsplit("/", 2)[0]
    filename = artifact_url.rsplit("/", 1)[1]

    (tmp_path / "conda.toml").write_text(
        "[workspace]\n"
        'name = "sigstore-test"\n'
        f'channels = ["{channel}"]\n'
        f'platforms = ["{context.subdir}"]\n'
        "\n[dependencies]\n"
        'pkg = "1.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "conda.lock").write_text(
        json.dumps(
            {
                "version": 1,
                "environments": {
                    "default": {
                        "channels": [{"url": channel}],
                        "packages": {
                            context.subdir: [{"conda": artifact_url}],
                        },
                    }
                },
                "packages": [
                    {
                        "conda": artifact_url,
                        "sha256": digest,
                        "depends": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    prefix = tmp_path / ".conda" / "envs" / "default"
    calls: list[tuple[str, str, bool]] = []

    def verify(_record: object, package_path: PathType, sha256: str) -> None:
        calls.append(
            (
                str(package_path),
                sha256,
                (prefix / "payload.txt").exists(),
            )
        )
        if not accept:
            raise CondaVerificationError("workspace package rejected")

    monkeypatch.setattr(
        InstallVerifier,
        "current",
        classmethod(lambda _cls: SimpleNamespace(verify=verify)),
    )
    monkeypatch.setenv("CONDA_PKGS_DIRS", str(package_cache))
    monkeypatch.setenv("CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE", "true")
    monkeypatch.setenv("CONDA_REGISTER_ENVS", "false")
    monkeypatch.chdir(tmp_path)
    reset_context()

    arguments = ("workspace", "install", "--locked")
    if accept:
        _stdout, stderr, code = conda_cli(*arguments)
        assert code == 0, stderr
        assert (prefix / "payload.txt").read_text(encoding="utf-8") == (
            "locked package\n"
        )
    else:
        _stdout, stderr, code = conda_cli(*arguments)
        assert code != 0
        assert "workspace package rejected" in stderr
        assert not prefix.exists()

    assert calls
    assert all(call[0].endswith(filename) for call in calls)
    assert all(call[1] == digest for call in calls)
    assert all(not call[2] for call in calls)
