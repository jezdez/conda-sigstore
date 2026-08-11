"""Performance benchmarks for the conda startup and verification paths."""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

import conda.base.context
import pytest

from conda_sigstore import plugin
from conda_sigstore.evidence import VerificationStatus
from conda_sigstore.transport import SidecarTransport
from conda_sigstore.verification import SigstoreVerifier, verify_bundles

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

pytestmark = pytest.mark.benchmark

ARTIFACT_NAME = "actionlint-1.7.12-h60d57d3_0.conda"
ARTIFACT_SHA256 = "e3e0f35dec5b09b18baac8729d14115903b5adfd25065f8bbb90a2b3be5401e4"
CHANNEL = "https://prefix.dev/github-releases"
PREFIX_CHANNEL = "https://prefix.dev/sigstore-example"
PREFIX_PACKAGE = "signed-package=2.1.0=hb0f4dca_0"


def test_bench_disabled_plugin_startup(
    benchmark: BenchmarkFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Import the plugin and collect its disabled install hook."""
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(
            plugins=SimpleNamespace(conda_sigstore_enforce=False),
        ),
    )

    def load_disabled_plugin() -> tuple[object, ...]:
        importlib.reload(plugin)
        return tuple(plugin.conda_package_verifiers())

    assert benchmark(load_disabled_plugin) == ()


def test_bench_full_prefix_bundle_verification(
    benchmark: BenchmarkFixture,
) -> None:
    """Verify captured production evidence without network or solver noise."""
    body = (
        (Path(__file__).with_name("fixtures") / "prefix-actionlint.v0.sigs")
        .read_bytes()
        .removesuffix(b"\n")
    )
    sidecar = SidecarTransport.parse(body, prefix_sidecar=True)
    verifier = SigstoreVerifier(offline=True)
    result = verify_bundles(
        sidecar,
        artifact_name=ARTIFACT_NAME,
        artifact_sha256=ARTIFACT_SHA256,
        verifier=verifier,
        channel=CHANNEL,
    )
    assert result.status is VerificationStatus.VERIFIED

    result = benchmark(
        verify_bundles,
        sidecar,
        artifact_name=ARTIFACT_NAME,
        artifact_sha256=ARTIFACT_SHA256,
        verifier=verifier,
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED


@pytest.mark.live_interop
@pytest.mark.skipif(
    os.environ.get("CONDA_SIGSTORE_PREFIX_BENCHMARK") != "1",
    reason="set CONDA_SIGSTORE_PREFIX_BENCHMARK=1 to run",
)
@pytest.mark.parametrize("enforce", [False, True], ids=("disabled", "enabled"))
def test_bench_live_prefix_create(
    benchmark: BenchmarkFixture,
    tmp_path: Path,
    enforce: bool,
) -> None:
    """Compare cached Prefix creates with install verification off and on."""
    package_cache = tmp_path / "pkgs"
    environment = os.environ.copy()
    environment["CONDA_PKGS_DIRS"] = str(package_cache)
    environment["CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE"] = "false"
    command = [
        sys.executable,
        "-m",
        "conda",
        "create",
        "--yes",
        "--quiet",
        "--override-channels",
        "--channel",
        PREFIX_CHANNEL,
        "--subdir",
        "linux-64",
        "--solver",
        "classic",
        "--no-deps",
    ]
    warm_prefix = tmp_path / "warm"
    completed = subprocess.run(
        [*command, "--prefix", str(warm_prefix), PREFIX_PACKAGE],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    shutil.rmtree(warm_prefix)

    environment["CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE"] = str(enforce).lower()
    iteration = 0

    def create_prefix() -> int:
        nonlocal iteration
        prefix = tmp_path / f"run-{iteration}"
        iteration += 1
        result = subprocess.run(
            [*command, "--prefix", str(prefix), PREFIX_PACKAGE],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, result.stderr
        shutil.rmtree(prefix)
        return result.returncode

    assert benchmark.pedantic(create_prefix, rounds=3, iterations=1) == 0
