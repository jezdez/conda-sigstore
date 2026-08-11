"""Performance benchmarks for the conda startup and verification paths."""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import perf_counter
from types import SimpleNamespace
from typing import TYPE_CHECKING

import conda.base.context
import conda.misc
import conda_package_handling.api as package_handling
import pytest
from conda.base.constants import PACKAGE_CACHE_MAGIC_FILE
from conda.base.context import reset_context
from conda.core import package_cache_data, path_actions
from conda.core.package_cache_data import PackageCacheData, ProgressiveFetchExtract
from conda.gateways.disk.read import compute_sum
from conda.models.records import PackageRecord
from conda.plugins.types import CondaPackageVerifier

from conda_sigstore import plugin
from conda_sigstore.evidence import VerificationStatus
from conda_sigstore.transport import SidecarTransport
from conda_sigstore.verification import SigstoreVerifier, verify_bundles

if TYPE_CHECKING:
    from typing import Literal

    from pytest_benchmark.fixture import BenchmarkFixture

pytestmark = pytest.mark.benchmark

ARTIFACT_NAME = "actionlint-1.7.12-h60d57d3_0.conda"
ARTIFACT_SHA256 = "e3e0f35dec5b09b18baac8729d14115903b5adfd25065f8bbb90a2b3be5401e4"
CHANNEL = "https://prefix.dev/github-releases"
PREFIX_CHANNEL = "https://prefix.dev/sigstore-example"
PREFIX_PACKAGE = "signed-package=2.1.0=hb0f4dca_0"
LARGE_PAYLOAD_BYTES = 32 * 1024 * 1024
WORKSPACE_PACKAGE_COUNT = 3


@pytest.fixture(scope="module")
def large_conda_archive(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one large package for matched hashing and extraction benchmarks."""
    root = tmp_path_factory.mktemp("large-conda-archive")
    source = root / "source"
    (source / "info").mkdir(parents=True)
    (source / "info" / "index.json").write_text(
        '{"name":"benchmark-package","version":"1.0","build":"0",'
        '"build_number":0,"subdir":"linux-64"}\n'
    )
    (source / "payload.bin").write_bytes(
        random.Random(0).randbytes(LARGE_PAYLOAD_BYTES)
    )
    archive = package_handling.create(
        source,
        None,
        "benchmark-package-1.0-0.conda",
        root,
    )
    return Path(archive)


@pytest.fixture(scope="module")
def workspace_conda_archives(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, ...]:
    """Build packages for the conda-workspaces prepare and install sequence."""
    root = tmp_path_factory.mktemp("workspace-conda-archives")
    archives = []
    for index in range(WORKSPACE_PACKAGE_COUNT):
        name = f"workspace-benchmark-{index}"
        source = root / f"source-{index}"
        (source / "info").mkdir(parents=True)
        (source / "info" / "index.json").write_text(
            f'{{"name":"{name}","version":"1.0","build":"0",'
            '"build_number":0,"subdir":"noarch","noarch":"generic"}\n'
        )
        (source / "info" / "files").write_text(f"share/{name}.txt\n")
        (source / "share").mkdir()
        (source / "share" / f"{name}.txt").write_text(f"payload {index}\n")
        archives.append(
            Path(
                package_handling.create(
                    source,
                    None,
                    f"{name}-1.0-0.conda",
                    root,
                )
            )
        )
    return tuple(archives)


def test_bench_disabled_plugin_hook_collection(
    benchmark: BenchmarkFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collect the disabled install hook from an imported plugin."""
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(
            plugins=SimpleNamespace(conda_sigstore_enforce=False),
        ),
    )

    def collect_disabled_hook() -> tuple[object, ...]:
        return tuple(plugin.conda_package_verifiers())

    assert benchmark(collect_disabled_hook) == ()


def test_bench_warm_prefix_bundle_verification(
    benchmark: BenchmarkFixture,
) -> None:
    """Measure in-process verification after trust initialization."""
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
    benchmark.extra_info["measurement"] = "warm in-process verification"

    result = benchmark(
        verify_bundles,
        sidecar,
        artifact_name=ARTIFACT_NAME,
        artifact_sha256=ARTIFACT_SHA256,
        verifier=verifier,
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED


def test_bench_cold_prefix_bundle_verification(
    benchmark: BenchmarkFixture,
    tmp_path: Path,
) -> None:
    """Measure first verification with imports and offline trust loading."""
    fixture = Path(__file__).with_name("fixtures") / "prefix-actionlint.v0.sigs"
    script = """\
import sys
from pathlib import Path

from conda_sigstore.evidence import VerificationStatus
from conda_sigstore.transport import SidecarTransport
from conda_sigstore.verification import SigstoreVerifier, verify_bundles

body = Path(sys.argv[1]).read_bytes().removesuffix(b"\\n")
sidecar = SidecarTransport.parse(body, prefix_sidecar=True)
result = verify_bundles(
    sidecar,
    artifact_name=sys.argv[2],
    artifact_sha256=sys.argv[3],
    verifier=SigstoreVerifier(offline=True),
    channel=sys.argv[4],
)
if result.status is not VerificationStatus.VERIFIED:
    raise SystemExit(result.status.value)
"""
    environment = os.environ.copy()
    environment["CONDA_OFFLINE"] = "true"
    environment["XDG_CACHE_HOME"] = str(tmp_path / "cache")
    environment["XDG_DATA_HOME"] = str(tmp_path / "data")
    benchmark.extra_info["measurement"] = (
        "fresh subprocess with imports and offline trust loading"
    )

    def verify_in_subprocess() -> int:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(fixture),
                ARTIFACT_NAME,
                ARTIFACT_SHA256,
                CHANNEL,
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        return completed.returncode

    assert (
        benchmark.pedantic(
            verify_in_subprocess,
            rounds=5,
            iterations=1,
        )
        == 0
    )


def test_bench_large_retained_archive_verification(
    benchmark: BenchmarkFixture,
    large_conda_archive: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measure conda's retained-archive selection and verification path."""
    artifact_sha256 = compute_sum(large_conda_archive, "sha256")
    large_conda_archive.with_suffix("").mkdir()
    record = PackageRecord.from_objects(
        {
            "name": "benchmark-package",
            "version": "1.0",
            "build": "0",
            "build_number": 0,
            "subdir": "linux-64",
            "fn": large_conda_archive.name,
            "url": f"https://example.invalid/linux-64/{large_conda_archive.name}",
            "sha256": artifact_sha256,
            "size": large_conda_archive.stat().st_size,
        }
    )
    package_cache = SimpleNamespace(pkgs_dir=os.fspath(large_conda_archive.parent))

    def verify_record(_record: object, _path: object, sha256: str) -> None:
        assert sha256 == artifact_sha256

    verifier = SimpleNamespace(name="benchmark", verify=verify_record)
    benchmark_context = SimpleNamespace(
        plugin_manager=SimpleNamespace(get_package_verifiers=lambda: (verifier,))
    )
    monkeypatch.setattr(package_cache_data, "context", benchmark_context)
    monkeypatch.setattr(path_actions, "context", benchmark_context)
    monkeypatch.setattr(
        PackageCacheData,
        "all_caches_writable_first",
        classmethod(lambda _cls, _pkgs_dirs=None: (package_cache,)),
    )
    monkeypatch.setattr(
        PackageCacheData,
        "first_writable",
        classmethod(lambda _cls, _pkgs_dirs=None: package_cache),
    )

    hash_calls = 0

    def recording_compute_sum(
        path: str | os.PathLike[str],
        algorithm: Literal["md5", "sha256"],
    ) -> str:
        nonlocal hash_calls
        hash_calls += 1
        return compute_sum(path, algorithm)

    monkeypatch.setattr(package_cache_data, "compute_sum", recording_compute_sum)
    monkeypatch.setattr(path_actions, "compute_sum", recording_compute_sum)
    benchmark.extra_info["archive_bytes"] = large_conda_archive.stat().st_size

    def verify_retained_archive() -> int:
        before = hash_calls
        cache_action, extract_action = ProgressiveFetchExtract.make_actions_for_record(
            record
        )
        assert cache_action is None
        assert extract_action is not None
        extract_action.verify()
        return hash_calls - before

    sha256_passes = benchmark.pedantic(
        verify_retained_archive,
        rounds=5,
        iterations=1,
    )
    benchmark.extra_info["sha256_passes"] = sha256_passes


def test_bench_large_retained_archive_extraction(
    benchmark: BenchmarkFixture,
    large_conda_archive: Path,
    tmp_path: Path,
) -> None:
    """Measure forced extraction of the same retained package archive."""
    benchmark.extra_info["archive_bytes"] = large_conda_archive.stat().st_size
    iteration = 0

    def prepare_extract() -> tuple[tuple[Path], dict[str, object]]:
        nonlocal iteration
        destination = tmp_path / f"extract-{iteration}"
        iteration += 1
        return (destination,), {}

    def extract(destination: Path) -> int:
        package_handling.extract(os.fspath(large_conda_archive), os.fspath(destination))
        return (destination / "payload.bin").stat().st_size

    def remove_extract(destination: Path) -> None:
        shutil.rmtree(destination)

    assert (
        benchmark.pedantic(
            extract,
            setup=prepare_extract,
            teardown=remove_extract,
            rounds=5,
            iterations=1,
        )
        == LARGE_PAYLOAD_BYTES
    )


def test_bench_workspace_locked_install_sequence(
    benchmark: BenchmarkFixture,
    workspace_conda_archives: tuple[Path, ...],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Measure the prepare-then-install sequence used by conda-workspaces."""
    package_cache = tmp_path / "pkgs"
    package_cache.mkdir()
    (package_cache / PACKAGE_CACHE_MAGIC_FILE).touch()
    for archive in workspace_conda_archives:
        shutil.copy2(archive, package_cache / archive.name)
    monkeypatch.setenv("CONDA_PKGS_DIRS", os.fspath(package_cache))
    monkeypatch.setenv("CONDA_JSON", "true")
    monkeypatch.setenv("CONDA_QUIET", "true")
    monkeypatch.setenv("CONDA_REGISTER_ENVS", "false")
    reset_context([])

    callback_count = 0

    def record_verification(_record: object, _path: object, _sha256: str) -> None:
        nonlocal callback_count
        callback_count += 1

    verifier = CondaPackageVerifier("benchmark", record_verification)
    plugin_manager = conda.base.context.context.plugin_manager
    monkeypatch.setattr(
        plugin_manager,
        "get_package_verifiers",
        lambda: (verifier,),
    )

    extraction_calls = 0
    extract_package = plugin_manager.extract_package

    def record_extraction(
        source_full_path: str | os.PathLike[str],
        destination_directory: str | os.PathLike[str],
    ) -> None:
        nonlocal extraction_calls
        extraction_calls += 1
        extract_package(source_full_path, destination_directory)

    monkeypatch.setattr(plugin_manager, "extract_package", record_extraction)
    monkeypatch.setattr(package_cache_data, "EXTRACT_PROCESSES", 1)

    sha256_passes = 0
    conda_compute_sum = path_actions.compute_sum

    def record_compute_sum(
        path: str | os.PathLike[str],
        algorithm: Literal["md5", "sha256"],
    ) -> str:
        nonlocal sha256_passes
        if algorithm == "sha256":
            sha256_passes += 1
        return conda_compute_sum(path, algorithm)

    monkeypatch.setattr(path_actions, "compute_sum", record_compute_sum)
    monkeypatch.setattr(package_cache_data, "compute_sum", record_compute_sum)
    explicit_specs = [
        f"{archive.as_uri()}#{compute_sum(archive, 'sha256')}"
        for archive in workspace_conda_archives
    ]
    iteration = 0

    def prepare_install() -> tuple[tuple[Path], dict[str, object]]:
        nonlocal callback_count, extraction_calls, iteration, sha256_passes
        callback_count = 0
        extraction_calls = 0
        sha256_passes = 0
        prefix = tmp_path / f"prefix-{iteration}"
        iteration += 1
        return (prefix,), {}

    def install(prefix: Path) -> dict[str, int]:
        records = list(conda.misc.get_package_records_from_explicit(explicit_specs))
        prepare_callbacks = callback_count
        prepare_extractions = extraction_calls
        prepare_sha256_passes = sha256_passes

        conda.misc.install_explicit_packages(records, os.fspath(prefix))
        assert len(tuple((prefix / "conda-meta").glob("*.json"))) == len(records)
        return {
            "package_count": len(records),
            "prepare_callbacks": prepare_callbacks,
            "install_callbacks": callback_count - prepare_callbacks,
            "prepare_extractions": prepare_extractions,
            "install_extractions": extraction_calls - prepare_extractions,
            "prepare_sha256_passes": prepare_sha256_passes,
            "install_sha256_passes": sha256_passes - prepare_sha256_passes,
        }

    measurements = benchmark.pedantic(
        install,
        setup=prepare_install,
        rounds=5,
        iterations=1,
    )
    benchmark.extra_info.update(measurements)

    assert measurements == {
        "package_count": WORKSPACE_PACKAGE_COUNT,
        "prepare_callbacks": WORKSPACE_PACKAGE_COUNT,
        "install_callbacks": WORKSPACE_PACKAGE_COUNT,
        "prepare_extractions": WORKSPACE_PACKAGE_COUNT,
        "install_extractions": WORKSPACE_PACKAGE_COUNT,
        "prepare_sha256_passes": WORKSPACE_PACKAGE_COUNT * 2,
        "install_sha256_passes": WORKSPACE_PACKAGE_COUNT * 2,
    }


@pytest.mark.live_interop
@pytest.mark.skipif(
    os.environ.get("CONDA_SIGSTORE_PREFIX_BENCHMARK") != "1",
    reason="set CONDA_SIGSTORE_PREFIX_BENCHMARK=1 to run",
)
def test_bench_live_prefix_create_pair(
    benchmark: BenchmarkFixture,
    tmp_path: Path,
) -> None:
    """Compare paired cached Prefix creates with verification off and on."""
    package_cache = tmp_path / "pkgs"
    environment = os.environ.copy()
    environment["CONDA_PKGS_DIRS"] = str(package_cache)
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

    def create_prefix(prefix: Path, enabled: bool) -> int:
        run_environment = environment.copy()
        run_environment["CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE"] = str(enabled).lower()
        result = subprocess.run(
            [*command, "--prefix", str(prefix), PREFIX_PACKAGE],
            check=False,
            capture_output=True,
            env=run_environment,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, result.stderr
        return result.returncode

    warm_prefix = tmp_path / "warm"
    assert create_prefix(warm_prefix, False) == 0
    shutil.rmtree(warm_prefix)

    samples: list[dict[str, object]] = []
    disabled_samples = []
    enabled_samples = []
    deltas = []

    def compare_pair() -> int:
        order = (False, True) if len(samples) % 2 == 0 else (True, False)
        durations = {}
        for enabled in order:
            prefix = tmp_path / f"run-{len(samples)}-{int(enabled)}"
            started = perf_counter()
            assert create_prefix(prefix, enabled) == 0
            durations[enabled] = (perf_counter() - started) * 1_000
            shutil.rmtree(prefix)
        delta = durations[True] - durations[False]
        disabled_samples.append(durations[False])
        enabled_samples.append(durations[True])
        deltas.append(delta)
        samples.append(
            {
                "order": ["enabled" if value else "disabled" for value in order],
                "disabled_ms": durations[False],
                "enabled_ms": durations[True],
                "delta_ms": delta,
            }
        )
        return 0

    assert benchmark.pedantic(compare_pair, rounds=4, iterations=1) == 0
    benchmark.extra_info["paired_samples"] = samples
    benchmark.extra_info["disabled_median_ms"] = median(disabled_samples)
    benchmark.extra_info["enabled_median_ms"] = median(enabled_samples)
    benchmark.extra_info["delta_median_ms"] = median(deltas)
