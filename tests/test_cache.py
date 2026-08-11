from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest
from conda.exceptions import LockError

from conda_sigstore.cache import DigestCache

if TYPE_CHECKING:
    from pathlib import Path


def test_sidecar_cache_rehashes_every_read(tmp_path: Path) -> None:
    cache = DigestCache(tmp_path)
    body = b"sidecar"
    digest = cache.store_sidecar(body)
    assert cache.load_sidecar(digest) == body

    (tmp_path / "sidecars" / f"{digest}.json").write_bytes(b"tampered")
    assert cache.load_sidecar(digest) is None


def test_sidecar_cache_rejects_wrong_expected_digest(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="expected SHA-256"):
        DigestCache(tmp_path).store_sidecar(b"sidecar", expected_sha256="ab" * 32)


def test_sidecar_cache_returns_miss_for_missing_or_oversized_entry(
    tmp_path: Path,
) -> None:
    cache = DigestCache(tmp_path)
    assert cache.load_sidecar("ab" * 32) is None

    body = b"sidecar"
    digest = cache.store_sidecar(body)
    assert cache.load_sidecar(digest, max_bytes=len(body) - 1) is None


def test_artifact_binding_loads_only_content_addressed_sidecar(tmp_path: Path) -> None:
    cache = DigestCache(tmp_path)
    artifact = "ab" * 32
    scope = "channel\0package.conda"
    body = b"sidecar"

    sidecar = cache.store_artifact_sidecar(artifact, scope, body)
    other_scope = "other\0package.conda"
    other_body = b"other sidecar"
    cache.store_artifact_sidecar(artifact, other_scope, other_body)

    assert sidecar == hashlib.sha256(body).hexdigest()
    assert cache.load_artifact_sidecar(artifact, scope) == body
    assert cache.load_artifact_sidecar(artifact, other_scope) == other_body

    (tmp_path / "sidecars" / f"{sidecar}.json").write_bytes(b"tampered")
    assert cache.load_artifact_sidecar(artifact, scope) is None


def test_artifact_binding_rejects_corrupt_pointer(tmp_path: Path) -> None:
    cache = DigestCache(tmp_path)
    artifact = "ab" * 32
    scope = "channel\0package.conda"
    cache.store_artifact_sidecar(artifact, scope, b"sidecar")
    next((tmp_path / "artifacts").iterdir()).write_bytes(b"not-a-digest")

    assert cache.load_artifact_sidecar(artifact, scope) is None


def test_cache_uses_conda_disk_lock(tmp_path: Path, monkeypatch) -> None:
    entered = []

    class Lock:
        def __enter__(self):
            entered.append(True)

        def __exit__(self, *exc):
            return False

    def recording_lock(file):
        assert file.name.endswith(".write-lock")
        assert file.seek(0, 2) > 21
        return Lock()

    monkeypatch.setattr("conda_sigstore.cache.lock", recording_lock)
    cache = DigestCache(tmp_path)
    cache.store_sidecar(b"sidecar")

    assert entered == [True]


def test_cache_reports_conda_lock_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_lock(_file):
        raise LockError("lock unavailable")

    monkeypatch.setattr("conda_sigstore.cache.lock", fail_lock)

    with pytest.raises(OSError, match="could not lock"):
        DigestCache(tmp_path).store_sidecar(b"sidecar")
