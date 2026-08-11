from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

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
