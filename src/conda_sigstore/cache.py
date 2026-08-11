"""Content-addressed sidecar caching."""

from __future__ import annotations

import hashlib
import os
import tempfile
from contextlib import nullcontext
from pathlib import Path
from typing import TYPE_CHECKING

from .model import validate_sha256
from .settings import DEFAULT_MAX_SIDECAR_BYTES

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager


class DigestCache:
    """A small filesystem cache whose reads always recheck content digests."""

    def __init__(
        self,
        root: Path,
        *,
        write_lock: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> None:
        self.root = Path(root)
        self._write_lock = write_lock or nullcontext

    def _atomic_write(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock():
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{path.name}.", dir=path.parent
            )
            temporary_path = Path(temporary)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_path, path)
            finally:
                temporary_path.unlink(missing_ok=True)

    def store_sidecar(self, body: bytes, *, expected_sha256: str | None = None) -> str:
        """Store exact sidecar bytes and return their content digest."""
        if not isinstance(body, bytes):
            raise TypeError("sidecar body must be bytes")
        digest = hashlib.sha256(body).hexdigest()
        if expected_sha256 is not None and digest != validate_sha256(
            expected_sha256,
            field_name="expected_sha256",
        ):
            raise ValueError("sidecar does not match expected SHA-256")
        self._atomic_write(self.root / "sidecars" / f"{digest}.json", body)
        return digest

    def load_sidecar(
        self,
        sha256: str,
        *,
        max_bytes: int = DEFAULT_MAX_SIDECAR_BYTES,
    ) -> bytes | None:
        """Read a sidecar only when its filename and bytes agree."""
        expected = validate_sha256(sha256, field_name="sidecar_sha256")
        path = self.root / "sidecars" / f"{expected}.json"
        try:
            if path.stat().st_size > max_bytes:
                return None
            with path.open("rb") as stream:
                body = stream.read(max_bytes + 1)
        except FileNotFoundError:
            return None
        if len(body) > max_bytes or hashlib.sha256(body).hexdigest() != expected:
            return None
        return body


__all__ = ["DigestCache"]
