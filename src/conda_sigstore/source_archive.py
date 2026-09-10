"""Bounded inspection of retained package recipe files."""

from __future__ import annotations

import bz2
import ntpath
import sys
import tarfile
from contextlib import ExitStack
from dataclasses import dataclass
from io import BufferedIOBase
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING
from zipfile import ZIP_STORED, BadZipFile, ZipFile

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

if TYPE_CHECKING:
    from pathlib import Path

MAX_ZIP_METADATA_BYTES = 1024 * 1024
MAX_ZIP_MEMBERS = 16
MAX_EXPANDED_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_METADATA_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ZSTD_WINDOW_LOG = 26  # 64 MiB decoder window.


@dataclass
class ArchiveReader(BufferedIOBase):
    """Cap parser read allocations and optionally the whole expanded stream."""

    source: BufferedIOBase
    max_read_bytes: int
    remaining: int | None = None
    metadata_remaining: int | None = None
    reading_metadata: bool = True

    def read(self, size: int | None = -1) -> bytes:
        if size is None:
            size = -1
        if size > self.max_read_bytes:
            raise ValueError("archive metadata read exceeds the audit limit")
        if size < 0:
            size = self.max_read_bytes + 1
        if self.remaining is not None:
            size = min(size, self.remaining + 1)
        if self.reading_metadata and self.metadata_remaining is not None:
            size = min(size, self.metadata_remaining + 1)
        data = self.source.read(size)
        if len(data) > self.max_read_bytes:
            raise ValueError("archive metadata read exceeds the audit limit")
        if self.remaining is not None:
            self.remaining -= len(data)
            if self.remaining < 0:
                raise ValueError("expanded archive exceeds the audit limit")
        if self.reading_metadata and self.metadata_remaining is not None:
            self.metadata_remaining -= len(data)
            if self.metadata_remaining < 0:
                raise ValueError("tar metadata exceeds the audit limit")
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.source.seek(offset, whence)

    def tell(self) -> int:
        return self.source.tell()

    def seekable(self) -> bool:
        return self.source.seekable()


@dataclass(frozen=True)
class SourceArchive:
    """A digest-checked snapshot whose recipe files may be inspected."""

    path: Path
    filename: str

    def extract_recipe(
        self, destination: Path, *, max_recipe_bytes: int, max_bundle_bytes: int
    ) -> None:
        """Copy only bounded regular recipe files, without archive extraction."""
        try:
            with ExitStack() as stack:
                source = stack.enter_context(self.path.open("rb"))
                if self.filename.endswith(".conda"):
                    container = stack.enter_context(
                        ZipFile(ArchiveReader(source, MAX_ZIP_METADATA_BYTES))
                    )
                    entries = container.infolist()
                    if len(entries) > MAX_ZIP_MEMBERS:
                        raise ValueError("too many ZIP members for source auditing")
                    name = f"info-{self.filename.removesuffix('.conda')}.tar.zst"
                    selected = [entry for entry in entries if entry.filename == name]
                    if len(selected) != 1:
                        raise ValueError(
                            "package must contain one matching info component"
                        )
                    if selected[0].compress_type != ZIP_STORED:
                        raise ValueError("package info component must use ZIP_STORED")
                    component = stack.enter_context(container.open(selected[0]))
                    # Bound decoder allocation as well as the bytes returned to tarfile.
                    options = {
                        zstd.DecompressionParameter.window_log_max: MAX_ZSTD_WINDOW_LOG
                    }
                    expanded = stack.enter_context(
                        zstd.ZstdFile(component, options=options)
                    )
                elif self.filename.endswith(".tar.bz2"):
                    expanded = stack.enter_context(bz2.BZ2File(source))
                else:
                    raise ValueError("retained archive is not a conda package")
                reader = ArchiveReader(
                    expanded,
                    MAX_EXPANDED_ARCHIVE_BYTES,
                    remaining=MAX_EXPANDED_ARCHIVE_BYTES,
                    metadata_remaining=MAX_ARCHIVE_METADATA_BYTES,
                )
                # Do not charge prefetched file contents to the metadata budget.
                tar = stack.enter_context(
                    tarfile.open(
                        fileobj=reader,
                        mode="r|",
                        bufsize=tarfile.BLOCKSIZE,
                        encoding="utf-8",
                    )
                )
                seen: set[str] = set()
                for count, member in enumerate(tar, 1):
                    if count > MAX_ARCHIVE_MEMBERS:
                        raise ValueError("too many archive members for source auditing")
                    if member.size < 0 or member.size > MAX_EXPANDED_ARCHIVE_BYTES:
                        raise ValueError("archive member exceeds the audit limit")
                    if member.issparse():
                        raise ValueError("recipe archive members must be regular files")
                    name = member.name.rstrip("/")
                    parsed = PurePosixPath(name)
                    if (
                        parsed.is_absolute()
                        or ".." in parsed.parts
                        or "\\" in name
                        or "\0" in name
                        or parsed.as_posix() != name
                    ):
                        raise ValueError("archive contains an unsafe member path")
                    if name == "info/recipe/rendered_recipe.yaml":
                        limit = max_recipe_bytes
                        description = "rendered recipe"
                    elif (
                        len(parsed.parts) == 4
                        and parsed.parts[:3] == ("info", "recipe", "attestations")
                        and name.endswith(".sigstore.json")
                    ):
                        limit = max_bundle_bytes
                        description = "embedded bundle"
                    else:
                        # Drain ordinary payload under the expanded-byte budget, not
                        # the metadata budget used while tarfile parses headers.
                        if member.isreg():
                            body = tar.extractfile(member)
                            assert body is not None
                            reader.reading_metadata = False
                            with body:
                                while body.read(64 * 1024):
                                    pass
                            reader.reading_metadata = True
                        continue
                    if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                        raise ValueError("recipe archive members must be regular files")
                    reserved = (
                        ntpath.isreserved(name)
                        if sys.version_info >= (3, 13)
                        else PureWindowsPath(name).is_reserved()
                    )
                    if reserved or ":" in name:
                        raise ValueError(
                            "recipe archive contains an unsafe member path"
                        )
                    key = name.casefold()
                    if key in seen:
                        raise ValueError("recipe archive contains duplicate file paths")
                    seen.add(key)
                    if member.size > limit:
                        raise ValueError(f"{description} exceeds {limit} bytes")
                    body = tar.extractfile(member)
                    assert body is not None
                    reader.reading_metadata = False
                    with body:
                        data = body.read(limit + 1)
                    reader.reading_metadata = True
                    if len(data) != member.size or len(data) > limit:
                        raise ValueError("recipe archive member has an invalid size")
                    output = destination.joinpath(*parsed.parts)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with output.open("xb") as target:
                        target.write(data)
        except (
            BadZipFile,
            tarfile.TarError,
            zstd.ZstdError,
            OSError,
            EOFError,
            RuntimeError,
            RecursionError,
        ) as exc:
            # bz2 reports corrupt input as OSError without an OS error number.
            if isinstance(exc, OSError) and exc.errno is not None:
                raise
            raise ValueError("retained package archive is malformed") from exc
