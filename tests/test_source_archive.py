from __future__ import annotations

import bz2
import hashlib
import io
import json
import struct
import tarfile
import zipfile
from types import SimpleNamespace

import pytest

from conda_sigstore import source_archive
from conda_sigstore.audit import EnvironmentAuditor
from conda_sigstore.settings import SigstoreSettings
from conda_sigstore.source_archive import ArchiveReader, SourceArchive, zstd


@pytest.fixture(params=[".conda", ".tar.bz2"])
def archive_factory(tmp_path, request):
    def create(members=(), *, raw_tar=None):
        archive = tmp_path / f"pkg-1-0{request.param}"
        if raw_tar is None:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                for member, body in members:
                    tar.addfile(member, io.BytesIO(body))
            raw_tar = stream.getvalue()
        if request.param == ".conda":
            with zipfile.ZipFile(archive, "w") as container:
                container.writestr("metadata.json", '{"conda_pkg_format_version":2}')
                container.writestr("info-pkg-1-0.tar.zst", zstd.compress(raw_tar))
        else:
            archive.write_bytes(bz2.compress(raw_tar))
        return archive

    return create


@pytest.fixture
def regular_member():
    def create(name="info/recipe/rendered_recipe.yaml", body=b"{}", **attributes):
        member = tarfile.TarInfo(name)
        member.size = len(body)
        for key, value in attributes.items():
            setattr(member, key, value)
        return member, body

    return create


@pytest.fixture
def extract_archive(tmp_path):
    def extract(archive, *, max_recipe_bytes=1024, max_bundle_bytes=1024):
        destination = tmp_path / "extracted"
        SourceArchive(archive, archive.name).extract_recipe(
            destination,
            max_recipe_bytes=max_recipe_bytes,
            max_bundle_bytes=max_bundle_bytes,
        )
        return destination

    return extract


@pytest.fixture
def zip_archive_factory(tmp_path, regular_member):
    stream = io.BytesIO()
    member, body = regular_member()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        tar.addfile(member, io.BytesIO(body))
    compressed = zstd.compress(stream.getvalue())

    def create(
        names=("info-pkg-1-0.tar.zst",),
        *,
        compression=zipfile.ZIP_STORED,
        force_zip64=False,
        content=compressed,
    ):
        archive = tmp_path / "pkg-1-0.conda"
        with zipfile.ZipFile(archive, "w", compression=compression) as container:
            for name in names:
                with container.open(name, "w", force_zip64=force_zip64) as component:
                    component.write(content)
        return archive

    return create


@pytest.fixture
def audit_archive(monkeypatch):
    def audit(archive):
        monkeypatch.setattr(
            EnvironmentAuditor,
            "retained_archive",
            staticmethod(lambda _record: archive),
        )
        auditor = EnvironmentAuditor(SigstoreSettings(), None)
        return auditor.audit_sources(
            SimpleNamespace(fn=archive.name),
            package_verified=True,
            package_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        )

    return audit


def test_real_source_archive_preserves_recipe(archive_factory, audit_archive):
    body = json.dumps({"source": {"url": "https://example.org/source"}}).encode()
    member = tarfile.TarInfo("info/recipe/rendered_recipe.yaml")
    member.size = len(body)
    assert audit_archive(archive_factory([(member, body)])) == []


def test_source_archive_rejects_unsupported_suffix(tmp_path, extract_archive):
    archive = tmp_path / "pkg-1-0.zip"
    archive.write_bytes(b"")
    with pytest.raises(ValueError, match="retained archive is not a conda package"):
        extract_archive(archive)


def test_source_archive_preserves_existing_destination(
    archive_factory, regular_member, extract_archive, tmp_path
):
    output = tmp_path / "extracted/info/recipe/rendered_recipe.yaml"
    output.parent.mkdir(parents=True)
    output.write_bytes(b"original")
    archive = archive_factory([regular_member(body=b"replacement")])
    with pytest.raises(FileExistsError):
        extract_archive(archive)
    assert output.read_bytes() == b"original"


def test_source_archive_cannot_write_through_hardlink(
    archive_factory, audit_archive, tmp_path
):
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    link = tarfile.TarInfo("info/recipe/rendered_recipe.yaml")
    link.type = tarfile.LNKTYPE
    link.linkname = str(outside)
    replacement = tarfile.TarInfo(link.name)
    replacement.size = 7
    report = audit_archive(archive_factory([(link, b""), (replacement, b"changed")]))
    assert outside.read_bytes() == b"original"
    assert report[0]["status"] == "invalid"


@pytest.mark.parametrize(
    "size", [None, -1, 5], ids=["read-all-none", "read-all", "oversized-read"]
)
def test_archive_reader_caps_read_allocations(size):
    source = io.BytesIO(b"0123456789")
    reader = ArchiveReader(source, max_read_bytes=4)
    with pytest.raises(ValueError, match="metadata read exceeds"):
        reader.read(size)
    assert source.tell() == (0 if size == 5 else 5)


def test_archive_reader_reads_short_stream_without_unbounded_read():
    reader = ArchiveReader(io.BytesIO(b"abc"), max_read_bytes=4, remaining=3)
    assert reader.read() == b"abc"
    assert reader.remaining == 0
    assert reader.read() == b""


@pytest.mark.parametrize("size", [-1, 8], ids=["read-all", "sized-read"])
def test_archive_reader_stops_after_expansion_budget(size):
    source = io.BytesIO(b"0123456789")
    reader = ArchiveReader(source, max_read_bytes=8, remaining=3)
    with pytest.raises(ValueError, match="expanded archive exceeds"):
        reader.read(size)
    assert source.tell() == 4


def test_archive_reader_seek_does_not_reset_expansion_budget():
    reader = ArchiveReader(io.BytesIO(b"0123456789"), max_read_bytes=8, remaining=6)
    assert reader.seekable()
    assert reader.read(4) == b"0123"
    assert reader.tell() == 4
    assert reader.seek(-2, io.SEEK_CUR) == 2
    assert reader.tell() == 2
    with pytest.raises(ValueError, match="expanded archive exceeds"):
        reader.read(3)


@pytest.mark.parametrize("pax_header", [False, True], ids=["body", "pax-header"])
def test_source_archive_bounds_expansion_before_tar_metadata_parsing(
    archive_factory, regular_member, extract_archive, monkeypatch, pax_header
):
    monkeypatch.setattr(source_archive, "MAX_EXPANDED_ARCHIVE_BYTES", 12 * 1024)
    if pax_header:
        members = [regular_member(pax_headers={"comment": "x" * (20 * 1024)})]
    else:
        members = [
            regular_member("info/unused", b"x" * (11 * 1024)),
            regular_member(body=b"{}"),
        ]
    with pytest.raises(ValueError, match="expanded archive exceeds"):
        extract_archive(archive_factory(members))


def test_source_archive_bounds_tar_metadata_separately_from_payload(
    archive_factory, regular_member, extract_archive, monkeypatch
):
    monkeypatch.setattr(source_archive, "MAX_ARCHIVE_METADATA_BYTES", 2048)
    member = regular_member(pax_headers={"comment": "x" * 4096})
    with pytest.raises(ValueError, match="tar metadata exceeds"):
        extract_archive(archive_factory([member]))


def test_source_archive_skipped_payload_does_not_consume_metadata_budget(
    archive_factory, regular_member, extract_archive, monkeypatch
):
    monkeypatch.setattr(source_archive, "MAX_ARCHIVE_METADATA_BYTES", 4096)
    members = [regular_member("lib/payload", b"x" * 65536), regular_member()]
    destination = extract_archive(archive_factory(members))
    assert (destination / "info/recipe/rendered_recipe.yaml").read_bytes() == b"{}"
    assert not (destination / "lib").exists()


def test_source_archive_rejects_oversized_member_before_reading_its_body(
    archive_factory, extract_archive, monkeypatch
):
    limit = 12 * 1024
    monkeypatch.setattr(source_archive, "MAX_EXPANDED_ARCHIVE_BYTES", limit)
    member = tarfile.TarInfo("info/unused")
    member.size = limit + 1
    raw_tar = member.tobuf() + b"\0" * (10 * 1024)
    with pytest.raises(ValueError, match="archive member exceeds"):
        extract_archive(archive_factory(raw_tar=raw_tar))


def test_source_archive_counts_unselected_members(
    archive_factory, regular_member, extract_archive, monkeypatch
):
    monkeypatch.setattr(source_archive, "MAX_ARCHIVE_MEMBERS", 2)
    members = [regular_member(f"info/unused-{index}") for index in range(3)]
    with pytest.raises(ValueError, match="too many archive members"):
        extract_archive(archive_factory(members))


@pytest.mark.parametrize(
    ("name", "limit_name", "message"),
    [
        (
            "info/recipe/rendered_recipe.yaml",
            "max_recipe_bytes",
            "rendered recipe exceeds",
        ),
        (
            "info/recipe/attestations/source.sigstore.json",
            "max_bundle_bytes",
            "embedded bundle exceeds",
        ),
    ],
)
@pytest.mark.parametrize("limit", [3, 4], ids=["over-limit", "exact-limit"])
def test_source_archive_bounds_each_recipe_file(
    archive_factory, regular_member, extract_archive, name, limit_name, message, limit
):
    archive = archive_factory([regular_member(name, b"1234")])
    limits = {limit_name: limit}
    if limit == 3:
        with pytest.raises(ValueError, match=message):
            extract_archive(archive, **limits)
    else:
        destination = extract_archive(archive, **limits)
        assert (destination / name).read_bytes() == b"1234"


@pytest.mark.parametrize(
    "member_type",
    [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE, b"Z"],
    ids=["symlink", "hardlink", "fifo", "sparse", "unknown"],
)
def test_source_archive_rejects_nonregular_recipe_members(
    archive_factory, extract_archive, member_type
):
    member = tarfile.TarInfo("info/recipe/rendered_recipe.yaml")
    member.type = member_type
    member.linkname = "elsewhere"
    with pytest.raises(ValueError, match="must be regular files"):
        extract_archive(archive_factory([(member, b"")]))


def test_source_archive_rejects_sparse_pax_recipe_member(
    archive_factory, regular_member, extract_archive
):
    member = regular_member(
        body=b"x",
        pax_headers={"GNU.sparse.map": "0,1", "GNU.sparse.realsize": "1"},
    )
    with pytest.raises(ValueError, match="must be regular files"):
        extract_archive(archive_factory([member]))


@pytest.mark.parametrize("name", ["info", "info/recipe", "info/recipe/attestations"])
@pytest.mark.parametrize("member_type", [tarfile.REGTYPE, tarfile.SYMTYPE])
def test_source_archive_does_not_create_archive_parent_entries(
    archive_factory, regular_member, extract_archive, name, member_type
):
    member = regular_member(name, b"", type=member_type, linkname="elsewhere")
    destination = extract_archive(archive_factory([member, regular_member()]))
    assert (destination / "info/recipe/rendered_recipe.yaml").read_bytes() == b"{}"
    assert not (destination / name).is_symlink()


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/outside",
        "info/recipe/../outside",
        "info//recipe/rendered_recipe.yaml",
        "info/recipe/./rendered_recipe.yaml",
        "info/recipe\\outside",
        "info/recipe/attestations/stream:source.sigstore.json",
        "info/recipe/attestations/AUX.sigstore.json",
    ],
)
def test_source_archive_rejects_unsafe_member_paths(
    archive_factory, regular_member, extract_archive, name
):
    with pytest.raises(ValueError, match="unsafe member path"):
        extract_archive(archive_factory([regular_member(name)]))


@pytest.mark.parametrize(
    "second_name",
    [
        "info/recipe/attestations/source.sigstore.json",
        "info/recipe/attestations/SOURCE.sigstore.json",
    ],
    ids=["duplicate", "case-collision"],
)
def test_source_archive_rejects_duplicate_recipe_file_paths(
    archive_factory, regular_member, extract_archive, second_name
):
    with pytest.raises(ValueError, match="duplicate file paths"):
        extract_archive(
            archive_factory(
                [
                    regular_member("info/recipe/attestations/source.sigstore.json"),
                    regular_member(second_name),
                ]
            )
        )


def test_source_archive_ignores_payload_symlinks_without_writing_them(
    archive_factory, regular_member, extract_archive, tmp_path
):
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    payload = regular_member(
        "bin/link", b"", type=tarfile.SYMTYPE, linkname=str(outside)
    )
    destination = extract_archive(archive_factory([payload, regular_member()]))
    assert (destination / "info/recipe/rendered_recipe.yaml").read_bytes() == b"{}"
    assert not (destination / "bin").exists()
    assert outside.read_bytes() == b"original"


@pytest.mark.parametrize("malformation", ["invalid-header", "truncated-body"])
def test_source_archive_normalizes_malformed_tar_errors(
    archive_factory, regular_member, audit_archive, malformation
):
    if malformation == "invalid-header":
        raw_tar = b"not a tar header" + b"\0" * 10240
    else:
        member, body = regular_member(body=b"1234")
        raw_tar = member.tobuf() + body[:-1]
    report = audit_archive(archive_factory(raw_tar=raw_tar))
    assert report[0]["status"] == "invalid"
    assert report[0]["failure"] == "retained package archive is malformed"


@pytest.mark.parametrize("extension", [".conda", ".tar.bz2"])
def test_source_archive_normalizes_malformed_compressed_stream_errors(
    tmp_path, zip_archive_factory, audit_archive, extension
):
    if extension == ".conda":
        archive = zip_archive_factory(content=b"not a zstandard stream")
    else:
        archive = tmp_path / "pkg-1-0.tar.bz2"
        archive.write_bytes(b"not a bzip2 stream")
    report = audit_archive(archive)
    assert report[0]["status"] == "invalid"
    assert report[0]["failure"] == "retained package archive is malformed"


def test_source_archive_accepts_normal_zip64(zip_archive_factory, extract_archive):
    archive = zip_archive_factory(force_zip64=True)
    destination = extract_archive(archive)
    assert (destination / "info/recipe/rendered_recipe.yaml").read_bytes() == b"{}"


def test_source_archive_bounds_zstandard_decoder_window(
    zip_archive_factory, audit_archive, monkeypatch
):
    compressed = zstd.compress(
        b"\0" * 10240,
        options={zstd.CompressionParameter.content_size_flag: 0},
    )
    archive = zip_archive_factory(content=compressed)
    assert audit_archive(archive)[0]["status"] == "evidence-unavailable"
    monkeypatch.setattr(source_archive, "MAX_ZSTD_WINDOW_LOG", 10)
    report = audit_archive(archive)
    assert report[0]["status"] == "invalid"
    assert report[0]["failure"] == "retained package archive is malformed"


def test_source_archive_bounds_zip_central_directory_before_parsing(
    zip_archive_factory, extract_archive, monkeypatch
):
    monkeypatch.setattr(source_archive, "MAX_ZIP_METADATA_BYTES", 128)
    archive = zip_archive_factory(("info-pkg-1-0.tar.zst", "pkg-pkg-1-0.tar.zst"))
    with pytest.raises(ValueError, match="metadata read exceeds"):
        extract_archive(archive)


def test_source_archive_counts_all_zip_members(
    zip_archive_factory, extract_archive, monkeypatch
):
    monkeypatch.setattr(source_archive, "MAX_ZIP_MEMBERS", 1)
    archive = zip_archive_factory(("info-pkg-1-0.tar.zst", "pkg-pkg-1-0.tar.zst"))
    with pytest.raises(ValueError, match="too many ZIP members"):
        extract_archive(archive)


@pytest.mark.parametrize("names", [(), ("info-other-1-0.tar.zst",)])
def test_source_archive_requires_matching_info_zip_member(
    zip_archive_factory, extract_archive, names
):
    with pytest.raises(ValueError, match="one matching info component"):
        extract_archive(zip_archive_factory(names))


def test_source_archive_rejects_ambiguous_info_zip_members(
    zip_archive_factory, extract_archive
):
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive = zip_archive_factory(("info-pkg-1-0.tar.zst",) * 2)
    with pytest.raises(ValueError, match="one matching info component"):
        extract_archive(archive)


def test_source_archive_rejects_compressed_info_zip_member(
    zip_archive_factory, extract_archive
):
    archive = zip_archive_factory(compression=zipfile.ZIP_DEFLATED)
    with pytest.raises(ValueError, match="must use ZIP_STORED"):
        extract_archive(archive)


def test_source_archive_rejects_encrypted_info_zip_member(
    zip_archive_factory, audit_archive
):
    archive = zip_archive_factory()
    body = bytearray(archive.read_bytes())
    for signature, flag_offset in [(b"PK\x03\x04", 6), (b"PK\x01\x02", 8)]:
        offset = body.index(signature) + flag_offset
        flags = struct.unpack_from("<H", body, offset)[0]
        struct.pack_into("<H", body, offset, flags | 1)
    archive.write_bytes(body)
    report = audit_archive(archive)
    assert report[0]["status"] == "invalid"
    assert report[0]["failure"] == "retained package archive is malformed"
