from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import conda.base.context
import pytest
from conda.base.context import reset_context
from conda.core.package_cache_data import PackageCacheData
from conda.exceptions import CondaMultiError, CondaVerificationError
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from conda_sigstore.audit import EnvironmentAuditor
from conda_sigstore.cache import DigestCache
from conda_sigstore.evidence import SignerIdentity
from conda_sigstore.exceptions import BundleVerificationError, TransportError
from conda_sigstore.install import InstallVerifier
from conda_sigstore.settings import SigstoreSettings
from conda_sigstore.statements import InTotoStatement, PublishStatement
from conda_sigstore.transport import SidecarTransport
from conda_sigstore.verification import CryptographicVerification, SigstoreVerifier

if TYPE_CHECKING:
    from pathlib import Path

    from conda.testing.fixtures import CondaCLIFixture

FILENAME = "pkg-1.0-0.conda"
DIGEST = "ab" * 32
CHANNEL = "https://conda.example.org/team"
IDENTITY = SignerIdentity(
    "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1",
    "https://token.actions.githubusercontent.com",
)


class FakeVerifier:
    def __init__(self, result: CryptographicVerification | Exception) -> None:
        self.result = result
        self.calls: list[str] = []

    def verify(self, bundle_json: str) -> CryptographicVerification:
        self.calls.append(bundle_json)
        assert json.loads(bundle_json) == {"bundle": "one"}
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def sidecar() -> bytes:
    return json.dumps([{"bundle": "one"}]).encode()


@pytest.fixture
def package_record() -> PackageRecord:
    return PackageRecord(
        name="pkg",
        version="1.0",
        build="0",
        build_number=0,
        subdir="linux-64",
        fn=FILENAME,
        url=f"{CHANNEL}/linux-64/{FILENAME}",
        channel=CHANNEL,
        sha256=DIGEST,
    )


def verified_publication(
    filename: str = FILENAME,
    digest: str = DIGEST,
) -> CryptographicVerification:
    return CryptographicVerification(
        InTotoStatement.PAYLOAD_TYPE,
        PublishStatement(filename, digest, CHANNEL).payload(),
        IDENTITY,
        ("signed-time",),
    )


def test_current_install_verifiers_share_sigstore_trust(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(offline=False),
    )
    monkeypatch.setattr(
        SigstoreSettings,
        "current",
        classmethod(lambda cls: cls()),
    )
    monkeypatch.setattr(
        PackageCacheData,
        "first_writable",
        classmethod(lambda _cls: SimpleNamespace(pkgs_dir=tmp_path)),
    )
    SigstoreVerifier.shared.cache_clear()

    first = InstallVerifier.current()
    second = InstallVerifier.current()
    conda.base.context.context.offline = True
    offline = InstallVerifier.current()

    assert first is not second
    assert first.auditor.verifier is second.auditor.verifier
    assert offline.auditor.verifier is not first.auditor.verifier
    SigstoreVerifier.shared.cache_clear()


def test_install_verifier_accepts_advertised_sidecar_without_rehashing(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    package_record.attestations = {
        "sha256": hashlib.sha256(sidecar).hexdigest(),
        "size": len(sidecar),
    }
    fetched = []

    def fetch(url: str, max_bytes: int) -> bytes:
        fetched.append((url, max_bytes))
        return sidecar

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(max_sidecar_bytes=1024),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(max_bytes=1024, fetcher=fetch),
        )
    )
    missing_archive = tmp_path / FILENAME

    assert verifier.verify(package_record, missing_archive, DIGEST) is None
    assert fetched == [(f"{CHANNEL}/linux-64/{FILENAME}.sigs", 1024)]
    assert not missing_archive.exists()


def test_install_verifier_accepts_adjacent_prefix_sidecar_without_descriptor(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    fetched: list[str] = []

    def fetch(url: str, _max_bytes: int) -> bytes:
        fetched.append(url)
        return sidecar

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(fetcher=fetch),
        )
    )

    assert verifier.verify(package_record, tmp_path / FILENAME, DIGEST) is None
    assert fetched == [f"{CHANNEL}/linux-64/{FILENAME}.v0.sigs"]


def test_install_verifier_does_not_fall_back_from_broken_descriptor(
    tmp_path: Path,
    package_record: PackageRecord,
) -> None:
    package_record.attestations = {"sha256": "bad", "size": 1}
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail(
                    "a broken advertised descriptor must not fall back"
                )
            ),
        )
    )

    with pytest.raises(CondaVerificationError, match="invalid-descriptor"):
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)


def test_install_verifier_does_not_fall_back_when_advertised_sidecar_is_missing(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    package_record.attestations = {
        "sha256": hashlib.sha256(sidecar).hexdigest(),
        "size": len(sidecar),
    }
    fetched: list[str] = []

    def fetch(url: str, _max_bytes: int) -> bytes:
        fetched.append(url)
        raise TransportError("missing-sidecar", "advertised sidecar is missing")

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(fetcher=fetch),
        )
    )

    with pytest.raises(CondaVerificationError, match="missing-sidecar"):
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)

    assert fetched == [f"{CHANNEL}/linux-64/{FILENAME}.sigs"]


def test_install_verifier_rejects_explicit_local_package_without_fetching(
    tmp_path: Path,
) -> None:
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail(
                    "explicit packages must not be probed"
                )
            ),
        )
    )
    archive = tmp_path / FILENAME
    spec = MatchSpec(url=archive.as_uri())

    with pytest.raises(CondaVerificationError, match="must be HTTP or HTTPS"):
        verifier.verify(spec, archive, DIGEST)


def test_install_verifier_accepts_explicit_remote_package(
    tmp_path: Path,
    sidecar: bytes,
) -> None:
    fetched: list[str] = []

    def fetch(url: str, _max_bytes: int) -> bytes:
        fetched.append(url)
        return sidecar

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(fetcher=fetch),
        )
    )
    url = f"{CHANNEL}/linux-64/{FILENAME}?token=secret#sha256={DIGEST}"

    assert verifier.verify(MatchSpec(url=url), tmp_path / FILENAME, DIGEST) is None
    assert fetched == [f"{CHANNEL}/linux-64/{FILENAME}.v0.sigs?token=secret"]


def test_install_verifier_rejects_archive_filename_mismatch(
    tmp_path: Path,
    package_record: PackageRecord,
) -> None:
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail("mismatched archive must not fetch")
            ),
        )
    )

    with pytest.raises(CondaVerificationError, match="filename"):
        verifier.verify(package_record, tmp_path / "other-1.0-0.conda", DIGEST)


def test_install_verifier_rejects_malformed_hook_sha(
    tmp_path: Path,
    package_record: PackageRecord,
) -> None:
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail("malformed digest must not fetch")
            ),
        )
    )

    with pytest.raises(CondaVerificationError, match="64-character hexadecimal"):
        verifier.verify(package_record, tmp_path / FILENAME, "not-a-sha256")


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (TransportError("missing-sidecar", "sidecar is missing"), "missing-sidecar"),
        (
            TransportError("retrieval-failed", "could not retrieve sidecar"),
            "retrieval-failed",
        ),
        (
            TransportError("offline-cache-miss", "offline evidence is unavailable"),
            "offline-cache-miss",
        ),
        (BundleVerificationError("bad signature"), "invalid-bundle"),
    ],
    ids=("missing", "retrieval", "offline", "invalid-bundle"),
)
def test_install_verifier_reports_evidence_failures(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
    failure: Exception,
    expected: str,
) -> None:
    def fetch(_url: str, _max_bytes: int) -> bytes:
        if isinstance(failure, TransportError):
            raise failure
        return sidecar

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(failure),
            transport="install",
            sidecars=SidecarTransport(fetcher=fetch),
        )
    )

    with pytest.raises(CondaVerificationError) as raised:
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)

    message = str(raised.value)
    assert FILENAME in message
    assert expected in message


def test_install_verifier_rejects_malformed_adjacent_sidecar(
    tmp_path: Path,
    package_record: PackageRecord,
) -> None:
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(fetcher=lambda _url, _limit: b"{"),
        )
    )

    with pytest.raises(CondaVerificationError, match="invalid-sidecar"):
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)


def test_install_verifier_rejects_nonmatching_adjacent_statement(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    nonmatching = CryptographicVerification(
        InTotoStatement.PAYLOAD_TYPE,
        PublishStatement(FILENAME, "cd" * 32, CHANNEL).payload(),
        IDENTITY,
    )
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(nonmatching),
            transport="install",
            sidecars=SidecarTransport(fetcher=lambda _url, _limit: sidecar),
        )
    )

    with pytest.raises(CondaVerificationError, match="invalid-cep27"):
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)


def test_install_verifier_reuses_verified_adjacent_sidecar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    cache = DigestCache(tmp_path / "cache")
    online = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda _url, _limit: sidecar,
                cache=cache,
            ),
        )
    )
    online.verify(package_record, tmp_path / FILENAME, DIGEST)
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(offline=True),
    )

    offline_bundle_verifier = FakeVerifier(verified_publication())
    offline = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            offline_bundle_verifier,
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail(
                    "verified adjacent evidence must be reused"
                ),
                cache=cache,
            ),
        )
    )

    assert offline.verify(package_record, tmp_path / FILENAME, DIGEST) is None
    assert len(offline_bundle_verifier.calls) == 1
    assert cache.load_artifact_sidecar(DIGEST, f"{CHANNEL}\0{FILENAME}") == sidecar


def test_install_verifier_refreshes_adjacent_sidecar_online(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(offline=False),
    )
    cache = DigestCache(tmp_path / "cache")
    cache.store_artifact_sidecar(
        DIGEST,
        f"{CHANNEL}\0{FILENAME}",
        json.dumps([{"bundle": "stale"}]).encode(),
    )
    fetched: list[str] = []

    def fetch(url: str, _max_bytes: int) -> bytes:
        fetched.append(url)
        return sidecar

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            transport="install",
            sidecars=SidecarTransport(fetcher=fetch, cache=cache),
        )
    )

    assert verifier.verify(package_record, tmp_path / FILENAME, DIGEST) is None
    assert fetched == [f"{CHANNEL}/linux-64/{FILENAME}.v0.sigs"]
    assert cache.load_artifact_sidecar(DIGEST, f"{CHANNEL}\0{FILENAME}") == sidecar


def test_install_verifier_does_not_cache_invalid_adjacent_sidecar(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    cache = DigestCache(tmp_path / "cache")
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(BundleVerificationError("bad signature")),
            transport="install",
            sidecars=SidecarTransport(
                fetcher=lambda _url, _limit: sidecar,
                cache=cache,
            ),
        )
    )

    with pytest.raises(CondaVerificationError, match="invalid-bundle"):
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)

    assert cache.load_artifact_sidecar(DIGEST, f"{CHANNEL}\0{FILENAME}") is None


@pytest.mark.parametrize("valid_evidence", [True, False], ids=("valid", "rejected"))
def test_pixi_lock_install_enforces_evidence_before_extraction(
    conda_cli: CondaCLIFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sidecar: bytes,
    locked_conda_package: tuple[Path, str, str, Path],
    valid_evidence: bool,
) -> None:
    package_cache, digest, artifact_url, extracted_payload = locked_conda_package
    subdir = artifact_url.rsplit("/", 2)[1]
    lockfile = tmp_path / "pixi.lock"
    lockfile.write_text(
        json.dumps(
            {
                "version": 6,
                "environments": {
                    "default": {
                        "channels": [{"url": CHANNEL}],
                        "packages": {
                            subdir: [{"conda": artifact_url}],
                        },
                    }
                },
                "packages": [
                    {"conda": artifact_url, "sha256": digest},
                ],
            }
        ),
        encoding="utf-8",
    )
    prefix = tmp_path / "prefix"
    fetched: list[str] = []

    def fetch(url: str, _max_bytes: int) -> bytes:
        if not fetched:
            assert not extracted_payload.exists()
        fetched.append(url)
        return sidecar if valid_evidence else b"{"

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication(FILENAME, digest)),
            transport="install",
            sidecars=SidecarTransport(fetcher=fetch),
        )
    )
    monkeypatch.setattr(
        InstallVerifier,
        "current",
        classmethod(lambda _cls: verifier),
    )
    monkeypatch.setenv("CONDA_PKGS_DIRS", str(package_cache))
    monkeypatch.setenv("CONDA_PLUGINS_CONDA_SIGSTORE_ENFORCE", "true")
    reset_context()

    arguments = (
        "create",
        "--yes",
        "--quiet",
        "--prefix",
        prefix,
        "--file",
        lockfile,
    )

    if valid_evidence:
        _stdout, stderr, code = conda_cli(*arguments)
        assert code == 0, stderr
        assert (prefix / "payload.txt").read_text(encoding="utf-8") == (
            "locked package\n"
        )
    else:
        _stdout, _stderr, raised = conda_cli(*arguments, raises=CondaMultiError)
        assert "invalid-sidecar" in str(raised.value)
        assert not prefix.exists()
    assert fetched[0] == f"{artifact_url}.v0.sigs"
