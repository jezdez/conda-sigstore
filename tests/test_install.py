from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest
from conda.exceptions import CondaVerificationError
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from conda_sigstore.audit import EnvironmentAuditor
from conda_sigstore.exceptions import BundleVerificationError, TransportError
from conda_sigstore.install import InstallVerifier
from conda_sigstore.model import SignerIdentity
from conda_sigstore.settings import SigstoreSettings
from conda_sigstore.statements import InTotoStatement, PublishStatement
from conda_sigstore.transport import SidecarTransport
from conda_sigstore.verification import CryptographicVerification

if TYPE_CHECKING:
    from pathlib import Path

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

    def verify(self, bundle_json: str) -> CryptographicVerification:
        assert json.loads(bundle_json) == {"bundle": "one"}
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def sidecar() -> bytes:
    return json.dumps([{"bundle": "one"}]).encode()


@pytest.fixture
def package_record(sidecar: bytes) -> PackageRecord:
    record = PackageRecord(
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
    record.attestations = {
        "sha256": hashlib.sha256(sidecar).hexdigest(),
        "size": len(sidecar),
    }
    return record


def verified_publication() -> CryptographicVerification:
    return CryptographicVerification(
        InTotoStatement.PAYLOAD_TYPE,
        PublishStatement(FILENAME, DIGEST, CHANNEL).payload(),
        IDENTITY.identity,
        IDENTITY.issuer,
        ("signed-time",),
    )


def test_install_verifier_accepts_advertised_sidecar_without_rehashing(
    tmp_path: Path,
    package_record: PackageRecord,
    sidecar: bytes,
) -> None:
    fetched = []

    def fetch(url: str, max_bytes: int) -> bytes:
        fetched.append((url, max_bytes))
        return sidecar

    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(max_sidecar_bytes=1024),
            FakeVerifier(verified_publication()),
            sidecars=SidecarTransport(max_bytes=1024, fetcher=fetch),
        )
    )
    missing_archive = tmp_path / FILENAME

    assert verifier.verify(package_record, missing_archive, DIGEST) is None
    assert fetched == [(f"{CHANNEL}/linux-64/{FILENAME}.sigs", 1024)]
    assert not missing_archive.exists()


def test_install_verifier_rejects_missing_descriptor_without_fetching(
    tmp_path: Path,
    package_record: PackageRecord,
) -> None:
    del package_record.attestations
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail(
                    "missing evidence must not be probed"
                )
            ),
        )
    )

    with pytest.raises(CondaVerificationError, match="missing-attestations"):
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)


def test_install_verifier_rejects_explicit_local_package_without_fetching(
    tmp_path: Path,
) -> None:
    verifier = InstallVerifier(
        EnvironmentAuditor(
            SigstoreSettings(),
            FakeVerifier(verified_publication()),
            sidecars=SidecarTransport(
                fetcher=lambda *_args: pytest.fail(
                    "explicit packages must not be probed"
                )
            ),
        )
    )
    archive = tmp_path / FILENAME
    spec = MatchSpec(url=archive.as_uri())

    with pytest.raises(CondaVerificationError, match="explicit"):
        verifier.verify(spec, archive, DIGEST)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (
            TransportError("retrieval-failed", "could not retrieve sidecar"),
            "retrieval-failed",
        ),
        (BundleVerificationError("bad signature"), "invalid-bundle"),
    ],
    ids=("retrieval", "invalid-bundle"),
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
            sidecars=SidecarTransport(fetcher=fetch),
        )
    )

    with pytest.raises(CondaVerificationError) as raised:
        verifier.verify(package_record, tmp_path / FILENAME, DIGEST)

    message = str(raised.value)
    assert FILENAME in message
    assert expected in message
