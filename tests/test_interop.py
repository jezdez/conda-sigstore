from __future__ import annotations

import hashlib
import os
from urllib.request import Request, urlopen

import pytest
from conda.gateways.disk.read import compute_sum

from conda_sigstore.attestation import create_attestation
from conda_sigstore.model import Sidecar, VerificationStatus
from conda_sigstore.transport import SidecarTransport
from conda_sigstore.verification import SigstoreVerifier, verify_bundles

PREFIX_ARTIFACT = (
    "https://prefix.dev/sigstore-example/linux-64/signed-package-2.1.0-hb0f4dca_0.conda"
)
PREFIX_ARTIFACT_NAME = "signed-package-2.1.0-hb0f4dca_0.conda"
PREFIX_ARTIFACT_SHA256 = (
    "3862a3677d33a45134a2ce3452b23f8f7459fe581cefbc3818272648cd987cfb"
)
PREFIX_SIDECAR_SHA256 = (
    "823d6078e08809cdd85e40cf2d55a83f86226c9d9b6d4134d42ecf80456e55e1"
)
PREFIX_CHANNEL = "https://prefix.dev/sigstore-example"
PREFIX_IDENTITY = (
    "https://github.com/prefix-dev/sigstore-example/"
    ".github/workflows/action.yaml@refs/heads/main"
)
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
STAGING_CHANNEL = "https://staging.example.invalid/conda-sigstore"


def fetch_example(url: str, max_bytes: int) -> bytes:
    """Fetch bounded bytes for an explicitly enabled live example."""
    request = Request(url, headers={"User-Agent": "conda-sigstore-interoperability"})
    with urlopen(request, timeout=30) as response:
        return response.read(max_bytes + 1)


@pytest.mark.live_interop
@pytest.mark.skipif(
    os.environ.get("CONDA_SIGSTORE_PREFIX_INTEROP") != "1",
    reason="set CONDA_SIGSTORE_PREFIX_INTEROP=1 to run",
)
def test_prefix_sidecar_fixed_example_reports_authenticated_signer() -> None:
    artifact = fetch_example(PREFIX_ARTIFACT, 32 * 1024 * 1024)
    assert hashlib.sha256(artifact).hexdigest() == PREFIX_ARTIFACT_SHA256

    sidecar = SidecarTransport(fetcher=fetch_example).load_prefix(PREFIX_ARTIFACT)
    assert sidecar.sha256 == PREFIX_SIDECAR_SHA256

    result = verify_bundles(
        sidecar,
        artifact_name=PREFIX_ARTIFACT_NAME,
        artifact_sha256=PREFIX_ARTIFACT_SHA256,
        verifier=SigstoreVerifier(),
        channel=PREFIX_CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.prefix_sidecar
    assert result.evidence[0].identity == PREFIX_IDENTITY
    assert result.evidence[0].issuer == GITHUB_ISSUER
    assert result.evidence[0].verified
    assert result.to_dict()["authorization"] == "not-evaluated"
    assert "authorized" not in result.evidence[0].to_dict()


@pytest.mark.live_interop
@pytest.mark.skipif(
    os.environ.get("CONDA_SIGSTORE_STAGING_INTEROP") != "1",
    reason="set CONDA_SIGSTORE_STAGING_INTEROP=1 to run",
)
def test_sigstore_staging_round_trip_reports_authenticated_signer(tmp_path) -> None:
    from sigstore.models import ClientTrustConfig

    expected_identity = os.environ["CONDA_SIGSTORE_STAGING_IDENTITY"]
    trust_config = ClientTrustConfig.staging()
    trust_config_path = tmp_path / "sigstore-staging.json"
    # sigstore-python 4.5 has no public ClientTrustConfig serializer. This
    # live-only round trip needs its exact combined trust-root and signing JSON.
    trust_config_path.write_text(trust_config._inner.to_json(), encoding="utf-8")

    artifact = tmp_path / "conda-sigstore-staging-0-0.conda"
    artifact.write_bytes(b"conda-sigstore staging interoperability\n")
    output = create_attestation(
        artifact,
        target_channel=STAGING_CHANNEL,
        trust_config_path=trust_config_path,
    )
    bundle = output.read_text(encoding="utf-8").strip()
    sidecar = Sidecar(
        url="local:staging",
        sha256=hashlib.sha256(bundle.encode()).hexdigest(),
        bundles=(bundle,),
    )

    result = verify_bundles(
        sidecar,
        artifact_name=artifact.name,
        artifact_sha256=compute_sum(artifact, "sha256"),
        verifier=SigstoreVerifier(trust_config=trust_config_path),
        channel=STAGING_CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].identity == expected_identity
    assert result.evidence[0].issuer == GITHUB_ISSUER
    assert result.evidence[0].verified
    assert result.to_dict()["authorization"] == "not-evaluated"
    assert "authorized" not in result.evidence[0].to_dict()
