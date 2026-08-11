from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import conda.base.context
import conda.gateways.connection.session
import pytest

from conda_sigstore.cache import DigestCache
from conda_sigstore.exceptions import TransportError
from conda_sigstore.model import AttestationDescriptor
from conda_sigstore.transport import FetchResponse, SidecarTransport


def sidecar_bytes() -> bytes:
    return json.dumps(
        [
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "dsseEnvelope": {},
                "verificationMaterial": {},
            }
        ]
    ).encode()


def test_repodata_fetches_only_advertised_integrity_bound_sidecar() -> None:
    body = sidecar_bytes()
    seen: list[tuple[str, int]] = []

    def fetch(url: str, limit: int) -> FetchResponse:
        seen.append((url, limit))
        return FetchResponse(body, "text/plain")

    sidecar = SidecarTransport(max_bytes=1024, fetcher=fetch).load_repodata(
        "https://user:secret@EXAMPLE.org/channel/pkg-1-0.conda?token=x",
        AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body)),
    )
    expected_url = "https://user:secret@EXAMPLE.org/channel/pkg-1-0.conda.sigs?token=x"
    assert seen == [(expected_url, 1024)]
    assert len(sidecar.bundles) == 1
    assert sidecar.url == "https://example.org/pkg-1-0.conda.sigs"
    assert not sidecar.prefix_sidecar


def test_repodata_refuses_oversized_descriptor_before_fetch() -> None:
    called = False

    def fetch(url: str, limit: int) -> bytes:
        nonlocal called
        called = True
        return b""

    descriptor = AttestationDescriptor("ab" * 32, 11)
    with pytest.raises(TransportError, match="exceeds"):
        SidecarTransport(max_bytes=10, fetcher=fetch).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )
    assert not called


def test_repodata_descriptor_requires_lowercase_sha256() -> None:
    with pytest.raises(ValueError, match="lowercase"):
        AttestationDescriptor("AB" * 32, 1)


@pytest.mark.parametrize("changed", [b"x", b"xx"])
def test_repodata_rejects_size_or_digest_mismatch(changed: bytes) -> None:
    body = sidecar_bytes()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    with pytest.raises(TransportError):
        SidecarTransport(fetcher=lambda url, limit: changed).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )


def test_repodata_fetches_when_cache_read_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    body = sidecar_bytes()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    cache = DigestCache(tmp_path / "cache")
    fetched: list[str] = []

    def fail_cache_read(_sha256: str, *, max_bytes: int) -> bytes | None:
        assert max_bytes == 1024
        raise OSError("unreadable cache")

    def fetch(url: str, _limit: int) -> bytes:
        fetched.append(url)
        return body

    monkeypatch.setattr(cache, "load_sidecar", fail_cache_read)

    sidecar = SidecarTransport(
        max_bytes=1024,
        fetcher=fetch,
        cache=cache,
    ).load_repodata(
        "https://example.org/pkg-1-0.conda",
        descriptor,
    )

    assert fetched == ["https://example.org/pkg-1-0.conda.sigs"]
    assert sidecar.sha256 == descriptor.sha256


def test_prefix_sidecar_is_explicit_and_unpinned() -> None:
    body = sidecar_bytes()
    sidecar = SidecarTransport(fetcher=lambda url, limit: body).load_prefix(
        "https://prefix.dev/channel/linux-64/pkg-1-0.conda"
    )
    assert sidecar.url.endswith(".conda.v0.sigs")
    assert sidecar.prefix_sidecar
    assert sidecar.sha256 == hashlib.sha256(body).hexdigest()


def test_bundle_input_accepts_raw_single_bundle(tmp_path) -> None:
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {},
    }
    source = tmp_path / "bundle.sigstore.json"
    source.write_text(json.dumps(bundle), encoding="utf-8")

    sidecar = SidecarTransport(max_bytes=1024).load_input(str(source))

    assert sidecar.url == source.name
    assert sidecar.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert len(sidecar.bundles) == 1
    assert json.loads(sidecar.bundles[0]) == bundle
    assert not sidecar.prefix_sidecar


def test_bundle_input_labels_prefix_sidecar(tmp_path) -> None:
    source = tmp_path / "package-1-0.conda.v0.sigs"
    source.write_text(sidecar_bytes().decode(), encoding="utf-8")

    sidecar = SidecarTransport(max_bytes=1024).load_input(str(source))

    assert sidecar.prefix_sidecar


def test_sidecar_must_be_nonempty_bundle_array() -> None:
    body = b"[]"
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    with pytest.raises(TransportError, match="nonempty JSON array"):
        SidecarTransport(fetcher=lambda url, limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )


def test_sidecar_rejects_nonobject_bundle_elements() -> None:
    bundles = [
        None,
        {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
    ]
    body = json.dumps(bundles).encode()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))

    with pytest.raises(TransportError, match="bundle objects"):
        SidecarTransport(fetcher=lambda url, limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )


def test_default_transport_uses_conda_session_for_url(monkeypatch) -> None:
    body = sidecar_bytes()
    calls: list[tuple[object, ...]] = []

    class Response:
        status_code = 200
        headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def raise_for_status(self):
            calls.append(("raise_for_status",))

        def iter_content(self, *, chunk_size):
            calls.append(("iter_content", chunk_size))
            return (body,)

    class Session:
        def get(self, url, *, stream, timeout):
            calls.append(("get", url, stream, timeout))
            return Response()

    def get_session(url):
        calls.append(("get_session", url))
        return Session()

    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(
            offline=False,
            remote_connect_timeout_secs=9,
            remote_read_timeout_secs=61,
        ),
    )
    monkeypatch.setattr(
        conda.gateways.connection.session,
        "get_session",
        get_session,
    )
    url = "https://example.org/pkg-1-0.conda.sigs"

    assert SidecarTransport(max_bytes=1024).fetch(url) == body
    assert calls == [
        ("get_session", url),
        ("get", url, True, (9, 61)),
        ("raise_for_status",),
        ("iter_content", 64 * 1024),
    ]


def test_retrieval_error_redacts_credentials_and_formats_ipv6() -> None:
    body = sidecar_bytes()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    artifact_url = (
        "https://user:secret@[2001:db8::1]:8443/t/super-secret/channel/"
        "pkg-1-0.conda?auth=value"
    )

    def fetch(url: str, limit: int) -> bytes:
        raise OSError(f"failed for {url}")

    with pytest.raises(TransportError) as raised:
        SidecarTransport(fetcher=fetch).load_repodata(artifact_url, descriptor)

    message = str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    assert message == (
        "could not retrieve https://[2001:db8::1]:8443/pkg-1-0.conda.sigs (OSError)"
    )
    for secret in ("user", "secret", "super-secret", "auth", "value"):
        assert secret not in message


def test_local_read_error_does_not_expose_underlying_cause(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    def fail_read(*_args, **_kwargs) -> bytes:
        raise OSError("local secret")

    monkeypatch.setattr("conda_sigstore.transport.read_bounded_file", fail_read)

    with pytest.raises(TransportError) as raised:
        SidecarTransport().load_input(str(tmp_path / "bundle.json"))

    assert str(raised.value) == "could not read bundle bundle.json (OSError)"
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    assert "local secret" not in str(raised.value)
