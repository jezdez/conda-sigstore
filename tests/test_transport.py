from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import conda.base.context
import conda.gateways.connection.session
import pytest

from conda_sigstore.cache import DigestCache
from conda_sigstore.evidence import AttestationDescriptor
from conda_sigstore.exceptions import TransportError
from conda_sigstore.transport import SidecarTransport

if TYPE_CHECKING:
    from collections.abc import Iterable


class HTTPResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        blocks: Iterable[bytes] = (),
        error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.blocks = blocks
        self.error = error
        self.calls: list[tuple[object, ...]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self) -> None:
        self.calls.append(("raise_for_status",))
        if self.error is not None:
            raise self.error

    def iter_content(self, *, chunk_size: int) -> Iterable[bytes]:
        self.calls.append(("iter_content", chunk_size))
        return self.blocks


@pytest.fixture
def conda_response(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[object, ...]] = []
    response = HTTPResponse()

    class Session:
        def get(self, url, *, stream, timeout):
            calls.append(("get", url, stream, timeout))
            return response

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
    return response, calls


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

    def fetch(url: str, limit: int) -> bytes:
        seen.append((url, limit))
        return body

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
    with pytest.raises(TransportError, match="exceeds") as raised:
        SidecarTransport(max_bytes=10, fetcher=fetch).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )
    assert raised.value.code == "sidecar-too-large"
    assert not called


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda body: body[:-1], "size-mismatch"),
        (lambda body: b"x" * len(body), "digest-mismatch"),
    ],
    ids=("size", "digest"),
)
def test_repodata_rejects_size_or_digest_mismatch(change, code: str) -> None:
    body = sidecar_bytes()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    with pytest.raises(TransportError) as raised:
        SidecarTransport(fetcher=lambda url, limit: change(body)).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )
    assert raised.value.code == code


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


def test_repodata_ignores_cache_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    body = sidecar_bytes()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    cache = DigestCache(tmp_path / "cache")

    def fail_cache_write(*_args, **_kwargs):
        raise OSError("unwritable cache")

    monkeypatch.setattr(cache, "store_sidecar", fail_cache_write)

    sidecar = SidecarTransport(
        fetcher=lambda _url, _limit: body,
        cache=cache,
    ).load_repodata(
        "https://example.org/pkg-1-0.conda",
        descriptor,
    )

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


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (json.dumps([{}]).encode("utf-16"), "UTF-8"),
        (b'[{"extension": NaN}]', "invalid JSON constant"),
    ],
)
def test_sidecar_requires_strict_utf8_json(body: bytes, message: str) -> None:
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))

    with pytest.raises(TransportError, match=message):
        SidecarTransport(fetcher=lambda url, limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            descriptor,
        )


def test_default_transport_uses_conda_session_for_url(conda_response) -> None:
    body = sidecar_bytes()
    response, calls = conda_response
    response.headers = {"Content-Length": str(len(body))}
    response.blocks = (body,)
    url = "https://example.org/pkg-1-0.conda.sigs"

    assert SidecarTransport(max_bytes=1024).fetch(url) == body
    assert calls == [
        ("get_session", url),
        ("get", url, True, (9, 61)),
    ]
    assert response.calls == [("raise_for_status",), ("iter_content", 64 * 1024)]


def test_default_transport_refuses_network_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        conda.base.context,
        "context",
        SimpleNamespace(offline=True),
    )
    monkeypatch.setattr(
        conda.gateways.connection.session,
        "get_session",
        lambda _url: pytest.fail("offline transport must not create a session"),
    )

    with pytest.raises(TransportError) as raised:
        SidecarTransport().fetch("https://example.org/pkg-1-0.conda.sigs")

    assert raised.value.code == "offline-cache-miss"


@pytest.mark.parametrize(
    ("status_code", "error", "code"),
    [
        (404, None, "missing-sidecar"),
        (500, OSError("server failed"), "retrieval-failed"),
    ],
    ids=("missing", "http-error"),
)
def test_default_transport_preserves_http_failure_codes(
    conda_response,
    status_code: int,
    error: Exception | None,
    code: str,
) -> None:
    response, _calls = conda_response
    response.status_code = status_code
    response.error = error

    with pytest.raises(TransportError) as raised:
        SidecarTransport().fetch("https://example.org/pkg-1-0.conda.sigs")

    assert raised.value.code == code


def test_default_transport_refuses_declared_oversized_response(
    conda_response,
) -> None:
    response, _calls = conda_response
    response.headers = {"Content-Length": "11"}

    with pytest.raises(TransportError) as raised:
        SidecarTransport(max_bytes=10).fetch("https://example.org/pkg-1-0.conda.sigs")

    assert raised.value.code == "sidecar-too-large"
    assert response.calls == [("raise_for_status",)]


def test_default_transport_refuses_streamed_oversized_response(
    conda_response,
) -> None:
    response, _calls = conda_response
    response.blocks = (b"12345", b"678901")

    with pytest.raises(TransportError) as raised:
        SidecarTransport(max_bytes=10).fetch("https://example.org/pkg-1-0.conda.sigs")

    assert raised.value.code == "sidecar-too-large"
    assert response.calls == [("raise_for_status",), ("iter_content", 64 * 1024)]


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("not bytes", "invalid-response"),
        (b"oversized", "sidecar-too-large"),
    ],
    ids=("non-bytes", "oversized"),
)
def test_injected_fetcher_rejects_invalid_response(body: object, code: str) -> None:
    with pytest.raises(TransportError) as raised:
        SidecarTransport(max_bytes=4, fetcher=lambda _url, _limit: body).fetch(
            "https://example.org/bundle.sigs"
        )

    assert raised.value.code == code


def test_retrieval_error_redacts_credentials_and_formats_ipv6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = sidecar_bytes()
    descriptor = AttestationDescriptor(hashlib.sha256(body).hexdigest(), len(body))
    artifact_url = (
        "https://user:secret@[2001:db8::1]:8443/t/super-secret/channel/"
        "pkg-1-0.conda?auth=value"
    )

    class Session:
        def get(self, url, *, stream, timeout):
            raise OSError(f"failed for {url}")

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
        lambda url: Session(),
    )

    with pytest.raises(TransportError) as raised:
        SidecarTransport().load_repodata(artifact_url, descriptor)

    message = str(raised.value)
    assert raised.value.__cause__ is None
    assert message == (
        "could not retrieve https://[2001:db8::1]:8443/pkg-1-0.conda.sigs (OSError)"
    )
    for secret in ("user", "secret", "super-secret", "auth", "value"):
        assert secret not in message


def test_injected_fetcher_programming_errors_are_not_transport_results() -> None:
    def fetch(url: str, limit: int) -> bytes:
        raise AssertionError("fetcher bug")

    with pytest.raises(AssertionError, match="fetcher bug"):
        SidecarTransport(fetcher=fetch).fetch("https://example.org/bundle.sigs")


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


def test_local_input_preserves_oversized_failure_code(tmp_path) -> None:
    source = tmp_path / "bundle.json"
    source.write_bytes(b"oversized")

    with pytest.raises(TransportError) as raised:
        SidecarTransport(max_bytes=4).load_input(str(source))

    assert raised.value.code == "sidecar-too-large"
