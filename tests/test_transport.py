from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import conda.base.context
import conda.gateways.connection.session
import pytest

from conda_sigstore.cache import DigestCache
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
    digest = hashlib.sha256(body).hexdigest()
    seen: list[tuple[str, int]] = []

    def fetch(url: str, limit: int) -> bytes:
        seen.append((url, limit))
        return body

    sidecar = SidecarTransport(max_bytes=1024, fetcher=fetch).load_repodata(
        "https://user:secret@EXAMPLE.org/channel/pkg-1-0.conda?token=x#sha256=abc",
        digest,
    )
    expected_url = (
        f"https://user:secret@EXAMPLE.org/channel/pkg-1-0.conda.sigs.{digest}?token=x"
    )
    assert seen == [(expected_url, 1024)]
    assert len(sidecar.bundles) == 1
    assert not sidecar.prefix_sidecar


@pytest.mark.parametrize(
    "advertised_sha256",
    [
        None,
        1,
        "AB" * 32,
        "ab" * 31,
        "ab" * 32 + "a",
        "gg" * 32,
        "ab" * 31 + "a/",
        "ab" * 31 + "a?",
        "ab" * 31 + "a#",
    ],
    ids=(
        "null",
        "integer",
        "uppercase",
        "short",
        "long",
        "non-hexadecimal",
        "path-separator",
        "query-delimiter",
        "fragment-delimiter",
    ),
)
def test_repodata_rejects_invalid_advertised_sha256_before_fetch(
    advertised_sha256: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        SidecarTransport,
        "sidecar_url",
        staticmethod(
            lambda *_args: pytest.fail(
                "invalid attestations_sha256 must be rejected before URL construction"
            )
        ),
    )
    with pytest.raises(TransportError) as raised:
        SidecarTransport(
            fetcher=lambda *_args: pytest.fail(
                "invalid attestations_sha256 must be rejected before fetch"
            )
        ).load_repodata(
            "https://example.org/pkg-1-0.conda",
            advertised_sha256,
        )
    assert raised.value.code == "invalid-attestations-sha256"


def test_repodata_rejects_digest_mismatch() -> None:
    body = sidecar_bytes()
    with pytest.raises(TransportError) as raised:
        SidecarTransport(fetcher=lambda _url, _limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            "ab" * 32,
        )
    assert raised.value.code == "digest-mismatch"


def test_repodata_fetches_when_cache_read_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    body = sidecar_bytes()
    digest = hashlib.sha256(body).hexdigest()
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
        digest,
    )

    assert fetched == [f"https://example.org/pkg-1-0.conda.sigs.{digest}"]
    assert sidecar.sha256 == digest


def test_repodata_ignores_cache_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    body = sidecar_bytes()
    digest = hashlib.sha256(body).hexdigest()
    cache = DigestCache(tmp_path / "cache")

    def fail_cache_write(*_args, **_kwargs):
        raise OSError("unwritable cache")

    monkeypatch.setattr(cache, "store_sidecar", fail_cache_write)

    transport = SidecarTransport(
        fetcher=lambda _url, _limit: body,
        cache=cache,
    )
    sidecar = transport.load_repodata(
        "https://example.org/pkg-1-0.conda",
        digest,
    )
    transport.store_repodata(sidecar)

    assert sidecar.sha256 == digest


def test_repodata_does_not_cache_before_bundle_verification(tmp_path) -> None:
    body = sidecar_bytes()
    digest = hashlib.sha256(body).hexdigest()
    cache = DigestCache(tmp_path / "cache")

    SidecarTransport(
        cache=cache,
        fetcher=lambda _url, _limit: body,
    ).load_repodata(
        "https://example.org/pkg-1-0.conda",
        digest,
    )

    assert cache.load_sidecar(digest) is None


def test_repodata_uses_cached_sidecar_without_fetching(tmp_path) -> None:
    body = sidecar_bytes()
    digest = hashlib.sha256(body).hexdigest()
    cache = DigestCache(tmp_path / "cache")
    cache.store_sidecar(body)

    sidecar = SidecarTransport(
        cache=cache,
        fetcher=lambda *_args: pytest.fail("cached sidecar must be reused"),
    ).load_repodata(
        "https://example.org/pkg-1-0.conda",
        digest,
    )

    assert sidecar.sha256 == digest


def test_prefix_sidecar_is_explicit_and_unpinned() -> None:
    body = sidecar_bytes()
    sidecar = SidecarTransport(fetcher=lambda url, limit: body).load_prefix(
        "https://prefix.dev/channel/linux-64/pkg-1-0.conda"
    )
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
    with pytest.raises(TransportError, match="nonempty JSON array"):
        SidecarTransport(fetcher=lambda url, limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            hashlib.sha256(body).hexdigest(),
        )


def test_sidecar_rejects_nonobject_bundle_elements() -> None:
    bundles = [
        None,
        {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
    ]
    body = json.dumps(bundles).encode()

    with pytest.raises(TransportError, match="bundle objects"):
        SidecarTransport(fetcher=lambda url, limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            hashlib.sha256(body).hexdigest(),
        )


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (json.dumps([{}]).encode("utf-16"), "UTF-8"),
        (b'[{"extension": NaN}]', "invalid JSON constant"),
    ],
)
def test_sidecar_requires_strict_utf8_json(body: bytes, message: str) -> None:
    with pytest.raises(TransportError, match=message):
        SidecarTransport(fetcher=lambda url, limit: body).load_repodata(
            "https://example.org/pkg-1-0.conda",
            hashlib.sha256(body).hexdigest(),
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
    digest = hashlib.sha256(body).hexdigest()
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
        SidecarTransport().load_repodata(artifact_url, digest)

    message = str(raised.value)
    assert raised.value.__cause__ is None
    assert message == (
        "could not retrieve https://[2001:db8::1]:8443/"
        f"pkg-1-0.conda.sigs.{digest} (OSError)"
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
