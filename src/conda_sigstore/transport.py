"""Bounded loading of Sigstore bundle sidecars."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from .exceptions import TransportError
from .model import Sidecar
from .settings import DEFAULT_MAX_SIDECAR_BYTES

if TYPE_CHECKING:
    from typing import NoReturn

    from .cache import DigestCache
    from .model import AttestationDescriptor


Fetch = Callable[[str, int], bytes]


def read_bounded_file(
    path: Path,
    max_bytes: int,
    *,
    description: str = "file",
) -> bytes:
    """Read a regular file without exceeding the configured byte limit."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{description} exceeds {max_bytes} bytes")
    with path.open("rb") as stream:
        body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"{description} exceeds {max_bytes} bytes")
    return body


@dataclass(frozen=True, slots=True)
class SidecarTransport:
    """Load local, repodata-advertised, or Prefix.dev bundle evidence."""

    max_bytes: int = DEFAULT_MAX_SIDECAR_BYTES
    fetcher: Fetch | None = None
    cache: DigestCache | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or self.max_bytes < 1
        ):
            raise ValueError("max_bytes must be a positive integer")

    @staticmethod
    def display_url(url: str) -> str:
        """Keep only a remote host and filename in diagnostics."""
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            host = f"{host}:{port}"
        filename = parsed.path.rsplit("/", 1)[-1]
        return urlunsplit((parsed.scheme.lower(), host, f"/{filename}", "", ""))

    @classmethod
    def sidecar_urls(cls, artifact_url: str, suffix: str) -> tuple[str, str]:
        """Return request and credential-free URLs for one package sidecar."""
        try:
            parsed = urlsplit(artifact_url)
            hostname = parsed.hostname
            parsed.port
        except ValueError as exc:
            raise TransportError("invalid-url", "package URL is invalid") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            raise TransportError("invalid-url", "package URL must be HTTP or HTTPS")
        if parsed.fragment:
            raise TransportError(
                "invalid-url",
                "package URL cannot contain a fragment",
            )
        request_url = parsed._replace(
            scheme=parsed.scheme.lower(),
            path=f"{parsed.path}{suffix}",
            fragment="",
        ).geturl()
        return request_url, cls.display_url(request_url)

    def fetch(self, url: str) -> bytes:
        """Fetch bounded evidence through an injected or conda HTTP session."""
        safe_url = self.display_url(url)
        if self.fetcher is not None:
            body = self.fetcher(url, self.max_bytes)
        else:
            try:
                from conda.base.context import context
                from conda.gateways.connection.session import get_session

                if context.offline:
                    raise TransportError(
                        "offline-cache-miss",
                        "offline mode has no cached attestation sidecar",
                    )
                timeout = (
                    context.remote_connect_timeout_secs,
                    context.remote_read_timeout_secs,
                )
                with get_session(url).get(
                    url,
                    stream=True,
                    timeout=timeout,
                ) as http_response:
                    if http_response.status_code == 404:
                        raise TransportError(
                            "missing-sidecar",
                            f"attestation sidecar does not exist: {safe_url}",
                        )
                    http_response.raise_for_status()
                    length = http_response.headers.get("Content-Length")
                    if length is not None and int(length) > self.max_bytes:
                        raise TransportError(
                            "sidecar-too-large",
                            f"attestation sidecar exceeds {self.max_bytes} bytes",
                        )
                    content = bytearray()
                    for block in http_response.iter_content(chunk_size=64 * 1024):
                        content.extend(block)
                        if len(content) > self.max_bytes:
                            raise TransportError(
                                "sidecar-too-large",
                                f"attestation sidecar exceeds {self.max_bytes} bytes",
                            )
                    body = bytes(content)
            except TransportError:
                raise
            except Exception as exc:
                raise TransportError(
                    "retrieval-failed",
                    f"could not retrieve {safe_url} ({type(exc).__name__})",
                ) from None

        if not isinstance(body, bytes):
            raise TransportError(
                "invalid-response",
                "sidecar fetch must return bytes",
            )
        if len(body) > self.max_bytes:
            raise TransportError(
                "sidecar-too-large",
                f"sidecar is {len(body)} bytes and exceeds the "
                f"{self.max_bytes}-byte limit",
            )
        return body

    @staticmethod
    def parse(
        body: bytes,
        *,
        label: str,
        allow_single: bool = False,
        prefix_sidecar: bool = False,
    ) -> Sidecar:
        """Parse a nonempty bundle array or an explicitly allowed single bundle."""

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise TransportError(
                        "invalid-sidecar",
                        f"duplicate JSON key: {key}",
                    )
                result[key] = value
            return result

        def reject_constant(value: str) -> NoReturn:
            raise TransportError(
                "invalid-sidecar",
                f"invalid JSON constant: {value}",
            )

        try:
            value = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except UnicodeDecodeError as exc:
            raise TransportError(
                "invalid-sidecar",
                "sidecar must be UTF-8 JSON",
            ) from exc
        except json.JSONDecodeError as exc:
            raise TransportError("invalid-sidecar", "sidecar must be JSON") from exc
        if allow_single and isinstance(value, dict):
            value = [value]
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(bundle, dict) for bundle in value)
        ):
            expected = (
                "bundle object or nonempty bundle array"
                if allow_single
                else "nonempty JSON array of bundle objects"
            )
            raise TransportError(
                "invalid-sidecar",
                f"sidecar must be a {expected}",
            )
        bundles = tuple(
            json.dumps(
                bundle,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            for bundle in value
        )
        return Sidecar(
            label,
            hashlib.sha256(body).hexdigest(),
            bundles,
            prefix_sidecar=prefix_sidecar,
        )

    def load_input(self, source: str) -> Sidecar:
        """Load one raw bundle or bundle array from a local path or URL."""
        try:
            parsed = urlsplit(source)
        except ValueError as exc:
            raise TransportError("invalid-url", "bundle URL is invalid") from exc
        if parsed.scheme in {"http", "https"}:
            label = self.display_url(source)
            body = self.fetch(source)
        else:
            path = Path(source).expanduser()
            label = path.name
            try:
                body = read_bounded_file(path, self.max_bytes, description="bundle")
            except ValueError as exc:
                raise TransportError("sidecar-too-large", str(exc)) from exc
            except OSError as exc:
                raise TransportError(
                    "retrieval-failed",
                    f"could not read bundle {label} ({type(exc).__name__})",
                ) from None
        return self.parse(
            body,
            label=label,
            allow_single=True,
            prefix_sidecar=label.endswith(".v0.sigs"),
        )

    def load_repodata(
        self,
        artifact_url: str,
        descriptor: AttestationDescriptor,
    ) -> Sidecar:
        """Load an integrity-bound ``.sigs`` file advertised by repodata."""
        if descriptor.size > self.max_bytes:
            raise TransportError(
                "sidecar-too-large",
                f"advertised sidecar is {descriptor.size} bytes and exceeds the limit",
            )

        request_url, display_url = self.sidecar_urls(artifact_url, ".sigs")
        try:
            body = (
                self.cache.load_sidecar(descriptor.sha256, max_bytes=self.max_bytes)
                if self.cache is not None
                else None
            )
        except OSError:
            body = None
        cache_miss = body is None
        if body is None:
            body = self.fetch(request_url)
        if len(body) != descriptor.size:
            raise TransportError(
                "size-mismatch",
                f"sidecar size {len(body)} does not match advertised "
                f"size {descriptor.size}",
            )
        digest = hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(digest, descriptor.sha256):
            raise TransportError(
                "digest-mismatch",
                "sidecar SHA-256 does not match the repodata descriptor",
            )
        if cache_miss and self.cache is not None:
            try:
                self.cache.store_sidecar(body, expected_sha256=descriptor.sha256)
            except OSError:
                pass
        return self.parse(body, label=display_url)

    def load_prefix(self, artifact_url: str) -> Sidecar:
        """Load Prefix.dev's current repodata-unpinned ``.v0.sigs`` file."""
        request_url, display_url = self.sidecar_urls(artifact_url, ".v0.sigs")
        return self.parse(
            self.fetch(request_url),
            label=display_url,
            prefix_sidecar=True,
        )
