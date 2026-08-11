"""Exceptions raised by conda-sigstore."""

from __future__ import annotations


class StatementError(ValueError):
    """An in-toto statement is malformed."""


class PublishStatementError(StatementError):
    """A publish statement is malformed or does not bind the expected package."""


class ProvenanceError(StatementError):
    """Provenance evidence is malformed."""


class TransportError(RuntimeError):
    """Retrieval, integrity, or sidecar-container verification failed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class BundleVerificationError(RuntimeError):
    """A Sigstore bundle is malformed or cryptographically invalid."""


class TrustMaterialUnavailableError(BundleVerificationError):
    """Configured Sigstore trust material could not be loaded."""


__all__ = [
    "BundleVerificationError",
    "ProvenanceError",
    "PublishStatementError",
    "StatementError",
    "TransportError",
    "TrustMaterialUnavailableError",
]
