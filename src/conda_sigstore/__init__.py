"""Sigstore signing and verification for conda packages."""

from __future__ import annotations

try:
    from ._version import __version__
except ImportError:  # pragma: no cover
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
