"""CLI package for ``conda sigstore``."""

from __future__ import annotations

from .main import configure_parser, execute

__all__ = [
    "configure_parser",
    "execute",
]
