from __future__ import annotations

from argparse import ArgumentParser
from io import StringIO

import pytest
from rich.console import Console

from conda_sigstore.cli import configure_parser


@pytest.fixture
def sigstore_parser() -> ArgumentParser:
    parser = ArgumentParser()
    configure_parser(parser)
    return parser


@pytest.fixture
def rich_console() -> Console:
    return Console(
        file=StringIO(),
        width=200,
        highlight=False,
        force_terminal=False,
    )
