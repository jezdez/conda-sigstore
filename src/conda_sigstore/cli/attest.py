"""Implementation of ``conda sigstore attest``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

from ..attestation import create_attestation
from ..exceptions import BundleVerificationError, CondaSigstoreError
from ..settings import SigstoreSettings

if TYPE_CHECKING:
    from argparse import Namespace


def execute_attest(args: Namespace, *, console: Console | None = None) -> int:
    """Create one locally verified CEP 27 bundle."""
    try:
        settings = SigstoreSettings.current()
        output = create_attestation(
            args.package,
            target_channel=args.target_channel,
            output=args.output,
            trust_config_path=settings.trust_config,
        )
    except (BundleVerificationError, OSError, ValueError) as exc:
        raise CondaSigstoreError(str(exc)) from None
    if console is None:
        console = Console(highlight=False)
    console.print(Text(str(output), style="bold cyan"))
    return 0
