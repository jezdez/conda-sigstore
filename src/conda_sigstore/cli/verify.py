"""Implementation of ``conda sigstore verify``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from conda.base.context import context
from conda.models.channel import Channel
from rich.console import Console
from rich.text import Text

from ..evidence import SignerIdentity
from ..exceptions import CondaSigstoreError, TransportError
from ..settings import SigstoreSettings
from ..transport import SidecarTransport
from ..verification import SigstoreVerifier, verify_artifact
from .output import STATUS_STYLES, print_evidence

if TYPE_CHECKING:
    from argparse import Namespace


def execute_verify(args: Namespace, *, console: Console | None = None) -> int:
    """Verify package binding and report the authenticated signer."""
    artifact = Path(args.artifact).expanduser()
    if not artifact.is_file():
        raise CondaSigstoreError(f"package does not exist: {artifact}")
    if (args.cert_identity is None) != (args.cert_oidc_issuer is None):
        raise CondaSigstoreError(
            "--cert-identity and --cert-oidc-issuer must be used together"
        )
    try:
        settings = SigstoreSettings.current()
        channel = Channel(args.channel).base_url if args.channel else None
        expected_signer = (
            SignerIdentity(args.cert_identity, args.cert_oidc_issuer)
            if args.cert_identity is not None
            else None
        )
        result = verify_artifact(
            artifact,
            SidecarTransport(max_bytes=settings.max_sidecar_bytes).load_input(
                args.bundle
            ),
            verifier=SigstoreVerifier(
                offline=context.offline,
                trust_config=settings.trust_config,
            ),
            channel=channel,
            expected_signer=expected_signer,
        )
    except TransportError as exc:
        raise CondaSigstoreError(str(exc), code=exc.code) from None
    except (OSError, ValueError) as exc:
        raise CondaSigstoreError(str(exc)) from None
    if args.json or args.console == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        if console is None:
            console = Console(highlight=False)
        report = result.to_dict()
        heading = Text(result.artifact, style="bold")
        heading.append(": ")
        heading.append(
            result.status.value,
            style=STATUS_STYLES.get(result.status.value, "bold yellow"),
        )
        console.print(heading)
        if report["authorization"] != "not-evaluated":
            console.print(
                Text("  signer requirement:", style="dim"),
                Text(str(report["authorization"])),
            )
        print_evidence(console, report)
    return 0 if result.verified else 1
