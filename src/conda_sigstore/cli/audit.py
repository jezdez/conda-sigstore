"""Implementation of ``conda sigstore audit``."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..audit import EnvironmentAuditor, resolve_prefix
from .output import STATUS_STYLES, print_evidence, print_source_evidence

if TYPE_CHECKING:
    from argparse import Namespace


def execute_audit(args: Namespace, *, console: Console | None = None) -> int:
    """Audit installed package and optional source evidence."""
    report = EnvironmentAuditor.current(
        transport="prefix" if args.prefix_sidecars else "repodata"
    ).audit_environment(
        resolve_prefix(name=args.name, prefix=args.prefix),
        include_sources=args.sources,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if console is None:
            console = Console(highlight=False)
        packages = report.get("packages")
        if not isinstance(packages, list):  # pragma: no cover - internal invariant
            raise TypeError("audit report packages must be a list")
        table = Table(show_edge=False, pad_edge=False)
        table.add_column("Artifact")
        table.add_column("Status")
        for package in packages:
            if not isinstance(package, Mapping):  # pragma: no cover
                raise TypeError("audit report package must be an object")
            status = str(package["status"])
            table.add_row(
                Text(str(package["artifact"])),
                Text(status, style=STATUS_STYLES.get(status, "bold yellow")),
            )
        console.print(table)
        for package in packages:
            if not any(
                package.get(key) for key in ("evidence", "failures", "source_evidence")
            ):
                continue
            console.print()
            console.print(Text(str(package["artifact"]), style="bold"))
            print_evidence(console, package)
            print_source_evidence(console, package)
    return 0
