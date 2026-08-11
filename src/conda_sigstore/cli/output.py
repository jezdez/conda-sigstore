"""Human-readable output for ``conda sigstore`` commands."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from rich.console import Console

STATUS_STYLES = {
    "verified": "bold cyan",
    "invalid": "bold red",
    "untrusted-identity": "bold red",
    "missing": "bold yellow",
    "retrieval-failed": "bold yellow",
    "record-digest-only": "bold yellow",
    "evidence-unavailable": "bold yellow",
}


def print_evidence(console: Console, report: Mapping[str, object]) -> None:
    """Render package evidence and failures."""
    evidence = report.get("evidence", ())
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, Mapping):
                continue
            state = "verified" if item.get("verified") else "reported"
            bundle = Text(str(item.get("bundle_index")))
            bundle.append(
                f" ({state})",
                style="bold cyan" if state == "verified" else "bold yellow",
            )
            table = Table(show_header=False, show_edge=False, pad_edge=False)
            table.add_column("Key", style="dim")
            table.add_column("Value")
            table.add_row("Bundle", bundle)
            table.add_row("Predicate", Text(str(item.get("predicate_type"))))
            table.add_row("Identity", Text(str(item.get("identity"))))
            table.add_row("Issuer", Text(str(item.get("issuer"))))
            timestamps = item.get("timestamps", ())
            if isinstance(timestamps, list):
                for timestamp in timestamps:
                    table.add_row("Timestamp", Text(str(timestamp)))
            details = item.get("details")
            if isinstance(details, Mapping):
                if target_channel := details.get("target_channel"):
                    table.add_row("Target channel", Text(str(target_channel)))
                provenance = details.get("provenance")
                if isinstance(provenance, Mapping):
                    table.add_row("Builder", Text(str(provenance.get("builder"))))
                    table.add_row(
                        "Build type",
                        Text(str(provenance.get("build_type"))),
                    )
                    if invocation := provenance.get("invocation"):
                        table.add_row("Invocation", Text(str(invocation)))
                    materials = provenance.get("materials", ())
                    if isinstance(materials, list):
                        for material in materials:
                            if isinstance(material, Mapping):
                                table.add_row(
                                    "Material",
                                    Text(str(material.get("uri"))),
                                )
            console.print(table)

    failures = report.get("failures", ())
    if isinstance(failures, list) and failures:
        table = Table(show_edge=False, pad_edge=False)
        table.add_column("Failure", style="bold red")
        table.add_column("Message")
        for failure in failures:
            if isinstance(failure, Mapping):
                table.add_row(
                    Text(str(failure.get("code"))),
                    Text(str(failure.get("message"))),
                )
        console.print(table)


def print_source_evidence(console: Console, report: Mapping[str, object]) -> None:
    """Render embedded source-attestation audit evidence."""
    sources = report.get("source_evidence", ())
    if not isinstance(sources, list):
        return
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        status = str(source.get("status"))
        status_text = Text(status)
        status_text.stylize(STATUS_STYLES.get(status, "bold yellow"))
        table = Table(show_header=False, show_edge=False, pad_edge=False)
        table.add_column("Key", style="dim")
        table.add_column("Value")
        table.add_row(
            "Source",
            Text.assemble(
                str(source.get("source_index", "unavailable")),
                " ",
                status_text,
            ),
        )
        if failure := source.get("failure"):
            table.add_row("Failure", Text(str(failure), style="bold red"))
        publishers = source.get("required_publishers", ())
        if isinstance(publishers, list):
            for publisher in publishers:
                if isinstance(publisher, Mapping):
                    table.add_row(
                        "Required publisher",
                        Text(str(publisher.get("identity"))),
                    )
                    table.add_row("Issuer", Text(str(publisher.get("issuer"))))
        bundles = source.get("bundles", ())
        if isinstance(bundles, list):
            for bundle in bundles:
                if not isinstance(bundle, Mapping):
                    continue
                table.add_row(
                    "Bundle",
                    Text(f"{bundle.get('path')} ({bundle.get('status')})"),
                )
                if identity := bundle.get("identity"):
                    table.add_row("Identity", Text(str(identity)))
                if issuer := bundle.get("issuer"):
                    table.add_row("Issuer", Text(str(issuer)))
                if predicate := bundle.get("predicate_type"):
                    table.add_row("Predicate", Text(str(predicate)))
                timestamps = bundle.get("timestamps", ())
                if isinstance(timestamps, list):
                    for timestamp in timestamps:
                        table.add_row("Timestamp", Text(str(timestamp)))
                if failure := bundle.get("failure"):
                    table.add_row("Failure", Text(str(failure), style="bold red"))
        console.print(table)
