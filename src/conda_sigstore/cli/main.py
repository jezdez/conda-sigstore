"""Argument parsing and dispatch for ``conda sigstore``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace


def configure_parser(parser: ArgumentParser) -> None:
    """Configure the ``conda sigstore`` parser."""
    from conda.cli.helpers import add_parser_json, add_parser_prefix

    commands = parser.add_subparsers(dest="sigstore_command", required=True)

    attest = commands.add_parser("attest", help="Create a CEP 27 Sigstore bundle.")
    package = attest.add_argument("package")
    setattr(package, "completion_type", "file")
    target_channel = attest.add_argument("--target-channel", required=True)
    setattr(target_channel, "completion_type", "channel")
    output = attest.add_argument("--output")
    setattr(output, "completion_type", "file")

    verify = commands.add_parser("verify", help="Verify a package and bundle.")
    artifact = verify.add_argument("artifact")
    setattr(artifact, "completion_type", "file")
    bundle = verify.add_argument("--bundle", required=True)
    setattr(bundle, "completion_type", "file")
    verify.add_argument("--channel")
    verify.add_argument(
        "--cert-identity",
        metavar="IDENTITY",
        help="Require the exact certificate Subject Alternative Name.",
    )
    verify.add_argument(
        "--cert-oidc-issuer",
        metavar="URL",
        help="Require the exact certificate OIDC issuer.",
    )
    add_parser_json(verify)

    audit = commands.add_parser("audit", help="Audit an installed environment.")
    add_parser_prefix(audit)
    audit.add_argument("--sources", action="store_true")
    audit.add_argument(
        "--prefix-sidecars",
        action="store_true",
        help="Use Prefix.dev's current unpinned .v0.sigs sidecars.",
    )
    add_parser_json(audit)


def execute(args: Namespace) -> int:
    """Dispatch the selected ``conda sigstore`` command."""
    if args.sigstore_command == "attest":
        from .attest import execute_attest

        return execute_attest(args)
    if args.sigstore_command == "verify":
        from .verify import execute_verify

        return execute_verify(args)
    if args.sigstore_command == "audit":
        from .audit import execute_audit

        return execute_audit(args)
    raise AssertionError(f"unknown command: {args.sigstore_command}")
