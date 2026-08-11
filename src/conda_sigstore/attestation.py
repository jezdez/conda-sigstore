"""Create CEP 27 Sigstore attestations without owning upload behavior."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from .settings import MAX_TRUST_CONFIG_BYTES
from .statements import PublishStatement
from .transport import read_bounded_file


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sign_statement(
    statement: PublishStatement,
    *,
    trust_config_path: Path | None = None,
) -> str:
    """Sign a statement and locally verify the resulting Sigstore bundle."""
    from sigstore.dsse import Statement
    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken, Issuer, detect_credential
    from sigstore.sign import SigningContext
    from sigstore.verify import Verifier

    from .verification import SigstoreVerifier

    trust_config = (
        ClientTrustConfig.from_json(
            read_bounded_file(
                trust_config_path,
                MAX_TRUST_CONFIG_BYTES,
                description="trust configuration",
            ).decode("utf-8")
        )
        if trust_config_path is not None
        else ClientTrustConfig.production()
    )
    raw_token = detect_credential()
    token = (
        IdentityToken(raw_token)
        if raw_token
        else Issuer(trust_config.signing_config.get_oidc_url()).identity_token()
    )
    signing_context = SigningContext.from_trust_config(trust_config)
    dsse_statement = Statement(statement.payload())

    with signing_context.signer(token) as signer:
        bundle = signer.sign_dsse(dsse_statement)

    bundle_json = bundle.to_json()
    verifier = SigstoreVerifier(
        verifier=Verifier(trusted_root=trust_config.trusted_root)
    )
    verified = verifier.verify(bundle_json)
    if statement.target_channel is None:  # pragma: no cover - build contract
        raise ValueError("CEP 27 signing requires targetChannel")
    PublishStatement.from_payload(verified.payload).bind(
        expected_filename=statement.filename,
        expected_sha256=statement.sha256,
        accepted_target_channels=(statement.target_channel,),
        require_target_channel=True,
    )
    return bundle_json


def create_attestation(
    artifact: str | Path,
    *,
    target_channel: str,
    output: str | Path | None = None,
    trust_config_path: str | Path | None = None,
) -> Path:
    """Create one locally verified CEP 27 bundle for a conda package."""
    package = Path(artifact)
    if not package.is_file():
        raise ValueError(f"package does not exist: {package}")
    if not package.name.endswith((".conda", ".tar.bz2")):
        raise ValueError("package must end in .conda or .tar.bz2")
    destination = (
        Path(output).expanduser() if output else Path(f"{package}.sigstore.json")
    )
    if destination.resolve() == package.resolve():
        raise ValueError("attestation output must not replace the package")
    if destination.exists():
        raise FileExistsError(f"attestation output already exists: {destination}")

    digest = sha256_file(package)
    statement = PublishStatement(
        package.name,
        digest,
        target_channel=target_channel,
    )
    bundle = sign_statement(
        statement,
        trust_config_path=Path(trust_config_path).expanduser()
        if trust_config_path
        else None,
    )
    if sha256_file(package) != digest:
        raise ValueError("package changed while its attestation was being created")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(bundle)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary_path, destination)
        except FileExistsError:
            raise FileExistsError(
                f"attestation output already exists: {destination}"
            ) from None
    finally:
        temporary_path.unlink(missing_ok=True)
    return destination
