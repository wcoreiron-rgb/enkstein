# NOTE: mirrored from backend/app/services/provenance.py — keep in sync via scripts/sync_core.sh.
# This module is intentionally dependency-light (stdlib + cryptography) so it
# can run embedded with no Enkstein server.
"""
Enkstein — Connector / Skill-Pack Provenance Service
Verifies manifest integrity at install time via SHA-256 content hash
and optional Ed25519 signature (when publisher key is available).
"""
import base64
import hashlib
import logging
import warnings
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("enkstein.provenance")


# ─── Core utilities ───────────────────────────────────────────────────────────

def compute_manifest_hash(manifest_json: str) -> str:
    """Return the SHA-256 hex digest of the UTF-8-encoded manifest JSON string."""
    return hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()


def verify_manifest_signature(
    manifest_json: str,
    signature_b64: str,
    public_key_pem: str,
) -> bool:
    """
    Verify an Ed25519 signature over the manifest JSON.

    Parameters
    ----------
    manifest_json   : Raw manifest JSON string (same bytes that were signed).
    signature_b64   : Base64-encoded Ed25519 signature produced by the publisher.
    public_key_pem  : PEM-encoded Ed25519 public key from the publisher.

    Returns True when the signature is valid, False otherwise.
    Raises ValueError if the key cannot be loaded or the signature cannot be decoded.
    """
    try:
        public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Cannot load publisher public key: {exc}") from exc

    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError(
            "Provided public key is not an Ed25519 key; "
            f"got {type(public_key).__name__}"
        )

    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception as exc:
        raise ValueError(f"Cannot base64-decode signature: {exc}") from exc

    try:
        public_key.verify(sig_bytes, manifest_json.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class ProvenanceResult:
    """Outcome of a provenance verification pass for a skill pack / connector."""

    valid: bool
    hash_verified: bool
    sig_verified: bool
    hash: str
    error: str | None = field(default=None)


# ─── High-level verify_package ────────────────────────────────────────────────

def verify_package(
    manifest_json: str,
    expected_hash: str | None,
    signature_b64: str | None,
    public_key_pem: str | None,
) -> ProvenanceResult:
    """
    Run provenance checks on a skill-pack or connector manifest.

    Rules
    -----
    - If neither *expected_hash* nor (*signature_b64* + *public_key_pem*) are
      provided the package is treated as an unsigned community package.  Install
      proceeds with a warning; ``valid=True, hash_verified=False, sig_verified=False``.
    - If *expected_hash* is provided the computed SHA-256 must match exactly.
    - If *signature_b64* and *public_key_pem* are both provided the Ed25519
      signature must verify against the manifest bytes.
    - Any failure sets ``valid=False`` and populates ``error``.
    """
    computed_hash = compute_manifest_hash(manifest_json)
    hash_verified = False
    sig_verified = False

    has_hash = expected_hash is not None and expected_hash.strip() != ""
    has_sig = (
        signature_b64 is not None
        and public_key_pem is not None
        and signature_b64.strip() != ""
        and public_key_pem.strip() != ""
    )

    # Unsigned community package — warn and allow
    if not has_hash and not has_sig:
        warnings.warn(
            "Installing unsigned skill pack with no content hash or publisher "
            "signature. Proceed with caution.",
            stacklevel=2,
        )
        logger.warning(
            "Unsigned skill pack install — no hash or signature provided. "
            "Manifest SHA-256: %s",
            computed_hash,
        )
        return ProvenanceResult(
            valid=True,
            hash_verified=False,
            sig_verified=False,
            hash=computed_hash,
        )

    errors: list[str] = []

    # Hash check
    if has_hash:
        if computed_hash == expected_hash.strip().lower():
            hash_verified = True
        else:
            errors.append(
                f"Content hash mismatch — expected {expected_hash!r}, "
                f"computed {computed_hash!r}"
            )

    # Signature check
    if has_sig:
        try:
            ok = verify_manifest_signature(manifest_json, signature_b64, public_key_pem)
            if ok:
                sig_verified = True
            else:
                errors.append("Ed25519 signature verification failed")
        except ValueError as exc:
            errors.append(f"Signature verification error: {exc}")

    if errors:
        error_msg = "; ".join(errors)
        logger.error("Provenance check FAILED: %s", error_msg)
        return ProvenanceResult(
            valid=False,
            hash_verified=hash_verified,
            sig_verified=sig_verified,
            hash=computed_hash,
            error=error_msg,
        )

    logger.info(
        "Provenance check passed — hash_verified=%s sig_verified=%s hash=%s",
        hash_verified,
        sig_verified,
        computed_hash,
    )
    return ProvenanceResult(
        valid=True,
        hash_verified=hash_verified,
        sig_verified=sig_verified,
        hash=computed_hash,
    )
