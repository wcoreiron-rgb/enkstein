"""
enkstein-core — the embeddable Enkstein governance + scanning primitives.

These run **in-process with no server, no database, no Docker** — just
`pip install enkstein-core`. They are the dependency-light heart of
Enkstein's Zero Trust enforcement:

    from enkstein_core import classify_ring, evaluate_ring     # execution ring policy
    from enkstein_core import verify_package, compute_manifest_hash  # provenance
    from enkstein_core import scan_text, classify_prompt        # secret / PII scanner

Example — gate an action locally:

    from enkstein_core import classify_ring, evaluate_ring
    ring = classify_ring("quarantine_device")
    decision = evaluate_ring(ring, trust_score=72, caller_role="analyst")
    if not decision["allowed"]:
        raise PermissionError(decision["deny_reason"])

Example — scan a string for secrets before committing:

    from enkstein_core import scan_text
    result = scan_text(open("config.env").read())
    if result.is_sensitive:
        print("Blocked: secrets detected", result.findings)

The full platform (24+ claws, swarms, remediation, Trust Fabric audit) runs
as the server — see https://github.com/wcoreiron-rgb/enkstein. This package
is the subset that is genuinely standalone.
"""
__version__ = "0.8.1"

from .ring_policy import (  # noqa: F401
    classify_ring,
    evaluate_ring,
    ring_to_int,
    ACTION_RING_MAP,
    CHANNEL_RING_MAP,
    RING_REQUIREMENTS,
)
from .provenance import (  # noqa: F401
    compute_manifest_hash,
    verify_manifest_signature,
    verify_package,
    ProvenanceResult,
)
from .scanner import (  # noqa: F401
    scan_text,
    classify_prompt,
    ScanResult,
)

__all__ = [
    "classify_ring", "evaluate_ring", "ring_to_int",
    "ACTION_RING_MAP", "CHANNEL_RING_MAP", "RING_REQUIREMENTS",
    "compute_manifest_hash", "verify_manifest_signature", "verify_package",
    "ProvenanceResult",
    "scan_text", "classify_prompt", "ScanResult",
]
