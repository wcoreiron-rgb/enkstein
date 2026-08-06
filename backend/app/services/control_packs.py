"""Versioned, source-traceable baseline controls for every Capability Node.

These are not copied framework prose. They are concise Enkstein control
objectives with references to public authoritative families. Controls without
a deterministic evidence collector are deliberately marked recommendation-only
until a node adapter is implemented.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.zero_trust import default_pillar
from app.models.control import Control, ControlSource, ControlStatus

CONTROL_PACK_VERSION = "enkstein-baseline-2026.07"

_PACKS: dict[str, list[dict[str, Any]]] = {
    "identityclaw": [
        ("identity-lifecycle", "Disable identities promptly after termination", "AC-2", "revoke_sessions"),
        ("identity-authentication", "Require strong authentication for sensitive access", "IA-2", "force_mfa_reset"),
    ],
    "accessclaw": [
        ("privilege-least", "Review and constrain privileged permissions", "AC-6", "recommendation_only"),
        ("privilege-jit", "Use time-bound privileged assignment", "AC-6(5)", "recommendation_only"),
    ],
    "userclaw": [("user-risk", "Review anomalous user behavior before access expansion", "AU-12", "recommendation_only")],
    "insiderclaw": [("insider-separation", "Monitor high-risk insider activity with separation of duties", "AU-6", "recommendation_only")],
    "endpointclaw": [
        ("device-inventory", "Maintain an authoritative device inventory", "CM-8", "recommendation_only"),
        ("device-posture", "Deny or isolate devices that fail required posture", "CM-6", "quarantine_device"),
    ],
    "netclaw": [
        ("network-segmentation", "Enforce deny-by-default network boundaries", "SC-7", "recommendation_only"),
        ("network-encryption", "Protect traffic in transit with approved cryptography", "SC-8", "recommendation_only"),
    ],
    "exposureclaw": [("external-exposure", "Continuously identify and reduce internet exposure", "RA-5", "recommendation_only")],
    "cloudclaw": [
        ("cloud-identity", "Enforce least privilege for cloud identities", "AC-6", "recommendation_only"),
        ("cloud-encryption", "Encrypt sensitive cloud data at rest and in transit", "SC-8", "recommendation_only"),
        ("cloud-logging", "Collect security-relevant cloud audit events", "AU-12", "recommendation_only"),
    ],
    "appclaw": [
        ("app-authz", "Enforce server-side authorization on protected resources", "AC-3", "recommendation_only"),
        ("app-validation", "Validate and safely handle untrusted input", "SI-10", "recommendation_only"),
    ],
    "devclaw": [
        ("dev-review", "Require review and automated checks before protected branches merge", "SA-11", "recommendation_only"),
        ("dev-secrets", "Prevent secrets from entering source control or build artifacts", "IA-5", "recommendation_only"),
    ],
    "terraclaw": [
        ("iac-network", "Reject public administrative ingress in infrastructure code", "SC-7", "recommendation_only"),
        ("iac-data", "Require encryption and private access for managed data services", "SC-28", "recommendation_only"),
    ],
    "configclaw": [("configuration-baseline", "Detect and enforce approved secure configuration baselines", "CM-2", "recommendation_only")],
    "releaseclaw": [("release-integrity", "Verify artifact provenance before deployment", "SA-10", "recommendation_only")],
    "arcclaw": [
        ("ai-input", "Inspect AI inputs for injection and sensitive data", "SI-10", "recommendation_only"),
        ("ai-output", "Inspect AI outputs before downstream execution or disclosure", "SI-10", "recommendation_only"),
    ],
    "customclaw": [("custom-evidence", "Require evidence and an evaluator for custom capabilities", "CA-2", "recommendation_only")],
    "modelclaw": [("model-governance", "Apply policy, provenance, and data classification to model calls", "AC-4", "recommendation_only")],
    "dataclaw": [
        ("data-classification", "Classify sensitive data and enforce handling rules", "MP-3", "recommendation_only"),
        ("data-access", "Review access to sensitive data by identity and purpose", "AC-6", "recommendation_only"),
    ],
    "privacyclaw": [("privacy-minimization", "Collect and retain only data required for the declared purpose", "PM-25", "recommendation_only")],
    "saasclaw": [("saas-audit", "Monitor SaaS administrative actions and exports", "AU-12", "recommendation_only")],
    "logclaw": [("telemetry-integrity", "Protect and retain audit records sufficient for investigation", "AU-9", "recommendation_only")],
    "threatclaw": [("threat-detection", "Correlate threat indicators with observable enterprise evidence", "SI-4", "recommendation_only")],
    "intelclaw": [("intel-provenance", "Record source, confidence, and freshness for intelligence", "RA-10", "recommendation_only")],
    "attackpathclaw": [("attack-path", "Identify exploitable chains across identity, network, and resources", "RA-3", "recommendation_only")],
    "automationclaw": [("automation-governance", "Constrain automated actions by policy, scope, and approval", "CM-3", "recommendation_only")],
    "recoveryclaw": [("recovery-test", "Test recovery objectives and preserve evidence of results", "CP-4", "recommendation_only")],
    "complianceclaw": [("control-evidence", "Maintain traceable evidence for each selected control", "CA-2", "recommendation_only")],
    "vendorclaw": [("vendor-assurance", "Assess provider security posture and contractual obligations", "SR-6", "recommendation_only")],
}


def baseline_controls() -> list[dict[str, Any]]:
    result = []
    for claw, entries in _PACKS.items():
        for slug, title, nist_id, action in entries:
            result.append({
                "control_id": f"enkstein:{claw}:{slug}",
                "source": ControlSource.AUTHORED.value,
                "source_version": CONTROL_PACK_VERSION,
                "title": title,
                "description": f"Enkstein baseline objective for {claw}.",
                "zt_pillar": default_pillar(claw),
                "zt_tenets": ["T4", "T5", "T6"],
                "claw": claw,
                "frameworks": {"nist_800_53": [nist_id]},
                "severity": "medium",
                "remediation_action": None if action == "recommendation_only" else action,
                "remediation_mode": action,
                "recommendation_only": action == "recommendation_only",
                "evidence_method": "Node-specific evidence collector required; baseline is recommendation-only until implemented.",
                "evaluator_key": None,
                "status": ControlStatus.PENDING_REVIEW.value,
                "automated": False,
            })
    # TerraClaw and ArcClaw already have deterministic evaluators. Promote
    # every rule/pattern into the shared catalog rather than leaving those
    # checks stranded in their module-local result shapes.
    try:
        from app.claws.terraclaw.routes import _RULES
        for rule in _RULES:
            result.append({
                "control_id": f"terraclaw:{rule['id']}",
                "source": ControlSource.AUTHORED.value,
                "source_version": CONTROL_PACK_VERSION,
                "title": rule["name"],
                "description": f"Deterministic TerraClaw IaC rule {rule['id']}.",
                "zt_pillar": "applications",
                "zt_tenets": ["T2", "T4", "T5"],
                "claw": "terraclaw",
                "frameworks": {"references": rule.get("frameworks", [])},
                "severity": str(rule.get("severity", "medium")).lower(),
                "remediation": rule.get("remediation"),
                "remediation_mode": "recommendation_only",
                "recommendation_only": True,
                "evidence_method": "TerraClaw HCL rule evaluator.",
                "evaluator_key": "terraclaw.rule",
                "status": ControlStatus.ACTIVE.value,
                "automated": True,
            })
    except Exception:
        pass
    try:
        from app.claws.arcclaw.scanner import PATTERNS
        for name, _pattern, signal in PATTERNS:
            slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
            result.append({
                "control_id": f"arcclaw:pattern:{slug}",
                "source": ControlSource.AUTHORED.value,
                "source_version": CONTROL_PACK_VERSION,
                "title": f"AI Security detects {name}",
                "description": f"ArcClaw deterministic sensitive-data or execution pattern ({signal}).",
                "zt_pillar": "applications",
                "zt_tenets": ["T1", "T4", "T6"],
                "claw": "arcclaw",
                "frameworks": {"owasp": ["LLM02", "LLM06", "LLM07"]},
                "severity": "high" if "credential" in signal else "medium",
                "remediation_mode": "recommendation_only",
                "recommendation_only": True,
                "evidence_method": "ArcClaw input/output pattern scanner.",
                "evaluator_key": "arcclaw.pattern",
                "status": ControlStatus.ACTIVE.value,
                "automated": True,
            })
    except Exception:
        pass
    return result


async def bootstrap_baseline_controls(db: AsyncSession) -> dict[str, int]:
    added = 0
    for payload in baseline_controls():
        exists = await db.execute(
            select(Control).where(
                Control.control_id == payload["control_id"],
                Control.source == payload["source"],
            )
        )
        if exists.scalar_one_or_none():
            continue
        db.add(Control(**payload))
        added += 1
    await db.commit()
    # Installing the pack without binding its collectors leaves every control
    # permanently NOT_ASSESSED and every connector feeding it reporting an
    # empty control scope, so the binding runs as part of bootstrap. It is
    # idempotent, so an existing deployment is unaffected.
    from app.services.control_collectors import attach_evaluators

    bound = await attach_evaluators(db)
    return {
        "added": added,
        "total": len(baseline_controls()),
        "evaluators_attached": bound["evaluators_attached"],
        "remediation_linked": bound["remediation_linked"],
    }
