"""Per-Security-Arm control applicability.

A catalog is not a profile. NIST SP 800-53 publishes ~1,100 controls covering
everything from cryptographic modules to physical facility access; presenting
all of them under every Capability Node would tell an operator that Identity
Security has a thousand controls, which is false and makes coverage
meaningless.

OSCAL calls the selected subset a *profile*. This module is Enkstein's
profile layer: it decides which control families a given Arm is actually
accountable for, so each node reports its own honest denominator.

Applicability is derived from the control family, not hand-maintained per
control, because a family is a stable published grouping while individual
control ids churn between revisions.
"""
from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.zero_trust import ZTPillar
from app.models.control import Control

# NIST SP 800-53 Rev 5 families, with the CISA pillar each predominantly
# supports. A family maps to one pillar for scoring; controls that genuinely
# span pillars are still visible through every Arm that claims the family.
NIST_FAMILY_PILLAR: dict[str, str] = {
    "ac": ZTPillar.IDENTITY,       # Access Control
    "ia": ZTPillar.IDENTITY,       # Identification and Authentication
    "ps": ZTPillar.IDENTITY,       # Personnel Security
    "at": ZTPillar.GOVERNANCE,     # Awareness and Training
    "au": ZTPillar.VISIBILITY,     # Audit and Accountability
    "ca": ZTPillar.GOVERNANCE,     # Assessment, Authorization, Monitoring
    "cm": ZTPillar.APPLICATIONS,   # Configuration Management
    "cp": ZTPillar.AUTOMATION,     # Contingency Planning
    "ir": ZTPillar.AUTOMATION,     # Incident Response
    "ma": ZTPillar.DEVICES,        # Maintenance
    "mp": ZTPillar.DATA,           # Media Protection
    "pe": ZTPillar.DEVICES,        # Physical and Environmental Protection
    "pl": ZTPillar.GOVERNANCE,     # Planning
    "pm": ZTPillar.GOVERNANCE,     # Program Management
    "pt": ZTPillar.DATA,           # PII Processing and Transparency
    "ra": ZTPillar.VISIBILITY,     # Risk Assessment
    "sa": ZTPillar.APPLICATIONS,   # System and Services Acquisition
    "sc": ZTPillar.NETWORKS,       # System and Communications Protection
    "si": ZTPillar.VISIBILITY,     # System and Information Integrity
    "sr": ZTPillar.GOVERNANCE,     # Supply Chain Risk Management
}

# Which NIST families each Security Arm is accountable for. Kept deliberately
# tight: an Arm claims a family only when it can plausibly produce evidence
# for it, so an empty evaluator shows up as a coverage gap rather than being
# hidden inside an inflated denominator.
ARM_NIST_FAMILIES: dict[str, tuple[str, ...]] = {
    "identityclaw": ("ac", "ia"),
    "accessclaw": ("ac", "ia"),
    "userclaw": ("ac", "au", "ps"),
    "insiderclaw": ("au", "ps", "si"),
    "endpointclaw": ("cm", "ma", "si"),
    "netclaw": ("sc", "ac"),
    "exposureclaw": ("ra", "sc"),
    "cloudclaw": ("ac", "cm", "sc", "si"),
    "appclaw": ("sa", "si", "ac"),
    "devclaw": ("sa", "cm", "ia"),
    "terraclaw": ("cm", "sc", "sa"),
    "configclaw": ("cm",),
    "releaseclaw": ("sa", "cm"),
    "arcclaw": ("si", "ac", "sa"),
    "customclaw": ("ca",),
    "modelclaw": ("ac", "sa", "si"),
    "dataclaw": ("mp", "ac", "sc"),
    "privacyclaw": ("pt", "mp"),
    "saasclaw": ("ac", "au"),
    "logclaw": ("au", "si"),
    "threatclaw": ("si", "ra"),
    "intelclaw": ("ra", "si"),
    "attackpathclaw": ("ra", "ac", "sc"),
    "automationclaw": ("cm", "ir"),
    "recoveryclaw": ("cp", "ir"),
    "complianceclaw": ("ca", "pl", "pm"),
    "vendorclaw": ("sr", "sa"),
}

PROFILE_VERSION = "enkstein-profile-2026.07"


def family_of(control_id: str) -> str:
    """NIST family prefix for a control id such as ``ac-2.1``."""
    return str(control_id or "").split("-", 1)[0].strip().lower()


def pillar_for_nist(control_id: str) -> str:
    """CISA pillar for a NIST control, defaulting to Governance."""
    return NIST_FAMILY_PILLAR.get(family_of(control_id), ZTPillar.GOVERNANCE)


def families_for(claw: str) -> tuple[str, ...]:
    return ARM_NIST_FAMILIES.get(claw, ())


def applies_to(claw: str, control: Control) -> bool:
    """Whether a catalog control belongs in one Arm's profile."""
    if control.claw and control.claw == claw:
        return True
    if control.source == "nist_800_53":
        return family_of(control.control_id) in families_for(claw)
    return False


async def repillar_nist_controls(db: AsyncSession) -> dict[str, int]:
    """Re-tag imported NIST controls from their family, replacing the
    placeholder Governance pillar every OSCAL row was created with."""
    result = await db.execute(select(Control).where(Control.source == "nist_800_53"))
    changed = 0
    rows = result.scalars().all()
    for row in rows:
        pillar = pillar_for_nist(row.control_id)
        if row.zt_pillar != pillar:
            row.zt_pillar = pillar
            changed += 1
    await db.commit()
    return {"examined": len(rows), "repillared": changed}


async def profile_for(db: AsyncSession, claw: str) -> dict[str, Any]:
    """The tailored control set one Security Arm is accountable for."""
    families = families_for(claw)
    result = await db.execute(select(Control))
    selected = [row for row in result.scalars().all() if applies_to(claw, row)]
    automated = [row for row in selected if row.automated and not row.recommendation_only]
    evaluable = [row for row in selected if row.evaluator_key]
    return {
        "claw": claw,
        "profile_version": PROFILE_VERSION,
        "nist_families": list(families),
        "total": len(selected),
        "owned": sum(1 for row in selected if row.claw == claw),
        "inherited_nist": sum(1 for row in selected if row.claw != claw),
        "with_evaluator": len(evaluable),
        "automated_enforcing": len(automated),
        "recommendation_only": sum(1 for row in selected if row.recommendation_only),
        "coverage_percent": round(100 * len(evaluable) / len(selected), 1) if selected else 0.0,
        "by_pillar": _counts(selected, "zt_pillar"),
        "by_severity": _counts(selected, "severity"),
        "by_source": _counts(selected, "source"),
    }


def _counts(rows: Iterable[Control], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(getattr(row, field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


async def coverage_matrix(db: AsyncSession) -> dict[str, Any]:
    """Per-Arm coverage across every Capability Node in one pass."""
    from app.services.control_collectors import collector_ready, configured_connectors

    active = await configured_connectors(db)
    result = await db.execute(select(Control))
    rows = result.scalars().all()
    arms = []
    for claw in sorted(ARM_NIST_FAMILIES):
        selected = [row for row in rows if applies_to(claw, row)]
        evaluable = [row for row in selected if row.evaluator_key]
        # An evaluator with no configured connector cannot produce evidence,
        # so it counts toward assessable coverage but not toward ready.
        ready = [row for row in evaluable if collector_ready(row.evaluator_key, active)]
        arms.append({
            "claw": claw,
            "nist_families": list(families_for(claw)),
            "total": len(selected),
            "with_evaluator": len(evaluable),
            "collector_ready": len(ready),
            "recommendation_only": sum(1 for row in selected if row.recommendation_only),
            "coverage_percent": round(100 * len(evaluable) / len(selected), 1) if selected else 0.0,
            "ready_percent": round(100 * len(ready) / len(selected), 1) if selected else 0.0,
        })
    return {
        "profile_version": PROFILE_VERSION,
        "catalog_total": len(rows),
        "configured_connectors": sorted(active),
        "arms": arms,
    }
