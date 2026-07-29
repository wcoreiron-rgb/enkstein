"""Import the Prowler check catalog as Enkstein controls.

Prowler ships a metadata file beside every check describing what the check
asserts, its severity, its service, and its remediation. That metadata is a
control *definition* and exists whether or not any cloud credential is
configured, which is what lets a node answer "42 controls, 3 failing" instead
of only ever listing failures.

Reading the installed package is deliberate. The alternative -- running
``prowler --list-checks-json`` per provider -- returns bare check ids with no
severity, description, or remediation, and costs a subprocess per provider.

Prowler is Apache-2.0 licensed. Only factual fields are imported: identifier,
title, service, severity, resource type, categories, remediation
recommendation, and reference URL.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.control import Control, ControlSource, ControlStatus, ControlSync
from app.services import prowler as prowler_runner

logger = logging.getLogger("controls.prowler")

# Providers Enkstein presents as Capability Node evidence sources.
CATALOG_PROVIDERS = ("aws", "azure", "gcp", "kubernetes", "github")

# Which Security Arm owns each provider's posture evidence, and which CISA
# pillar the resulting controls belong to. Cloud posture is an Applications &
# Workloads concern; GitHub posture is evaluated by the developer node.
PROVIDER_NODE: dict[str, tuple[str, str]] = {
    "aws": ("cloudclaw", "applications"),
    "azure": ("cloudclaw", "applications"),
    "gcp": ("cloudclaw", "applications"),
    "kubernetes": ("cloudclaw", "applications"),
    "github": ("devclaw", "applications"),
}

# A check's own category is a better pillar signal than its provider, because
# an IAM check is an Identity control no matter which cloud it ran against.
_CATEGORY_PILLAR: dict[str, str] = {
    "identity-and-access-management": "identity",
    "iam": "identity",
    "encryption": "data",
    "secrets": "data",
    "data-protection": "data",
    "logging": "visibility",
    "monitoring": "visibility",
    "threat-detection": "visibility",
    "forensics-ready": "visibility",
    "network": "networks",
    "internet-exposed": "networks",
    "trustboundaries": "networks",
    "gen-ai": "applications",
    "vulnerability-management": "applications",
}

# Service names that clearly indicate a pillar when categories are absent.
_SERVICE_PILLAR: dict[str, str] = {
    "iam": "identity",
    "entra": "identity",
    "accessanalyzer": "identity",
    "organizations": "identity",
    "kms": "data",
    "keyvault": "data",
    "secretsmanager": "data",
    "s3": "data",
    "storage": "data",
    "rds": "data",
    "efs": "data",
    "dynamodb": "data",
    "vpc": "networks",
    "network": "networks",
    "elbv2": "networks",
    "elb": "networks",
    "route53": "networks",
    "cloudtrail": "visibility",
    "cloudwatch": "visibility",
    "guardduty": "visibility",
    "securityhub": "visibility",
    "logs": "visibility",
    "monitor": "visibility",
    "defender": "visibility",
}

_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def _package_root(executable: str | None = None) -> Path | None:
    """Locate the installed prowler package directory, if any."""
    import shutil

    path = executable or prowler_runner.resolve_executable()
    if not path:
        return None
    # <venv>/bin/prowler -> <venv>/lib/python3.X/site-packages/prowler
    base = Path(path).resolve().parent.parent
    for lib in sorted(base.glob("lib/python3.*/site-packages/prowler")):
        if lib.is_dir():
            return lib
    # Fall back to importing it, for environments that install prowler inline.
    try:
        import prowler as _prowler  # type: ignore

        return Path(_prowler.__file__).parent
    except Exception:
        return None


def _pillar(metadata: dict[str, Any], provider: str) -> str:
    for category in metadata.get("Categories") or []:
        mapped = _CATEGORY_PILLAR.get(str(category).strip().lower())
        if mapped:
            return mapped
    service = str(metadata.get("ServiceName") or "").strip().lower()
    if service in _SERVICE_PILLAR:
        return _SERVICE_PILLAR[service]
    return PROVIDER_NODE.get(provider, ("cloudclaw", "applications"))[1]


def _severity(value: Any) -> str:
    severity = str(value or "medium").strip().lower()
    if severity == "informational":
        return "low"
    return severity if severity in _SEVERITIES else "medium"


def _remediation(metadata: dict[str, Any]) -> tuple[str | None, str | None]:
    block = metadata.get("Remediation") or {}
    recommendation = (block.get("Recommendation") or {}) if isinstance(block, dict) else {}
    text = str(recommendation.get("Text") or "").strip() or None
    url = str(recommendation.get("Url") or "").strip() or None
    if not url:
        url = str(metadata.get("RelatedUrl") or "").strip() or None
    return (text[:4000] if text else None), (url[:512] if url else None)


def load_check_metadata(provider: str, root: Path | None = None) -> list[dict[str, Any]]:
    """Read every check metadata file shipped for one provider."""
    package = root or _package_root()
    if package is None:
        return []
    services = package / "providers" / provider / "services"
    if not services.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(services.rglob("*.metadata.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or not payload.get("CheckID"):
            continue
        records.append(payload)
    return records


def to_controls(provider: str, records: Iterable[dict[str, Any]], version: str) -> list[dict[str, Any]]:
    """Convert Prowler check metadata into control catalog payloads."""
    node = PROVIDER_NODE.get(provider, ("cloudclaw", "applications"))[0]
    controls: list[dict[str, Any]] = []
    for metadata in records:
        check_id = str(metadata.get("CheckID") or "").strip()
        if not check_id:
            continue
        remediation, url = _remediation(metadata)
        frameworks: dict[str, list[str]] = {"prowler": [check_id]}
        categories = [str(item) for item in (metadata.get("Categories") or []) if str(item).strip()]
        if categories:
            frameworks["prowler_categories"] = categories
        controls.append({
            "control_id": f"prowler:{provider}:{check_id}",
            "source": ControlSource.PROWLER.value,
            "source_version": version,
            "title": str(metadata.get("CheckTitle") or check_id)[:512],
            "description": str(metadata.get("Description") or "")[:4000] or None,
            "zt_pillar": _pillar(metadata, provider),
            "zt_tenets": ["T1", "T5", "T7"],
            "claw": node,
            "provider": f"prowler_{provider}",
            "resource_type": str(metadata.get("ResourceType") or "")[:128] or None,
            "frameworks": frameworks,
            "severity": _severity(metadata.get("Severity")),
            "remediation": remediation,
            # Prowler reports posture; it does not change the tenant's cloud.
            "remediation_action": None,
            "remediation_mode": "recommendation_only",
            "recommendation_only": True,
            "evidence_method": f"Prowler {provider} check {check_id} executed read-only against tenant credentials.",
            "evaluator_key": f"prowler.{provider}",
            "status": ControlStatus.ACTIVE.value,
            "automated": True,
            "reference_url": url,
        })
    return controls


def catalog(providers: Iterable[str] = CATALOG_PROVIDERS) -> list[dict[str, Any]]:
    """Full Prowler control catalog for the requested providers."""
    root = _package_root()
    if root is None:
        return []
    version = str(prowler_runner.installation_status().get("version") or "unknown")
    result: list[dict[str, Any]] = []
    for provider in providers:
        if provider not in prowler_runner.SUPPORTED_PROVIDERS:
            continue
        result.extend(to_controls(provider, load_check_metadata(provider, root), version))
    return result


async def sync_prowler_catalog(
    db: AsyncSession,
    providers: Iterable[str] = CATALOG_PROVIDERS,
) -> dict[str, Any]:
    """Import or refresh Prowler check definitions in the control catalog."""
    status = prowler_runner.installation_status()
    if not status.get("installed"):
        return {
            "source": "prowler",
            "installed": False,
            "added": 0,
            "changed": 0,
            "unchanged": 0,
            "detail": "Prowler is not installed on this host; no controls were imported.",
        }
    payloads = catalog(providers)
    added = changed = unchanged = 0
    for payload in payloads:
        result = await db.execute(
            select(Control).where(
                Control.control_id == payload["control_id"],
                Control.source == ControlSource.PROWLER.value,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            db.add(Control(**payload))
            added += 1
            continue
        mutated = False
        for field in ("title", "description", "severity", "zt_pillar", "remediation",
                      "source_version", "reference_url", "resource_type", "frameworks"):
            if getattr(existing, field) != payload[field]:
                setattr(existing, field, payload[field])
                mutated = True
        if mutated:
            existing.updated_at = datetime.utcnow()
            changed += 1
        else:
            unchanged += 1
    checksum = hashlib.sha256(
        json.dumps(sorted(item["control_id"] for item in payloads)).encode()
    ).hexdigest()
    db.add(ControlSync(
        source=ControlSource.PROWLER.value,
        source_version=str(status.get("version") or "unknown"),
        checksum=checksum,
        added=added,
        changed=changed,
        unchanged=unchanged,
        status="completed",
        completed_at=datetime.utcnow(),
    ))
    await db.commit()
    return {
        "source": "prowler",
        "installed": True,
        "source_version": status.get("version"),
        "providers": list(providers),
        "catalog_controls": len(payloads),
        "checksum": checksum,
        "added": added,
        "changed": changed,
        "unchanged": unchanged,
        "synced_at": datetime.utcnow().isoformat(),
    }
