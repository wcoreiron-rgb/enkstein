"""Minimal NIST OSCAL catalog importer.

OSCAL is deliberately consumed as machine-readable catalog data. The importer
stores identifiers, titles, statements, version, and references; it does not
copy a framework's long-form prose into a finding or claim automated evidence
where no evaluator exists.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.control import Control, ControlSource, ControlStatus

NIST_SP800_53_REV5_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)


def _statement(control: dict[str, Any]) -> str | None:
    parts = []
    for prop in control.get("parts", []) or []:
        if prop.get("name") in {"statement", "objective"} and prop.get("prose"):
            parts.append(str(prop["prose"]))
    return " ".join(parts)[:4000] or None


def _flatten_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    for group in groups or []:
        controls.extend(group.get("controls", []) or [])
        controls.extend(_flatten_groups(group.get("groups", []) or []))
    return controls


async def sync_nist_catalog(
    db: AsyncSession,
    *,
    url: str = NIST_SP800_53_REV5_URL,
    timeout_seconds: float = 30.0,
) -> dict[str, int | str]:
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.get(url)
        response.raise_for_status()
        payload = response.json()
    catalog = payload.get("catalog", payload)
    metadata = catalog.get("metadata", {})
    version = str(metadata.get("version") or metadata.get("last-modified") or "unknown")
    controls = _flatten_groups(catalog.get("groups", []))
    added = changed = unchanged = 0
    for item in controls:
        control_id = str(item.get("id") or "").strip()
        if not control_id:
            continue
        title = str(item.get("title") or control_id)[:512]
        description = _statement(item)
        result = await db.execute(
            select(Control).where(
                Control.control_id == control_id,
                Control.source == ControlSource.NIST_800_53.value,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            db.add(Control(
                control_id=control_id,
                source=ControlSource.NIST_800_53.value,
                source_version=version,
                title=title,
                description=description,
                zt_pillar="governance",
                frameworks={"nist_800_53": [control_id]},
                status=ControlStatus.PENDING_REVIEW.value,
                automated=False,
                recommendation_only=True,
                remediation_mode="recommendation_only",
                evidence_method="OSCAL catalog definition imported; an evaluator must be attached before assessment.",
            ))
            added += 1
        elif existing.title != title or existing.description != description or existing.source_version != version:
            existing.title = title
            existing.description = description
            existing.source_version = version
            changed += 1
        else:
            unchanged += 1
    await db.commit()
    return {
        "source": "nist_800_53",
        "source_version": version,
        "checksum": hashlib.sha256(response.content).hexdigest(),
        "catalog_controls": len(controls),
        "added": added,
        "changed": changed,
        "unchanged": unchanged,
        "synced_at": datetime.utcnow().isoformat(),
    }
