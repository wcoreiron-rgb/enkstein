"""
RegentClaw — Skill Pack API Routes (v2 — versioned packs)
Note: policy_packs.py already handles the original "Policy Pack" concept.
This module handles "Skill Packs" — versioned automation skill bundles.
"""
import hashlib
import json
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.fabric.providers.agt import get_agt_adapter
from app.models.skill_pack import SkillPack
from app.services.provenance import verify_package
from app.trust_fabric import ActionRequest, enforce

logger = logging.getLogger("regentclaw.skill_packs")
router = APIRouter(prefix="/skill-packs", tags=["Skill Packs"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class SkillPackCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    slug: str = Field(..., min_length=3, max_length=128, pattern=r"^[a-z0-9\-]+$")
    version: str = "1.0.0"
    description: str | None = None
    icon: str | None = None
    category: str | None = None
    publisher: str | None = None
    tags: str | None = None
    manifest_json: str = "{}"
    risk_level: str = "low"
    requires_approval: bool = False
    source_url: str | None = None
    license: str | None = None
    changelog: str | None = None


class SkillPackUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    version: str | None = None
    category: str | None = None
    tags: str | None = None
    changelog: str | None = None
    risk_level: str | None = None
    requires_approval: bool | None = None


class InstallRequest(BaseModel):
    installed_by: str = "platform_admin"
    scan_path: str | None = None


class SkillPackUpgradeRequest(BaseModel):
    version: str = Field(..., min_length=1, max_length=32)
    manifest_json: str = "{}"
    changelog: str | None = None
    upgraded_by: str = "platform_admin"


class SkillPackRollbackRequest(BaseModel):
    rolled_back_by: str = "platform_admin"
    reason: str | None = Field(default=None, max_length=1024)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _pack_out(p: SkillPack) -> dict:
    manifest = {}
    try:
        manifest = json.loads(p.manifest_json or "{}")
    except Exception:
        pass

    return {
        "id": str(p.id),
        "name": p.name,
        "slug": p.slug,
        "version": p.version,
        "description": p.description,
        "icon": p.icon,
        "category": p.category,
        "publisher": p.publisher,
        "tags": p.tags,
        "is_installed": p.is_installed,
        "is_active": p.is_active,
        "is_builtin": p.is_builtin,
        "risk_level": p.risk_level,
        "requires_approval": p.requires_approval,
        "skill_count": p.skill_count,
        "run_count": p.run_count,
        "installed_at": p.installed_at.isoformat() if p.installed_at else None,
        "installed_by": p.installed_by,
        "activated_at": p.activated_at.isoformat() if p.activated_at else None,
        "signature": p.signature,
        "source_url": p.source_url,
        "license": p.license,
        "changelog": p.changelog,
        "manifest": manifest,
        "rollback_available": bool((manifest.get("_lifecycle") or {}).get("previous_versions")),
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat(),
    }


def _manifest(raw: str) -> dict:
    try:
        parsed = json.loads(raw or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        raise HTTPException(status_code=400, detail="manifest_json must be valid JSON")


def _strip_lifecycle(manifest: dict) -> dict:
    cleaned = dict(manifest or {})
    cleaned.pop("_lifecycle", None)
    return cleaned


def _manifest_diff(old: dict, new: dict) -> dict:
    old_clean = _strip_lifecycle(old)
    new_clean = _strip_lifecycle(new)

    def _ids(items: list[dict], key: str = "id") -> set[str]:
        return {str(item.get(key) or item.get("name")) for item in items if isinstance(item, dict)}

    old_skills = _ids(old_clean.get("skills", []))
    new_skills = _ids(new_clean.get("skills", []))
    fields = ["required_connectors", "required_claws", "scope_permissions"]
    field_changes = {}
    for field in fields:
        before = set(map(str, old_clean.get(field, []) or []))
        after = set(map(str, new_clean.get(field, []) or []))
        field_changes[field] = {
            "added": sorted(after - before),
            "removed": sorted(before - after),
        }
    return {
        "skills_added": sorted(new_skills - old_skills),
        "skills_removed": sorted(old_skills - new_skills),
        "field_changes": field_changes,
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", summary="List all skill packs")
async def list_skill_packs(
    installed_only: bool = Query(False),
    category: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(SkillPack).order_by(SkillPack.is_installed.desc(), SkillPack.name)
    if installed_only:
        q = q.where(SkillPack.is_installed == True)
    if category:
        q = q.where(SkillPack.category == category)
    result = await db.execute(q)
    packs = result.scalars().all()
    return {
        "count": len(packs),
        "installed": sum(1 for p in packs if p.is_installed),
        "active": sum(1 for p in packs if p.is_active),
        "skill_packs": [_pack_out(p) for p in packs],
    }


@router.post("", summary="Register a new skill pack")
async def create_skill_pack(body: SkillPackCreate, db: AsyncSession = Depends(get_db)):
    # Check slug uniqueness
    existing = await db.execute(select(SkillPack).where(SkillPack.slug == body.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Skill pack with slug '{body.slug}' already exists")

    # Validate manifest JSON
    try:
        manifest = json.loads(body.manifest_json)
    except Exception:
        raise HTTPException(status_code=400, detail="manifest_json must be valid JSON")

    # Auto-count skills in manifest
    skill_count = len(manifest.get("skills", []))

    # Compute manifest signature
    sig = hashlib.sha256(body.manifest_json.encode()).hexdigest()[:32]

    pack = SkillPack(
        **body.dict(exclude={"manifest_json"}),
        manifest_json=body.manifest_json,
        skill_count=skill_count,
        signature=sig,
    )
    db.add(pack)
    await db.commit()
    return _pack_out(pack)


@router.get("/categories", summary="List distinct categories")
async def get_categories(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SkillPack.category).distinct())
    cats = [r for r in result.scalars().all() if r]
    return {"categories": sorted(cats)}


@router.get("/stats", summary="Skill pack statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SkillPack))
    packs = result.scalars().all()
    total_skills = sum(p.skill_count for p in packs)
    return {
        "total_packs": len(packs),
        "installed": sum(1 for p in packs if p.is_installed),
        "active": sum(1 for p in packs if p.is_active),
        "total_skills": total_skills,
        "high_risk": sum(1 for p in packs if p.risk_level in ("high", "critical") and p.is_installed),
        "requires_approval": sum(1 for p in packs if p.requires_approval and p.is_installed),
    }


@router.get("/{pack_id}", summary="Get skill pack detail")
async def get_skill_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    return _pack_out(pack)


@router.patch("/{pack_id}", summary="Update skill pack metadata")
async def update_skill_pack(pack_id: str, body: SkillPackUpdate, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    updates = {k: v for k, v in body.dict().items() if v is not None}
    for k, v in updates.items():
        setattr(pack, k, v)
    pack.updated_at = datetime.utcnow()
    await db.commit()
    return _pack_out(pack)


@router.delete("/{pack_id}", summary="Remove a skill pack (must be uninstalled first)")
async def delete_skill_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    if pack.is_installed:
        raise HTTPException(status_code=400, detail="Uninstall the pack before deleting it")
    await db.delete(pack)
    await db.commit()
    return {"deleted": pack_id}


@router.post("/{pack_id}/install", summary="Install a skill pack")
async def install_skill_pack(
    pack_id: str,
    body: InstallRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    if pack.is_installed:
        raise HTTPException(status_code=400, detail="Already installed")

    # 0) Provenance check — verify manifest integrity before proceeding
    result = verify_package(
        manifest_json=pack.manifest_json,
        expected_hash=pack.manifest_hash,
        signature_b64=pack.manifest_signature,
        public_key_pem=pack.publisher_key,
    )
    if not result.valid:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "manifest_integrity_failure",
                "message": f"Skill pack manifest failed provenance check: {result.error}",
                "hash": result.hash,
            },
        )

    # 1) Policy-govern the install action via Trust Fabric
    try:
        manifest = json.loads(pack.manifest_json or "{}")
    except Exception:
        manifest = {}
    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module="skillclaw",
            actor_id=body.installed_by,
            actor_name=body.installed_by,
            actor_type="human",
            action="install_skill_pack",
            target=pack.slug,
            target_type="skill_pack",
            context={
                "pack_risk_level": pack.risk_level,
                "requires_approval": pack.requires_approval,
                "skill_count": pack.skill_count,
                "scope_permissions": manifest.get("scope_permissions", []),
            },
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Skill pack install blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
                "outcome": policy_decision.outcome.value,
                "risk_score": policy_decision.risk_score,
            },
        )

    # 2) Optional AGT MCP gateway scan at install time
    adapter = get_agt_adapter()
    gateway_scan = None
    if adapter.flags.enable_mcp_gateway and body.scan_path:
        gateway_scan = adapter.scan_path(body.scan_path)
        if gateway_scan.get("critical_count", 0) > 0 or gateway_scan.get("risk_score", 0.0) >= 50.0:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Skill pack install blocked by MCP Security Gateway scan.",
                    "scan": gateway_scan,
                },
            )

    pack.is_installed = True
    pack.installed_at = datetime.utcnow()
    pack.installed_by = body.installed_by
    pack.updated_at   = datetime.utcnow()
    await db.commit()

    logger.info("Skill pack installed: %s v%s by %s", pack.slug, pack.version, body.installed_by)
    payload = _pack_out(pack)
    payload["install_policy"] = {
        "outcome": policy_decision.outcome.value,
        "risk_score": policy_decision.risk_score,
        "policy_name": policy_decision.policy_name,
    }
    if gateway_scan is not None:
        payload["gateway_scan"] = gateway_scan
    return payload


@router.post("/{pack_id}/preview-update", summary="Preview skill pack update diff")
async def preview_skill_pack_update(
    pack_id: str,
    body: SkillPackUpgradeRequest,
    db: AsyncSession = Depends(get_db),
):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    old_manifest = _manifest(pack.manifest_json)
    new_manifest = _manifest(body.manifest_json)
    return {
        "pack_id": pack_id,
        "slug": pack.slug,
        "current_version": pack.version,
        "target_version": body.version,
        "diff": _manifest_diff(old_manifest, new_manifest),
        "scope_preview": {
            "required_connectors": new_manifest.get("required_connectors", []),
            "required_claws": new_manifest.get("required_claws", []),
            "scope_permissions": new_manifest.get("scope_permissions", []),
        },
    }


@router.post("/{pack_id}/upgrade", summary="Upgrade an installed skill pack")
async def upgrade_skill_pack(
    pack_id: str,
    body: SkillPackUpgradeRequest,
    db: AsyncSession = Depends(get_db),
):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    if not pack.is_installed:
        raise HTTPException(status_code=400, detail="Install the pack before upgrading it")

    old_manifest = _manifest(pack.manifest_json)
    new_manifest = _manifest(body.manifest_json)
    lifecycle = new_manifest.get("_lifecycle") if isinstance(new_manifest.get("_lifecycle"), dict) else {}
    previous_versions = lifecycle.get("previous_versions") if isinstance(lifecycle.get("previous_versions"), list) else []
    previous_versions.append(
        {
            "version": pack.version,
            "manifest": _strip_lifecycle(old_manifest),
            "changelog": pack.changelog,
            "signature": pack.signature,
            "skill_count": pack.skill_count,
            "saved_at": datetime.utcnow().isoformat(),
            "saved_by": body.upgraded_by,
        }
    )
    lifecycle["previous_versions"] = previous_versions[-5:]
    lifecycle["last_upgraded_by"] = body.upgraded_by
    lifecycle["last_upgraded_at"] = datetime.utcnow().isoformat()
    new_manifest["_lifecycle"] = lifecycle

    pack.version = body.version
    pack.manifest_json = json.dumps(new_manifest)
    pack.skill_count = len(new_manifest.get("skills", []))
    pack.signature = hashlib.sha256(pack.manifest_json.encode()).hexdigest()[:32]
    pack.changelog = body.changelog
    pack.updated_at = datetime.utcnow()
    await db.commit()
    return {
        **_pack_out(pack),
        "upgrade_diff": _manifest_diff(old_manifest, new_manifest),
    }


@router.post("/{pack_id}/rollback", summary="Rollback a skill pack to its previous version")
async def rollback_skill_pack(
    pack_id: str,
    body: SkillPackRollbackRequest,
    db: AsyncSession = Depends(get_db),
):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    manifest = _manifest(pack.manifest_json)
    lifecycle = manifest.get("_lifecycle") if isinstance(manifest.get("_lifecycle"), dict) else {}
    previous_versions = lifecycle.get("previous_versions") if isinstance(lifecycle.get("previous_versions"), list) else []
    if not previous_versions:
        raise HTTPException(status_code=400, detail="No rollback version available")

    target = previous_versions.pop()
    restored_manifest = dict(target.get("manifest") or {})
    lifecycle["previous_versions"] = previous_versions
    lifecycle["last_rollback_by"] = body.rolled_back_by
    lifecycle["last_rollback_at"] = datetime.utcnow().isoformat()
    lifecycle["last_rollback_reason"] = body.reason
    restored_manifest["_lifecycle"] = lifecycle

    pack.version = str(target.get("version") or pack.version)
    pack.manifest_json = json.dumps(restored_manifest)
    pack.skill_count = int(target.get("skill_count") or len(restored_manifest.get("skills", [])))
    pack.signature = str(target.get("signature") or hashlib.sha256(pack.manifest_json.encode()).hexdigest()[:32])
    pack.changelog = target.get("changelog")
    pack.updated_at = datetime.utcnow()
    await db.commit()
    return _pack_out(pack)


@router.post("/{pack_id}/uninstall", summary="Uninstall a skill pack")
async def uninstall_skill_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    if pack.is_builtin:
        raise HTTPException(status_code=400, detail="Built-in packs cannot be uninstalled")

    pack.is_installed  = False
    pack.is_active     = False
    pack.installed_at  = None
    pack.installed_by  = None
    pack.activated_at  = None
    pack.updated_at    = datetime.utcnow()
    await db.commit()

    logger.info("Skill pack uninstalled: %s", pack.slug)
    return _pack_out(pack)


@router.post("/{pack_id}/activate", summary="Activate an installed skill pack")
async def activate_skill_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    if not pack.is_installed:
        raise HTTPException(status_code=400, detail="Install the pack before activating it")

    pack.is_active    = True
    pack.activated_at = datetime.utcnow()
    pack.updated_at   = datetime.utcnow()
    await db.commit()
    return _pack_out(pack)


@router.post("/{pack_id}/deactivate", summary="Deactivate a skill pack (keep installed)")
async def deactivate_skill_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    pack.is_active  = False
    pack.updated_at = datetime.utcnow()
    await db.commit()
    return _pack_out(pack)


@router.get("/{pack_id}/skills", summary="List skills in a pack")
async def list_pack_skills(pack_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    pack = await db.get(SkillPack, UUID(pack_id))
    if not pack:
        raise HTTPException(status_code=404, detail="Skill pack not found")
    try:
        manifest = json.loads(pack.manifest_json or "{}")
    except Exception:
        manifest = {}
    return {
        "pack_id": pack_id,
        "pack_name": pack.name,
        "skills": manifest.get("skills", []),
        "required_connectors": manifest.get("required_connectors", []),
        "required_claws": manifest.get("required_claws", []),
        "scope_permissions": manifest.get("scope_permissions", []),
        "policy_mappings": manifest.get("policy_mappings", []),
    }
