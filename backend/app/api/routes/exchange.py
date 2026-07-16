"""
Enkstein — Security Exchange API
GET  /exchange/packages          — browse marketplace
GET  /exchange/packages/{id}     — package detail
POST /exchange/packages/{id}/install  — install a package
GET  /exchange/publishers        — list publishers
GET  /exchange/publishers/{slug} — publisher detail
GET  /exchange/stats             — marketplace stats
GET  /exchange/featured          — featured packages
GET  /exchange/search            — full-text search
"""
from datetime import datetime
from typing import Optional
import uuid
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Header
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.exchange import ExchangePackage, ExchangePublisher, ExchangeInstallRecord
from app.models.skill_pack import SkillPack

router = APIRouter(prefix="/exchange", tags=["exchange"])


# ─── helpers ────────────────────────────────────────────────────────────────

def _pkg_out(p: ExchangePackage) -> dict:
    return {
        "id":               p.id,
        "publisher_id":     p.publisher_id,
        "publisher_name":   p.publisher_name,
        "name":             p.name,
        "slug":             p.slug,
        "package_type":     p.package_type,
        "category":         p.category,
        "tags":             p.tags or [],
        "description":      p.description,
        "long_description": p.long_description,
        "version":          p.version,
        "license_type":     p.license_type,
        "homepage":         p.homepage,
        "source_url":       p.source_url,
        "changelog":        p.changelog,
        "sha256_checksum":  p.sha256_checksum,
        "is_signed":        p.is_signed,
        "signature_verified": p.signature_verified,
        "trust_score":      p.trust_score,
        "download_count":   p.download_count,
        "rating":           round(p.rating, 1),
        "rating_count":     p.rating_count,
        "is_featured":      p.is_featured,
        "is_official":      p.is_official,
        "is_deprecated":    p.is_deprecated,
        "manifest_json":    p.manifest_json or {},
        "created_at":       p.created_at.isoformat() if p.created_at else None,
        "updated_at":       p.updated_at.isoformat() if p.updated_at else None,
    }


def _pub_out(p: ExchangePublisher) -> dict:
    return {
        "id":              p.id,
        "name":            p.name,
        "slug":            p.slug,
        "description":     p.description,
        "website":         p.website,
        "logo_url":        p.logo_url,
        "tier":            p.tier,
        "is_verified":     p.is_verified,
        "pgp_fingerprint": p.pgp_fingerprint,
        "total_packages":  p.total_packages,
        "avg_trust_score": round(p.avg_trust_score, 1),
        "created_at":      p.created_at.isoformat() if p.created_at else None,
    }


def _canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest or {}, sort_keys=True, separators=(",", ":")).encode()


# ─── packages ───────────────────────────────────────────────────────────────

@router.get("/packages")
def list_packages(
    package_type: Optional[str] = Query(None),
    category:     Optional[str] = Query(None),
    publisher_id: Optional[str] = Query(None),
    is_official:  Optional[bool] = Query(None),
    is_signed:    Optional[bool] = Query(None),
    sort:         str = Query("downloads"),  # downloads|rating|newest|trust
    limit:        int = Query(50, ge=1, le=200),
    offset:       int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(ExchangePackage).filter(ExchangePackage.is_deprecated == False)
    if package_type:
        q = q.filter(ExchangePackage.package_type == package_type)
    if category:
        q = q.filter(ExchangePackage.category == category)
    if publisher_id:
        q = q.filter(ExchangePackage.publisher_id == publisher_id)
    if is_official is not None:
        q = q.filter(ExchangePackage.is_official == is_official)
    if is_signed is not None:
        q = q.filter(ExchangePackage.is_signed == is_signed)
    if sort == "downloads":
        q = q.order_by(ExchangePackage.download_count.desc())
    elif sort == "rating":
        q = q.order_by(ExchangePackage.rating.desc())
    elif sort == "newest":
        q = q.order_by(ExchangePackage.created_at.desc())
    elif sort == "trust":
        q = q.order_by(ExchangePackage.trust_score.desc())
    total   = q.count()
    results = q.offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "packages": [_pkg_out(p) for p in results]}


@router.get("/packages/{package_id}")
def get_package(package_id: str, db: Session = Depends(get_db)):
    p = db.query(ExchangePackage).filter(ExchangePackage.id == package_id).first()
    if not p:
        raise HTTPException(404, "Package not found")
    return _pkg_out(p)


@router.post("/packages/{package_id}/install")
def install_package(
    package_id:   str,
    installed_by: str = "platform_admin",
    x_package_sha256: str | None = Header(default=None, alias="x-package-sha256"),
    db: Session = Depends(get_db),
):
    pkg = db.query(ExchangePackage).filter(ExchangePackage.id == package_id).first()
    if not pkg:
        raise HTTPException(404, "Package not found")
    if pkg.is_deprecated:
        raise HTTPException(400, "Package is deprecated and cannot be installed")

    # Check signature for non-community packages
    if pkg.is_official and not pkg.signature_verified:
        raise HTTPException(400, "Official package signature could not be verified")

    manifest = pkg.manifest_json if isinstance(pkg.manifest_json, dict) else {}
    actual_checksum = hashlib.sha256(_canonical_manifest_bytes(manifest)).hexdigest()
    expected_checksum = (pkg.sha256_checksum or "").strip().lower()
    provided_checksum = (x_package_sha256 or "").strip().lower()

    # Hard gate 1: package metadata checksum must match content hash
    if expected_checksum and expected_checksum != actual_checksum:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "package_checksum_mismatch",
                "message": "Package checksum does not match manifest payload.",
                "expected": expected_checksum,
                "actual": actual_checksum,
            },
        )

    # Hard gate 2: caller-provided checksum (e.g. installer lock) must match metadata
    if provided_checksum and expected_checksum and provided_checksum != expected_checksum:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "package_checksum_header_mismatch",
                "message": "Provided package checksum does not match exchange metadata.",
                "expected": expected_checksum,
                "provided": provided_checksum,
            },
        )

    # Materialise into a SkillPack if type = skill_pack
    if pkg.package_type == "skill_pack":
        existing = db.query(SkillPack).filter(SkillPack.slug == pkg.slug).first()
        if not existing:
            sp = SkillPack(
                id            = str(uuid.uuid4()),
                name          = pkg.name,
                slug          = pkg.slug,
                description   = pkg.description,
                category      = pkg.category,
                version       = pkg.version,
                publisher     = pkg.publisher_name,
                manifest_json = json.dumps(manifest),
                signature     = pkg.sha256_checksum[:32] if pkg.sha256_checksum else "",
                is_builtin    = False,
                is_installed  = True,
                installed_at  = datetime.utcnow(),
                installed_by  = installed_by,
            )
            db.add(sp)

    # Record install
    record = ExchangeInstallRecord(
        package_id   = pkg.id,
        package_name = pkg.name,
        package_type = pkg.package_type,
        installed_by = installed_by,
        version      = pkg.version,
        status       = "installed",
    )
    db.add(record)

    # Bump download count
    pkg.download_count = (pkg.download_count or 0) + 1
    db.commit()

    return {
        "success":      True,
        "message":      f"Package '{pkg.name}' installed successfully",
        "package_id":   pkg.id,
        "package_name": pkg.name,
        "package_type": pkg.package_type,
        "version":      pkg.version,
    }


@router.post("/packages/{package_id}/submit")
def submit_package(package_id: str, db: Session = Depends(get_db)):
    """
    Submit a package for marketplace review.
    Transitions status: draft → pending_review.
    Sets submitted_at on the manifest_json metadata.
    """
    pkg = db.query(ExchangePackage).filter(ExchangePackage.id == package_id).first()
    if not pkg:
        raise HTTPException(404, "Package not found")

    manifest = dict(pkg.manifest_json or {})
    current_status = manifest.get("status", "draft")
    if current_status not in ("draft", "rejected"):
        raise HTTPException(
            400,
            f"Package cannot be submitted from status '{current_status}'. "
            "Only draft or rejected packages can be resubmitted.",
        )

    now = datetime.utcnow().isoformat()
    manifest["status"]       = "pending_review"
    manifest["submitted_at"] = now
    pkg.manifest_json = manifest
    pkg.updated_at    = datetime.utcnow()
    db.commit()
    db.refresh(pkg)

    return {
        "success":      True,
        "package_id":   pkg.id,
        "package_name": pkg.name,
        "status":       "pending_review",
        "submitted_at": now,
        "message":      "Package submitted for review. An admin will approve or reject it.",
    }


@router.post("/packages/{package_id}/approve")
def approve_package(package_id: str, body: dict = None, db: Session = Depends(get_db)):
    """
    Approve a pending package and publish it to the marketplace.
    Requires admin role — enforced via body field "approved_by" (production
    implementations should validate JWT role claim).
    """
    body = body or {}
    pkg  = db.query(ExchangePackage).filter(ExchangePackage.id == package_id).first()
    if not pkg:
        raise HTTPException(404, "Package not found")

    manifest = dict(pkg.manifest_json or {})
    if manifest.get("status") != "pending_review":
        raise HTTPException(
            400,
            f"Package is not pending review (status: '{manifest.get('status', 'unknown')}').",
        )

    approved_by = body.get("approved_by", "admin")
    now = datetime.utcnow().isoformat()

    manifest["status"]      = "published"
    manifest["approved_by"] = approved_by
    manifest["approved_at"] = now
    pkg.manifest_json    = manifest
    pkg.updated_at       = datetime.utcnow()
    pkg.is_deprecated    = False   # ensure not deprecated on publish
    db.commit()
    db.refresh(pkg)

    return {
        "success":      True,
        "package_id":   pkg.id,
        "package_name": pkg.name,
        "status":       "published",
        "approved_by":  approved_by,
        "approved_at":  now,
    }


@router.post("/packages/{package_id}/reject")
def reject_package(package_id: str, body: dict = None, db: Session = Depends(get_db)):
    """
    Reject a pending package, recording the rejection reason.
    The publisher may fix issues and resubmit.
    """
    body = body or {}
    pkg  = db.query(ExchangePackage).filter(ExchangePackage.id == package_id).first()
    if not pkg:
        raise HTTPException(404, "Package not found")

    manifest = dict(pkg.manifest_json or {})
    if manifest.get("status") != "pending_review":
        raise HTTPException(
            400,
            f"Package is not pending review (status: '{manifest.get('status', 'unknown')}').",
        )

    reason      = body.get("reason", "No reason provided")
    rejected_by = body.get("rejected_by", "admin")
    now         = datetime.utcnow().isoformat()

    manifest["status"]       = "rejected"
    manifest["rejected_by"]  = rejected_by
    manifest["rejected_at"]  = now
    manifest["reject_reason"] = reason
    pkg.manifest_json = manifest
    pkg.updated_at    = datetime.utcnow()
    db.commit()
    db.refresh(pkg)

    return {
        "success":      True,
        "package_id":   pkg.id,
        "package_name": pkg.name,
        "status":       "rejected",
        "rejected_by":  rejected_by,
        "rejected_at":  now,
        "reason":       reason,
        "message":      "Package rejected. The publisher may fix issues and resubmit.",
    }


@router.get("/packages/{package_id}/reviews")
def get_package_reviews(package_id: str, db: Session = Depends(get_db)):
    """
    Return install records as a proxy for reviews.
    Aggregates rating counts (1-5 stars) and returns per-install metadata.

    Note: ExchangeInstallRecord does not have a `rating` column yet,
    so we return install history and aggregate what we can from the package.
    """
    pkg = db.query(ExchangePackage).filter(ExchangePackage.id == package_id).first()
    if not pkg:
        raise HTTPException(404, "Package not found")

    installs = (
        db.query(ExchangeInstallRecord)
        .filter(ExchangeInstallRecord.package_id == package_id)
        .order_by(ExchangeInstallRecord.installed_at.desc())
        .all()
    )

    install_list = [
        {
            "id":           rec.id,
            "installed_by": rec.installed_by,
            "installed_at": rec.installed_at.isoformat() if rec.installed_at else None,
            "version":      rec.version,
            "status":       rec.status,
        }
        for rec in installs
    ]

    # Aggregate from package-level rating fields
    return {
        "package_id":      pkg.id,
        "package_name":    pkg.name,
        "overall_rating":  round(pkg.rating, 1),
        "rating_count":    pkg.rating_count,
        "total_installs":  len(install_list),
        "installs":        install_list,
    }


@router.get("/featured")
def get_featured(db: Session = Depends(get_db)):
    pkgs = (
        db.query(ExchangePackage)
        .filter(ExchangePackage.is_featured == True, ExchangePackage.is_deprecated == False)
        .order_by(ExchangePackage.trust_score.desc())
        .limit(12)
        .all()
    )
    return [_pkg_out(p) for p in pkgs]


@router.get("/search")
def search_packages(
    q:   str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    term = f"%{q.lower()}%"
    pkgs = (
        db.query(ExchangePackage)
        .filter(
            ExchangePackage.is_deprecated == False,
            (
                ExchangePackage.name.ilike(term)
                | ExchangePackage.description.ilike(term)
                | ExchangePackage.category.ilike(term)
            ),
        )
        .order_by(ExchangePackage.download_count.desc())
        .limit(30)
        .all()
    )
    return [_pkg_out(p) for p in pkgs]


# ─── publishers ─────────────────────────────────────────────────────────────

@router.get("/publishers")
def list_publishers(db: Session = Depends(get_db)):
    pubs = db.query(ExchangePublisher).order_by(ExchangePublisher.avg_trust_score.desc()).all()
    return [_pub_out(p) for p in pubs]


@router.get("/publishers/{slug}")
def get_publisher(slug: str, db: Session = Depends(get_db)):
    pub = db.query(ExchangePublisher).filter(ExchangePublisher.slug == slug).first()
    if not pub:
        raise HTTPException(404, "Publisher not found")
    pkgs = (
        db.query(ExchangePackage)
        .filter(ExchangePackage.publisher_id == pub.id)
        .order_by(ExchangePackage.download_count.desc())
        .all()
    )
    return {**_pub_out(pub), "packages": [_pkg_out(p) for p in pkgs]}


# ─── stats ───────────────────────────────────────────────────────────────────

@router.get("/stats")
def exchange_stats(db: Session = Depends(get_db)):
    total_pkgs       = db.query(ExchangePackage).count()
    signed_pkgs      = db.query(ExchangePackage).filter(ExchangePackage.is_signed == True).count()
    official_pkgs    = db.query(ExchangePackage).filter(ExchangePackage.is_official == True).count()
    total_pubs       = db.query(ExchangePublisher).count()
    verified_pubs    = db.query(ExchangePublisher).filter(ExchangePublisher.is_verified == True).count()
    total_installs   = db.query(ExchangeInstallRecord).count()
    type_breakdown   = {}
    for row in db.query(ExchangePackage.package_type).distinct():
        t = row[0]
        count = db.query(ExchangePackage).filter(ExchangePackage.package_type == t).count()
        type_breakdown[t] = count
    categories = []
    for row in db.query(ExchangePackage.category).distinct():
        cat = row[0]
        if cat:
            cnt = db.query(ExchangePackage).filter(ExchangePackage.category == cat).count()
            categories.append({"category": cat, "count": cnt})
    categories.sort(key=lambda x: x["count"], reverse=True)
    return {
        "total_packages":  total_pkgs,
        "signed_packages": signed_pkgs,
        "official_packages": official_pkgs,
        "total_publishers": total_pubs,
        "verified_publishers": verified_pubs,
        "total_installs":  total_installs,
        "type_breakdown":  type_breakdown,
        "categories":      categories,
    }
