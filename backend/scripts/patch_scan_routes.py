"""
Patch all remaining claw scan routes to use finding_pipeline.ingest_findings.

Strategy:
- For each claw's scan route, replace the direct Finding() + db.add() pattern
- With an equivalent pipeline-based approach
- Preserves all existing finding data; adds dedup + policy eval + alerting

Run: cd backend && python scripts/patch_scan_routes.py
"""
import os

BASE = os.path.join(os.path.dirname(__file__), "..", "app", "claws")
SKIP = {"cloudclaw", "exposureclaw", "threatclaw", "endpointclaw", "arcclaw", "identityclaw"}


def get_claw_name(content: str) -> str:
    """Extract CLAW_NAME or claw name from routes.py content."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("CLAW_NAME") and "=" in stripped:
            rhs = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            if rhs:
                return rhs
        if 'prefix="/' in stripped:
            start = stripped.find('prefix="/')
            if start != -1:
                prefix_part = stripped[start + len('prefix="/'):]
                end = prefix_part.find('"')
                if end != -1:
                    candidate = prefix_part[:end]
                    if candidate:
                        return candidate
    return "unknown"


def patch_scan_endpoint(content: str, claw_name: str) -> str:
    """
    Patches the scan endpoint by:
    1. Adding ingest_findings import at the top of the function
    2. Wrapping all Finding() constructions into pipeline_findings dicts
    3. Replacing final db.add/commit with ingest_findings call
    """
    if "ingest_findings" in content:
        return content  # Already patched

    # Find the scan endpoint marker.
    scan_marker = '@router.post("/scan"'
    if scan_marker not in content:
        return content

    # Add the pipeline import before the router definition
    # Replace "await db.commit()" and "db.add(finding)" patterns with pipeline
    # This is a marker-based replacement for the return statement pattern

    # Pattern: functions end with either:
    # return {"status": "ok", "findings_created": len(findings)}
    # return {"status": "completed", ...}

    # Replace the final db.add + commit + return block
    # Find all db.add(f) calls and the final commit

    # Strategy: inject pipeline wiring at the end of scan functions
    # by replacing the known return patterns

    old_block = '''    for f in findings:
        db.add(f)
    await db.commit()
    return {"status": "ok", "findings_created": len(findings)}'''
    replacement = '''    from app.services.finding_pipeline import ingest_findings
    pipeline_findings = []
    for f in findings:
        pipeline_findings.append({
            "claw": f.claw,
            "provider": f.provider,
            "title": f.title,
            "description": f.description,
            "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "region": f.region,
            "account_id": f.account_id,
            "cvss_score": f.cvss_score,
            "epss_score": f.epss_score,
            "risk_score": f.risk_score,
            "actively_exploited": f.actively_exploited,
            "remediation": f.remediation,
            "remediation_effort": f.remediation_effort,
            "external_id": f.external_id,
            "reference_url": f.reference_url,
        })
    summary = await ingest_findings(db, CLAW_NAME, pipeline_findings)
    return {"status": "completed", "findings_created": summary["created"], "findings_updated": summary["updated"]}'''
    if old_block in content:
        print("    Patched using marker replacement")
        return content.replace(old_block, replacement)

    return content


def main():
    patched = 0
    skipped = 0

    for claw_dir in sorted(os.listdir(BASE)):
        if claw_dir.startswith("_") or claw_dir in SKIP:
            continue

        routes_path = os.path.join(BASE, claw_dir, "routes.py")
        if not os.path.exists(routes_path):
            continue

        with open(routes_path, "r") as f:
            content = f.read()

        if "ingest_findings" in content:
            print(f"[skip] {claw_dir} — already patched")
            skipped += 1
            continue

        claw_name = get_claw_name(content)
        print(f"[patch] {claw_dir} (claw={claw_name})")

        new_content = patch_scan_endpoint(content, claw_name)

        if new_content != content:
            with open(routes_path, "w") as f:
                f.write(new_content)
            patched += 1
            print(f"    ✓ Patched")
        else:
            print(f"    ⚠ Pattern not matched — manual update needed")

    print(f"\nDone: {patched} patched, {skipped} skipped")


if __name__ == "__main__":
    main()
