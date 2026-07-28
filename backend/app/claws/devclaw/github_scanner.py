"""
GitHub Security Scanner
===================================
Pulls real security findings from GitHub via the REST API:
  - Secret scanning alerts
  - Code scanning (SAST) alerts
  - Dependabot vulnerability alerts

Auth: Personal Access Token stored in the secrets manager under the
      'github' connector record.

Credentials expected:
  {
    "personal_access_token": "ghp_..."
  }
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import secrets_manager
from app.services import device_code_auth

logger = logging.getLogger("devclaw.github_scanner")

TIMEOUT = httpx.Timeout(30.0)
GITHUB_API = "https://api.github.com"

# Severity → risk score
_RISK_SCORES: dict[str, float] = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.60,
    "low": 0.35,
}

# Code-scanning rule severity → internal severity
_CODE_SCAN_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "note": "low",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sev_risk(severity: str) -> float:
    return _RISK_SCORES.get(severity.lower(), 0.35)


def _make_headers(pat: str) -> dict[str, str]:
    # GitHub accepts "Bearer" for both classic PATs and OAuth tokens, whereas
    # the older "token" scheme rejects OAuth device-code tokens.
    return {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ── Per-alert parsers ──────────────────────────────────────────────────────────

def _parse_secret_alert(alert: dict, full_name: str) -> dict:
    repo_name = full_name.split("/")[-1]
    number = alert.get("number", 0)
    secret_type_display = alert.get("secret_type_display_name", alert.get("secret_type", "Unknown Secret"))
    locations = alert.get("locations", [])
    bypassed = alert.get("push_protection_bypassed", False)

    description_parts = [
        f"Secret type: {secret_type_display}",
        f"Secret type ID: {alert.get('secret_type', 'unknown')}",
        f"Push protection bypassed: {bypassed}",
    ]
    if locations:
        loc_strs = []
        for loc in locations[:5]:
            loc_detail = loc.get("details", {})
            loc_type = loc.get("type", "unknown")
            if loc_type == "commit":
                loc_strs.append(
                    f"commit {loc_detail.get('commit_sha', '?')[:8]} "
                    f"at {loc_detail.get('path', '?')}:{loc_detail.get('start_line', '?')}"
                )
            else:
                loc_strs.append(f"{loc_type}: {loc_detail}")
        description_parts.append("Locations: " + "; ".join(loc_strs))

    return {
        "id": f"github-secret-{full_name.replace('/', '-')}-{number}",
        "claw": "devclaw",
        "provider": "github",
        "title": f"Secret Exposed: {secret_type_display} in {repo_name}",
        "description": "\n".join(description_parts),
        "category": "secret_exposure",
        "severity": "critical",
        "resource_id": f"{full_name}#{number}",
        "resource_type": "GitRepository",
        "resource_name": full_name,
        "region": "global",
        "status": "OPEN",
        "remediation": (
            f"1. Immediately revoke the exposed {secret_type_display} credential. "
            "2. Remove the secret from git history using 'git filter-repo'. "
            "3. Enable GitHub secret scanning push protection to block future commits."
        ),
        "remediation_effort": "Medium",
        "risk_score": _sev_risk("critical"),
        "actively_exploited": False,
        "first_seen": alert.get("created_at", ""),
        "external_id": f"github:{full_name}:{number}",
    }


def _parse_code_alert(alert: dict, full_name: str) -> dict:
    number = alert.get("number", 0)
    rule = alert.get("rule", {})
    rule_severity = rule.get("severity", "warning")
    severity = _CODE_SCAN_SEVERITY.get(rule_severity, "medium")

    title = rule.get("description") or rule.get("id") or "Code Scanning Alert"
    instance = alert.get("most_recent_instance", {})
    location = instance.get("location", {})
    loc_str = ""
    if location:
        loc_str = (
            f" at {location.get('path', '?')}:"
            f"{location.get('start_line', '?')}-{location.get('end_line', '?')}"
        )

    description_parts = [
        f"Rule: {rule.get('id', 'unknown')} — {rule.get('description', '')}",
        f"Rule severity: {rule_severity}",
        f"Tool: {alert.get('tool', {}).get('name', 'unknown')}",
        f"Most recent instance{loc_str}: {instance.get('message', {}).get('text', '')}",
    ]
    if rule.get("help_uri"):
        description_parts.append(f"Reference: {rule['help_uri']}")

    return {
        "id": f"github-code-{full_name.replace('/', '-')}-{number}",
        "claw": "devclaw",
        "provider": "github",
        "title": title,
        "description": "\n".join(description_parts),
        "category": "code_scanning",
        "severity": severity,
        "resource_id": f"{full_name}#{number}",
        "resource_type": "GitRepository",
        "resource_name": full_name,
        "region": "global",
        "status": "OPEN",
        "remediation": rule.get("help", f"Review and fix the issue identified by rule {rule.get('id', 'unknown')}."),
        "remediation_effort": "Medium",
        "risk_score": _sev_risk(severity),
        "actively_exploited": False,
        "first_seen": alert.get("created_at", ""),
        "external_id": f"github:{full_name}:{number}",
    }


def _parse_dependabot_alert(alert: dict, full_name: str) -> dict:
    number = alert.get("number", 0)
    advisory = alert.get("security_advisory", {})
    vulnerability = alert.get("security_vulnerability", {})
    dependency = alert.get("dependency", {})
    package = dependency.get("package", {})
    package_name = package.get("name", "unknown")
    patched_version = vulnerability.get("first_patched_version", {}) or {}
    patched = patched_version.get("identifier", "unknown") if isinstance(patched_version, dict) else str(patched_version)
    affected_range = vulnerability.get("vulnerable_version_range", "unknown")

    raw_severity = vulnerability.get("severity", "medium")
    severity = raw_severity.lower() if raw_severity.lower() in _RISK_SCORES else "medium"

    cve_ids = [i["value"] for i in advisory.get("identifiers", []) if i.get("type") == "CVE"]
    cvss = advisory.get("cvss", {})
    cvss_score = cvss.get("score", "N/A") if cvss else "N/A"

    description_parts = [
        f"Package: {package_name} (ecosystem: {package.get('ecosystem', 'unknown')})",
        f"Affected versions: {affected_range}",
        f"Patched version: {patched}",
        f"Summary: {advisory.get('summary', '')}",
        f"CVEs: {', '.join(cve_ids) if cve_ids else 'None'}",
        f"CVSS score: {cvss_score}",
        f"Manifest path: {dependency.get('manifest_path', 'unknown')}",
    ]
    if advisory.get("description"):
        description_parts.append(f"Details: {advisory['description'][:500]}")

    return {
        "id": f"github-dependabot-{full_name.replace('/', '-')}-{number}",
        "claw": "devclaw",
        "provider": "github",
        "title": f"{advisory.get('summary', 'Vulnerability')} in {package_name}",
        "description": "\n".join(description_parts),
        "category": "vulnerable_dependency",
        "severity": severity,
        "resource_id": f"{full_name}#{number}",
        "resource_type": "GitRepository",
        "resource_name": full_name,
        "region": "global",
        "status": "OPEN",
        "remediation": f"Update {package_name} to {patched}",
        "remediation_effort": "Medium",
        "risk_score": _sev_risk(severity),
        "actively_exploited": False,
        "first_seen": alert.get("created_at", ""),
        "external_id": f"github:{full_name}:{number}",
    }


# ── Per-repo fetcher ───────────────────────────────────────────────────────────

async def _fetch_repo_alerts(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    full_name: str,
) -> list[dict]:
    """Fetch all alert types for one repo in parallel. Returns parsed findings."""

    async def _get(url: str, params: Optional[dict] = None) -> list[dict]:
        try:
            resp = await client.get(url, headers=headers, params=params, timeout=TIMEOUT)
            if resp.status_code in (403, 404, 422):
                # Feature not enabled or no access — skip silently
                return []
            if resp.status_code == 401:
                raise ValueError("GitHub PAT is invalid or expired")
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, list) else []
        except ValueError:
            raise
        except Exception as exc:
            logger.debug("GitHub API error for %s (%s): %s", full_name, url, exc)
            return []

    secret_task = _get(
        f"{GITHUB_API}/repos/{full_name}/secret-scanning/alerts",
        {"state": "open", "per_page": 50},
    )
    code_task = _get(
        f"{GITHUB_API}/repos/{full_name}/code-scanning/alerts",
        {"state": "open", "per_page": 50},
    )
    dependabot_task = _get(
        f"{GITHUB_API}/repos/{full_name}/dependabot/alerts",
        {"state": "open", "per_page": 50},
    )

    secret_raw, code_raw, dependabot_raw = await asyncio.gather(
        secret_task, code_task, dependabot_task
    )

    findings: list[dict] = []
    for alert in secret_raw:
        try:
            findings.append(_parse_secret_alert(alert, full_name))
        except Exception as exc:
            logger.debug("Failed to parse secret alert in %s: %s", full_name, exc)

    for alert in code_raw:
        try:
            findings.append(_parse_code_alert(alert, full_name))
        except Exception as exc:
            logger.debug("Failed to parse code alert in %s: %s", full_name, exc)

    for alert in dependabot_raw:
        try:
            findings.append(_parse_dependabot_alert(alert, full_name))
        except Exception as exc:
            logger.debug("Failed to parse dependabot alert in %s: %s", full_name, exc)

    return findings


# ── Public entry point ─────────────────────────────────────────────────────────

async def fetch_github_findings(db: AsyncSession) -> list[dict]:
    """
    Query GitHub REST API for security alerts across the user's repositories
    and return a list of normalised finding dicts ready for ingest_findings().

    Raises:
        ValueError: If no GitHub connector is configured, or if the PAT is invalid/expired.
    """
    # 1. Look up ALL connector rows for github (seed row + user-added row may coexist)
    result = await db.execute(
        text("SELECT id FROM connectors WHERE connector_type = 'github'")
    )
    rows = result.fetchall()
    if not rows:
        raise ValueError("GitHub connector not configured")

    # 2. Find the row that actually has a usable credential (skip seed
    #    placeholder rows). Either a PAT or an interactive device-code token.
    pat: str | None = None
    for row in rows:
        creds = secrets_manager.get_credential(str(row[0]))
        if not creds:
            continue
        device_token = await device_code_auth.resolve_access_token(creds)
        if device_token:
            pat = device_token
            break
        if creds.get("personal_access_token"):
            pat = creds["personal_access_token"]
            break

    if not pat:
        raise ValueError(
            "GitHub connector credentials not found — sign in or add a PAT in Connector Marketplace"
        )

    headers = _make_headers(pat)

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        # 3. List repos (up to 100)
        repos_resp = await client.get(
            f"{GITHUB_API}/user/repos",
            headers=headers,
            params={"per_page": 100, "affiliation": "owner,collaborator"},
            timeout=TIMEOUT,
        )
        if repos_resp.status_code == 401:
            raise ValueError("GitHub PAT is invalid or expired")
        repos_resp.raise_for_status()

        repos: list[dict] = repos_resp.json() if isinstance(repos_resp.json(), list) else []

        # Cap at 20 repos to avoid rate limits
        repos = repos[:20]

        if not repos:
            return []

        # 4. Fetch alerts for each repo in parallel, tolerating per-repo errors
        repo_tasks = [
            _fetch_repo_alerts(client, headers, repo["full_name"])
            for repo in repos
            if repo.get("full_name")
        ]

        results = await asyncio.gather(*repo_tasks, return_exceptions=True)

        all_findings: list[dict] = []
        for idx, res in enumerate(results):
            if isinstance(res, ValueError):
                # PAT invalid — propagate immediately
                raise res
            if isinstance(res, Exception):
                repo_name = repos[idx].get("full_name", f"repo[{idx}]")
                logger.warning("Skipping repo %s due to error: %s", repo_name, res)
                continue
            all_findings.extend(res)

    logger.info(
        "GitHub scan complete: %d repos scanned, %d findings collected",
        len(repos),
        len(all_findings),
    )
    return all_findings
