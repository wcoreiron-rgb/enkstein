"""
Enkstein — Intelligence Fetcher
==================================
Calls real public APIs for security intelligence data.
All sources here are FREE — no API key required (rate limits apply).

Sources:
  NVD  (nvd.nist.gov)       — CVE database with CVSS v3.1 scores
  EPSS (api.first.org)      — Exploit Prediction Scoring System
  CISA KEV (cisa.gov)       — Known Exploited Vulnerabilities catalogue
  MITRE ATT&CK (GitHub)     — Threat actor TTPs mapped to techniques
"""
import asyncio
import logging
from typing import Optional
import httpx

logger = logging.getLogger("intel_fetcher")

# ─── Public API endpoints ────────────────────────────────────────────────────

NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE   = "https://api.first.org/data/v1/epss"
CISA_KEV    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MITRE_ATT   = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

TIMEOUT = httpx.Timeout(30.0)


# ─── NVD — CVE lookup ────────────────────────────────────────────────────────

async def fetch_recent_cves(
    days_back: int = 30,
    cvss_min: float = 7.0,
    max_results: int = 50,
) -> list[dict]:
    """
    Fetch recent high/critical CVEs from NVD published in the last N days.
    Returns list of: {cve_id, description, cvss_score, severity, published, references}
    """
    from datetime import datetime, timedelta, timezone
    now   = datetime.now(timezone.utc)
    start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": start,
        "pubEndDate":   end,
        "cvssV3Severity": "HIGH",   # HIGH and CRITICAL
        "resultsPerPage": max_results,
    }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(NVD_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning(f"NVD fetch failed: {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descs  = cve.get("descriptions", [])
        desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # Extract CVSS v3.1 score
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity   = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_score = m.get("baseScore")
                severity   = m.get("baseSeverity", "UNKNOWN")
                break

        if cvss_score and cvss_score < cvss_min:
            continue

        results.append({
            "cve_id":      cve_id,
            "description": desc[:300],
            "cvss_score":  cvss_score,
            "severity":    severity,
            "published":   cve.get("published", ""),
            "references":  [r["url"] for r in cve.get("references", [])[:3]],
        })

    logger.info(f"NVD: fetched {len(results)} CVEs (last {days_back}d, CVSS≥{cvss_min})")
    return results


async def lookup_cve(cve_id: str) -> Optional[dict]:
    """Look up a single CVE by ID."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(NVD_BASE, params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve = vulns[0].get("cve", {})
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            return {"cve_id": cve_id, "description": desc[:300]}
    except Exception as e:
        logger.warning(f"NVD CVE lookup {cve_id} failed: {e}")
        return None


# ─── EPSS — Exploitation Probability ─────────────────────────────────────────

async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS (Exploit Prediction Scoring System) scores for a list of CVEs.
    Returns {cve_id: epss_score} where score is 0.0-1.0 (probability of exploitation in 30d).
    Score > 0.1 = watch. > 0.5 = high risk. > 0.9 = patch now.
    """
    if not cve_ids:
        return {}

    # EPSS accepts comma-separated CVE IDs
    chunk_size = 30
    scores = {}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for i in range(0, len(cve_ids), chunk_size):
                chunk = cve_ids[i:i+chunk_size]
                resp = await client.get(EPSS_BASE, params={"cve": ",".join(chunk)})
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []):
                    cve  = item.get("cve", "")
                    epss = float(item.get("epss", 0))
                    scores[cve] = epss
    except Exception as e:
        logger.warning(f"EPSS fetch failed: {e}")

    logger.info(f"EPSS: scored {len(scores)} CVEs")
    return scores


# ─── CISA KEV — Actively Exploited Vulnerabilities ───────────────────────────

async def fetch_cisa_kev() -> set[str]:
    """
    Download the CISA Known Exploited Vulnerabilities catalogue.
    Returns a set of CVE IDs that are being actively exploited in the wild.
    CISA requires federal agencies to patch these on a fixed deadline.
    Updated daily by CISA. No API key needed.
    """
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(CISA_KEV)
            resp.raise_for_status()
            data = resp.json()
            kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
            logger.info(f"CISA KEV: loaded {len(kev_set)} actively exploited CVEs")
            return kev_set
    except Exception as e:
        logger.warning(f"CISA KEV fetch failed: {e}")
        return set()


# ─── MITRE ATT&CK — Threat Technique Lookup ──────────────────────────────────

_MITRE_CACHE: Optional[dict] = None

async def fetch_mitre_techniques(limit: int = 20) -> list[dict]:
    """
    Load MITRE ATT&CK enterprise techniques.
    Cached in memory after first call.
    Returns: [{technique_id, name, description, tactics}]
    """
    global _MITRE_CACHE

    if _MITRE_CACHE is not None:
        techniques = _MITRE_CACHE.get("techniques", [])
        return techniques[:limit]

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            resp = await client.get(MITRE_ATT)
            resp.raise_for_status()
            bundle = resp.json()
    except Exception as e:
        logger.warning(f"MITRE ATT&CK fetch failed: {e}")
        return []

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        tech_id  = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            ""
        )
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append({
            "technique_id":  tech_id,
            "name":          obj.get("name", ""),
            "description":   (obj.get("description") or "")[:200],
            "tactics":       tactics,
        })

    _MITRE_CACHE = {"techniques": techniques}
    logger.info(f"MITRE ATT&CK: loaded {len(techniques)} techniques")
    return techniques[:limit]


# ─── Composite: Full CVE + EPSS + KEV scan ───────────────────────────────────

async def run_vulnerability_scan(
    days_back: int = 30,
    cvss_min: float = 7.0,
    max_cves: int = 50,
) -> dict:
    """
    Main entry point for the CVE Vulnerability Scanner agent.
    Calls NVD + EPSS + CISA KEV in parallel, merges results.

    Returns:
    {
        total_cves: int,
        critical: [...],
        high: [...],
        actively_exploited: [...],   # in CISA KEV
        epss_high: [...],            # EPSS > 0.1
        summary_stats: {...}
    }
    """
    # Fetch CVEs + KEV in parallel
    cves_task = fetch_recent_cves(days_back, cvss_min, max_cves)
    kev_task  = fetch_cisa_kev()
    cves, kev_set = await asyncio.gather(cves_task, kev_task)

    if not cves:
        return {
            "total_cves": 0,
            "critical": [],
            "high": [],
            "actively_exploited": [],
            "epss_high": [],
            "summary_stats": {"source": "NVD", "days_back": days_back, "status": "no_results"},
        }

    # Fetch EPSS scores for all CVEs
    cve_ids = [c["cve_id"] for c in cves]
    epss_map = await fetch_epss_scores(cve_ids)

    # Enrich CVEs
    for cve in cves:
        cid  = cve["cve_id"]
        cve["epss_score"]          = epss_map.get(cid, 0.0)
        cve["actively_exploited"]  = cid in kev_set
        cve["epss_risk"]           = (
            "critical" if cve["epss_score"] > 0.5
            else "high" if cve["epss_score"] > 0.1
            else "low"
        )

    # Sort by combined risk
    cves.sort(key=lambda c: (
        c.get("actively_exploited", False),
        c.get("epss_score", 0),
        c.get("cvss_score", 0)
    ), reverse=True)

    actively_exploited = [c for c in cves if c["actively_exploited"]]
    epss_high          = [c for c in cves if c["epss_score"] > 0.1]
    critical           = [c for c in cves if c.get("severity") == "CRITICAL"]
    high               = [c for c in cves if c.get("severity") == "HIGH"]

    return {
        "total_cves":          len(cves),
        "critical":            critical,
        "high":                high,
        "actively_exploited":  actively_exploited,
        "epss_high":           epss_high,
        "all_cves":            cves[:20],   # top 20 for context window
        "summary_stats": {
            "source":              "NVD + EPSS + CISA KEV",
            "days_back":           days_back,
            "cvss_min":            cvss_min,
            "total_found":         len(cves),
            "critical_count":      len(critical),
            "high_count":          len(high),
            "actively_exploited":  len(actively_exploited),
            "epss_high_count":     len(epss_high),
            "kev_catalogue_size":  len(kev_set),
        },
    }
