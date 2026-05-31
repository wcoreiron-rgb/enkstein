#!/usr/bin/env python3
"""
RegentClaw CI supply-chain policy gate.

Fails CI when dependency audit reports exceed configured thresholds.
"""
from __future__ import annotations

import argparse
import json
from datetime import date
import sys
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def npm_vulnerability_counts(data: Any) -> dict[str, int]:
    if not isinstance(data, dict):
        return {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    meta = data.get("metadata", {})
    vulns = meta.get("vulnerabilities", {}) if isinstance(meta, dict) else {}
    return {
        "critical": int(vulns.get("critical", 0) or 0),
        "high": int(vulns.get("high", 0) or 0),
        "moderate": int(vulns.get("moderate", 0) or 0),
        "low": int(vulns.get("low", 0) or 0),
    }


def pip_audit_vulnerability_counts(data: Any) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    if not isinstance(data, list):
        return counts

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "moderate",
        "moderate": "moderate",
        "low": "low",
    }

    # pip-audit JSON format: list[{"name","version","vulns":[...]}]
    for dep in data:
        if not isinstance(dep, dict):
            continue
        vulns = dep.get("vulns", [])
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            aliases = vuln.get("aliases", [])
            sev = None
            # pip-audit does not always emit severity; parse if present.
            if isinstance(vuln.get("severity"), str):
                sev = vuln.get("severity", "").lower().strip()
            elif isinstance(vuln.get("cvss"), dict):
                score = vuln.get("cvss", {}).get("score")
                if isinstance(score, (float, int)):
                    if score >= 9.0:
                        sev = "critical"
                    elif score >= 7.0:
                        sev = "high"
                    elif score >= 4.0:
                        sev = "moderate"
                    else:
                        sev = "low"
            # fallback when severity unavailable
            normalized = severity_map.get(sev or "", "high")
            counts[normalized] += 1
            # keep aliases referenced to avoid lint "unused" in strict contexts
            _ = aliases
    return counts


def merge_counts(*items: dict[str, int]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    for item in items:
        for k in out:
            out[k] += int(item.get(k, 0) or 0)
    return out


def _parse_iso_date(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        return date.fromisoformat(raw.strip())
    except Exception:
        return None


def _active_waiver_counts(baseline: Any, source_key: str) -> dict[str, int]:
    if not isinstance(baseline, dict):
        return {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    waivers = baseline.get("waivers", {})
    source = waivers.get(source_key, {}) if isinstance(waivers, dict) else {}
    if not isinstance(source, dict):
        return {"critical": 0, "high": 0, "moderate": 0, "low": 0}

    expires_on = _parse_iso_date(source.get("expires_on"))
    if expires_on and date.today() > expires_on:
        return {"critical": 0, "high": 0, "moderate": 0, "low": 0}

    allowed = source.get("allowed_existing", {})
    if not isinstance(allowed, dict):
        return {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    return {
        "critical": int(allowed.get("critical", 0) or 0),
        "high": int(allowed.get("high", 0) or 0),
        "moderate": int(allowed.get("moderate", 0) or 0),
        "low": int(allowed.get("low", 0) or 0),
    }


def apply_waiver(current: dict[str, int], waiver: dict[str, int]) -> dict[str, int]:
    return {
        k: max(0, int(current.get(k, 0) or 0) - int(waiver.get(k, 0) or 0))
        for k in ("critical", "high", "moderate", "low")
    }


def _check_threshold(name: str, counts: dict[str, int], args: argparse.Namespace) -> list[str]:
    failures: list[str] = []
    if counts["critical"] > args.max_critical:
        failures.append(f"{name}: critical={counts['critical']} exceeds max_critical={args.max_critical}")
    if counts["high"] > args.max_high:
        failures.append(f"{name}: high={counts['high']} exceeds max_high={args.max_high}")
    if counts["moderate"] > args.max_moderate:
        failures.append(f"{name}: moderate={counts['moderate']} exceeds max_moderate={args.max_moderate}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce RegentClaw supply-chain vulnerability thresholds.")
    parser.add_argument("--pip-report", type=Path, required=True)
    parser.add_argument("--pip-test-report", type=Path, required=True)
    parser.add_argument("--npm-report", type=Path, required=True)
    parser.add_argument("--max-critical", type=int, default=0)
    parser.add_argument("--max-high", type=int, default=0)
    parser.add_argument("--max-moderate", type=int, default=5)
    parser.add_argument("--baseline", type=Path, default=None)
    args = parser.parse_args()

    baseline = _read_json(args.baseline) if args.baseline else {}

    pip_counts = merge_counts(
        pip_audit_vulnerability_counts(_read_json(args.pip_report)),
        pip_audit_vulnerability_counts(_read_json(args.pip_test_report)),
    )
    npm_counts = npm_vulnerability_counts(_read_json(args.npm_report))
    pip_waiver = _active_waiver_counts(baseline, "pip_audit")
    npm_waiver = _active_waiver_counts(baseline, "npm_audit")
    pip_effective = apply_waiver(pip_counts, pip_waiver)
    npm_effective = apply_waiver(npm_counts, npm_waiver)

    failures: list[str] = []
    failures.extend(_check_threshold("pip-audit", pip_effective, args))
    failures.extend(_check_threshold("npm-audit", npm_effective, args))

    print("Supply-chain policy evaluation")
    print(f"  pip-audit: {pip_counts}")
    print(f"  npm-audit: {npm_counts}")
    if args.baseline:
        print(f"  baseline: {args.baseline}")
        print(f"  pip waiver: {pip_waiver}")
        print(f"  npm waiver: {npm_waiver}")
        print(f"  pip effective: {pip_effective}")
        print(f"  npm effective: {npm_effective}")

    if failures:
        print("Policy violations:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("Policy check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
