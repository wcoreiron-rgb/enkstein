#!/usr/bin/env python3
"""
RegentClaw CI supply-chain policy gate.

Fails CI when dependency audit reports exceed configured thresholds.
"""
from __future__ import annotations

import argparse
import json
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
    args = parser.parse_args()

    pip_counts = merge_counts(
        pip_audit_vulnerability_counts(_read_json(args.pip_report)),
        pip_audit_vulnerability_counts(_read_json(args.pip_test_report)),
    )
    npm_counts = npm_vulnerability_counts(_read_json(args.npm_report))

    failures: list[str] = []
    failures.extend(_check_threshold("pip-audit", pip_counts, args))
    failures.extend(_check_threshold("npm-audit", npm_counts, args))

    print("Supply-chain policy evaluation")
    print(f"  pip-audit: {pip_counts}")
    print(f"  npm-audit: {npm_counts}")

    if failures:
        print("Policy violations:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("Policy check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
