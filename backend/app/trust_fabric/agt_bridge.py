"""
Trust Fabric — Microsoft AGT Bridge
=====================================
Integrates the Agent Governance Toolkit (agent_compliance) into RegentClaw.

What AGT Python provides (and where it plugs in):
  PromptDefenseEvaluator  → ArcClaw: 12-vector prompt injection audit
  SupplyChainGuard        → Module/connector registration: typosquatting, drift, freshness
  SecurityScanner         → Skill/module scanning: directory-level security checks
  governance.validate_attestation → ComplianceClaw: attestation validation

What AGT Python does NOT provide (handled by our Trust Fabric):
  Runtime policy enforcement (PolicyEvaluator) — TypeScript/.NET only
  Execution rings / sandboxing — not in Python SDK
  Zero-trust identity (Ed25519/ML-DSA-65) — not in Python SDK

Our custom Trust Fabric handles runtime enforcement.
AGT handles scanning, audit intelligence, and supply chain security.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _resolve_repo_scoped_path(untrusted_path: str) -> Path:
    """
    Resolve and constrain an untrusted file path to the repository root.
    Rejects absolute paths and traversal patterns.
    """
    raw = Path(untrusted_path)
    candidate = raw.resolve(strict=False) if raw.is_absolute() else (_REPO_ROOT / raw).resolve(strict=False)
    try:
        candidate.relative_to(_REPO_ROOT)
    except ValueError as exc:
        raise ValueError("path escapes repository root") from exc
    return candidate

# ── AGT availability check ───────────────────────────────────────────────────

try:
    from agent_compliance import (
        PromptDefenseEvaluator,
        PromptDefenseConfig,
        SupplyChainGuard,
        SupplyChainConfig,
    )
    from agent_compliance.security.scanner import SecurityScanner
    AGT_AVAILABLE = True
    logger.info("AGT (agent_compliance) loaded — compliance/audit layer active")
except ImportError:
    AGT_AVAILABLE = False
    logger.warning(
        "AGT not installed — falling back to built-in scanning. "
        "Run: pip install agent-governance-toolkit"
    )


# ── Prompt Defense (ArcClaw integration) ─────────────────────────────────────

@dataclass
class PromptAuditResult:
    """Result from AGT prompt defense evaluation."""
    is_injection_risk: bool
    risk_score: float                          # 0–100
    findings: list[dict] = field(default_factory=list)
    vectors_flagged: list[str] = field(default_factory=list)
    recommendation: str = ""
    agt_used: bool = False


def audit_prompt(text: str) -> PromptAuditResult:
    """
    Run AGT's 12-vector prompt injection audit on a prompt.

    DESIGN NOTE — why keyword scanner drives the blocking decision:
    AGT's PromptDefenseEvaluator reports all 12 defense vectors as "findings"
    for *every* prompt, regardless of whether the prompt is actually malicious.
    The vector names and severities are populated even for benign input like
    "hello". This means AGT's `is_injection_risk` and cumulative `risk_score`
    are structurally unreliable for binary block/allow decisions.

    Strategy:
      • AGT is still called and its vector list is kept for audit/visibility.
      • The BLOCKING decision (`is_injection_risk`, `risk_score`) comes from our
        keyword scanner, which is deterministic and well-calibrated.
      • Real attacks contain injection keywords → keyword scanner fires → blocked.
      • Benign prompts → no keywords → allowed, even if AGT reports 12 vectors.
    """
    # Keyword result is always computed — it drives the security decision.
    keyword_result = _fallback_prompt_audit(text)

    if not AGT_AVAILABLE:
        return keyword_result

    try:
        config    = PromptDefenseConfig()
        evaluator = PromptDefenseEvaluator(config)
        report    = evaluator.evaluate(text)

        # Collect AGT vector data for the audit trail only — do NOT use these
        # to set is_injection_risk or risk_score (see design note above).
        agt_findings: list[dict] = []
        vectors_flagged: list[str] = []

        for f in (getattr(report, "findings", None) or []):
            vector = (
                getattr(f, "vector",     None)
                or getattr(f, "name",    None)
                or getattr(f, "type",    None)
                or "unknown"
            )
            sev = (
                getattr(f, "severity", None)
                or getattr(f, "level",  None)
                or "unknown"
            )
            agt_findings.append({
                "vector":      vector,
                "severity":    sev,
                "description": getattr(f, "description", None) or getattr(f, "message", None) or "",
            })
            vectors_flagged.append(vector)

        logger.debug(
            "AGT audit complete — %d vectors, keyword_risk=%s, score=%.0f",
            len(agt_findings), keyword_result.is_injection_risk, keyword_result.risk_score,
        )

        # Merge: use keyword scanner's decision but surface AGT's vector list
        return PromptAuditResult(
            is_injection_risk = keyword_result.is_injection_risk,
            risk_score        = keyword_result.risk_score,
            findings          = agt_findings,          # AGT data for audit visibility
            vectors_flagged   = list(set(vectors_flagged)),
            recommendation    = getattr(report, "recommendation", ""),
            agt_used          = True,
        )

    except Exception as e:
        logger.warning("AGT prompt audit failed, using fallback: %s", e)
        return keyword_result


def _fallback_prompt_audit(text: str) -> PromptAuditResult:
    """Basic prompt risk check when AGT is unavailable."""
    injection_patterns = [
        "ignore previous instructions",
        "disregard your instructions",
        "you are now",
        "pretend you are",
        "act as",
        "jailbreak",
        "bypass restrictions",
        "system prompt",
        "override",
    ]
    text_lower = text.lower()
    hits = [p for p in injection_patterns if p in text_lower]
    risk_score = min(len(hits) * 20.0, 100.0)
    return PromptAuditResult(
        is_injection_risk=bool(hits),
        risk_score=risk_score,
        findings=[{"vector": "keyword_match", "pattern": h} for h in hits],
        vectors_flagged=["keyword_match"] if hits else [],
        recommendation="Review prompt for injection patterns." if hits else "",
        agt_used=False,
    )


# ── Supply Chain Guard (Module/Connector registration) ───────────────────────

@dataclass
class SupplyChainResult:
    """Result from AGT supply chain scan."""
    is_safe: bool
    risk_score: float
    issues: list[dict] = field(default_factory=list)
    typosquatting_hits: list[str] = field(default_factory=list)
    outdated_packages: list[str] = field(default_factory=list)
    agt_used: bool = False


def scan_requirements(requirements_path: str) -> SupplyChainResult:
    """
    Run AGT SupplyChainGuard on a requirements.txt file.
    Used when validating backend module dependencies.
    """
    if not AGT_AVAILABLE:
        return SupplyChainResult(is_safe=True, risk_score=0.0, agt_used=False)

    try:
        config = SupplyChainConfig()
        guard = SupplyChainGuard(config)
        path = _resolve_repo_scoped_path(requirements_path)
        if not path.exists():
            return SupplyChainResult(is_safe=True, risk_score=0.0, agt_used=True)

        result = guard.check_requirements(str(path))
        issues = []
        typo_hits = []
        outdated = []
        risk_score = 0.0

        if hasattr(result, "findings") and result.findings:
            for f in result.findings:
                finding_type = getattr(f, "finding_type", "unknown")
                pkg = getattr(f, "package", "unknown")
                issues.append({
                    "type": finding_type,
                    "package": pkg,
                    "detail": getattr(f, "detail", ""),
                })
                if "typosquat" in finding_type.lower():
                    typo_hits.append(pkg)
                    risk_score += 40
                elif "outdated" in finding_type.lower() or "stale" in finding_type.lower():
                    outdated.append(pkg)
                    risk_score += 10

        risk_score = min(risk_score, 100.0)
        return SupplyChainResult(
            is_safe=risk_score < 40,
            risk_score=risk_score,
            issues=issues,
            typosquatting_hits=typo_hits,
            outdated_packages=outdated,
            agt_used=True,
        )

    except ValueError:
        logger.warning("Rejected requirements scan path outside repository root")
        return SupplyChainResult(
            is_safe=False,
            risk_score=100.0,
            issues=[{"type": "path_policy_violation", "package": "n/a", "detail": "path escapes repository root"}],
            agt_used=True,
        )
    except Exception:
        logger.warning("AGT supply chain scan failed")
        return SupplyChainResult(is_safe=True, risk_score=0.0, agt_used=False)


def scan_package_json(package_json_path: str) -> SupplyChainResult:
    """Run AGT SupplyChainGuard on a package.json file."""
    if not AGT_AVAILABLE:
        return SupplyChainResult(is_safe=True, risk_score=0.0, agt_used=False)

    try:
        config = SupplyChainConfig()
        guard = SupplyChainGuard(config)
        path = _resolve_repo_scoped_path(package_json_path)
        if not path.exists():
            return SupplyChainResult(is_safe=True, risk_score=0.0, agt_used=True)
        result = guard.check_package_json(str(path))

        issues = []
        risk_score = 0.0
        if hasattr(result, "findings") and result.findings:
            for f in result.findings:
                issues.append({
                    "type": getattr(f, "finding_type", "unknown"),
                    "package": getattr(f, "package", "unknown"),
                    "detail": getattr(f, "detail", ""),
                })
                risk_score += 15

        risk_score = min(risk_score, 100.0)
        return SupplyChainResult(
            is_safe=risk_score < 40,
            risk_score=risk_score,
            issues=issues,
            agt_used=True,
        )
    except ValueError:
        logger.warning("Rejected package.json scan path outside repository root")
        return SupplyChainResult(
            is_safe=False,
            risk_score=100.0,
            issues=[{"type": "path_policy_violation", "package": "n/a", "detail": "path escapes repository root"}],
            agt_used=True,
        )
    except Exception:
        logger.warning("AGT package.json scan failed")
        return SupplyChainResult(is_safe=True, risk_score=0.0, agt_used=False)


# ── Security Scanner (Module/Skill scanning) ──────────────────────────────────

@dataclass
class ModuleScanResult:
    """Result from AGT directory security scan."""
    is_safe: bool
    risk_score: float
    findings: list[dict] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    agt_used: bool = False


def scan_module_directory(directory_path: str) -> ModuleScanResult:
    """
    Run AGT SecurityScanner on a module or skill directory.
    Detects hardcoded secrets, unsafe patterns, injection risks.
    """
    if not AGT_AVAILABLE:
        return ModuleScanResult(is_safe=True, risk_score=0.0, agt_used=False)

    try:
        scanner = SecurityScanner()
        try:
            path = Path(directory_path).resolve(strict=False)
            path.relative_to(_REPO_ROOT)
        except ValueError:
            logger.warning("Rejected AGT module scan path outside repository root")
            return ModuleScanResult(is_safe=False, risk_score=100.0, agt_used=True)

        if not path.exists() or not path.is_dir():
            return ModuleScanResult(is_safe=True, risk_score=0.0, agt_used=True)

        results = scanner.scan_directory(str(path))
        findings = []
        critical = 0
        high = 0
        risk_score = 0.0

        if results:
            for finding in (results if isinstance(results, list) else []):
                sev = getattr(finding, "severity", "medium")
                findings.append({
                    "file": getattr(finding, "file", ""),
                    "line": getattr(finding, "line", 0),
                    "severity": sev,
                    "message": getattr(finding, "message", str(finding)),
                })
                if sev == "critical":
                    critical += 1
                    risk_score += 40
                elif sev == "high":
                    high += 1
                    risk_score += 25
                elif sev == "medium":
                    risk_score += 10

        risk_score = min(risk_score, 100.0)
        return ModuleScanResult(
            is_safe=critical == 0 and risk_score < 50,
            risk_score=risk_score,
            findings=findings,
            critical_count=critical,
            high_count=high,
            agt_used=True,
        )

    except Exception:
        logger.warning("AGT module directory scan failed")
        return ModuleScanResult(is_safe=True, risk_score=0.0, agt_used=False)


# ── Status endpoint ───────────────────────────────────────────────────────────

def agt_status() -> dict[str, Any]:
    """Return AGT integration status for the platform dashboard."""
    return {
        "agt_available": AGT_AVAILABLE,
        "version": "3.2.2" if AGT_AVAILABLE else None,
        "capabilities": {
            "prompt_defense": AGT_AVAILABLE,       # 12-vector injection audit (ArcClaw)
            "supply_chain_guard": AGT_AVAILABLE,   # Typosquatting/drift (module reg)
            "security_scanner": AGT_AVAILABLE,     # Directory scanning (skill security)
            "runtime_enforcement": False,           # TypeScript/.NET only — our Trust Fabric handles this
            "execution_rings": False,               # TypeScript/.NET only
            "zero_trust_identity": False,           # TypeScript/.NET only
        },
        "runtime_enforcement": "RegentClaw Trust Fabric (custom — deterministic policy engine)",
        "note": (
            "AGT Python covers compliance/audit/scanning. "
            "Runtime policy enforcement, execution rings, and ZT identity "
            "are TypeScript/.NET SDK features — handled by RegentClaw Trust Fabric."
        ),
    }
