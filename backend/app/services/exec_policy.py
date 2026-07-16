"""
Enkstein — Governed Execution policy engine
Evaluates whether a shell/browser/credential/production request is allowed,
needs approval, or should be blocked outright.
"""
from __future__ import annotations

from typing import Any

# ─── risk patterns ────────────────────────────────────────────────────────────

# Shell commands that require approval regardless of environment
_APPROVAL_SNIPPETS = (
    "rm -rf", "chmod 777", "chown", "dd if=", "mkfs", "fdisk", "shutdown", "reboot",
    "iptables", "ufw", "systemctl stop", "systemctl disable", "systemctl mask",
    "kubectl delete deployment", "kubectl delete statefulset", "kubectl delete all",
    "kubectl scale deployment", "kubectl scale statefulset", "kubectl rollout deployment",
    "kubectl rollout statefulset", "helm uninstall", "terraform destroy", "terraform apply",
    "terraform import", "aws ec2 delete", "aws ec2 create", "aws ec2 put", "aws ec2 update",
    "aws iam delete", "aws iam create", "aws iam put", "aws iam update", "aws s3 delete",
    "aws s3 create", "aws s3 put", "aws s3 update", "aws rds delete", "aws rds create",
    "aws rds put", "aws rds update", "aws lambda delete", "aws lambda create",
    "aws lambda put", "aws lambda update",
)

# Shell commands that are always blocked
_BLOCKED_SNIPPETS = (
    "curl ", "| sh", "wget ", "bash -c", "eval(", "cat /etc/shadow", "cat /etc/passwd",
    "grep root", "ncat", "socat", "base64 -d", "export aws_secret", "printenv",
)

# Production keywords
_PROD_WORDS = ("prod", "production", "live", "prd")


def _contains_approval_pattern(command: str) -> bool:
    c = command.lower()
    return any(snippet in c for snippet in _APPROVAL_SNIPPETS)


def _contains_blocked_pattern(command: str) -> bool:
    c = command.lower()
    if ("curl " in c or "wget " in c) and "| sh" in c:
        return True
    if "bash -c" in c and "curl " in c:
        return True
    if "python" in c and "exec(" in c and "os." in c:
        return True
    if "cat /etc/passwd" in c and "grep root" in c:
        return True
    if ("nc -e" in c) or ("nc -l" in c):
        return True
    if "base64 -d" in c and ("| sh" in c or "| bash" in c):
        return True
    if "printenv" in c and "secret" in c:
        return True
    return any(snippet in c for snippet in _BLOCKED_SNIPPETS)


def _is_production_command(command: str) -> bool:
    c = command.lower()
    return any(word in c for word in _PROD_WORDS)


def _risk_score(channel: str, command: str, environment: str, requested_by: str) -> dict:
    """
    Compute risk score (0-100) and risk_level for a request.
    """
    score  = 20  # baseline
    flags  = []

    if _contains_blocked_pattern(command):
        return {"score": 100, "level": "critical", "flags": ["blocked_command_pattern"], "blocked": True}

    if environment in ("prod", "production", "live", "prd") or _is_production_command(command):
        score += 40
        flags.append("production_environment")

    if _contains_approval_pattern(command):
        score += 30
        flags.append("destructive_or_privileged_command")

    if channel == "shell":
        score += 10
    if channel == "credential":
        score += 15
        flags.append("credential_access")
    if channel == "production":
        score += 25
        flags.append("production_gate")

    if "root" in requested_by.lower() or "admin" in requested_by.lower():
        score += 5

    score   = min(score, 99)
    level   = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
    return {"score": score, "level": level, "flags": flags, "blocked": False}


def evaluate_exec_request(
    channel:       str,
    command:       str,
    environment:   str,
    requested_by:  str,
    justification: str,
    agent_id:      str = "",
) -> dict[str, Any]:
    """
    Full policy evaluation for a governed execution request.
    Returns: { decision, risk_level, trust_score, policy_flags, requires_approval, reason }
    """
    risk = _risk_score(channel, command, environment, requested_by)

    if risk["blocked"]:
        return {
            "decision":          "blocked",
            "risk_level":        "critical",
            "trust_score":       0.0,
            "policy_flags":      risk["flags"],
            "requires_approval": False,
            "reason":            "Command matches blocked pattern — refused by security policy",
        }

    flags             = list(risk["flags"])
    requires_approval = False
    decision          = "allowed"

    # Production always requires dual approval
    if channel == "production" or "production_environment" in flags:
        requires_approval = True
        decision          = "requires_approval"
        flags.append("production_dual_approval_required")

    # High-risk operations require approval
    elif risk["level"] in ("critical", "high"):
        requires_approval = True
        decision          = "requires_approval"

    # Missing justification for privileged ops
    if "destructive_or_privileged_command" in flags and not justification.strip():
        flags.append("justification_required")
        if decision == "allowed":
            decision          = "requires_approval"
            requires_approval = True

    trust_score = max(0.0, 100.0 - risk["score"])

    return {
        "decision":          decision,
        "risk_level":        risk["level"],
        "trust_score":       round(trust_score, 1),
        "policy_flags":      flags,
        "requires_approval": requires_approval,
        "reason":            (
            "Blocked by security policy" if decision == "blocked" else
            "Requires approval — high-risk or production operation" if requires_approval else
            "Allowed"
        ),
    }


# ─── Ring policy integration ──────────────────────────────────────────────────

from app.services.ring_policy import classify_ring, evaluate_ring  # noqa: E402


def apply_ring_policy(action_type: str, channel: str, trust_score: float, caller_role: str) -> dict:
    """Classify action into ring and evaluate enforcement. Returns ring policy result."""
    ring = classify_ring(action_type, channel)
    result = evaluate_ring(ring, trust_score, caller_role)
    result["ring"] = ring
    return result
