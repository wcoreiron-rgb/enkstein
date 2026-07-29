# NOTE: mirrored from backend/app/services/ring_policy.py — keep in sync via scripts/sync_core.sh.
# This module is intentionally dependency-light (stdlib + cryptography) so it
# can run embedded with no Enkstein server.
"""
Enkstein — Execution Ring Policy
Implements ring-based isolation (ring0..ring3) for governed actions.
Ring levels map to privilege tiers with deterministic enforcement rules.
"""
from __future__ import annotations

# ─── Action → Ring mapping ─────────────────────────────────────────────────────
# ring0: System/kernel level — completely blocked, no exceptions
# ring1: Privileged — requires 2 approvals
# ring2: Standard — requires 1 approval OR conditional auto-allow if trust_score >= 80
# ring3: Unprivileged — auto-allowed, no approval required

ACTION_RING_MAP: dict[str, str] = {
    # ring0 — system level (blocked unconditionally)
    "kernel_exec":              "ring0",
    "system_call":              "ring0",
    "load_kernel_module":       "ring0",
    "raw_socket":               "ring0",
    "ptrace":                   "ring0",
    "modify_boot":              "ring0",
    # ring1 — privileged
    "quarantine_device":        "ring1",
    "suspend_user":             "ring1",
    "revoke_sessions":          "ring1",
    "disable_iam_user":         "ring1",
    "deactivate_access_key":    "ring1",
    "attach_deny_policy":       "ring1",
    "delete_secret":            "ring1",
    "revoke_token":             "ring1",
    # ring2 — standard
    "create_ticket":            "ring2",
    "send_alert":               "ring2",
    "slack_message":            "ring2",
    "force_mfa_reset":          "ring2",
    "remove_group_member":      "ring2",
    "kill_process":             "ring2",
    "unquarantine_device":      "ring2",
    "webhook":                  "ring2",
    # ring3 — unprivileged
    "read_logs":                "ring3",
    "get_findings":             "ring3",
    "lookup_cve":               "ring3",
    "list_resources":           "ring3",
    "get_status":               "ring3",
}

# ─── Channel → Ring mapping ────────────────────────────────────────────────────

CHANNEL_RING_MAP: dict[str, str] = {
    # Channels that imply privileged execution
    "shell":        "ring1",
    "credential":   "ring1",
    "kernel":       "ring0",
    "system":       "ring0",
    # Standard channels
    "production":   "ring2",
    "browser":      "ring2",
    "webhook":      "ring2",
    # Low-privilege channels
    "read":         "ring3",
    "api":          "ring3",
    "query":        "ring3",
}

# ─── Per-ring enforcement config ──────────────────────────────────────────────

RING_REQUIREMENTS: dict[str, dict] = {
    "ring0": {
        "blocked":            True,
        "approvals_required": 0,
        "trust_min":          None,  # irrelevant — always blocked
        "description":        "System/kernel level. Completely blocked for all agents. No exceptions.",
    },
    "ring1": {
        "blocked":            False,
        "approvals_required": 2,
        "trust_min":          None,  # trust score alone cannot bypass ring1
        "allowed_roles":      {"admin", "security_admin", "super_admin"},
        "description":        "Privileged. Requires 2 approvals regardless of trust score.",
    },
    "ring2": {
        "blocked":            False,
        "approvals_required": 1,
        "trust_min":          80.0,  # auto-allow if trust_score >= 80
        "allowed_roles":      {"admin", "security_admin", "super_admin", "analyst"},
        "description":        "Standard. 1 approval required, or auto-allowed if trust_score >= 80.",
    },
    "ring3": {
        "blocked":            False,
        "approvals_required": 0,
        "trust_min":          None,  # always auto-allowed
        "allowed_roles":      None,  # all roles
        "description":        "Unprivileged. Auto-allowed, no approval required.",
    },
}

# Roles that cannot request ring1 actions
_RING1_BLOCKED_ROLES = {"viewer", "readonly", "guest", "monitor"}


# ─── Public API ───────────────────────────────────────────────────────────────

def ring_to_int(ring: str) -> int:
    """Convert ring name to integer (0-3)."""
    mapping = {"ring0": 0, "ring1": 1, "ring2": 2, "ring3": 3}
    return mapping.get(ring, 2)  # unknown defaults to ring2


def classify_ring(action_type: str, channel: str | None = None) -> str:
    """
    Classify a request into a ring level.

    Resolution order:
    1. action_type lookup in ACTION_RING_MAP
    2. channel lookup in CHANNEL_RING_MAP
    3. Default to ring2 (unknown → treated as standard, requires approval)

    The more restrictive ring wins when both action and channel are provided:
    e.g. ring3 action on a ring1 channel → ring1 applies.
    """
    action_ring = ACTION_RING_MAP.get(action_type or "")
    channel_ring = CHANNEL_RING_MAP.get(channel or "")

    if action_ring and channel_ring:
        # Take the more restrictive (lower ring number = higher privilege = stricter)
        return action_ring if ring_to_int(action_ring) <= ring_to_int(channel_ring) else channel_ring

    if action_ring:
        return action_ring

    if channel_ring:
        return channel_ring

    # Unknown action_type → default to ring2 (requires 1 approval)
    return "ring2"


def evaluate_ring(ring: str, trust_score: float, caller_role: str) -> dict:
    """
    Evaluate whether a request in the given ring is allowed.

    Args:
        ring:        Ring level string (ring0..ring3)
        trust_score: Caller trust score 0..100
        caller_role: Caller role string (e.g. "admin", "viewer")

    Returns:
        {
            "allowed":            bool,
            "requires_approval":  bool,
            "approvals_required": int,
            "policy_name":        str,
            "deny_reason":        str | None,
        }
    """
    req = RING_REQUIREMENTS.get(ring, RING_REQUIREMENTS["ring2"])
    policy_name = "execution_ring_policy"

    # ring0 — always blocked, no exceptions
    if req["blocked"]:
        return {
            "allowed":            False,
            "requires_approval":  False,
            "approvals_required": 0,
            "policy_name":        "execution_ring_violation",
            "deny_reason":        f"Ring 0 (system/kernel) actions are unconditionally blocked. No agent or role may execute system-level operations.",
        }

    # ring1 — privileged: check role eligibility before approval logic
    if ring == "ring1":
        role_lower = (caller_role or "").lower()
        if role_lower in _RING1_BLOCKED_ROLES:
            return {
                "allowed":            False,
                "requires_approval":  False,
                "approvals_required": 0,
                "policy_name":        "execution_ring_violation",
                "deny_reason":        f"Role '{caller_role}' is not permitted to request ring1 (privileged) actions. Requires admin or security_admin.",
            }
        # ring1 always requires 2 approvals — trust score cannot bypass
        return {
            "allowed":            False,
            "requires_approval":  True,
            "approvals_required": 2,
            "policy_name":        policy_name,
            "deny_reason":        None,
        }

    # ring2 — standard: auto-allow if trust_score >= trust_min
    if ring == "ring2":
        trust_min = req.get("trust_min") or 80.0
        if trust_score >= trust_min:
            return {
                "allowed":            True,
                "requires_approval":  False,
                "approvals_required": 0,
                "policy_name":        policy_name,
                "deny_reason":        None,
            }
        # Below threshold — requires 1 approval
        return {
            "allowed":            False,
            "requires_approval":  True,
            "approvals_required": 1,
            "policy_name":        policy_name,
            "deny_reason":        None,
        }

    # ring3 — unprivileged: always auto-allowed
    return {
        "allowed":            True,
        "requires_approval":  False,
        "approvals_required": 0,
        "policy_name":        policy_name,
        "deny_reason":        None,
    }
