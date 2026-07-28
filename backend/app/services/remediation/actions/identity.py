"""
Identity provider remediation actions — Okta + Microsoft Entra ID (Azure AD).

Supported actions:
  suspend_user        — Okta: lifecycle/suspend; Entra: accountEnabled=false
  unsuspend_user      — Okta: lifecycle/unsuspend; Entra: accountEnabled=true
  revoke_sessions     — Okta: DELETE /sessions; Entra: revokeSignInSessions
  force_mfa_reset     — Okta: lifecycle/resetFactors
  remove_group_member — Okta: DELETE groups/{group_id}/users/{user_id}

Credentials dict expected keys (from secrets_manager):
  For Okta:  {"okta_domain": "https://xxx.okta.com", "okta_token": "..."}
  For Entra: {"tenant_id": "...", "client_id": "...", "client_secret": "..."}
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import ActionResult, not_configured

logger = logging.getLogger(__name__)

SUPPORTED_ACTIONS = [
    "suspend_user",
    "unsuspend_user",
    "revoke_sessions",
    "force_mfa_reset",
    "remove_group_member",
]

OKTA_ACTIONS   = {"suspend_user", "unsuspend_user", "revoke_sessions", "force_mfa_reset", "remove_group_member"}
ENTRA_ACTIONS  = {"suspend_user", "unsuspend_user", "revoke_sessions"}


# ─── Okta helpers ─────────────────────────────────────────────────────────────

async def _okta_request(
    method: str,
    path: str,
    credentials: dict,
    json_body: dict | None = None,
) -> tuple[int, dict]:
    """Make an authenticated request to Okta. Returns (status_code, response_json)."""
    domain = credentials.get("okta_domain", "").rstrip("/")
    token  = credentials.get("okta_token", "")
    url    = f"{domain}{path}"
    headers = {
        "Authorization": f"SSWS {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.request(method, url, headers=headers, json=json_body)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
    return resp.status_code, body


async def _okta_suspend_user(user_id: str, creds: dict) -> ActionResult:
    status, body = await _okta_request("POST", f"/api/v1/users/{user_id}/lifecycle/suspend", creds)
    if status in (200, 204):
        return ActionResult(
            success=True,
            message=f"Okta user {user_id} suspended successfully",
            rollback_data={"was_active": True, "user_id": user_id, "provider": "okta"},
            output={"okta_response": body},
        )
    return ActionResult(
        success=False,
        message=f"Okta suspend failed (HTTP {status})",
        error=str(body),
    )


async def _okta_unsuspend_user(user_id: str, creds: dict) -> ActionResult:
    status, body = await _okta_request("POST", f"/api/v1/users/{user_id}/lifecycle/unsuspend", creds)
    if status in (200, 204):
        return ActionResult(success=True, message=f"Okta user {user_id} unsuspended", output={"okta_response": body})
    return ActionResult(success=False, message=f"Okta unsuspend failed (HTTP {status})", error=str(body))


async def _okta_revoke_sessions(user_id: str, creds: dict) -> ActionResult:
    status, body = await _okta_request("DELETE", f"/api/v1/users/{user_id}/sessions", creds)
    if status in (200, 204):
        return ActionResult(
            success=True,
            message=f"Okta sessions revoked for user {user_id}",
            rollback_data={"user_id": user_id, "provider": "okta"},
            output={"okta_response": body},
        )
    return ActionResult(success=False, message=f"Okta revoke sessions failed (HTTP {status})", error=str(body))


async def _okta_force_mfa_reset(user_id: str, creds: dict) -> ActionResult:
    status, body = await _okta_request("POST", f"/api/v1/users/{user_id}/lifecycle/resetFactors", creds)
    if status in (200, 204):
        return ActionResult(
            success=True,
            message=f"Okta MFA factors reset for user {user_id}",
            rollback_data={"user_id": user_id, "provider": "okta"},
            output={"okta_response": body},
        )
    return ActionResult(success=False, message=f"Okta MFA reset failed (HTTP {status})", error=str(body))


async def _okta_remove_group_member(user_id: str, params: dict, creds: dict) -> ActionResult:
    group_id = params.get("group_id", "")
    if not group_id:
        return ActionResult(success=False, message="remove_group_member requires params.group_id", error="Missing group_id")
    status, body = await _okta_request("DELETE", f"/api/v1/groups/{group_id}/users/{user_id}", creds)
    if status in (200, 204):
        return ActionResult(
            success=True,
            message=f"Okta user {user_id} removed from group {group_id}",
            rollback_data={"user_id": user_id, "group_id": group_id, "provider": "okta"},
            output={"okta_response": body},
        )
    return ActionResult(success=False, message=f"Okta remove group member failed (HTTP {status})", error=str(body))


# ─── Entra (Azure AD) helpers ─────────────────────────────────────────────────

async def _entra_get_token(creds: dict) -> str | None:
    """Acquire an access token for Microsoft Graph API."""
    tenant_id     = creds.get("tenant_id", "")
    client_id     = creds.get("client_id", "")
    client_secret = creds.get("client_secret", "")
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://graph.microsoft.com/.default",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, data=data)
        if resp.status_code == 200:
            return resp.json().get("access_token")
    return None


async def _entra_request(
    method: str,
    path: str,
    credentials: dict,
    json_body: dict | None = None,
) -> tuple[int, dict]:
    token = await _entra_get_token(credentials)
    if not token:
        return 401, {"error": "Could not acquire Entra access token"}
    url     = f"https://graph.microsoft.com/v1.0{path}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.request(method, url, headers=headers, json=json_body)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
    return resp.status_code, body


async def _entra_suspend_user(user_id: str, creds: dict) -> ActionResult:
    status, body = await _entra_request("PATCH", f"/users/{user_id}", creds, {"accountEnabled": False})
    if status in (200, 204):
        return ActionResult(
            success=True,
            message=f"Entra user {user_id} account disabled",
            rollback_data={"was_active": True, "user_id": user_id, "provider": "entra"},
            output={"entra_response": body},
        )
    return ActionResult(success=False, message=f"Entra disable user failed (HTTP {status})", error=str(body))


async def _entra_unsuspend_user(user_id: str, creds: dict) -> ActionResult:
    status, body = await _entra_request("PATCH", f"/users/{user_id}", creds, {"accountEnabled": True})
    if status in (200, 204):
        return ActionResult(success=True, message=f"Entra user {user_id} re-enabled", output={"entra_response": body})
    return ActionResult(success=False, message=f"Entra enable user failed (HTTP {status})", error=str(body))


async def _entra_revoke_sessions(user_id: str, creds: dict) -> ActionResult:
    status, body = await _entra_request("POST", f"/users/{user_id}/revokeSignInSessions", creds)
    if status in (200, 204):
        return ActionResult(
            success=True,
            message=f"Entra sign-in sessions revoked for user {user_id}",
            rollback_data={"user_id": user_id, "provider": "entra"},
            output={"entra_response": body},
        )
    return ActionResult(success=False, message=f"Entra revoke sessions failed (HTTP {status})", error=str(body))


# ─── Dispatcher ───────────────────────────────────────────────────────────────

def _has_okta_creds(creds: dict) -> bool:
    return bool(creds.get("okta_domain") and creds.get("okta_token"))


def _has_entra_creds(creds: dict) -> bool:
    return bool(creds.get("tenant_id") and creds.get("client_id") and creds.get("client_secret"))


async def execute(
    action_type: str,
    target_id: str,
    params: dict,
    credentials: dict,
) -> ActionResult:
    """Execute an identity action. Try Okta first, then Entra. Simulate if neither configured."""
    creds = credentials or {}

    if action_type == "suspend_user":
        if _has_okta_creds(creds):
            return await _okta_suspend_user(target_id, creds)
        if _has_entra_creds(creds):
            return await _entra_suspend_user(target_id, creds)
        return not_configured(action_type, target_id, {"was_active": True})

    if action_type == "unsuspend_user":
        if _has_okta_creds(creds):
            return await _okta_unsuspend_user(target_id, creds)
        if _has_entra_creds(creds):
            return await _entra_unsuspend_user(target_id, creds)
        return not_configured(action_type, target_id)

    if action_type == "revoke_sessions":
        if _has_okta_creds(creds):
            return await _okta_revoke_sessions(target_id, creds)
        if _has_entra_creds(creds):
            return await _entra_revoke_sessions(target_id, creds)
        return not_configured(action_type, target_id)

    if action_type == "force_mfa_reset":
        if _has_okta_creds(creds):
            return await _okta_force_mfa_reset(target_id, creds)
        return not_configured(action_type, target_id)

    if action_type == "remove_group_member":
        if _has_okta_creds(creds):
            return await _okta_remove_group_member(target_id, params, creds)
        return not_configured(action_type, target_id)

    return ActionResult(success=False, message=f"Unknown identity action: {action_type}", error="unsupported_action")


async def rollback(
    action_type: str,
    target_id: str,
    rollback_data: dict,
    credentials: dict,
) -> ActionResult:
    """Reverse a previously executed identity action."""
    creds = credentials or {}
    provider = rollback_data.get("provider", "")

    if action_type == "suspend_user":
        if rollback_data.get("was_active"):
            if provider == "okta" or _has_okta_creds(creds):
                return await _okta_unsuspend_user(target_id, creds)
            if provider == "entra" or _has_entra_creds(creds):
                return await _entra_unsuspend_user(target_id, creds)
            return not_configured("unsuspend_user", target_id)

    if action_type == "remove_group_member":
        group_id = rollback_data.get("group_id", "")
        if group_id and (provider == "okta" or _has_okta_creds(creds)):
            status, body = await _okta_request(
                "PUT",
                f"/api/v1/groups/{group_id}/users/{target_id}",
                creds,
            )
            return ActionResult(
                success=status in (200, 204),
                message=f"Restored group membership for user {target_id}",
                output={"okta_response": body},
            )
        return not_configured("restore_group_member", target_id)

    return ActionResult(
        success=False,
        message=f"No rollback handler for identity action '{action_type}'",
        error="no_rollback",
    )
