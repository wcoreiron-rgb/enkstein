"""
Endpoint remediation actions — CrowdStrike Falcon, Microsoft Defender, SentinelOne.

Supported actions:
  quarantine_device   — Network isolate a host
  unquarantine_device — Lift network isolation
  kill_process        — Terminate a running process (CrowdStrike RTR)

Credentials dict expected keys (from secrets_manager):
  CrowdStrike: {"cs_client_id": "...", "cs_client_secret": "...", "cs_base_url": "https://api.crowdstrike.com"}
  Defender:    {"defender_tenant_id": "...", "defender_client_id": "...", "defender_client_secret": "..."}
  SentinelOne: {"s1_base_url": "https://xxx.sentinelone.net", "s1_api_token": "..."}
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import ActionResult, not_configured

logger = logging.getLogger(__name__)

SUPPORTED_ACTIONS = [
    "quarantine_device",
    "unquarantine_device",
    "kill_process",
]


# ─── CrowdStrike ──────────────────────────────────────────────────────────────

def _has_cs_creds(creds: dict) -> bool:
    return bool(creds.get("cs_client_id") and creds.get("cs_client_secret"))


async def _cs_get_token(creds: dict) -> str | None:
    base = creds.get("cs_base_url", "https://api.crowdstrike.com").rstrip("/")
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base}/oauth2/token",
            data={
                "client_id":     creds["cs_client_id"],
                "client_secret": creds["cs_client_secret"],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code == 201:
            return resp.json().get("access_token")
    return None


async def _cs_contain_host(device_id: str, contain: bool, creds: dict) -> ActionResult:
    token = await _cs_get_token(creds)
    if not token:
        return ActionResult(success=False, message="CrowdStrike auth failed", error="auth_error")

    base   = creds.get("cs_base_url", "https://api.crowdstrike.com").rstrip("/")
    action = "contain" if contain else "lift_containment"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base}/devices/actions/v2",
            params={"action_name": action},
            json={"ids": [device_id]},
            headers=headers,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

    if resp.status_code in (200, 202):
        verb = "quarantined" if contain else "released from quarantine"
        return ActionResult(
            success=True,
            message=f"CrowdStrike device {device_id} {verb}",
            rollback_data={"device_id": device_id, "provider": "crowdstrike", "was_contained": not contain},
            output={"cs_response": body},
        )
    return ActionResult(success=False, message=f"CrowdStrike {action} failed (HTTP {resp.status_code})", error=str(body))


async def _cs_kill_process(device_id: str, params: dict, creds: dict) -> ActionResult:
    """Use CrowdStrike Real Time Response to kill a process."""
    token = await _cs_get_token(creds)
    if not token:
        return ActionResult(success=False, message="CrowdStrike auth failed", error="auth_error")

    process_name = params.get("process_name", "")
    pid          = params.get("pid", "")
    base         = creds.get("cs_base_url", "https://api.crowdstrike.com").rstrip("/")
    headers      = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 1. Init RTR session
    async with httpx.AsyncClient(timeout=30) as client:
        session_resp = await client.post(
            f"{base}/real-time-response/entities/sessions/v1",
            json={"device_id": device_id, "origin": "Enkstein"},
            headers=headers,
        )
        if session_resp.status_code not in (200, 201):
            return ActionResult(
                success=False,
                message=f"RTR session init failed (HTTP {session_resp.status_code})",
                error=str(session_resp.text),
            )
        session_id = session_resp.json().get("resources", [{}])[0].get("session_id", "")

        # 2. Execute kill command
        cmd    = f"kill {pid}" if pid else f"kill {process_name}"
        cmd_resp = await client.post(
            f"{base}/real-time-response/entities/active-responder-command/v1",
            json={
                "base_command":     "kill",
                "command_string":   cmd,
                "session_id":       session_id,
                "persist_all":      False,
            },
            headers=headers,
        )

    if cmd_resp.status_code in (200, 201):
        return ActionResult(
            success=True,
            message=f"Process kill command issued on device {device_id}: {cmd}",
            rollback_data={"device_id": device_id, "provider": "crowdstrike"},
            output={"command": cmd, "cs_response": cmd_resp.json() if cmd_resp.text else {}},
        )
    return ActionResult(
        success=False,
        message=f"RTR kill command failed (HTTP {cmd_resp.status_code})",
        error=str(cmd_resp.text),
    )


# ─── Microsoft Defender ───────────────────────────────────────────────────────

def _has_defender_creds(creds: dict) -> bool:
    return bool(
        creds.get("defender_tenant_id")
        and creds.get("defender_client_id")
        and creds.get("defender_client_secret")
    )


async def _defender_get_token(creds: dict) -> str | None:
    tenant_id     = creds["defender_tenant_id"]
    client_id     = creds["defender_client_id"]
    client_secret = creds["defender_client_secret"]
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
            "scope":         "https://api.securitycenter.microsoft.com/.default",
        })
        if resp.status_code == 200:
            return resp.json().get("access_token")
    return None


async def _defender_isolate(machine_id: str, isolate: bool, creds: dict) -> ActionResult:
    token = await _defender_get_token(creds)
    if not token:
        return ActionResult(success=False, message="Defender auth failed", error="auth_error")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    action  = "isolate" if isolate else "unisolate"
    url     = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/{action}"

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            url,
            json={"Comment": f"Enkstein autonomous {action}"},
            headers=headers,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

    if resp.status_code in (200, 201, 202):
        verb = "isolated" if isolate else "un-isolated"
        return ActionResult(
            success=True,
            message=f"Defender machine {machine_id} {verb}",
            rollback_data={"machine_id": machine_id, "provider": "defender", "was_isolated": not isolate},
            output={"defender_response": body},
        )
    return ActionResult(success=False, message=f"Defender {action} failed (HTTP {resp.status_code})", error=str(body))


# ─── SentinelOne ──────────────────────────────────────────────────────────────

def _has_s1_creds(creds: dict) -> bool:
    return bool(creds.get("s1_base_url") and creds.get("s1_api_token"))


async def _s1_disconnect(agent_id: str, disconnect: bool, creds: dict) -> ActionResult:
    base    = creds.get("s1_base_url", "").rstrip("/")
    token   = creds.get("s1_api_token", "")
    action  = "disconnect" if disconnect else "reconnect"
    headers = {"Authorization": f"ApiToken {token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base}/web/api/v2.1/agents/actions/{action}",
            json={"filter": {"ids": [agent_id]}},
            headers=headers,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

    if resp.status_code in (200, 202):
        verb = "disconnected (quarantined)" if disconnect else "reconnected"
        return ActionResult(
            success=True,
            message=f"SentinelOne agent {agent_id} {verb}",
            rollback_data={"agent_id": agent_id, "provider": "sentinelone", "was_connected": not disconnect},
            output={"s1_response": body},
        )
    return ActionResult(
        success=False,
        message=f"SentinelOne {action} failed (HTTP {resp.status_code})",
        error=str(body),
    )


# ─── Dispatcher ───────────────────────────────────────────────────────────────

async def execute(
    action_type: str,
    target_id: str,
    params: dict,
    credentials: dict,
) -> ActionResult:
    """Execute endpoint action. Tries CrowdStrike → Defender → S1. Simulates if none configured."""
    creds = credentials or {}

    if action_type == "quarantine_device":
        if _has_cs_creds(creds):
            return await _cs_contain_host(target_id, True, creds)
        if _has_defender_creds(creds):
            return await _defender_isolate(target_id, True, creds)
        if _has_s1_creds(creds):
            return await _s1_disconnect(target_id, True, creds)
        return not_configured(action_type, target_id, {"was_contained": False})

    if action_type == "unquarantine_device":
        if _has_cs_creds(creds):
            return await _cs_contain_host(target_id, False, creds)
        if _has_defender_creds(creds):
            return await _defender_isolate(target_id, False, creds)
        if _has_s1_creds(creds):
            return await _s1_disconnect(target_id, False, creds)
        return not_configured(action_type, target_id)

    if action_type == "kill_process":
        if _has_cs_creds(creds):
            return await _cs_kill_process(target_id, params, creds)
        return not_configured(action_type, target_id)

    return ActionResult(success=False, message=f"Unknown endpoint action: {action_type}", error="unsupported_action")


async def rollback(
    action_type: str,
    target_id: str,
    rollback_data: dict,
    credentials: dict,
) -> ActionResult:
    """Reverse an endpoint action."""
    creds    = credentials or {}
    provider = rollback_data.get("provider", "")

    if action_type == "quarantine_device":
        if provider == "crowdstrike" or _has_cs_creds(creds):
            return await _cs_contain_host(target_id, False, creds)
        if provider == "defender" or _has_defender_creds(creds):
            return await _defender_isolate(target_id, False, creds)
        if provider == "sentinelone" or _has_s1_creds(creds):
            return await _s1_disconnect(target_id, False, creds)
        return not_configured("unquarantine_device", target_id)

    return ActionResult(
        success=False,
        message=f"No rollback handler for endpoint action '{action_type}'",
        error="no_rollback",
    )
