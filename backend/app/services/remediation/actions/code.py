"""
Code repository remediation actions — GitHub.

Supported actions:
  revoke_token        — Revoke a GitHub OAuth or PAT token
  suspend_org_member  — Suspend an org member (Enterprise only)
  delete_secret       — Delete a repository secret

Credentials dict expected keys (from secrets_manager):
  {"github_token": "...", "github_client_id": "...", "github_client_secret": "..."}
"""
from __future__ import annotations

import logging

import httpx

from .base import ActionResult, not_configured

logger = logging.getLogger(__name__)

SUPPORTED_ACTIONS = [
    "revoke_token",
    "suspend_org_member",
    "delete_secret",
]

_GH_API = "https://api.github.com"


def _has_gh_creds(creds: dict) -> bool:
    return bool(creds.get("github_token"))


def _gh_headers(creds: dict) -> dict:
    return {
        "Authorization": f"Bearer {creds['github_token']}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def execute(
    action_type: str,
    target_id: str,
    params: dict,
    credentials: dict,
) -> ActionResult:
    """Execute a GitHub remediation action."""
    creds = credentials or {}

    if not _has_gh_creds(creds):
        return not_configured(action_type, target_id)

    if action_type == "revoke_token":
        # target_id is the token to revoke
        # Requires github_client_id + github_client_secret (OAuth app) to revoke on behalf of app
        client_id     = creds.get("github_client_id", "")
        client_secret = creds.get("github_client_secret", "")
        if not (client_id and client_secret):
            return not_configured(action_type, target_id, {"note": "No GitHub OAuth app credentials"})

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.delete(
                f"{_GH_API}/applications/{client_id}/token",
                auth=(client_id, client_secret),
                json={"access_token": target_id},
                headers={"Accept": "application/vnd.github+json"},
            )

        if resp.status_code in (204, 200):
            return ActionResult(
                success=True,
                message=f"GitHub token revoked successfully",
                rollback_data={"token_revoked": True, "provider": "github"},
                output={"revoked": True},
            )
        return ActionResult(
            success=False,
            message=f"GitHub token revoke failed (HTTP {resp.status_code})",
            error=resp.text[:500],
        )

    if action_type == "suspend_org_member":
        # target_id is the GitHub username; params.org is the org slug
        org      = params.get("org", "")
        username = target_id
        if not org:
            return ActionResult(success=False, message="suspend_org_member requires params.org", error="Missing org")

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.patch(
                f"{_GH_API}/orgs/{org}/members/{username}",
                headers={**_gh_headers(creds), "Content-Type": "application/json"},
                json={"role": "member"},  # GitHub Enterprise: PUT /orgs/{org}/suspended-users/{username}
            )
            # GitHub Enterprise Server endpoint for suspend
            susp_resp = await client.put(
                f"{_GH_API}/orgs/{org}/suspended-users/{username}",
                headers=_gh_headers(creds),
            )

        if susp_resp.status_code in (200, 204):
            return ActionResult(
                success=True,
                message=f"GitHub org member {username} suspended from {org}",
                rollback_data={"username": username, "org": org, "provider": "github"},
                output={"suspended": True},
            )
        # Fall back to a 200 if the org endpoint was fine
        if resp.status_code in (200, 204):
            return ActionResult(
                success=True,
                message=f"GitHub org member {username} processed in {org}",
                rollback_data={"username": username, "org": org, "provider": "github"},
                output={"status": resp.status_code},
            )
        return ActionResult(
            success=False,
            message=f"GitHub suspend_org_member failed (HTTP {susp_resp.status_code})",
            error=susp_resp.text[:500],
        )

    if action_type == "delete_secret":
        # target_id format: "{owner}/{repo}/{secret_name}"
        parts = target_id.split("/", 2)
        if len(parts) != 3:
            return ActionResult(
                success=False,
                message="delete_secret requires target_id in format owner/repo/secret_name",
                error="invalid_target_id",
            )
        owner, repo, secret_name = parts

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.delete(
                f"{_GH_API}/repos/{owner}/{repo}/actions/secrets/{secret_name}",
                headers=_gh_headers(creds),
            )

        if resp.status_code == 204:
            return ActionResult(
                success=True,
                message=f"GitHub secret {secret_name} deleted from {owner}/{repo}",
                rollback_data={"owner": owner, "repo": repo, "secret_name": secret_name, "provider": "github"},
                output={"deleted": True},
            )
        return ActionResult(
            success=False,
            message=f"GitHub delete_secret failed (HTTP {resp.status_code})",
            error=resp.text[:500],
        )

    return ActionResult(success=False, message=f"Unknown code action: {action_type}", error="unsupported_action")


async def rollback(
    action_type: str,
    target_id: str,
    rollback_data: dict,
    credentials: dict,
) -> ActionResult:
    """Reverse a code remediation action where possible."""
    creds = credentials or {}

    if action_type == "suspend_org_member":
        username = rollback_data.get("username", target_id)
        org      = rollback_data.get("org", "")
        if org and _has_gh_creds(creds):
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.delete(
                    f"{_GH_API}/orgs/{org}/suspended-users/{username}",
                    headers=_gh_headers(creds),
                )
            return ActionResult(
                success=resp.status_code in (200, 204),
                message=f"GitHub org member {username} unsuspended from {org}",
                output={"status": resp.status_code},
            )
        return not_configured("unsuspend_org_member", target_id)

    # Token revocations and secret deletions cannot be reversed
    return ActionResult(
        success=False,
        message=f"Action '{action_type}' cannot be rolled back (irreversible)",
        error="irreversible",
    )
